"""Payload-independent packet import. Never expose endpoints as ML features."""
from __future__ import annotations
import csv
import ipaddress
import math
import struct
from pathlib import Path
import numpy as np
import pandas as pd

COLUMNS = ['timestamp', 'length', 'direction']

def validate_packets(frame: pd.DataFrame) -> pd.DataFrame:
    if set(frame.columns) != set(COLUMNS):
        raise ValueError('Packet CSV must contain exactly timestamp,length,direction; no endpoint or label columns.')
    if frame.empty:
        raise ValueError('No packets found.')
    frame = frame[COLUMNS].apply(pd.to_numeric, errors='raise')
    if not np.isfinite(frame.to_numpy()).all():
        raise ValueError('Packet values must be finite.')
    if not frame.direction.isin([-1, 1]).all():
        raise ValueError('direction must be 1 (uplink) or -1 (downlink).')
    if ((frame.length < 20) | (frame.length > 65575) | (frame.length % 1 != 0)).any():
        raise ValueError('length must be an integer IP datagram size (20..65575 bytes).')
    frame.length = frame.length.astype(int)
    frame.direction = frame.direction.astype(int)
    return frame.sort_values('timestamp', kind='stable').reset_index(drop=True)

def read_packets(path):
    return validate_packets(pd.read_csv(path))

def _exact(f, n):
    value = f.read(n)
    if len(value) != n:
        raise ValueError('Truncated capture file.')
    return value

def _options(buf, endian):
    offset = 0
    while offset + 4 <= len(buf):
        code, n = struct.unpack_from(endian+'HH', buf, offset)
        offset += 4
        if code == 0:
            break
        if offset+n > len(buf):
            raise ValueError('Truncated pcapng option.')
        yield code, buf[offset:offset+n]
        offset += (n+3)//4*4

def capture_records(path):
    """Yield (epoch seconds, linktype, captured bytes), streaming classic PCAP/PCAPNG.

    PCAPNG supports section, interface and enhanced packet blocks. Timestamp-less
    simple packet blocks and obsolete packet blocks fail instead of losing timing.
    """
    with open(path, 'rb') as f:
        magic = _exact(f, 4)
        formats = {b'\xd4\xc3\xb2\xa1':('<',1e-6), b'\xa1\xb2\xc3\xd4':('>',1e-6),
                   b'\x4d\x3c\xb2\xa1':('<',1e-9), b'\xa1\xb2\x3c\x4d':('>',1e-9)}
        if magic in formats:
            endian, resolution = formats[magic]
            hdr = _exact(f, 20)
            major, minor, _, _, snaplen, linktype = struct.unpack(endian+'HHIIII', hdr)
            if (major, minor) != (2,4):
                raise ValueError('Unsupported PCAP version.')
            linktype &= 0xffff
            while True:
                h = f.read(16)
                if not h: break
                if len(h) != 16: raise ValueError('Truncated packet header.')
                sec, frac, caplen, wirelen = struct.unpack(endian+'IIII',h)
                if caplen > 16*1024*1024 or caplen > wirelen or caplen > snaplen:
                    raise ValueError('Invalid packet length.')
                yield sec+frac*resolution, linktype, _exact(f,caplen)
            return
        if magic != b'\x0a\x0d\x0d\x0a':
            raise ValueError('Expected PCAP or PCAPNG file.')
        f.seek(0)
        endian = None
        interfaces = []
        while True:
            head = f.read(8)
            if not head: break
            if len(head) != 8: raise ValueError('Truncated pcapng block.')
            if head[:4] == b'\x0a\x0d\x0d\x0a':
                bom = _exact(f,4)
                if bom == b'\x4d\x3c\x2b\x1a': endian = '<'
                elif bom == b'\x1a\x2b\x3c\x4d': endian = '>'
                else: raise ValueError('Invalid pcapng byte order.')
                n = struct.unpack(endian+'I',head[4:])[0]
                if n < 28 or n > 16*1024*1024 or n % 4: raise ValueError('Invalid section block.')
                rest = _exact(f,n-12)
                if struct.unpack(endian+'I',rest[-4:])[0] != n: raise ValueError('Block length mismatch.')
                interfaces = []
                continue
            if endian is None: raise ValueError('Missing pcapng section.')
            kind,n = struct.unpack(endian+'II',head)
            if n < 12 or n > 16*1024*1024 or n % 4: raise ValueError('Invalid pcapng block length.')
            data = _exact(f,n-8)
            if struct.unpack(endian+'I',data[-4:])[0] != n: raise ValueError('Block length mismatch.')
            data=data[:-4]
            if kind == 1:
                if len(data)<8: raise ValueError('Invalid interface block.')
                linktype,_,snap = struct.unpack_from(endian+'HHI',data)
                resolution,offset=1e-6,0
                for code,value in _options(data[8:],endian):
                    if code == 9 and value:
                        r=value[0];resolution=(2.0**-(r&127)) if r&128 else 10.0**-r
                    if code == 14 and len(value)==8: offset=struct.unpack(endian+'q',value)[0]
                interfaces.append((linktype,resolution,offset))
            elif kind == 6:
                if len(data)<20: raise ValueError('Invalid enhanced packet block.')
                idx,hi,lo,caplen,wirelen=struct.unpack_from(endian+'IIIII',data)
                if idx>=len(interfaces) or caplen>wirelen or 20+caplen>len(data):
                    raise ValueError('Invalid enhanced packet metadata.')
                link,res,offset=interfaces[idx]
                yield ((hi<<32)|lo)*res+offset,link,data[20:20+caplen]
            elif kind in (2,3):
                raise ValueError('Timestamp-less/obsolete packet block unsupported; convert to enhanced PCAPNG or PCAP.')

def ip_metadata(link, packet):
    if link == 1:  # Ethernet, including stacked VLAN tags
        if len(packet)<14: raise ValueError('Truncated Ethernet header.')
        proto=struct.unpack_from('!H',packet,12)[0];offset=14
        while proto in (0x8100,0x88a8,0x9100):
            if len(packet)<offset+4: raise ValueError('Truncated VLAN header.')
            proto=struct.unpack_from('!H',packet,offset+2)[0];offset+=4
        if proto not in (0x0800,0x86dd): return None
    elif link == 113:  # Linux cooked
        if len(packet)<16: raise ValueError('Truncated Linux SLL header.')
        if struct.unpack_from('!H',packet,14)[0] not in (0x0800,0x86dd): return None
        offset=16
    elif link == 276:
        if len(packet)<20: raise ValueError('Truncated Linux SLL2 header.')
        if struct.unpack_from('!H',packet)[0] not in (0x0800,0x86dd): return None
        offset=20
    elif link in (101,228,229): offset=0
    elif link in (0,108): offset=4
    else: raise ValueError(f'Unsupported capture link type {link}. Use Ethernet, RAW IP, or Linux SLL/SLL2.')
    p=packet[offset:]
    if not p: raise ValueError('Missing IP header.')
    version=p[0]>>4
    if version==4:
        if len(p)<20 or (p[0]&15)<5: raise ValueError('Truncated/invalid IPv4 header.')
        n=struct.unpack_from('!H',p,2)[0]
        if n < (p[0]&15)*4: raise ValueError('Invalid IPv4 total length.')
        return str(ipaddress.ip_address(p[12:16])),str(ipaddress.ip_address(p[16:20])),n
    if version==6:
        if len(p)<40: raise ValueError('Truncated IPv6 header.')
        plen=struct.unpack_from('!H',p,4)[0]
        if plen==0: raise ValueError('IPv6 jumbograms are outside the supported dataset schema.')
        return str(ipaddress.ip_address(p[8:24])),str(ipaddress.ip_address(p[24:40])),40+plen
    return None

def import_capture(source, output, device_ips):
    devices={str(ipaddress.ip_address(ip)) for ip in device_ips}
    if not devices: raise ValueError('At least one test-device address is required.')
    rows=[];seen=0;nonip=0;other=0
    for t,link,raw in capture_records(source):
        seen+=1;meta=ip_metadata(link,raw)
        if meta is None: nonip+=1;continue
        src,dst,length=meta
        if (src in devices)==(dst in devices): other+=1;continue
        rows.append((t,length,1 if src in devices else -1))
    data=validate_packets(pd.DataFrame(rows,columns=COLUMNS))
    out=Path(output)
    if out.exists(): raise FileExistsError(f'Refusing to overwrite {out}')
    out.parent.mkdir(parents=True,exist_ok=True)
    data.to_csv(out,index=False,float_format='%.9f')
    return {'seen':seen,'imported':len(data),'non_ip':nonip,'other_or_ambiguous':other}
