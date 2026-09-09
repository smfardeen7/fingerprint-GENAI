"""Artificial traffic fixtures; NOT a model of any provider or empirical result."""
from pathlib import Path
import csv
import json
import struct
import numpy as np
import pandas as pd
from .dataset import REQUIRED

CLASSES=[('ai_a_voice','Service A','voice',1),('ai_a_video','Service A','video',1),
         ('ai_b_voice','Service B','voice',1),('ai_b_video','Service B','video',1),
         ('conventional_voice','Conventional','voice',0),('conventional_video','Conventional','video',0)]
PROFILES=['good','constrained','lossy']

def generate(out,seed=692,groups=20):
    out=Path(out)
    if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
    if groups<10:raise ValueError('At least ten scenario groups are needed for separate partitions.')
    out.mkdir(parents=True);(out/'packets').mkdir()
    rng=np.random.default_rng(seed);rows=[]
    ntrain=int(groups*.6);nval=int(groups*.2)
    for group in range(groups):
        split='train' if group<ntrain else ('validation' if group<ntrain+nval else 'test')
        day={'train':'2026-09-01','validation':'2026-09-02','test':'2026-09-03'}[split]
        scenario_speed=rng.uniform(.75,1.25)
        for ci,(label,service,mode,ai) in enumerate(CLASSES):
            for pi,profile in enumerate(PROFILES):
                sid=f'syn-g{group:02d}-c{ci}-p{pi}'
                t=np.arange(0,60,.02)
                period=12+rng.uniform(-2,2)
                phase=(t+rng.uniform(0,3))%period
                activity=np.where(phase<4,.75,1.25) if ai else np.ones(len(t))
                rates=np.array([22,46,26,51,30,55])
                n=rng.poisson(rates[ci]*scenario_speed*.02*activity)
                ts=np.repeat(t,n)+rng.uniform(0,.02,n.sum())
                phase=(ts+1)%period
                up_prob=np.where(phase<4,.82,.16) if ai else np.full(len(ts),.49)
                if mode=='video':up_prob=np.minimum(.95,up_prob+.25)
                direct=np.where(rng.random(len(ts))<up_prob,1,-1)
                mu=[260,940,430,1120,180,810][ci]
                sizes=np.clip(rng.normal(mu,mu*.3,len(ts)),40,1480).astype(int)
                if mode=='video':sizes=np.where(direct==1,sizes,np.clip(sizes*.4,40,1480)).astype(int)
                # Deliberately overlapping toy distributions; no calibrated network simulation.
                if pi:
                    ts+=rng.exponential(.015 if pi==1 else .03,len(ts))
                    sizes=np.clip(sizes*rng.uniform(.65,1.0),40,1480).astype(int)
                keep=(ts<60)&(rng.random(len(ts))>(.01 if pi==2 else 0))
                epoch=100000+group*1000+ci*100+pi*70
                p=pd.DataFrame({'timestamp':epoch+ts[keep],'length':sizes[keep],'direction':direct[keep]}).sort_values('timestamp')
                file=f'packets/{sid}.csv.gz';p.to_csv(out/file,index=False,float_format='%.9f',compression={'method':'gzip','mtime':0})
                rows.append([sid,f'scenario-{group:02d}',split,day,label,service,mode,ai,profile,file,epoch,60,'synthetic','toy-phone','not-a-real-app',0])
    pd.DataFrame(rows,columns=REQUIRED).to_csv(out/'manifest.csv',index=False)
    (out/'PROVENANCE.txt').write_text('SYNTHETIC SOFTWARE DEMONSTRATION ONLY.\nThese packets, classes, dates and profiles are generated fixtures. Scores do not measure real services or validate the research hypothesis.\n')
    sample_row=next(r for r in rows if r[2]=='test')
    sample=pd.read_csv(out/sample_row[9]);write_pcap(sample,out/'sample.pcap')
    (out/'sample_metadata.json').write_text(json.dumps({'device_ips':['192.0.2.10'],'ready_time':sample_row[10],'duration':60,'provenance':'synthetic'},indent=2))
    return out/'manifest.csv'

def write_pcap(p,path):
    """Write valid Ethernet/IPv4/UDP test packets. Documentation-only IP ranges."""
    with open(path,'wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for row in p.itertuples():
            length=max(28,int(row.length));src=b'\xc0\x00\x02\x0a';dst=b'\xc6\x33\x64\x14'
            if row.direction<0:src,dst=dst,src
            header=struct.pack('!BBHHHBBH4s4s',0x45,0,length,0,0,64,17,0,src,dst)
            words=struct.unpack('!10H',header);s=sum(words);s=(s&65535)+(s>>16);s=(s&65535)+(s>>16)
            header=header[:10]+struct.pack('!H',(~s)&65535)+header[12:]
            udp=struct.pack('!HHHH',5000,5001,length-20,0)+bytes(length-28)
            raw=bytes(12)+b'\x08\x00'+header+udp
            sec=int(row.timestamp);micro=int(round((row.timestamp-sec)*1e6))
            if micro==1000000:sec+=1;micro=0
            f.write(struct.pack('<IIII',sec,micro,len(raw),len(raw)));f.write(raw)
