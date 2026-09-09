"""Local capture and explicitly isolated network emulation."""
import ipaddress,json,re,shutil,subprocess,time
from pathlib import Path
PROFILES={'good':['rate','10mbit'],'constrained':['rate','1mbit','delay','50ms'],'lossy':['rate','1mbit','delay','50ms','loss','random','1%']}
def network_plan(namespace,uplink,downlink,profile):
    for name in (namespace,uplink,downlink):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',name):raise ValueError('Invalid namespace/interface name.')
    if uplink==downlink:raise ValueError('Use distinct gateway egress interfaces.')
    base=['ip','netns','exec',namespace,'tc']
    return [{'inspect':base+['-j','qdisc','show','dev',dev],
             'apply':base+['qdisc','add','dev',dev,'root','handle','692:','netem']+PROFILES[profile],
             'remove':base+['qdisc','del','dev',dev,'root','handle','692:']} for dev in (uplink,downlink)]
def network_change(namespace,uplink,downlink,profile,remove=False):
    plan=network_plan(namespace,uplink,downlink,profile)
    for item in plan:
        state=json.loads(subprocess.check_output(item['inspect'],text=True))
        owned=[q for q in state if q.get('handle')=='692:' and q.get('kind')=='netem']
        if remove and not owned:raise ValueError('Refusing to remove a qdisc not owned by this project.')
        if not remove and any(q.get('kind')!='noqueue' for q in state):raise ValueError('Existing qdisc; use fresh dedicated lab interfaces.')
    done=[]
    try:
        for item in plan:subprocess.run(item['remove' if remove else 'apply'],check=True);done.append(item)
    except subprocess.CalledProcessError:
        if not remove:
            for item in reversed(done):subprocess.run(item['remove'],check=False)
        raise
    return {'namespace':namespace,'profile':profile,'removed':remove,'commands':plan}
def capture(interface,device_ips,out,duration=60):
    exe=shutil.which('tshark')
    if not exe:raise RuntimeError('TShark is not installed. Install tshark on the capture gateway.')
    if duration<35:raise ValueError('Capture at least 35 seconds.')
    devices=[str(ipaddress.ip_address(ip)) for ip in device_ips]
    out=Path(out)
    if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
    out.parent.mkdir(parents=True,exist_ok=True)
    command=[exe,'-q','-n','-i',interface,'-f',' or '.join('host '+ip for ip in devices),'-s','160','-a',f'duration:{duration+5}','-w',str(out)]
    started=time.time();proc=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    try:
        time.sleep(5);ready=time.time()
        if proc.poll() is not None:raise RuntimeError(proc.communicate()[1] or 'Capture stopped before ready marker.')
        print('READY: active observation begins now. Perform the scenario.',flush=True)
        _,stderr=proc.communicate(timeout=duration+30);ended=time.time()
        if proc.returncode:raise RuntimeError(stderr)
        if ended-ready<30:raise RuntimeError('Capture did not cover 30 active seconds.')
    except BaseException:
        if proc.poll() is None:proc.terminate();proc.communicate()
        raise
    out.with_suffix(out.suffix+'.log').write_text(stderr)
    found=re.findall(r'(\d+)\s+(?:packets\s+)?dropped',stderr,re.I)
    record={'ready_time':ready,'duration':min(duration,ended-ready),'capture_started_at':started,'capture_ended_at':ended,
            'device_ips':devices,'provenance':'real','capture_drops':int(found[-1]) if found else None,
            'drop_count_note':'Verify statistics in the capture log before adding a manifest row.',
            'command':command,'clock':'gateway wall clock; same clock as packet timestamps'}
    out.with_suffix(out.suffix+'.json').write_text(json.dumps(record,indent=2));return record
