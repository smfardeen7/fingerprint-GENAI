import argparse,json
from pathlib import Path

def emit(v):print(json.dumps(v,indent=2,default=str))
def main(argv=None):
    p=argparse.ArgumentParser(prog='genai-fingerprint',description='Metadata-only traffic fingerprinting research pipeline')
    sub=p.add_subparsers(dest='cmd',required=True)
    q=sub.add_parser('demo',help='Full synthetic workflow');q.add_argument('--out',default='runs/demo');q.add_argument('--seed',type=int,default=692)
    q=sub.add_parser('synthetic');q.add_argument('--out',required=True);q.add_argument('--seed',type=int,default=692);q.add_argument('--groups',type=int,default=20)
    q=sub.add_parser('import-pcap');q.add_argument('source');q.add_argument('--out',required=True);q.add_argument('--device-ip',action='append',required=True)
    q=sub.add_parser('validate');q.add_argument('manifest')
    q=sub.add_parser('features');q.add_argument('manifest');q.add_argument('--out',required=True);q.add_argument('--burst-gap',type=float,default=.05)
    q=sub.add_parser('train');q.add_argument('features');q.add_argument('--out',required=True);q.add_argument('--seed',type=int,default=692);q.add_argument('--bootstrap',type=int,default=300)
    q=sub.add_parser('predict');q.add_argument('--model',required=True);q.add_argument('--packets',required=True);q.add_argument('--ready-time',required=True,type=float);q.add_argument('--duration',required=True,type=float);q.add_argument('--provenance',choices=['real','synthetic'],required=True)
    q=sub.add_parser('report');q.add_argument('run')
    q=sub.add_parser('capture');q.add_argument('--interface',required=True);q.add_argument('--device-ip',action='append',required=True);q.add_argument('--out',required=True);q.add_argument('--duration',type=int,default=60)
    q=sub.add_parser('network');q.add_argument('action',choices=['plan','apply','remove']);q.add_argument('--namespace',required=True);q.add_argument('--uplink',required=True);q.add_argument('--downlink',required=True);q.add_argument('--profile',choices=['good','constrained','lossy'],default='good')
    q=sub.add_parser('plan');q.add_argument('--out',required=True);q.add_argument('--seed',type=int,default=692)
    q=sub.add_parser('register',help='Import a completed real capture and append its worksheet label')
    for name in ['worksheet','session-id','source','date','service','device-id','app-version','dataset']:q.add_argument('--'+name,required=True)
    q.add_argument('--device-ip',action='append',required=True)
    q.add_argument('--ready-time',type=float,required=True);q.add_argument('--duration',type=float,required=True);q.add_argument('--capture-drops',type=int,required=True)
    a=p.parse_args(argv)
    try:
        if a.cmd=='synthetic':
            from .synthetic import generate
            emit({'manifest':generate(a.out,a.seed,a.groups),'provenance':'synthetic'})
        elif a.cmd=='demo':
            from .synthetic import generate
            from .dataset import build_features
            from .models import train_evaluate,predict
            from .packets import import_capture
            out=Path(a.out)
            if out.exists():raise FileExistsError(f'{out} exists; select a new output folder.')
            manifest=generate(out/'data',a.seed)
            import_capture(out/'data/sample.pcap',out/'data/sample_imported.csv',['192.0.2.10'])
            print('Synthetic packets generated; extracting features.',flush=True)
            build_features(manifest,out/'features')
            print('Training and evaluating held-out scenarios.',flush=True)
            summary=train_evaluate(out/'features',out/'evaluation',a.seed)
            meta=json.loads((out/'data/sample_metadata.json').read_text())
            result=predict(out/'evaluation/models/fingerprint_30s.joblib',out/'data/sample_imported.csv',meta['ready_time'],60,'synthetic')
            (out/'demo_prediction.json').write_text(json.dumps(result,indent=2))
            emit({'report':out/'evaluation/report.html','prediction':result,'notice':summary['notice']})
        elif a.cmd=='import-pcap':
            from .packets import import_capture
            emit(import_capture(a.source,a.out,a.device_ip))
        elif a.cmd=='register':
            from .dataset import register_capture
            emit(register_capture(a.worksheet,a.session_id,a.source,a.device_ip,a.ready_time,a.duration,a.date,a.service,a.device_id,a.app_version,a.capture_drops,a.dataset))
        elif a.cmd=='validate':
            from .dataset import load_manifest
            _,audit=load_manifest(a.manifest);emit({k:v for k,v in audit.items() if k!='packet_hashes'})
        elif a.cmd=='features':
            from .dataset import build_features
            audit=build_features(a.manifest,a.out,a.burst_gap);emit({k:v for k,v in audit.items() if k!='packet_hashes'})
        elif a.cmd=='train':
            from .models import train_evaluate
            if a.bootstrap<100:raise ValueError('Use at least 100 bootstrap resamples.')
            s=train_evaluate(a.features,a.out,a.seed,a.bootstrap);emit({'report':str(Path(a.out)/'report.html'),'notice':s['notice']})
        elif a.cmd=='predict':
            from .models import predict
            emit(predict(a.model,a.packets,a.ready_time,a.duration,a.provenance))
        elif a.cmd=='report':
            from .report import render_report
            render_report(a.run);emit({'report':str(Path(a.run)/'report.html')})
        elif a.cmd=='capture':
            from .acquire import capture
            emit(capture(a.interface,a.device_ip,a.out,a.duration))
        elif a.cmd=='network':
            from .acquire import network_plan,network_change
            kw=dict(namespace=a.namespace,uplink=a.uplink,downlink=a.downlink,profile=a.profile)
            emit(network_plan(**kw) if a.action=='plan' else network_change(**kw,remove=a.action=='remove'))
        elif a.cmd=='plan':
            import numpy as np,pandas as pd
            from .synthetic import CLASSES,PROFILES
            out=Path(a.out)
            if out.exists():raise FileExistsError(f'{out} exists.')
            rows=[];rng=np.random.default_rng(a.seed)
            for split,groups in [('train',range(12)),('validation',range(12,16)),('test',range(16,20))]:
                items=[{'session_id':f'g{g:02d}-c{c}-p{pi}','scenario_group':f'scenario-{g:02d}','split':split,
                        'planned_label':label,'service':service,'mode':mode,'is_genai':ai,'profile':profile,'status':'planned',
                        'date':'','packet_file':'','ready_time':'','duration':60,'provenance':'real','device_id':'','app_version':'','capture_drops':''}
                       for g in groups for c,(label,service,mode,ai) in enumerate(CLASSES) for pi,profile in enumerate(PROFILES)]
                rng.shuffle(items);rows.extend(items)
            out.parent.mkdir(parents=True,exist_ok=True);pd.DataFrame(rows).to_csv(out,index=False)
            emit({'worksheet':out,'sessions':len(rows),'note':'Replace service placeholders, fill measured fields, and rename planned_label to label for completed sessions.'})
    except (ValueError,FileExistsError,FileNotFoundError,RuntimeError) as exc:p.exit(2,f'Error: {exc}\n')
if __name__=='__main__':main()
