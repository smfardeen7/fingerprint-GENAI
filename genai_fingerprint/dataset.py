from __future__ import annotations
import hashlib
import json
from pathlib import Path
import numpy as np
import pandas as pd
from .features import extract_features,HORIZONS
from .packets import read_packets

REQUIRED=['session_id','scenario_group','split','date','label','service','mode','is_genai',
          'profile','packet_file','ready_time','duration','provenance','device_id','app_version','capture_drops']
SPLITS=('train','validation','test')

def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def load_manifest(path,check_files=True):
    path=Path(path).resolve()
    df=pd.read_csv(path,dtype={'session_id':str,'scenario_group':str,'date':str})
    missing=set(REQUIRED)-set(df.columns)
    if missing: raise ValueError(f'Missing manifest columns: {sorted(missing)}')
    if df.empty or df[REQUIRED].isna().any().any():raise ValueError('Manifest is empty or contains missing required values.')
    if df.session_id.duplicated().any():raise ValueError('Duplicate session_id.')
    if not set(df.split)==set(SPLITS):raise ValueError('Manifest must include train, validation, and test partitions only.')
    if not df.is_genai.isin([0,1]).all() or not df['mode'].isin(['voice','video']).all():raise ValueError('Invalid class metadata.')
    if not df.provenance.isin(['real','synthetic']).all() or df.provenance.nunique()!=1:
        raise ValueError('Use an entirely real or entirely synthetic dataset; never mix.')
    if df.groupby('label')[['service','mode','is_genai']].nunique().gt(1).any().any():
        raise ValueError('Each label must map to exactly one service, mode, and AI status.')
    if df[['label','service','mode','is_genai']].drop_duplicates().duplicated(['service','mode']).any():
        raise ValueError('Each service/mode combination must have one label.')
    if df.groupby('scenario_group').split.nunique().max()>1:raise ValueError('Scenario leakage across partitions.')
    dates=pd.to_datetime(df.date,format='%Y-%m-%d',errors='raise')
    if df.groupby('date').split.nunique().max()>1:raise ValueError('Collection day leakage across partitions.')
    for before,after in zip(SPLITS[:-1],SPLITS[1:]):
        if dates[df.split==before].max()>=dates[df.split==after].min():raise ValueError('Partitions must use later collection days in train/validation/test order.')
    classes=set(df.label)
    if len(classes)<2:raise ValueError('At least two classes required.')
    for part in SPLITS:
        if set(df.loc[df.split==part,'label'])!=classes:raise ValueError(f'{part} is missing a class.')
        if df.loc[df.split==part,'scenario_group'].nunique()<2:raise ValueError(f'{part} requires at least two independent scenario groups.')
    for field in ('ready_time','duration','capture_drops'):
        df[field]=pd.to_numeric(df[field],errors='raise')
        if not np.isfinite(df[field]).all():raise ValueError(f'Invalid {field}.')
    if (df.duration<max(HORIZONS)).any():raise ValueError('Every capture must cover at least 30 active seconds.')
    if (df.capture_drops<0).any():raise ValueError('Record capture drops as a nonnegative count.')
    hashes=[]
    if check_files:
        for raw in df.packet_file:
            target=(path.parent/raw).resolve()
            if not target.is_relative_to(path.parent):raise ValueError('Packet files must be inside the dataset directory.')
            if not target.is_file():raise ValueError(f'Packet file missing: {raw}')
            # Hash normalized contents, not gzip headers, filenames, or timestamps.
            p=read_packets(target)
            p.timestamp=p.timestamp-p.timestamp.iloc[0]
            canonical=p.to_csv(index=False,float_format='%.6f').encode()
            hashes.append(hashlib.sha256(canonical).hexdigest())
        if len(hashes)!=len(set(hashes)):raise ValueError('Duplicate packet trace content. Do not count a replayed file as a new capture.')
    audit={'sessions':len(df),'scenario_groups':int(df.scenario_group.nunique()),'classes':sorted(classes),
           'provenance':df.provenance.iloc[0],'splits':df.split.value_counts().to_dict(),
           'capture_drops_total':int(df.capture_drops.sum()),'manifest_sha256':sha256(path),
           'packet_hashes':dict(zip(df.session_id,hashes))}
    return df,audit

def build_features(manifest,out,burst_gap=.05):
    manifest=Path(manifest).resolve();out=Path(out)
    if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
    df,audit=load_manifest(manifest)
    rows=[]
    for _,r in df.iterrows():
        p=read_packets(manifest.parent/r.packet_file)
        for horizon in HORIZONS:
            row={key:r[key] for key in REQUIRED if key!='packet_file'}
            row['horizon']=horizon
            row.update(extract_features(p,float(r.ready_time),horizon,burst_gap))
            rows.append(row)
    out.mkdir(parents=True)
    pd.DataFrame(rows).to_csv(out/'features.csv',index=False)
    audit['burst_gap_seconds']=burst_gap;audit['horizons']=list(HORIZONS)
    audit['features_sha256']=sha256(out/'features.csv')
    (out/'audit.json').write_text(json.dumps(audit,indent=2))
    return audit

def register_capture(worksheet,session_id,source,device_ips,ready_time,duration,date,service,device_id,app_version,capture_drops,dataset):
    """Import one completed real session into a growing manifest; no fake labels."""
    from .packets import import_capture
    import re
    if not re.fullmatch(r'[A-Za-z0-9_-]+',session_id):raise ValueError('Invalid session identifier.')
    plan=pd.read_csv(worksheet);selected=plan[plan.session_id==session_id]
    if len(selected)!=1:raise ValueError('Session identifier must match exactly one worksheet row.')
    pd.to_datetime(date,format='%Y-%m-%d',errors='raise')
    if not np.isfinite([ready_time,duration,capture_drops]).all() or duration<30 or capture_drops<0:
        raise ValueError('Invalid timing/drop count.')
    if not all(str(v).strip() for v in (service,device_id,app_version)):raise ValueError('Actual service, device and app version required.')
    target=Path(dataset);target.mkdir(parents=True,exist_ok=True);manifest=target/'manifest.csv'
    existing=pd.read_csv(manifest) if manifest.exists() else pd.DataFrame()
    if len(existing) and session_id in set(existing.session_id):raise ValueError('Session already registered.')
    r=selected.iloc[0].to_dict();r['label']=r.get('planned_label',r.get('label'))
    if not isinstance(r['label'],str):raise ValueError('Worksheet needs a planned_label.')
    file=f'packets/{session_id}.csv'
    stats=import_capture(source,target/file,device_ips)
    try:
        packets=read_packets(target/file)
        for h in HORIZONS:extract_features(packets,ready_time,h)
        r.update({'packet_file':file,'ready_time':ready_time,'duration':duration,'date':date,'service':service,
                  'device_id':device_id,'app_version':app_version,'capture_drops':capture_drops,'provenance':'real'})
        row={k:r[k] for k in REQUIRED};row['capture_sha256']=sha256(source)
        result=pd.concat([existing,pd.DataFrame([row])],ignore_index=True)
        staged=manifest.with_suffix('.csv.tmp');result.to_csv(staged,index=False);staged.replace(manifest)
    except BaseException:
        (target/file).unlink(missing_ok=True);raise
    return {'manifest':str(manifest),'registered':session_id,'total_sessions':len(result),'import_stats':stats}
