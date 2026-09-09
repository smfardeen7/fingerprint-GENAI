"""Exactly the same feature computation for training and inference."""
from __future__ import annotations
import numpy as np
from .packets import validate_packets

HORIZONS=(5,10,30)

def _stats(prefix,values):
    a=np.asarray(values,dtype=float)
    names=['mean','std','min','q25','median','q75','p95','max']
    vals=[a.mean(),a.std(),a.min(),*np.quantile(a,[.25,.5,.75,.95]),a.max()] if len(a) else [0.]*8
    return dict(zip([prefix+'_'+n for n in names],map(float,vals)))

def extract_features(packets,ready_time,horizon,burst_gap=.05):
    if not np.isfinite([ready_time,horizon,burst_gap]).all() or horizon<=0 or burst_gap<=0:
        raise ValueError('Feature parameters must be finite; horizon/gap must be positive.')
    p=validate_packets(packets)
    p=p[(p.timestamp>=ready_time)&(p.timestamp<ready_time+horizon)]
    if p.empty: raise ValueError('No packets in observation window.')
    result={'volume_packets_per_s':len(p)/horizon,'volume_bytes_per_s':float(p.length.sum()/horizon)}
    for tag,part in [('all',p),('up',p[p.direction==1]),('down',p[p.direction==-1])]:
        sizes=part.length.to_numpy();ts=part.timestamp.to_numpy()
        result.update(_stats('size_'+tag,sizes))
        result.update(_stats('timing_'+tag+'_iat',np.diff(ts)))
        if len(part):
            cuts=np.r_[0,np.where(np.diff(ts)>burst_gap)[0]+1,len(ts)]
            counts=np.diff(cuts)
            byte_totals=[sizes[a:b].sum() for a,b in zip(cuts[:-1],cuts[1:])]
            durations=[ts[b-1]-ts[a] for a,b in zip(cuts[:-1],cuts[1:])]
            result['burst_'+tag+'_per_s']=(len(cuts)-1)/horizon
            result.update(_stats('burst_'+tag+'_packets',counts))
            result.update(_stats('burst_'+tag+'_bytes',byte_totals))
            result.update(_stats('burst_'+tag+'_duration',durations))
        else:
            result['burst_'+tag+'_per_s']=0.
            for key in ('packets','bytes','duration'):result.update(_stats('burst_'+tag+'_'+key,[]))
    result['direction_up_packet_fraction']=float((p.direction==1).mean())
    result['direction_up_byte_fraction']=float(p.loc[p.direction==1,'length'].sum()/p.length.sum())
    result['direction_switches_per_s']=float(np.count_nonzero(np.diff(p.direction))/horizon)
    return result

def feature_names(columns,subset):
    prefixes={'volume':('volume_',),'size':('size_',),'timing':('timing_',),
              'full':('volume_','size_','timing_','burst_','direction_')}
    if subset not in prefixes:raise ValueError('Unknown feature subset.')
    cols=sorted(c for c in columns if c.startswith(prefixes[subset]))
    if not cols:raise ValueError('No matching features.')
    return cols
