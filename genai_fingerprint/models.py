from __future__ import annotations
import json
import platform
from pathlib import Path
import warnings
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score,accuracy_score,confusion_matrix,classification_report
from sklearn.inspection import permutation_importance
from .features import feature_names,extract_features
from .dataset import sha256
from .packets import read_packets
from . import __version__

SPECS=[('majority','volume'),('volume_logistic','volume'),('size_logistic','size'),
       ('timing_logistic','timing'),('full_logistic','full'),('random_forest','full')]

def candidates(name,seed):
    if name=='majority':return [('most_frequent',DummyClassifier(strategy='most_frequent'))]
    if name=='random_forest':return [(f'depth={depth}',RandomForestClassifier(n_estimators=80,max_depth=depth,min_samples_leaf=2,class_weight='balanced',random_state=seed,n_jobs=1)) for depth in (8,None)]
    return [(f'C={c}',make_pipeline(StandardScaler(),LogisticRegression(C=c,max_iter=2000,class_weight='balanced',random_state=seed))) for c in (.1,1.,10.)]

def score(y,pred,labels):return float(f1_score(y,pred,labels=labels,average='macro',zero_division=0))

def paired_group_intervals(y,pred,baseline,groups,labels,seed,n=300):
    y=np.asarray(y);pred=np.asarray(pred);baseline=np.asarray(baseline);groups=np.asarray(groups)
    unique=np.unique(groups);rng=np.random.default_rng(seed);fs=[];diff=[]
    positions={g:np.flatnonzero(groups==g) for g in unique}
    for _ in range(n):
        ix=np.concatenate([positions[g] for g in rng.choice(unique,len(unique),replace=True)])
        f=score(y[ix],pred[ix],labels);fs.append(f);diff.append(f-score(y[ix],baseline[ix],labels))
    return {'macro_f1_95ci':np.quantile(fs,[.025,.975]).tolist(),
            'gain_over_volume_95ci':np.quantile(diff,[.025,.975]).tolist(),
            'scenario_groups':len(unique),'resamples':n,'method':'paired percentile bootstrap by scenario group',
            'warning':'Few independent test groups; intervals may be unstable.' if len(unique)<10 else ''}

def train_evaluate(feature_dir,out,seed=692,bootstrap=300):
    feature_dir=Path(feature_dir);out=Path(out)
    if out.exists():raise FileExistsError(f'Refusing to overwrite {out}; use a new experiment folder.')
    audit=json.loads((feature_dir/'audit.json').read_text())
    if sha256(feature_dir/'features.csv')!=audit['features_sha256']:raise ValueError('Feature file changed after extraction; rebuild audited features.')
    df=pd.read_csv(feature_dir/'features.csv')
    if df.duplicated(['session_id','horizon']).any():raise ValueError('Duplicate session horizon.')
    if df.groupby('scenario_group').split.nunique().max()>1:raise ValueError('Group leakage.')
    labels=sorted(df.label.unique());provenance=audit['provenance']
    if set(df.provenance)!={provenance}:raise ValueError('Provenance mismatch.')
    classmeta=df[['label','service','mode','is_genai']].drop_duplicates().set_index('label').to_dict('index')
    out.mkdir(parents=True);(out/'models').mkdir()
    metrics=[];predictions=[];details={};importance=[];saved=[]
    for horizon in sorted(df.horizon.unique()):
        hdf=df[df.horizon==horizon]
        for experiment in ['mixed_profiles','good_to_degraded']:
            tr=hdf[hdf.split=='train'];va=hdf[hdf.split=='validation'];te=hdf[hdf.split=='test']
            if experiment=='good_to_degraded':
                tr=tr[tr.profile=='good'];va=va[va.profile=='good']
                if tr.empty or va.empty:continue
            if set(tr.label)!=set(labels) or set(va.label)!=set(labels):raise ValueError(f'Missing class in training/validation for {experiment}.')
            fitted={};tests={};val_scores={}
            for name,subset in SPECS:
                cols=feature_names(df.columns,subset);best=None
                for setting,model in candidates(name,seed):
                    model.fit(tr[cols],tr.label)
                    f=score(va.label,model.predict(va[cols]),labels)
                    if best is None or f>best[0]:best=(f,setting,model)
                vf,setting,model=best;pred=model.predict(te[cols]);fitted[name]=(model,cols,setting);tests[name]=pred;val_scores[name]=vf
                metrics.append({'experiment':experiment,'horizon':int(horizon),'model':name,'feature_subset':subset,
                                'validation_macro_f1':vf,'test_macro_f1':score(te.label,pred,labels),
                                'test_accuracy':float(accuracy_score(te.label,pred)),'test_sessions':len(te),
                                'setting':setting,'provenance':provenance})
            # Crucially, select the deployed classifier by validation score, never test results.
            eligible=[name for name,_ in SPECS if name!='majority']
            winner=max(eligible,key=lambda k:val_scores[k]);model,cols,setting=fitted[winner];pred=tests[winner]
            key=f'{experiment}_{int(horizon)}s'
            profile_scores={p:score(te.loc[te.profile==p,'label'],pred[te.profile.to_numpy()==p],labels) for p in sorted(te.profile.unique())}
            ai_true=te.is_genai.to_numpy();ai_pred=np.array([classmeta[c]['is_genai'] for c in pred]);mask=ai_true==0
            ci=paired_group_intervals(te.label,pred,tests['volume_logistic'],te.scenario_group,labels,seed,bootstrap)
            details[key]={'selected_model':winner,'selected_setting':setting,'selection_basis':'validation macro-F1 only',
                          'profile_macro_f1':profile_scores,'confusion_matrix':confusion_matrix(te.label,pred,labels=labels).tolist(),
                          'classification_report':classification_report(te.label,pred,labels=labels,output_dict=True,zero_division=0),
                          'ai_false_positive_rate':float((ai_pred[mask]==1).mean()) if mask.any() else None,
                          'service_accuracy':float(np.mean([classmeta[p]['service']==s for p,s in zip(pred,te.service)])),
                          'mode_accuracy':float(np.mean([classmeta[p]['mode']==m for p,m in zip(pred,te['mode'])])),
                          'macro_f1_gain_over_volume':score(te.label,pred,labels)-score(te.label,tests['volume_logistic'],labels),**ci}
            for idx,(_,r) in enumerate(te.iterrows()):
                predictions.append({'experiment':experiment,'horizon':int(horizon),'session_id':r.session_id,
                    'scenario_group':r.scenario_group,'profile':r.profile,'actual':r.label,'predicted':pred[idx],
                    'model':winner,'provenance':provenance})
            if experiment=='mixed_profiles':
                bundle={'schema_version':1,'software_version':__version__,'sklearn_version':sklearn.__version__,
                        'model':model,'features':cols,'horizon':int(horizon),'burst_gap':audit['burst_gap_seconds'],
                        'labels':labels,'class_metadata':classmeta,'provenance':provenance,'model_name':winner,
                        'training_manifest_sha256':audit['manifest_sha256']}
                modelpath=out/'models'/f'fingerprint_{int(horizon)}s.joblib';joblib.dump(bundle,modelpath)
                saved.append({'path':str(modelpath.relative_to(out)),'sha256':sha256(modelpath),'horizon':int(horizon)})
                if horizon==30:
                    pi=permutation_importance(model,te[cols],te.label,scoring='f1_macro',n_repeats=3,random_state=seed,n_jobs=1)
                    importance=[{'feature':f,'mean_f1_decrease':float(m),'std':float(s)} for f,m,s in zip(cols,pi.importances_mean,pi.importances_std)]
    pd.DataFrame(metrics).to_csv(out/'metrics.csv',index=False)
    pd.DataFrame(predictions).to_csv(out/'predictions.csv',index=False)
    pd.DataFrame(importance).to_csv(out/'permutation_importance.csv',index=False)
    summary={'title':'Fingerprinting Human–GenAI Multimedia Traffic','provenance':provenance,
             'notice':'SYNTHETIC DEMO — these scores do not measure real GenAI services.' if provenance=='synthetic' else 'Measured dataset; conclusions are limited to the captured devices, services and scenarios.',
             'classes':labels,'class_metadata':classmeta,'audit':audit,'seed':seed,'details':details,
             'saved_models':saved,'runtime':{'python':platform.python_version(),'sklearn':sklearn.__version__,'numpy':np.__version__},
             'limitations':['Known classes only; no unknown-application detection.','Posterior scores are uncalibrated model scores, not guarantees.',
                            'One observation prefix per session and horizon.','Permutation importance is descriptive and is not used to retune on test data.',
                            'Scenario and collection-day changes are combined in the later test partition.']}
    (out/'summary.json').write_text(json.dumps(summary,indent=2))
    from .report import render_report
    render_report(out)
    return summary

def predict(model_path,packet_file,ready_time,duration,provenance):
    # joblib is executable serialization: only load your own trusted local artifacts.
    bundle=joblib.load(model_path)
    if bundle.get('schema_version')!=1:raise ValueError('Unsupported model schema.')
    if bundle['provenance']!=provenance:raise ValueError('Model/input provenance mismatch. Train a real model before classifying real captures.')
    if not np.isfinite(duration) or duration<bundle['horizon']:raise ValueError('Capture shorter than model observation horizon.')
    row=extract_features(read_packets(packet_file),ready_time,bundle['horizon'],bundle['burst_gap'])
    missing=set(bundle['features'])-row.keys()
    if missing:raise ValueError('Feature schema mismatch.')
    X=pd.DataFrame([row])[bundle['features']];model=bundle['model'];label=str(model.predict(X)[0])
    values=model.predict_proba(X)[0]
    return {'predicted_label':label,**bundle['class_metadata'][label],
            'horizon_seconds':bundle['horizon'],'model':bundle['model_name'],'provenance':provenance,
            'uncalibrated_scores':{str(k):float(v) for k,v in zip(model.classes_,values)},
            'notice':'Synthetic demonstration only.' if provenance=='synthetic' else 'Known-class prediction; unknown applications may be misclassified.'}
