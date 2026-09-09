"""Standalone, offline research report; all numbers come from evaluation output."""
import base64
import html
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def render_report(folder):
    folder=Path(folder);s=json.loads((folder/'summary.json').read_text());m=pd.read_csv(folder/'metrics.csv')
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    charts=folder/'figures';charts.mkdir(exist_ok=True);images=[]
    def save(fig,name):
        
        if s['provenance']=='synthetic':fig.suptitle('SYNTHETIC DEMO — not measurements of real services',fontsize=10,color='#9b5b00')
        fig.tight_layout();fig.savefig(charts/name,dpi=160,bbox_inches='tight');plt.close(fig)
        images.append((name,base64.b64encode((charts/name).read_bytes()).decode()))
    fig,ax=plt.subplots(figsize=(9,4.2))
    for name,part in m[m.experiment=='mixed_profiles'].groupby('model'):
        ax.plot(part.horizon,part.test_macro_f1,marker='o',label=name)
    ax.set(xlabel='Observation horizon (seconds)',ylabel='Test macro-F1',ylim=(-.03,1.04),xticks=[5,10,30],title='Held-out classification by observation time')
    ax.legend(fontsize=8,ncol=2);ax.grid(alpha=.15);save(fig,'horizons.png')
    d=s['details']['mixed_profiles_30s'];cm=np.array(d['confusion_matrix'])
    fig,ax=plt.subplots(figsize=(8,5.6));im=ax.imshow(cm,cmap='Blues')
    ax.set_xticks(range(len(s['classes'])),s['classes'],rotation=35,ha='right');ax.set_yticks(range(len(s['classes'])),s['classes'])
    ax.set(xlabel='Predicted class',ylabel='Actual class',title='30-second selected model: '+d['selected_model'])
    for i in range(len(cm)):
        for j in range(len(cm)):ax.text(j,i,str(cm[i,j]),ha='center',va='center',color='white' if cm[i,j]>cm.max()/2 else '#172e3b')
    save(fig,'confusion.png')
    imp=pd.read_csv(folder/'permutation_importance.csv').sort_values('mean_f1_decrease').tail(12)
    fig,ax=plt.subplots(figsize=(9,5));ax.barh(imp.feature,imp.mean_f1_decrease,color='#147d83',xerr=imp['std'])
    ax.set(xlabel='Test macro-F1 decrease after permutation',title='Descriptive permutation importance (3 repeats)');save(fig,'importance.png')
    E=html.escape
    rows=''.join('<tr>'+''.join(f'<td>{E(str(v))}</td>' for v in [r.experiment,f'{r.horizon}s',r.model,f'{r.validation_macro_f1:.3f}',f'{r.test_macro_f1:.3f}',r.setting])+'</tr>' for r in m.itertuples())
    galleries=''.join(f'<figure><img src="data:image/png;base64,{b}" alt="{E(n)}"><figcaption>{E(n)}</figcaption></figure>' for n,b in images)
    detailrows=''.join(f'<tr><td>{E(k)}</td><td>{E(v["selected_model"])}</td><td>{v["ai_false_positive_rate"]:.3f}</td><td>{v["macro_f1_95ci"][0]:.3f}–{v["macro_f1_95ci"][1]:.3f}</td><td>{E(json.dumps(v["profile_macro_f1"]))}</td></tr>' for k,v in s['details'].items())
    out=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GenAI traffic fingerprinting report</title><style>
    *{{box-sizing:border-box}}body{{margin:0;background:#f4f7f8;color:#172e3b;font:16px/1.6 system-ui,sans-serif}}main{{max-width:1120px;margin:auto;padding:42px 24px}}h1{{font-size:40px;line-height:1.15;max-width:900px}}h2{{margin-top:40px}}.notice{{padding:18px;background:#fff0ce;border-left:5px solid #b77700;font-weight:650}}.meta{{color:#53656f}}figure{{margin:24px 0;background:white;padding:14px}}img{{max-width:100%;height:auto}}figcaption{{font-size:12px;color:#53656f}}table{{border-collapse:collapse;width:100%;background:white;font-size:14px}}td,th{{padding:11px;border-bottom:1px solid #dce5e8;text-align:left}}th{{background:#172e3b;color:white}}.scroll{{overflow:auto}}input{{padding:12px;width:100%;max-width:420px;border:1px solid #b6c8ce;border-radius:4px;font:inherit}}footer{{margin-top:40px;font-size:13px}}code{{background:#e8eef0;padding:2px 4px}}
    </style></head><body><main><p class="meta">CS 692 / Reproducible experiment output</p><h1>Fingerprinting Human–GenAI Multimedia Traffic</h1><p class="notice">{E(s['notice'])}</p><p>{s['audit']['sessions']} sessions · {s['audit']['scenario_groups']} scenario groups · {len(s['classes'])} classes · seed {s['seed']}</p>
    <h2>What this run tests</h2><p>Packet sizes, timing, direction and burst summaries classify known service/mode labels. Models and hyperparameters are selected on validation data. Test data provides evaluation only. Addresses, domains, ports and payloads never enter the feature matrix.</p>
    {galleries}<h2>Model comparisons</h2><label for="filter">Filter experiment or model</label><p><input id="filter" placeholder="For example: good_to_degraded" autocomplete="off"></p><div class="scroll"><table id="results"><thead><tr><th>Experiment</th><th>Horizon</th><th>Model</th><th>Validation F1</th><th>Test F1</th><th>Setting</th></tr></thead><tbody>{rows}</tbody></table></div>
    <h2>Selected models and uncertainty</h2><p>Confidence intervals resample scenario groups, not packets. Only {d['scenario_groups']} independent final test groups are available; intervals may be unstable. Profile scores below belong to the selected model.</p><div class="scroll"><table><thead><tr><th>Experiment</th><th>Selected model</th><th>AI false positives</th><th>95% F1 interval</th><th>Profile F1</th></tr></thead><tbody>{detailrows}</tbody></table></div>
    <h2>Reproduction and limitations</h2><ul>{''.join('<li>'+E(x)+'</li>' for x in s['limitations'])}</ul><p>Machine-readable evidence: <code>summary.json</code>, <code>metrics.csv</code>, <code>predictions.csv</code>, and <code>permutation_importance.csv</code>. The model folder contains one trusted local artifact per horizon.</p><footer>Python {E(s['runtime']['python'])}; scikit-learn {E(s['runtime']['sklearn'])}. This report is fully offline. No captured packets are uploaded.</footer></main><script>
    document.getElementById('filter').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();document.querySelectorAll('#results tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q));}});
    </script></body></html>'''
    (folder/'report.html').write_text(out)
