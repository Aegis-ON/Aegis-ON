"""Compare frozen triage implementations; no commands are executed."""
from __future__ import annotations
import argparse,hashlib,json,os
from collections import Counter,defaultdict
from pathlib import Path
from .attack_experiment import baseline
from .attack_model import AttackModel
from .evaluation import _metrics


def compare(data,old,new):
    rows=[];recs={'baseline':[],'original':[],'refined':[]};groups=defaultdict(lambda:{'baseline':[],'original':[],'refined':[]}); excluded=Counter();tech=defaultdict(list)
    for c in data['cases']:
        command=c.get('command'); truth=c['label']
        if truth=='unknown': excluded['unknown_truth']+=1; continue
        a=old.predict(command);b=new.predict(command)
        if a.get('status')!='ok' or b.get('status')!='ok':
            excluded['model_unavailable_or_rejected']+=1;rows.append({'id':c['id'],'group':c['group'],'status_original':a.get('status'),'status_refined':b.get('status')});continue
        if any(r.get('label') not in ('review','below_threshold') for r in (a,b)):
            excluded['invalid_output']+=1;continue
        actual=truth=='positive'; flags={'baseline':baseline(command),'original':a['label']=='review','refined':b['label']=='review'}
        row={'id':c['id'],'group':c['group'],'truth':truth,'flags':flags,'original_score':a['score'],'refined_score':b['score']};rows.append(row)
        for key,pred in flags.items():
            recs[key].append((c['id'],actual,pred));groups[c['group']][key].append((c['id'],actual,pred))
        if actual:
            for t in c.get('technique_candidates',[]):tech[t].append({'id':c['id'],'flags':flags})
    report={key:_metrics(value) for key,value in recs.items()}
    for metric in report.values():
        denom=metric['fp']+metric['tn'];metric['false_alert_rate']=metric['fp']/denom if denom else None
    return {'total_cases':len(data['cases']),'groups':len({c['group'] for c in data['cases']}),'scored_cases':len(recs['original']),
            'scored_groups':len(groups),'excluded':dict(excluded),'overall':report,
            'by_group':{g:{k:_metrics(v) for k,v in methods.items()} for g,methods in sorted(groups.items())},
            'technique_candidate_review_flags':dict(tech),'cases':rows}


def load(path,manifest):
    previous={k:os.environ.get(k) for k in ('AEGIS_ATTACK_MODEL_DIR','AEGIS_ATTACK_MODEL_MANIFEST')}
    try:
        os.environ['AEGIS_ATTACK_MODEL_DIR']=str(path);os.environ['AEGIS_ATTACK_MODEL_MANIFEST']=str(manifest)
        return AttackModel.from_environment()
    finally:
        for k,v in previous.items():
            if v is None: os.environ.pop(k,None)
            else: os.environ[k]=v


def main():
    p=argparse.ArgumentParser();p.add_argument('--test',required=True);p.add_argument('--protocol',required=True);p.add_argument('--original-dir',required=True);p.add_argument('--original-manifest',required=True);p.add_argument('--refined-dir',required=True);p.add_argument('--refined-manifest',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    output=Path(a.output)
    if output.exists(): raise SystemExit('output exists')
    frozen=json.loads(Path(a.protocol).read_text());raw=Path(a.test).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=frozen['test_sha256'] or frozen['threshold']!=0.5: raise SystemExit('test or threshold mismatch')
    old=load(a.original_dir,a.original_manifest);new=load(a.refined_dir,a.refined_manifest)
    if old.state!='ready' or old.version!=frozen['original_weights_sha256'] or new.state!='ready' or new.version!=frozen['refined_weights_sha256']: raise SystemExit('model or hash unavailable')
    report=compare(json.loads(raw),old,new);report['protocol']=frozen
    output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n');print(json.dumps(report,ensure_ascii=False))
if __name__=='__main__': main()
