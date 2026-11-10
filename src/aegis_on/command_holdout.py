"""Frozen synthetic command triage evaluation; command text is never executed."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from .attack_experiment import baseline
from .attack_model import AttackModel
from .evaluation import _metrics

MODEL_SHA256 = 'c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28'
DATASET_SHA256 = '569cb879e46a049ad8fe25f2728aab06342a82aca01c4d71b48fca3b631a162b'
THRESHOLD = 0.5


def validate(data):
    if data.get('dataset_id') != 'aegis-command-holdout-v1' or data.get('synthetic') is not True:
        raise ValueError('Unexpected dataset')
    ids=set(); commands=set()
    for row in data['cases']:
        if not all(isinstance(row.get(k),str) and row[k] for k in ('id','group','reason')):
            raise ValueError('Invalid case metadata')
        if row['id'] in ids or row.get('label') not in ('positive','negative','unknown'):
            raise ValueError('Invalid case id or label')
        if row.get('expected_status') not in ('ok','missing_command','invalid_input','too_long'):
            raise ValueError('Invalid expected input status')
        if row.get('technique_candidates') and row['label'] != 'positive':
            raise ValueError('Technique candidate requires positive label')
        ids.add(row['id']); cmd=row.get('command')
        if isinstance(cmd,str) and cmd.strip():
            norm=' '.join(cmd.casefold().split())
            if norm in commands: raise ValueError('Duplicate command')
            commands.add(norm)
    return True


def evaluate(data, predictor):
    validate(data)
    common_b=[]; common_m=[]; baseline_all=[]; details=[]; excluded=Counter(); techniques=defaultdict(list); status_mismatches=[]
    for row in data['cases']:
        cmd=row.get('command',''); status=predictor.predict(cmd)
        state=status.get('status','invalid_output') if isinstance(status,dict) else 'invalid_output'
        if state != row['expected_status']:
            status_mismatches.append({'id':row['id'],'expected':row['expected_status'],'actual':state})
        detail={'id':row['id'],'group':row['group'],'truth':row['label'],'input_status':state}
        if isinstance(cmd,str) and cmd.strip() and len(cmd)<=20000:
            b=baseline(cmd); detail['baseline']=b
            if row['label']!='unknown': baseline_all.append((row['id'],row['label']=='positive',b))
        if state != 'ok': excluded['input_'+state]+=1
        elif row['label']=='unknown': excluded['unknown_truth']+=1
        else:
            score=status.get('score'); label=status.get('label')
            # The product determines its label before rounding the reported score.
            # Exactly 0.500000 can therefore legitimately have either label.
            if not isinstance(score,(float,int)) or isinstance(score,bool) or not 0<=score<=1 or label not in ('review','below_threshold') or (score != THRESHOLD and (label=='review') != (score>=THRESHOLD)):
                excluded['invalid_output']+=1; detail['input_status']='invalid_output'; details.append(detail); continue
            pred=label=='review'; truth=row['label']=='positive'; detail.update({'model':pred,'score':score})
            common_b.append((row['id'],truth,detail['baseline'])); common_m.append((row['id'],truth,pred))
            if truth:
                for tech in row.get('technique_candidates',[]): techniques[tech].append({'id':row['id'],'baseline':detail['baseline'],'model':pred})
        details.append(detail)
    return {'cases':len(data['cases']),'groups':len({r['group'] for r in data['cases']}),
            'truth_counts':dict(Counter(r['label'] for r in data['cases'])),
            'expected_status_mismatches':status_mismatches,
            'exclusions':dict(excluded),'scored_cases':len(common_m),
            'scored_groups':len({r['group'] for r in details if 'model' in r}),
            'baseline_all_eligible':_metrics(baseline_all),'baseline_common':_metrics(common_b),
            'model_common':_metrics(common_m),
            'technique_candidate_binary_recall':{tech:{'denominator':len(items),
                'baseline_flagged':sum(x['baseline'] for x in items),
                'model_flagged':sum(x['model'] for x in items),
                'baseline_rate':sum(x['baseline'] for x in items)/len(items),
                'model_rate':sum(x['model'] for x in items)/len(items), 'cases':items}
                for tech,items in techniques.items()},'details':details}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--dataset',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args(); raw=Path(args.dataset).read_bytes(); digest=hashlib.sha256(raw).hexdigest()
    if Path(args.output).resolve() == Path(args.dataset).resolve(): raise SystemExit('Output must differ from dataset')
    if digest != DATASET_SHA256: raise SystemExit('Frozen dataset hash mismatch')
    if not os.environ.get('AEGIS_ATTACK_MODEL_MANIFEST'): raise SystemExit('A trusted model manifest is required')
    predictor=AttackModel.from_environment()
    if predictor.state!='ready' or predictor.version != MODEL_SHA256: raise SystemExit('Expected model unavailable or hash mismatch')
    result=evaluate(json.loads(raw),predictor)
    result.update({'dataset_sha256':digest,'model_sha256':predictor.version,'model_artifacts_sha256':predictor.artifacts,'threshold':THRESHOLD})
    Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__': main()
