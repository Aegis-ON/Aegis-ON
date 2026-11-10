"""Synthetic research experiment. Inputs are analyzed as text, never executed."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import os
from pathlib import Path
from datetime import datetime, timezone

from .engine import RuleDetector, SemanticRiskAdapter
from .evaluation import _metrics
from .models import SecurityEvent

MODEL_ID = 'google/bert_uncased_L-2_H-128_A-2'
REVISION = '30b0a37ccaaa32f332884b96992754e246e48c5f'
MAX_TOKENS = 128
SEED = 42


def validate_data(data, prior=None):
    if data.get('version') != 'aegis-command-synthetic-v2' or data.get('synthetic') is not True:
        raise ValueError('unexpected dataset')
    groups, ids, commands = {}, set(), {}
    prior_commands = set()
    if prior:
        for c in prior['cases']:
            for event in c['events']:
                value = event.get('EventData', {}).get('CommandLine') if isinstance(event, dict) else None
                if isinstance(value, str): prior_commands.add(' '.join(value.casefold().split()))
    for row in data['cases']:
        if row['split'] not in {'train','validation','test','ambiguous'} or row['label'] not in {'positive','negative','unknown'}:
            raise ValueError('invalid split or label')
        if (row['split'] == 'ambiguous') != (row['label'] == 'unknown'):
            raise ValueError('ambiguous label mismatch')
        if row['id'] in ids or not row['command'].strip(): raise ValueError('duplicate id or empty command')
        ids.add(row['id'])
        norm = ' '.join(row['command'].casefold().split())
        if norm in commands: raise ValueError('duplicate command')
        if row['split'] in ('train', 'validation') and norm in prior_commands: raise ValueError('PR4 training overlap')
        commands[norm] = row['split']
        if row['group'] in groups and groups[row['group']] != row['split']: raise ValueError('group leakage')
        groups[row['group']] = row['split']
    return True


def baseline(command):
    process = command.split()[0] if command.split() else ''
    event = SecurityEvent(timestamp=datetime(2026,1,1,tzinfo=timezone.utc),host='synthetic',user='',process=process,command_line=command,event_id='synthetic')
    return bool(RuleDetector().detect(event) or SemanticRiskAdapter().classify(event))


def verify_base(path):
    root=Path(path)
    if any(p.is_file() and p.name not in {'config.json','vocab.txt','model.safetensors'} for p in root.iterdir()):
        raise ValueError('unexpected base artifact')
    expected={'config.json':'333ec19609b98a6cd11b79a5770a163a2f0464c8',
              'vocab.txt':'fb140275c155a9c7c5a3b3e0e77a9e839594a938'}
    for name, digest in expected.items():
        data=(root/name).read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if actual != digest: raise ValueError('base artifact integrity failure')
    if hashlib.sha256((root/'model.safetensors').read_bytes()).hexdigest() != '7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414':
        raise ValueError('base artifact integrity failure')


def train(args):
    import numpy as np
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    verify_base(args.base)
    data=json.loads(Path(args.dataset).read_text()); prior=json.loads(Path(args.prior).read_text()); validate_data(data,prior)
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED); torch.set_num_threads(2)
    torch.use_deterministic_algorithms(True)
    tokenizer=AutoTokenizer.from_pretrained(args.base,local_files_only=True,trust_remote_code=False)
    model=AutoModelForSequenceClassification.from_pretrained(args.base,num_labels=2,local_files_only=True,trust_remote_code=False,use_safetensors=True)
    model.train(); optim=torch.optim.AdamW(model.parameters(),lr=3e-5)
    train_cases=[r for r in data['cases'] if r['split']=='train']
    val=[r for r in data['cases'] if r['split']=='validation']
    def batch(rows):
        inputs=tokenizer([r['command'] for r in rows],padding=True,truncation=False,return_tensors='pt')
        if inputs['input_ids'].shape[1]>MAX_TOKENS: raise ValueError('training input exceeds token limit')
        return inputs,torch.tensor([int(r['label']=='positive') for r in rows])
    val_inputs,val_labels=batch(val)
    best=None; best_loss=float('inf'); history=[]
    for epoch in range(6):
        model.train(); random.shuffle(train_cases)
        for pos in range(0,len(train_cases),4):
            inputs,labels=batch(train_cases[pos:pos+4]); optim.zero_grad()
            loss=model(**inputs,labels=labels).loss; loss.backward(); optim.step()
        model.eval()
        with torch.no_grad(): val_loss=model(**val_inputs,labels=val_labels).loss.item()
        history.append(val_loss)
        if val_loss<best_loss:
            best_loss=val_loss; best={k:v.detach().clone() for k,v in model.state_dict().items()}
    model.load_state_dict(best); model.eval()
    out=Path(args.output); out.mkdir(parents=True,exist_ok=True)
    model.config.id2label={0:'benign',1:'review'}; model.config.label2id={'benign':0,'review':1}
    model.save_pretrained(out,safe_serialization=True); tokenizer.save_pretrained(out)
    report={'base_model':MODEL_ID,'revision':REVISION,'seed':SEED,'epochs':6,'batch_size':4,'learning_rate':3e-5,'max_tokens':MAX_TOKENS,'threshold':0.5,'selection':'lowest validation loss','validation_loss':history,'best_epoch':1+min(range(len(history)),key=history.__getitem__),'dataset_sha256':hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest()}
    (out/'experiment.json').write_text(json.dumps(report,indent=2)+'\n')
    evaluate(args.dataset,out,report)


def evaluate(path, model_dir, report=None, predictor=None):
    from .attack_model import AttackModel
    data=json.loads(Path(path).read_text()); validate_data(data)
    if predictor is None:
        previous=os.environ.get('AEGIS_ATTACK_MODEL_DIR')
        try:
            os.environ['AEGIS_ATTACK_MODEL_DIR']=str(model_dir)
            predictor=AttackModel.from_environment()
        finally:
            if previous is None: os.environ.pop('AEGIS_ATTACK_MODEL_DIR',None)
            else: os.environ['AEGIS_ATTACK_MODEL_DIR']=previous
        if predictor.state != 'ready': raise ValueError('attack model unavailable')
    reports={}
    for split in ('test','ambiguous'):
        rows=[r for r in data['cases'] if r['split']==split]; brec=[]; mrec=[]; details=[]
        for row in rows:
            result=predictor.predict(row['command'])
            if result.get('status') != 'ok':
                details.append({'id':row['id'],'status':result.get('status','invalid_output')}); continue
            score=result['score']; b=baseline(row['command']); pred=result['label']=='review'
            details.append({'id':row['id'],'label':row['label'],'baseline':b,'model':pred,'score':score})
            if row['label']!='unknown':
                truth=row['label']=='positive'; brec.append((row['id'],truth,b));mrec.append((row['id'],truth,pred))
        reports[split]={'baseline':_metrics(brec),'model':_metrics(mrec),'details':details}
    output={'experiment':report or json.loads((Path(model_dir)/'experiment.json').read_text()),'reports':reports}
    print('EXPERIMENT_REPORT '+json.dumps(output,sort_keys=True,allow_nan=False),flush=True)
    return output


def main():
    p=argparse.ArgumentParser();p.add_argument('--base',required=True);p.add_argument('--dataset',required=True);p.add_argument('--prior',required=True);p.add_argument('--output',required=True)
    train(p.parse_args())

if __name__=='__main__': main()
