"""Offline research-only fine-tuning on fictional commands; no command is executed."""
from __future__ import annotations
import argparse, hashlib, json, os, random
from pathlib import Path

EXPECTED_INITIAL='c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28'
FILES=('model.safetensors','config.json','tokenizer.json','tokenizer_config.json','special_tokens_map.json','vocab.txt')
SEED=101

def validate_development(data):
    if data.get('version')!='aegis-command-refine-v1' or data.get('synthetic') is not True: raise ValueError('invalid dataset')
    ids=set(); commands=set(); groups={}
    for c in data['cases']:
        if c['split'] not in ('train','validation') or c['label'] not in ('positive','negative'): raise ValueError('invalid development split')
        if not isinstance(c.get('command'),str) or not c['command'].strip(): raise ValueError('invalid command')
        norm=' '.join(c['command'].casefold().split())
        if c['id'] in ids or norm in commands: raise ValueError('duplicate case')
        if c['group'] in groups and groups[c['group']]!=c['split']: raise ValueError('group leakage')
        ids.add(c['id']);commands.add(norm);groups[c['group']]=c['split']
    if set(groups.values())!={'train','validation'}: raise ValueError('missing split')
    return True

def train(dataset, original_dir, original_manifest, output):
    import numpy as np
    import torch
    import transformers
    from .attack_model import AttackModel
    old_dir=os.environ.get('AEGIS_ATTACK_MODEL_DIR'); old_manifest=os.environ.get('AEGIS_ATTACK_MODEL_MANIFEST')
    try:
        os.environ['AEGIS_ATTACK_MODEL_DIR']=str(original_dir); os.environ['AEGIS_ATTACK_MODEL_MANIFEST']=str(original_manifest)
        original=AttackModel.from_environment()
    finally:
        for key,value in [('AEGIS_ATTACK_MODEL_DIR',old_dir),('AEGIS_ATTACK_MODEL_MANIFEST',old_manifest)]:
            if value is None: os.environ.pop(key,None)
            else: os.environ[key]=value
    if original.state!='ready' or original.version!=EXPECTED_INITIAL: raise ValueError('original model verification failed')
    out=Path(output)
    if out.exists(): raise ValueError('output exists; refuse to overwrite')
    data_bytes=Path(dataset).read_bytes(); data=json.loads(data_bytes); validate_development(data)
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED); torch.set_num_threads(2); torch.use_deterministic_algorithms(True)
    model=original.model; tokenizer=original.tokenizer; optim=torch.optim.AdamW(model.parameters(),lr=3e-5)
    training=[x for x in data['cases'] if x['split']=='train']; val=[x for x in data['cases'] if x['split']=='validation']
    def batch(rows):
        inputs=tokenizer([x['command'] for x in rows],return_tensors='pt',padding=True,truncation=False)
        if inputs['input_ids'].shape[1]>128: raise ValueError('token limit exceeded')
        return inputs,torch.tensor([int(x['label']=='positive') for x in rows])
    val_x,val_y=batch(val); best=None; best_loss=float('inf'); history=[]
    for epoch in range(8):
        model.train(); random.shuffle(training)
        for i in range(0,len(training),4):
            inp,labels=batch(training[i:i+4]); optim.zero_grad(); loss=model(**inp,labels=labels).loss; loss.backward(); optim.step()
        model.eval()
        with torch.no_grad(): v=model(**val_x,labels=val_y).loss.item()
        history.append(v)
        if v<best_loss: best_loss=v; best={k:t.detach().clone() for k,t in model.state_dict().items()}
    model.load_state_dict(best);model.eval();out.mkdir(parents=True)
    model.save_pretrained(out,safe_serialization=True);tokenizer.save_pretrained(out)
    hashes={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in FILES}
    manifest={'sha256':hashes,'initial_weights_sha256':EXPECTED_INITIAL,'dataset_sha256':hashlib.sha256(data_bytes).hexdigest(),'seed':SEED,'epochs':8,'batch_size':4,'learning_rate':3e-5,'best_epoch':1+min(range(len(history)),key=history.__getitem__),'validation_loss':history,'threshold':0.5,'max_tokens':128,'python':__import__('sys').version,'torch':torch.__version__,'transformers':transformers.__version__,'selection':'lowest validation loss; no test data used'}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,sort_keys=True))

def main():
    p=argparse.ArgumentParser();p.add_argument('--development',required=True);p.add_argument('--original-dir',required=True);p.add_argument('--original-manifest',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    train(a.development,a.original_dir,a.original_manifest,a.output)
if __name__=='__main__': main()
