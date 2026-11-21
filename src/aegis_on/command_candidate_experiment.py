"""Offline synthetic command classification research. Never executes commands.

Use separate processes for training and inference so peak inference memory does
not include optimizer state. Only local model files are loaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import resource
import statistics
import sys
import time
from pathlib import Path

SEED = 101
MAX_TOKENS = 128


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def datasets(dev_path, test_path):
    dev = json.loads(Path(dev_path).read_text())
    test = json.loads(Path(test_path).read_text())
    if any(c.get('split') not in ('train', 'validation') for c in dev['cases']):
        raise ValueError('development contains non-development split')
    if any(c.get('split') != 'test' for c in test['cases']):
        raise ValueError('test contains non-test split')
    groups, commands, ids = {}, {}, set()
    sets = {'train': [], 'validation': [], 'test': []}
    for c in dev['cases'] + test['cases']:
        split, label = c['split'], c['label']
        if split not in sets or label not in ('positive', 'negative', 'unknown'):
            raise ValueError('invalid split or label')
        if not isinstance(c.get('command'), str) or not c['command'].strip() or c['id'] in ids:
            raise ValueError('invalid or duplicate case')
        ids.add(c['id'])
        norm = ' '.join(c['command'].casefold().split())
        if norm in commands and commands[norm] != split:
            raise ValueError('exact command split overlap')
        if c['group'] in groups and groups[c['group']] != split:
            raise ValueError('group split overlap')
        commands[norm], groups[c['group']] = split, split
        if label != 'unknown':
            sets[split].append(c)
    if any(not sets[s] for s in sets):
        raise ValueError('empty dataset split')
    return sets


def inputs(tokenizer, rows):
    import torch
    encoded = tokenizer([r['command'] for r in rows], return_tensors='pt', padding=True, truncation=False)
    if encoded['input_ids'].shape[1] > MAX_TOKENS:
        raise ValueError('token limit exceeded')
    labels = torch.tensor([int(r['label'] == 'positive') for r in rows])
    return encoded, labels


def train(model_dir, output, dev, test, revision, model_name):
    import numpy as np
    import torch
    import transformers
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    path = Path(output)
    if path.exists():
        raise ValueError('output exists')
    data = datasets(dev, test)
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    torch.set_num_threads(2); torch.use_deterministic_algorithms(True)
    tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_dir, local_files_only=True, trust_remote_code=False, num_labels=2,
        id2label={0:'benign', 1:'review'}, label2id={'benign':0, 'review':1})
    model.to('cpu')
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5)
    training = list(data['train'])
    val_x, val_y = inputs(tokenizer, data['validation'])
    best, best_loss, losses = None, float('inf'), []
    for epoch in range(8):
        model.train(); random.shuffle(training)
        for i in range(0, len(training), 4):
            encoded, labels = inputs(tokenizer, training[i:i+4])
            optimizer.zero_grad(); loss = model(**encoded, labels=labels).loss
            loss.backward(); optimizer.step()
        model.eval()
        with torch.no_grad():
            loss = model(**val_x, labels=val_y).loss.item()
        losses.append(loss)
        if loss < best_loss:
            best_loss = loss
            best = {k: v.detach().clone() for k, v in model.state_dict().items()}
        print(f'epoch {epoch+1}/8 validation_loss={loss:.6f}', flush=True)
    model.load_state_dict(best); model.eval(); path.mkdir(parents=True)
    model.save_pretrained(path, safe_serialization=True)
    tokenizer.save_pretrained(path)
    source = Path(model_dir)
    files = {p.name: digest(p) for p in sorted(source.iterdir()) if p.is_file()}
    manifest = {'model':model_name, 'revision':revision, 'source_files_sha256':files,
                'development_sha256':digest(dev), 'test_sha256':digest(test),
                'split_sizes':{k:len(v) for k,v in data.items()},
                'unknown_excluded':sum(c['label'] == 'unknown' for c in json.loads(Path(test).read_text())['cases']),
                'seed':SEED, 'epochs':8, 'batch_size':4, 'learning_rate':3e-5,
                'best_epoch':1+min(range(len(losses)), key=losses.__getitem__),
                'validation_loss':losses, 'threshold':0.5, 'max_tokens':MAX_TOKENS,
                'python':sys.version, 'torch':torch.__version__, 'transformers':transformers.__version__,
                'selection':'lowest validation loss; test not used'}
    (path/'experiment.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps(manifest), flush=True)


def evaluate(model_dir, dev, test, output, name):
    import torch
    import transformers
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    data = datasets(dev, test)
    torch.set_num_threads(2)
    start = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True, trust_remote_code=False)
    if model.config.num_labels != 2 or model.config.id2label != {0:'benign', 1:'review'}:
        raise ValueError('unsupported labels')
    model.to('cpu'); model.eval()
    with torch.no_grad():
        model(**tokenizer('echo synthetic', return_tensors='pt'))
    load_seconds = time.perf_counter()-start
    rows, durations, confusion = [], [], {'tp':0,'fp':0,'tn':0,'fn':0}
    for case in data['test']:
        t = time.perf_counter(); x, _ = inputs(tokenizer, [case])
        with torch.no_grad():
            logits = model(**x).logits
            if tuple(logits.shape) != (1,2) or not torch.isfinite(logits).all():
                raise ValueError('invalid model output')
            score = float(torch.softmax(logits, dim=-1)[0,1])
        durations.append(1000*(time.perf_counter()-t))
        predicted, truth = score >= .5, case['label'] == 'positive'
        confusion['tp' if predicted and truth else 'fp' if predicted else 'fn' if truth else 'tn'] += 1
        rows.append({'id':case['id'], 'group':case['group'], 'truth':case['label'], 'review':predicted, 'score':round(score,6)})
    tp, fp, fn = confusion['tp'], confusion['fp'], confusion['fn']
    precision = tp/(tp+fp) if tp+fp else 0
    recall = tp/(tp+fn) if tp+fn else 0
    f1 = 2*precision*recall/(precision+recall) if precision+recall else 0
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform != 'darwin': peak *= 1024
    report = {'name':name, 'weight_sha256':digest(Path(model_dir)/'model.safetensors'),
              'development_sha256':digest(dev), 'test_sha256':digest(test), 'confusion':confusion,
              'precision':precision,'recall':recall,'f1':f1,'cases':rows,
              'load_seconds':load_seconds,'mean_ms':statistics.mean(durations),
              'median_ms':statistics.median(durations),'peak_rss_bytes':peak,
              'samples':len(rows),'threads':2,'threshold':0.5,'max_tokens':MAX_TOKENS,
              'python':sys.version,'torch':torch.__version__,'transformers':transformers.__version__}
    Path(output).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'}), flush=True)


def main():
    p = argparse.ArgumentParser(); p.add_argument('mode', choices=['train','evaluate'])
    p.add_argument('--model-dir', required=True); p.add_argument('--output', required=True); p.add_argument('--name', required=True)
    p.add_argument('--revision', default='local'); p.add_argument('--development', default='evaluation/command_refine_dev_v1.json')
    p.add_argument('--test', default='evaluation/command_refine_test_v1.json')
    args = p.parse_args()
    if args.mode == 'train': train(args.model_dir,args.output,args.development,args.test,args.revision,args.name)
    else: evaluate(args.model_dir,args.development,args.test,args.output,args.name)


if __name__ == '__main__': main()
