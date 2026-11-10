"""Optional local experimental command classifier; no automatic model download."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from threading import Lock
from typing import Any

MAX_TOKENS = 128
MAX_CHARS = 20000


class AttackModel:
    def __init__(self, model=None, tokenizer=None, state='disabled', reason='No local attack model configured', version=None, artifacts=None):
        self.model, self.tokenizer, self.state, self.reason, self.version = model, tokenizer, state, reason, version
        self.artifacts = artifacts or {}
        self._lock = Lock()

    @classmethod
    def from_environment(cls):
        directory = os.environ.get('AEGIS_ATTACK_MODEL_DIR', '')
        if not directory: return cls()
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            root = Path(directory)
            weights = root / 'model.safetensors'
            if not root.is_dir() or not weights.is_file(): raise ValueError('missing local model')
            names=('model.safetensors','config.json','tokenizer.json','tokenizer_config.json','special_tokens_map.json','vocab.txt')
            if any(not (root/name).is_file() for name in names): raise ValueError('missing model artifacts')
            artifacts={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}
            manifest = os.environ.get('AEGIS_ATTACK_MODEL_MANIFEST', '')
            if manifest:
                expected = json.loads(Path(manifest).read_text()).get('sha256')
                if not isinstance(expected, dict) or set(expected) != set(names) or expected != artifacts:
                    raise ValueError('artifact integrity mismatch')
            digest = artifacts['model.safetensors']
            tokenizer = AutoTokenizer.from_pretrained(root, local_files_only=True, trust_remote_code=False)
            model = AutoModelForSequenceClassification.from_pretrained(root, local_files_only=True, trust_remote_code=False, use_safetensors=True)
            if model.config.model_type != 'bert' or model.config.num_labels != 2:
                raise ValueError('unsupported model')
            if model.config.id2label != {0:'benign', 1:'review'}:
                raise ValueError('invalid labels')
            model.to('cpu'); model.eval()
            obj=cls(model,tokenizer,'ready','Experimental local classifier ready',digest,artifacts)
            result=obj.predict('echo synthetic')
            if result['status'] != 'ok': raise ValueError('warmup failed')
            return obj
        except Exception:
            # Do not expose local paths, model text, exception content or input.
            return cls(state='error', reason='Local attack model could not be loaded')

    def status(self):
        return {'state':self.state,'reason':self.reason,'weights_sha256':self.version,'artifacts_sha256':self.artifacts}

    def predict(self, command: Any) -> dict[str, Any]:
        if not isinstance(command,str): return {'status':'invalid_input'}
        if not command.strip(): return {'status':'missing_command'}
        if self.state != 'ready': return {'status':'model_unavailable'}
        if len(command) > MAX_CHARS: return {'status':'too_long'}
        try:
            import torch
            with self._lock:
                encoded=self.tokenizer(command,return_tensors='pt',truncation=False)
                if encoded['input_ids'].shape[1] > MAX_TOKENS: return {'status':'too_long'}
                with torch.no_grad(): logits=self.model(**encoded).logits
                if tuple(logits.shape) != (1,2) or not torch.isfinite(logits).all(): raise ValueError('invalid output')
                score=float(torch.softmax(logits,dim=-1)[0,1].item())
            if not math.isfinite(score): raise ValueError('invalid output')
            return {'status':'ok','label':'review' if score>=0.5 else 'below_threshold', 'score':round(score,6)}
        except Exception:
            return {'status':'inference_error'}
