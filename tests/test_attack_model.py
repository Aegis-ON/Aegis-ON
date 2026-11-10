import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from test_sysmon_api import make_event
from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.attack_experiment import validate_data, verify_base, evaluate
from aegis_on.service import DetectionService


class AttackModelTests(unittest.TestCase):
    def test_disabled_missing_and_load_failure(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertEqual(AttackModel.from_environment().state, 'disabled')
        with patch.dict('os.environ', {'AEGIS_ATTACK_MODEL_DIR':'/nonexistent/sensitive-path'}, clear=True):
            model=AttackModel.from_environment()
            self.assertEqual(model.state, 'error')
            self.assertNotIn('sensitive-path', json.dumps(model.status()))
            self.assertEqual(model.predict(''), {'status':'missing_command'})
            self.assertEqual(model.predict('command'), {'status':'model_unavailable'})

    def test_fake_model_output_and_token_limit(self):
        import torch
        class Tokenizer:
            def __call__(self, text, **kwargs):
                return {'input_ids':torch.ones((1, 129 if 'long' in text else 4),dtype=torch.long)}
        class Model:
            def __init__(self, output): self.output=output
            def __call__(self, **kwargs):
                if isinstance(self.output, Exception): raise self.output
                return type('Output',(),{'logits':self.output})()
        m=AttackModel(Model(torch.tensor([[1.,2.]])), Tokenizer(), 'ready')
        self.assertEqual(m.predict('sample')['label'],'review')
        self.assertEqual(m.predict('long')['status'],'too_long')
        self.assertEqual(m.predict(None)['status'],'invalid_input')
        for value in (torch.tensor([[float('nan'),0.]]),torch.tensor([[1.,2.,3.]]), RuntimeError('private text')):
            m.model=Model(value)
            self.assertEqual(m.predict('private text'),{'status':'inference_error'})

    def test_api_events_are_linked_and_failures_do_not_echo(self):
        class Fake:
            def status(self): return {'state':'ready','reason':'test','weights_sha256':'test'}
            def predict(self, command):
                if not command: return {'status':'missing_command'}
                if 'secret' in command: return {'status':'inference_error'}
                return {'status':'ok','label':'review','score':0.7}
        previous=api.attack_model
        self.addCleanup(setattr,api,'attack_model',previous)
        self.addCleanup(setattr,api,'service',api.service)
        api.attack_model=Fake(); api.service=DetectionService()
        with patch.dict('os.environ',{'AEGIS_API_TOKEN':'token','AEGIS_ANALYST_NAME':'analyst'},clear=True),TestClient(api.app) as client:
            h={'Authorization':'Bearer token'}
            event={'timestamp':'2026-01-01T00:00:00Z','host':'lab','user':'a','process':'curl','command_line':'curl secret','event_id':'evt'}
            response=client.post('/api/v1/analyze',json={'events':[event]},headers=h)
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json()['attack_model']['state'],'inference_error')
            self.assertNotIn('secret',response.text)
            self.assertEqual(response.json()['attack_model']['results'][0]['event_id'],response.json()['event_refs'][0]['event_id'])
            sysmon=make_event(3)
            response=client.post('/api/v1/sysmon/analyze',json={'events':[sysmon]},headers=h)
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json()['attack_model']['results'][0]['status'],'missing_command')
            self.assertEqual(response.json()['attack_model']['results'][0]['event_id'],response.json()['source_events'][0]['event_id'])
            self.assertEqual(client.get('/api/v1/attack-model/status').status_code,401)

    def test_dataset_group_and_prior_validation_overlap(self):
        d=json.loads(Path('evaluation/command_synthetic_v2.json').read_text())
        p=json.loads(Path('evaluation/synthetic_v1.json').read_text())
        self.assertTrue(validate_data(d,p))
        broken=copy.deepcopy(d); v=next(c for c in broken['cases'] if c['split']=='validation')
        prior=next(c for c in p['cases'] if c['case_id']=='eval-curl-tool')
        v['command']=prior['events'][0]['EventData']['CommandLine']
        with self.assertRaises(ValueError): validate_data(broken,p)
        broken=copy.deepcopy(d); broken['cases'][-1]['group']=broken['cases'][0]['group']
        with self.assertRaises(ValueError): validate_data(broken,p)

    def test_base_model_must_match_pinned_files(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder,'config.json').write_text('{}')
            with self.assertRaises(ValueError): verify_base(folder)

    def test_evaluation_excludes_inference_errors(self):
        class Fake:
            def predict(self,command): return {'status':'inference_error'}
        with patch('builtins.print'):
            r=evaluate('evaluation/command_synthetic_v2.json','unused',report={'test':True},predictor=Fake())
        self.assertEqual(r['reports']['test']['model']['support'],0)
        self.assertEqual(r['reports']['test']['baseline']['support'],0)
        self.assertTrue(all(x['status']=='inference_error' for x in r['reports']['test']['details']))

    def test_evaluation_reports_actual_input_hash_separately(self):
        class Fake:
            def predict(self,command): return {'status':'inference_error'}
        path=Path('evaluation/command_synthetic_v2.json')
        with patch('builtins.print'):
            r=evaluate(path,'unused',report={'dataset_sha256':'0'*64},predictor=Fake())
        self.assertEqual(r['evaluation_dataset_sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertFalse(r['training_dataset_matches'])

    def test_manifest_rejects_changed_artifacts_before_model_load(self):
        names=('model.safetensors','config.json','tokenizer.json','tokenizer_config.json','special_tokens_map.json','vocab.txt')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in names: (root/name).write_text('original')
            hashes={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}
            manifest=root/'manifest.json'; manifest.write_text(json.dumps({'sha256':hashes}))
            (root/'vocab.txt').write_text('changed')
            with patch.dict('os.environ',{'AEGIS_ATTACK_MODEL_DIR':folder,'AEGIS_ATTACK_MODEL_MANIFEST':str(manifest)},clear=True):
                with patch('transformers.AutoTokenizer.from_pretrained') as loader:
                    result=AttackModel.from_environment()
                    self.assertEqual(result.state,'error')
                    loader.assert_not_called()
            self.assertNotIn(folder,json.dumps(result.status()))
