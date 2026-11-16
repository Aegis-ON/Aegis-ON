"""Opt-in synthetic API-to-console check using an explicitly installed model."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.history_store import SQLiteHistory
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


@unittest.skipUnless(os.environ.get('AEGIS_ATTACK_INTEGRATION') == '1' and shutil.which('node'),
                     'local experimental model and Node.js required')
class RealModelConsoleTests(unittest.TestCase):
    def test_local_inference_is_saved_and_rendered(self):
        model = AttackModel.from_environment()
        self.assertEqual(model.state, 'ready')
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(api, 'attack_model', model), \
             patch.object(api, 'service', DetectionService(SQLiteHistory(Path(directory) / 'history.db'))), \
             patch.dict(os.environ, {'AEGIS_API_TOKEN': 'synthetic-token', 'AEGIS_ANALYST_NAME': 'analyst'}), \
             TestClient(api.app, base_url='https://testserver') as client:
            headers = {'Authorization': 'Bearer synthetic-token'}
            event = make_event()
            event['EventData']['CommandLine'] = 'whoami /groups'
            response = client.post('/api/v1/sysmon/analyze', headers=headers, json={'events': [event]})
            self.assertEqual(response.status_code, 200)
            history = client.get('/api/v1/history', headers=headers).json()
            result = history['analyses'][0]['attack_model']['results'][0]
            self.assertEqual(result['status'], 'ok')
            self.assertEqual(result['event_id'], history['analyses'][0]['source_events'][0]['event_id'])
            harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
class E{constructor(t='div'){this.tag=t;this.children=[];this._text='';this.value='';this.classList={add:()=>{}};this.style={}}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
get childNodes(){return this.children}append(...xs){this.children.push(...xs);if(this.tag==='select'&&!this.value&&this.children[0])this.value=this.children[0].value}
replaceChildren(...xs){this._text='';this.children=xs}addEventListener(){}setAttribute(){}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));
const document={querySelector:q=>entries[q]||null,createElement:t=>new E(t)};
const data=JSON.parse(fs.readFileSync(0,'utf8')),result=data.analyses[0].attack_model.results[0];
const script=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
vm.runInNewContext(script+'\nrenderDetections(data, "");',{document,window:{},location:{pathname:'/console/detections'},data,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array});
for(const text of ['실험용 명령 모델 결과',result.event_id,result.status,result.label,String(result.score)])assert(entries['#view'].textContent.includes(text),text);
'''
            completed = subprocess.run(['node', '-e', harness], input=json.dumps(history), capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
