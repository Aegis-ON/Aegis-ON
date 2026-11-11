"""Exercise local model -> authenticated Sysmon ingest -> SQLite -> console DOM."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.history_store import SQLiteHistory
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


@pytest.mark.skipif(os.environ.get('AEGIS_ATTACK_INTEGRATION') != '1' or not shutil.which('node'), reason='opt-in local model and Node required')
def test_real_inference_to_console_dom():
    model = AttackModel.from_environment()
    assert model.state == 'ready'
    with tempfile.TemporaryDirectory() as temp:
        env = {'AEGIS_API_TOKEN': 'fixture-token', 'AEGIS_ANALYST_NAME': 'analyst', 'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN': '1'}
        with patch.dict(os.environ, env), patch.object(api, 'service', DetectionService(SQLiteHistory(Path(temp) / 'history.sqlite3'))), \
             patch.object(api, 'attack_model', model), patch.object(api, 'pii_detector', PIIDetector()):
            with TestClient(api.app, base_url='https://testserver') as client:
                headers = {'Authorization': 'Bearer fixture-token', 'X-Collector-ID': 'demo', 'Idempotency-Key': 'one'}
                result = client.post('/api/v1/ingest/sysmon', json={'events': [make_event()]}, headers=headers)
                assert result.status_code == 200, result.text
                history = client.get('/api/v1/history', headers=headers).json()
                prediction = history['analyses'][0]['attack_model']['results'][0]
                assert prediction['status'] == 'ok' and prediction['label'] in ('review', 'below_threshold')
                assert prediction['event_id'] == history['analyses'][0]['source_events'][0]['event_id']
                code = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
class E{constructor(t='div'){this.tag=t;this.children=[];this._text='';this.value='';this.style={};this.classList={add(){}};}set textContent(x){this._text=String(x)}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}append(...xs){this.children.push(...xs)}addEventListener(){}setAttribute(){}replaceChildren(...xs){this.children=xs;this._text=''}}
const els=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(x=>[x,new E()]));
const document={querySelector:q=>els[q]||null,createElement:t=>new E(t)},window={},location={pathname:'/console/detections'};
const data=JSON.parse(fs.readFileSync(0,'utf8'));const p=data.analyses[0].attack_model.results[0];
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
vm.runInNewContext(code+'\nrenderDetections(data,null);',{document,window,location,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array,data});
const text=els['#view'].textContent;for(const v of ['실험용 명령 모델 결과',p.event_id,p.status,p.label,String(p.score)])assert(text.includes(v),v);
'''
                run = subprocess.run(['node', '-e', code], input=json.dumps(history), text=True, capture_output=True)
                assert run.returncode == 0, run.stderr
