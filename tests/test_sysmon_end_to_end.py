"""Run a real Sysmon API result through the dashboard's JavaScript handlers."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.service import DetectionService


class SysmonEndToEndTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_fixture_api_result_renders_linked_events(self):
        sample_path = Path('data/demo_sysmon.json')
        sample = sample_path.read_bytes()
        with patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst-1'}):
            api.service = DetectionService()
            with TestClient(api.app, base_url='https://testserver') as client:
                response = client.post('/api/v1/sysmon/analyze', content=sample, headers={
                    'Authorization': 'Bearer test-secret', 'Content-Type': 'application/json'})
                self.assertEqual(response.status_code, 200, response.text)
                data = response.json()
        self.assertEqual(data['summary']['processed'], 5)
        self.assertTrue(any(d['technique'] == 'T1105' for d in data['detections']))
        fanout = next(d for d in data['detections'] if d['source'] == 'correlation')
        self.assertEqual(len(fanout['event_ids']), 3)
        html = Path('static/index.html').read_text(encoding='utf-8')
        script = html.split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert = require('assert');
const vm = require('vm');
const actual = JSON.parse(require('fs').readFileSync(0, 'utf8'));
class Element {
  constructor() { this.children=[]; this._text=''; this.handlers={}; this.files=[]; }
  set textContent(value) { this._text=String(value); this.children=[]; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set innerHTML(value) { throw Error('unsafe HTML'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children=children; this._text=''; }
  addEventListener(name, fn) { this.handlers[name]=fn; }
}
const elements=Object.fromEntries(['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'].map(x => [x,new Element()]));
const document={querySelector:id=>elements[id],createElement:()=>new Element()};
const window={prompt:()=> 'test-secret'};
const file={name:'demo_sysmon.json', size:actual.fileSize};
elements['#sysmon-file'].files=[file];
const fetch=async (url, opts) => {
  assert.equal(url,'/api/v1/sysmon/analyze');
  assert.equal(opts.body,file);
  assert.equal(opts.headers.Authorization,'Bearer test-secret');
  return {ok:true,status:200,json:async()=>actual.result};
};
vm.runInNewContext(actual.script,{document,window,fetch,Map,String,Error,AbortController});
(async()=>{
  await elements['#run-sysmon'].handlers.click();
  assert.match(elements['#summary'].textContent,/처리 5건/);
  const text=elements['#results'].textContent;
  assert.ok(text.includes('탐지 근거'));
  for (const event of actual.result.source_events.filter(e => actual.fanoutIds.includes(e.event_id))) {
    assert.ok(text.includes(`레코드 ID: ${event.record_id}`));
    assert.ok(text.includes(String(event.log_source)));
  }
  assert.ok(text.includes('3 unique destinations'));
  console.log('fixture → API → dashboard passed');
})().catch(e=>{ console.error(e); process.exit(1); });
'''
        payload = {'result': data, 'fanoutIds': fanout['event_ids'], 'fileSize': len(sample), 'script': script}
        result = subprocess.run(['node', '-e', harness], input=json.dumps(payload), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('fixture → API → dashboard passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
