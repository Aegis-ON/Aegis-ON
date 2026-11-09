"""Exercise dashboard event handlers without a browser or network service."""
import shutil
import subprocess
import unittest
from pathlib import Path


class DashboardSysmonTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_dashboard_workflows(self):
        html = Path('static/index.html').read_text(encoding='utf-8')
        script = html.split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert = require('assert');
const vm = require('vm');
class Element {
  constructor() { this.children = []; this._text = ''; this.handlers = {}; this.files = []; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(value) { throw Error('HTML injection attempted'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ''; }
  addEventListener(name, fn) { this.handlers[name] = fn; }
}
const elements = Object.fromEntries(['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'].map(id => [id, new Element()]));
const document = {querySelector: id => elements[id], createElement: () => new Element()};
let token = 'secret';
let calls = [];
let answer = null;
const window = {prompt: () => token};
const fetch = async (url, options) => { calls.push({url, options}); return answer(url); };
vm.runInNewContext(process.argv[1], {document, window, fetch, Map, String, Error, AbortController});
const click = id => elements[id].handlers.click();
const response = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => body});
const detection = {technique:'T1595', title:'Potential active scanning fan-out', score:72, source:'correlation', host:'host', evidence:['3 unique destinations in ten minutes'], event_ids:['evt-a','evt-b']};
const eventA = {input_index:0, event_id:'evt-a', sysmon_event_id:3, record_id:'<script>alert(1)</script>', log_source:'Microsoft-Windows-Sysmon/Operational', host:'host', timestamp:'2026-01-01T00:00:00Z', process_guid:'guid-a', process_id:111, source_ip:'10.0.0.1', source_port:80, destination_ip:'10.0.0.2', destination_port:443};
const eventB = {...eventA, input_index:1, event_id:'evt-b', record_id:42, process_id:222};
const result = {summary:{total:3, processed:2, invalid:1, unsupported:0}, items:[{input_index:0,status:'processed'},{input_index:1,status:'processed'},{input_index:2,status:'invalid',reason:'<img src=x onerror=evil()>'}], source_events:[eventA,eventB], detections:[detection]};
(async () => {
  await click('#run-sysmon');
  assert.match(elements['#summary'].textContent, /파일을 선택/);
  assert.equal(calls.length, 0);
  elements['#sysmon-file'].files = [{name:'large.json',size:2 * 1024 * 1024 + 1}];
  await click('#run-sysmon');
  assert.match(elements['#summary'].textContent, /2 MiB/);
  assert.equal(calls.length, 0);
  const file = {name:'events.json',size:100};
  elements['#sysmon-file'].files = [file];
  token = '';
  await click('#run-sysmon');
  assert.match(elements['#summary'].textContent, /토큰이 입력되지/);
  assert.equal(calls.length, 0);
  token = 'secret';
  answer = url => response(result);
  await click('#run-sysmon');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/v1/sysmon/analyze');
  assert.equal(calls[0].options.body, file);
  assert.equal(calls[0].options.headers.Authorization, 'Bearer secret');
  assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
  const output = elements['#results'].textContent;
  assert.match(elements['#summary'].textContent, /유효하지 않음 1건/);
  for (const value of ['<script>alert(1)</script>', '<img src=x onerror=evil()>', '42', '111', '222', 'guid-a', '10.0.0.2', '443', '3 unique destinations in ten minutes']) assert.ok(output.includes(value), value);
  answer = () => response({}, 401);
  await click('#run-sysmon');
  assert.match(elements['#summary'].textContent, /인증 실패/);
  assert.equal(elements['#results'].textContent, '');
  calls = [];
  answer = url => url === '/data/demo_events.json' ? response({events:[]}) : response({detections:[detection],model_state:'semantic-baseline'});
  await click('#run-demo');
  assert.deepEqual(calls.map(call => call.url), ['/data/demo_events.json','/api/v1/analyze']);
  assert.ok(calls.every(call => call.options.headers.Authorization === 'Bearer secret'));
  assert.match(elements['#summary'].textContent, /1건 탐지됨/);
  console.log('dashboard workflows passed');
})().catch(error => { console.error(error); process.exit(1); });
'''
        result = subprocess.run(['node', '-e', harness, script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dashboard workflows passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
