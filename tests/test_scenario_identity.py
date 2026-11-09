"""Keep the completed analysis tied to its actual input, including delayed requests."""
import shutil
import subprocess
import unittest
from pathlib import Path


class ScenarioIdentityTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_scenario_file_demo_and_stale_results(self):
        script = Path('static/index.html').read_text(encoding='utf-8').split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert=require('assert'),vm=require('vm');
class Element{constructor(){this.children=[];this._text='';this.handlers={};this.files=[]}set textContent(v){this._text=String(v);this.children=[]}get textContent(){return this._text+this.children.map(c=>c.textContent).join('')}set innerHTML(v){throw Error('unsafe HTML')}append(...x){this.children.push(...x)}replaceChildren(...x){this.children=x;this._text=''}addEventListener(k,f){this.handlers[k]=f}}
const ids=['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'];
const el=Object.fromEntries(ids.map(id=>[id,new Element()])),document={querySelector:id=>el[id],createElement:()=>new Element()};
let token='token',calls=[],wait=false,pending=[];
const window={prompt:()=>token};
const sample={events:[{sample:'example'}]},data={summary:{total:1,processed:1,invalid:0,unsupported:0},items:[{input_index:0,status:'processed'}],source_events:[],detections:[]};
const response=(body,status=200)=>({ok:status>=200&&status<300,status,json:async()=>body});
let shouldFail=false;
const fetch=async(url,opts)=>{calls.push({url,opts});if(shouldFail)return response({},401);if(url==='/api/v1/sysmon/analyze'&&wait)return new Promise(resolve=>pending.push(resolve));if(url==='/api/v1/sysmon/analyze')return response(data);if(url==='/api/v1/analyze')return response({model_state:'semantic-baseline',detections:[]});return response(sample)};
vm.runInNewContext(process.argv[1],{document,window,fetch,Map,String,Error,AbortController,encodeURIComponent});
const click=id=>el[id].handlers.click();
(async()=>{
 for(const [name,label] of [['a','시나리오 A · 정상 프로세스'],['b','시나리오 B · 의심 다운로드 명령'],['c','시나리오 C · 다수 목적지 연결']]){
  await click('#scenario-'+name); assert.ok(el['#summary'].textContent.includes(label),el['#summary'].textContent);
 }
 el['#sysmon-file'].files=[{name:'<img onerror=evil>.json',size:100}];await click('#run-sysmon');
 assert.ok(el['#summary'].textContent.includes('<img onerror=evil>.json'));
 assert.ok(!el['#summary'].textContent.includes('시나리오 C'));
 await click('#run-demo');assert.match(el['#summary'].textContent,/기존 JSON 데모/);
 token=null;await click('#scenario-a');assert.match(el['#summary'].textContent,/토큰이 입력되지/);assert.doesNotMatch(el['#summary'].textContent,/기존 JSON 데모/);
 token='token';shouldFail=true;await click('#scenario-b');assert.match(el['#summary'].textContent,/인증 실패/);assert.doesNotMatch(el['#summary'].textContent,/시나리오 A/);shouldFail=false;
 el['#sysmon-file'].files=[];await click('#run-sysmon');assert.match(el['#summary'].textContent,/파일을 선택/);assert.doesNotMatch(el['#summary'].textContent,/시나리오/);
 wait=true;const first=click('#scenario-a');await new Promise(r=>setTimeout(r,0));const second=click('#scenario-c');await new Promise(r=>setTimeout(r,0));
 assert.equal(pending.length,2);pending[1](response(data));await second;pending[0](response(data));await first;
 assert.match(el['#summary'].textContent,/시나리오 C · 다수 목적지 연결/);assert.doesNotMatch(el['#summary'].textContent,/시나리오 A/);
 console.log('input identity checks passed');
})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness, script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('input identity checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
