"""Exercise PII status and safe rendering in the dashboard."""
import shutil
import subprocess
import unittest
from pathlib import Path


class PiiDashboardTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_pii_results_and_request_lifecycle(self):
        html = Path('static/index.html').read_text(encoding='utf-8')
        script = html.split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert = require('assert');
const vm = require('vm');
class Element {
  constructor() { this.children=[]; this._text=''; this.handlers={}; this.files=[]; }
  set textContent(value) { this._text=String(value); this.children=[]; }
  get textContent() { return this._text+this.children.map(child=>child.textContent).join(''); }
  set innerHTML(value) { throw Error('HTML injection attempted'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text=''; this.children=children; }
  addEventListener(name, fn) { this.handlers[name]=fn; }
}
const ids=['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'];
const elements=Object.fromEntries(ids.map(id=>[id,new Element()]));
const document={querySelector:id=>elements[id],createElement:()=>new Element()};
const window={prompt:()=> 'token'};
const requests=[];
const fetch=(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject}));
vm.runInNewContext(process.argv[1],{document,window,fetch,Map,String,Error,AbortController});
const click=id=>elements[id].handlers.click();
const response=pii=>({ok:true,status:200,json:async()=>({
  summary:{total:1,processed:1,invalid:0,unsupported:0},
  items:[{input_index:0,status:'processed'}],source_events:[],detections:[],pii
})});
const output=()=>elements['#results'].textContent;
const run=async pii=>{const action=click('#run-sysmon'); requests.at(-1).resolve(response(pii)); await action;};
(async()=>{
  elements['#sysmon-file'].files=[{name:'events.json',size:100}];
  await run({state:'ready',findings:[
    {input_index:0,event_id:'evt-safe',field:'command_line',type:'EMAIL',source:'regex',token:'<email_1>',raw:'raw-secret',host:'host-secret'},
    {input_index:0,event_id:'evt-safe',field:'user',type:'PERSON',source:'model',token:'<person_1>'}
  ],truncated:true});
  assert.match(output(),/개인정보 탐지 결과 2건/);
  for (const part of ['입력 0','command_line','EMAIL','정규식','<email_1>','PERSON','모델','<person_1>','일부 탐지 항목이 생략']) assert.ok(output().includes(part),part);
  assert.doesNotMatch(output(),/raw-secret|host-secret/);
  assert.match(output(),/모든 개인정보를 보호하지 못하며/);
  assert.match(output(),/키워드 기준선은 BERT가 아닙니다/);
  const loading=click('#run-sysmon');
  assert.equal(output(),'');
  assert.match(elements['#summary'].textContent,/분석하고 있습니다/);
  requests.at(-1).resolve(response({state:'ready',findings:[]})); await loading;
  assert.match(output(),/개인정보 탐지 결과가 없습니다/);
  assert.doesNotMatch(output(),/EMAIL|<email_1>|비활성화|탐지 오류/);
  const regexFinding={input_index:0,field:'user',type:'EMAIL',source:'regex',token:'<email_2>',raw:'never-show',host:'never-show-host'};
  await run({state:'disabled',reason:'설정에서 비활성화',findings:[regexFinding]});
  assert.match(output(),/개인정보 모델 비활성화.*설정에서 비활성화/);
  assert.match(output(),/정규식 탐지는 계속 적용/);
  assert.match(output(),/EMAIL.*정규식.*<email_2>/);
  assert.doesNotMatch(output(),/never-show|개인정보 탐지 결과가 없습니다/);
  await run({state:'error',reason:'<img src=x onerror=evil()>',findings:[regexFinding],truncated:true});
  assert.match(output(),/개인정보 모델 오류.*<img src=x onerror=evil\(\)>/);
  assert.match(output(),/EMAIL.*정규식.*<email_2>/);
  assert.match(output(),/일부 탐지 항목이 생략/);
  assert.doesNotMatch(output(),/never-show|개인정보 탐지 결과가 없습니다|비활성화/);
  await run({state:'disabled',findings:[]});
  assert.match(output(),/정규식 탐지 결과가 없습니다/);
  assert.doesNotMatch(output(),/개인정보 탐지 결과가 없습니다/);
  await run(undefined);
  assert.match(output(),/개인정보 탐지 결과가 제공되지 않았습니다/);
  const old=click('#run-sysmon'); const oldRequest=requests.at(-1);
  const recent=click('#run-sysmon'); const newRequest=requests.at(-1);
  newRequest.resolve(response({state:'ready',findings:[]})); await recent;
  oldRequest.resolve(response({state:'error',reason:'오래된 오류',findings:[]})); await old;
  assert.doesNotMatch(output(),/오래된 오류/);
  assert.match(output(),/개인정보 탐지 결과가 없습니다/);
  console.log('PII dashboard checks passed');
})().catch(error=>{console.error(error);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness, script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PII dashboard checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
