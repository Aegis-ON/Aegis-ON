"""Regression coverage for overlapping dashboard requests and network direction."""
import shutil
import subprocess
import unittest
from pathlib import Path


class DashboardReviewTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_overlapping_requests_and_sysmon_direction(self):
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
const elements=Object.fromEntries(['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'].map(id=>[id,new Element()]));
const document={querySelector:id=>elements[id],createElement:()=>new Element()};
let token='test-token';
const window={prompt:()=>token};
let requests=[];
const fetch=(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject}));
vm.runInNewContext(process.argv[1],{document,window,fetch,Map,String,Error,AbortController});
const click=id=>elements[id].handlers.click();
const file=name=>({name,size:100});
const apiResponse=(label,count=1,initiated=true)=>({ok:true,status:200,json:async()=>({
  summary:{total:count,processed:count,invalid:0,unsupported:0},
  items:[{input_index:0,status:'processed'}],
  source_events:[{event_id:'e1',input_index:0,sysmon_event_id:3,record_id:10,initiated}],
  detections:[{event_ids:['e1'],technique:'T1595',title:label,score:70,host:'host',source:'correlation',evidence:[]}]
})});
const setFile=name=>{elements['#sysmon-file'].files=[file(name)];};
(async()=>{
  setFile('old.json'); const old=click('#run-sysmon');
  setFile('new.json'); const recent=click('#run-sysmon');
  assert.equal(requests[0].options.signal.aborted,true);
  requests[1].resolve(apiResponse('new-result',2,true)); await recent;
  requests[0].resolve(apiResponse('old-result',1,false)); await old;
  assert.match(elements['#summary'].textContent,/전체 2건/);
  assert.match(elements['#results'].textContent,/new-result/);
  assert.doesNotMatch(elements['#results'].textContent,/old-result/);
  assert.match(elements['#results'].textContent,/발신/);
  requests=[];
  setFile('old.json'); const failed=click('#run-sysmon');
  setFile('new.json'); const ok=click('#run-sysmon');
  requests[1].resolve(apiResponse('last-result',1,false)); await ok;
  requests[0].reject(Error('old failure')); await failed;
  assert.doesNotMatch(elements['#summary'].textContent,/old failure/);
  assert.match(elements['#results'].textContent,/last-result/);
  assert.match(elements['#results'].textContent,/수신/);
  requests=[];
  setFile('old.json'); const invalidated=click('#run-sysmon');
  elements['#sysmon-file'].files=[]; await click('#run-sysmon');
  requests[0].resolve(apiResponse('must-not-render')); await invalidated;
  assert.equal(requests[0].options.signal.aborted,true);
  assert.match(elements['#summary'].textContent,/파일을 선택/);
  assert.doesNotMatch(elements['#results'].textContent,/must-not-render/);
  requests=[];
  setFile('old.json'); const canceled=click('#run-sysmon');
  token=null; setFile('new.json'); await click('#run-sysmon');
  requests[0].resolve(apiResponse('must-not-render')); await canceled;
  assert.match(elements['#summary'].textContent,/토큰이 입력되지/);
  assert.doesNotMatch(elements['#results'].textContent,/must-not-render/);
  token='test-token'; requests=[];
  setFile('old.json'); const oversized=click('#run-sysmon');
  elements['#sysmon-file'].files=[{name:'large.json',size:2*1024*1024+1}];
  await click('#run-sysmon');
  requests[0].resolve(apiResponse('must-not-render')); await oversized;
  assert.match(elements['#summary'].textContent,/2 MiB/);
  assert.doesNotMatch(elements['#results'].textContent,/must-not-render/);
  token='test-token'; requests=[];
  const demo=click('#run-demo');
  setFile('new.json'); const newer=click('#run-sysmon');
  requests[1].resolve(apiResponse('sysmon-result')); await newer;
  requests[0].resolve({ok:true,status:200,json:async()=>({events:[]})}); await demo;
  assert.equal(requests.length,2);
  assert.match(elements['#results'].textContent,/sysmon-result/);
  requests=[];
  setFile('old.json'); const oldSysmon=click('#run-sysmon');
  const newDemo=click('#run-demo');
  requests[1].resolve({ok:true,status:200,json:async()=>({events:[]})});
  await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(requests[2].url,'/api/v1/analyze');
  requests[2].resolve({ok:true,status:200,json:async()=>({model_state:'semantic-baseline',detections:[{technique:'T',title:'demo-result',score:50,host:'demo',source:'rule',evidence:[]}]})});
  await newDemo;
  requests[0].resolve(apiResponse('old-sysmon')); await oldSysmon;
  assert.match(elements['#results'].textContent,/demo-result/);
  assert.doesNotMatch(elements['#results'].textContent,/old-sysmon/);
  token='test-token'; requests=[];
  setFile('unknown.json'); const unknown=click('#run-sysmon');
  requests[0].resolve(apiResponse('unknown-result',1,null)); await unknown;
  assert.match(elements['#results'].textContent,/미상/);
  requests=[];
  setFile('no-detections.json'); const noDetections=click('#run-sysmon');
  requests[0].resolve({ok:true,status:200,json:async()=>({
    summary:{total:3,processed:3,invalid:0,unsupported:0},
    items:[{input_index:0,status:'processed'},{input_index:1,status:'processed'},{input_index:2,status:'processed'}],
    source_events:[{input_index:0,sysmon_event_id:3,initiated:true},{input_index:1,sysmon_event_id:3,initiated:false},{input_index:2,sysmon_event_id:3,initiated:null}],
    detections:[]
  })}); await noDetections;
  const output=elements['#results'].textContent;
  assert.match(output,/입력 0: 처리됨.*발신/);
  assert.match(output,/입력 1: 처리됨.*수신/);
  assert.match(output,/입력 2: 처리됨.*미상/);
  assert.match(output,/탐지 결과가 없습니다/);
  console.log('request race and direction checks passed');
})().catch(error=>{console.error(error);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness, script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('request race and direction checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
