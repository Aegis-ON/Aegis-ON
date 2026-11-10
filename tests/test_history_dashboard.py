import shutil
import subprocess
import unittest
from pathlib import Path


class HistoryDashboardTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_empty_error_and_restored_approval(self):
        html = Path('static/index.html').read_text(encoding='utf-8')
        script = html.split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert = require('assert'); const vm = require('vm');
class E {
  constructor(){this.children=[];this._text='';this.handlers={};this.files=[];}
  set textContent(v){this._text=String(v);this.children=[];}
  get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
  append(...c){this.children.push(...c);} replaceChildren(...c){this._text='';this.children=c;}
  addEventListener(n,f){this.handlers[n]=f;} set innerHTML(v){throw Error('unsafe HTML');}
}
const ids=['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections','#load-history','#history-list'];
const elements=Object.fromEntries(ids.map(id=>[id,new E()]));
const document={querySelector:id=>elements[id],createElement:()=>new E()}; let response;
const fetch=async()=>response; const window={prompt:()=>'test-token'};
vm.runInNewContext(process.argv[1],{document,window,fetch,Map,String,Error,AbortController});
(async()=>{
 response={ok:true,json:async()=>({analyses:[],detections:[]})};
 await elements['#load-history'].handlers.click(); assert.match(elements['#history-list'].textContent,/저장된 분석 이력이 없습니다/);
 response={ok:false,status:503,json:async()=>({detail:'history storage unavailable'})};
 await elements['#load-history'].handlers.click(); assert.match(elements['#history-list'].textContent,/저장소 상태/);
 const batch={analysis_id:'a1',analyzed_at:'2026',input_type:'json',detection_ids:['d1'],summary:{total:1,processed:1,invalid:0,unsupported:0},event_refs:[{event_id:'e1',input_index:0}]};
 const detection={detection_id:'d1',event_ids:['e1'],title:'synthetic finding',technique:'T1',score:50,host:'old-public-host',source:'rule',evidence:[],status:'approved_for_simulated_response',approval:{analyst:'analyst',rationale:'reviewed',approved_at:'2026',simulation_only:true}};
 response={ok:true,json:async()=>({analyses:[batch],detections:[detection]})};
 await elements['#load-history'].handlers.click();
 response={ok:true,json:async()=>({analyses:[batch],detections:[{...detection,host:'masked'}]})};
 await elements['#history-list'].children[0].handlers.click();
 assert.match(elements['#results'].textContent,/synthetic finding/); assert.match(elements['#results'].textContent,/이벤트 ID e1/);
 assert.match(elements['#results'].textContent,/시뮬레이션/); assert.match(elements['#results'].textContent,/reviewed/);
 assert.doesNotMatch(elements['#results'].textContent,/old-public-host/);
 const noFinding={analysis_id:'a2',analyzed_at:'2026',input_type:'sysmon',detection_ids:[],summary:{total:1,processed:1,invalid:0,unsupported:0},source_events:[{input_index:0,event_id:'e2',sysmon_event_id:1,record_id:42,log_source:'Synthetic-Sysmon'}]};
 response={ok:true,json:async()=>({analyses:[noFinding],detections:[]})};
 await elements['#load-history'].handlers.click(); await elements['#history-list'].children[0].handlers.click();
 assert.match(elements['#results'].textContent,/탐지 결과가 없습니다/);
 assert.match(elements['#results'].textContent,/레코드 ID: 42/);
 assert.match(elements['#results'].textContent,/Synthetic-Sysmon/);
})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness, script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
