"""Exercise scenario and approval interactions in a dependency-free DOM harness."""
import shutil
import subprocess
import unittest
import json
from pathlib import Path
from unittest.mock import patch


class DemoDashboardTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_scenarios_approval_and_output_safety(self):
        html = Path('static/index.html').read_text(encoding='utf-8')
        script = html.split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert=require('assert'), vm=require('vm');
class Element {
 constructor(){this.children=[];this._text='';this.handlers={};this.files=[];this.disabled=false}
 set textContent(v){this._text=String(v);this.children=[]}
 get textContent(){return this._text+this.children.map(c=>c.textContent).join('')}
 set innerHTML(v){throw Error('unsafe HTML assignment')}
 append(...c){this.children.push(...c)}
 replaceChildren(...c){this.children=c;this._text=''}
 addEventListener(k,f){this.handlers[k]=f}
}
const ids=['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'];
const elements=Object.fromEntries(ids.map(k=>[k,new Element()]));
const document={querySelector:k=>elements[k],createElement:()=>new Element()};
let prompts=[], calls=[], scenario='a', approvalReply={simulation_only:true,detection:{status:'approved_for_simulated_response'}}, approvalStatus=200, approvalDeferred=null;
const window={prompt:()=>prompts.shift()};
const src=(i)=>({input_index:i,event_id:'evt-'+i,sysmon_event_id:3,record_id:10+i,log_source:'Sysmon/Operational',host:'host',timestamp:'2026-11-09T10:00:00Z',process_id:i,process_guid:'guid-'+i,source_ip:'[IP:src]',source_port:50000+i,destination_ip:'[IP:'+i+']',destination_port:443,initiated:true});
const alert=(ids=['evt-0'])=>({detection_id:'det-1',status:'pending_review',technique:'T1105',title:'<img src=x onerror=evil()>',score:72,source:'rule',host:'host',event_ids:ids,evidence:['rule evidence <script>bad</script>']});
const response=(data,status=200)=>({ok:status>=200&&status<300,status,json:async()=>data});
const fetch=async(url,options)=>{
 calls.push({url,options});
 if(url.startsWith('/api/v1/demo/scenarios/')) return response({events:[{demo:url.slice(-1)}]});
 if(url==='/api/v1/sysmon/analyze'){
  assert.deepEqual(JSON.parse(options.body),{events:[{demo:scenario}]});
  const count=scenario==='c'?3:1;
  const source_events=Array.from({length:count},(_,i)=>src(i));
  const detections=scenario==='a'?[]:[alert(source_events.map(e=>e.event_id))];
  return response({summary:{total:count,processed:count,invalid:0,unsupported:0},items:source_events.map(e=>({input_index:e.input_index,status:'processed'})),source_events,detections});
 }
 if(url.endsWith('/approval')){
  if(approvalDeferred) return await approvalDeferred;
  return response(approvalReply,approvalStatus);
 }
 throw Error('unexpected URL '+url);
};
vm.runInNewContext(process.argv[1],{document,window,fetch,Map,String,Error,AbortController,encodeURIComponent});
const click=id=>elements[id].handlers.click();
function descendants(element){return [element,...element.children.flatMap(descendants)]}
function button(label){const b=descendants(elements['#results']).find(e=>e._text===label&&e.handlers.click);assert.ok(b,label);return b}
(async()=>{
 prompts=['tok']; scenario='a'; await click('#scenario-a');
 assert.deepEqual(calls.map(c=>c.url),['/api/v1/demo/scenarios/a','/api/v1/sysmon/analyze']);
 assert.ok(calls.every(c=>c.options.headers.Authorization==='Bearer tok'));
 assert.equal(elements['#stat-total'].textContent,'1'); assert.equal(elements['#stat-detections'].textContent,'0');
 assert.match(elements['#results'].textContent,/탐지 결과가 없습니다/);
 assert.match(elements['#results'].textContent,/레코드 ID: 10/);
 assert.match(elements['#results'].textContent,/Sysmon\/Operational/);
 calls=[]; prompts=['tok']; scenario='b'; await click('#scenario-b');
 assert.equal(elements['#stat-detections'].textContent,'1');
 assert.match(elements['#results'].textContent,/<img src=x onerror=evil\(\)>/);
 assert.match(elements['#results'].textContent,/<script>bad<\/script>/);
 assert.match(elements['#results'].textContent,/점수 기반 임시 분류/);
 let b=button('시뮬레이션 승인');
 prompts=['tok','analyst-1','검토'];
 let resolveApproval; approvalDeferred=new Promise(resolve=>{resolveApproval=resolve});
 let first=b.handlers.click(); await b.handlers.click();
 assert.equal(calls.filter(c=>c.url.endsWith('/approval')).length,1);
 const req=calls.find(c=>c.url.endsWith('/approval'));
 assert.equal(req.options.headers.Authorization,'Bearer tok');
 assert.deepEqual(JSON.parse(req.options.body),{analyst:'analyst-1',rationale:'검토'});
 resolveApproval(response(approvalReply)); await first; approvalDeferred=null;
 assert.equal(b.disabled,true);
 assert.match(elements['#results'].textContent,/approved_for_simulated_response/);
 assert.match(elements['#results'].textContent,/실제 차단 없음/);
 calls=[]; prompts=['tok']; scenario='b'; await click('#scenario-b');
 b=button('시뮬레이션 승인'); prompts=['bad','analyst-1','']; approvalStatus=401; await b.handlers.click();
 assert.match(elements['#results'].textContent,/인증 실패/); assert.equal(b.disabled,false);
 prompts=['tok','wrong','']; approvalStatus=403; await b.handlers.click();
 assert.match(elements['#results'].textContent,/분석가 이름/); assert.equal(b.disabled,false);
 prompts=['tok','analyst-1','']; approvalStatus=409; await b.handlers.click();
 assert.match(elements['#results'].textContent,/이미 처리된 요청/); assert.equal(b.disabled,false);
 approvalStatus=200; calls=[]; prompts=['tok']; scenario='c'; await click('#scenario-c');
 assert.equal(elements['#stat-total'].textContent,'3');
 assert.match(elements['#results'].textContent,/레코드 ID: 10/);
 assert.match(elements['#results'].textContent,/레코드 ID: 11/);
 assert.match(elements['#results'].textContent,/레코드 ID: 12/);
 assert.match(elements['#results'].textContent,/처리된 원본 이벤트 3건/);
 console.log('scenario and approval checks passed');
})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness, script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scenario and approval checks passed', result.stdout)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for dashboard JavaScript tests')
    def test_actual_scenario_api_results_render(self):
        from fastapi.testclient import TestClient
        from aegis_on import api
        from aegis_on.service import DetectionService

        cases = {}
        with patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst-1'}):
            api.service = DetectionService()
            with TestClient(api.app) as client:
                headers = {'Authorization': 'Bearer test-secret'}
                for name in ('a', 'b', 'c'):
                    sample_response = client.get(f'/api/v1/demo/scenarios/{name}', headers=headers)
                    self.assertEqual(sample_response.status_code, 200, sample_response.text)
                    sample = sample_response.json()
                    analysis = client.post('/api/v1/sysmon/analyze', json=sample, headers=headers)
                    self.assertEqual(analysis.status_code, 200, analysis.text)
                    cases[name] = {'sample': sample, 'result': analysis.json()}
        self.assertEqual(len(cases['a']['result']['detections']), 0)
        self.assertTrue(any(d['technique'] == 'T1105' for d in cases['b']['result']['detections']))
        self.assertTrue(any(d['source'] == 'correlation' for d in cases['c']['result']['detections']))
        script = Path('static/index.html').read_text(encoding='utf-8').split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert=require('assert'),vm=require('vm'),data=JSON.parse(require('fs').readFileSync(0,'utf8'));
class Element{constructor(){this.children=[];this._text='';this.handlers={};this.files=[]}set textContent(v){this._text=String(v);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}set innerHTML(v){throw Error('unsafe HTML')}append(...x){this.children.push(...x)}replaceChildren(...x){this._text='';this.children=x}addEventListener(k,v){this.handlers[k]=v}}
const ids=['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'];
const elements=Object.fromEntries(ids.map(k=>[k,new Element()])),document={querySelector:k=>elements[k],createElement:()=>new Element()},window={prompt:()=> 'test-secret'};
let current='';
const fetch=async(url,opts)=>{assert.equal(opts.headers.Authorization,'Bearer test-secret');if(url.startsWith('/api/v1/demo/scenarios/')){current=url.slice(-1);return {ok:true,status:200,json:async()=>data.cases[current].sample}}assert.equal(url,'/api/v1/sysmon/analyze');assert.deepEqual(JSON.parse(opts.body),data.cases[current].sample);return {ok:true,status:200,json:async()=>data.cases[current].result}};
vm.runInNewContext(data.script,{document,window,fetch,Map,String,Error,AbortController,encodeURIComponent});
(async()=>{for(const name of ['a','b','c']){await elements['#scenario-'+name].handlers.click();const r=data.cases[name].result;assert.equal(elements['#stat-total'].textContent,String(r.summary.total));assert.equal(elements['#stat-detections'].textContent,String(r.detections.length));for(const source of r.source_events){assert.ok(elements['#results'].textContent.includes(`레코드 ID: ${source.record_id}`))}}assert.match(elements['#results'].textContent,/3 unique destinations/);console.log('actual scenarios rendered')})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness], input=json.dumps({'cases': cases, 'script': script}), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('actual scenarios rendered', result.stdout)


if __name__ == '__main__':
    unittest.main()
