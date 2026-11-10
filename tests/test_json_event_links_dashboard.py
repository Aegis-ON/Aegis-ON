"""The JSON demo must link detection IDs to the displayed, redacted event refs."""
import shutil
import subprocess
import unittest
from pathlib import Path


class JsonEventLinkTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is required')
    def test_json_demo_links_duplicate_refs_without_exposing_unlinked_events(self):
        script = Path('static/index.html').read_text(encoding='utf-8').split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert = require('assert'), vm = require('vm');
class Element {
 constructor(){this.children=[];this._text='';this.handlers={};this.files=[];this.disabled=false}
 set textContent(v){this._text=String(v);this.children=[]}
 get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
 set innerHTML(v){throw Error('unsafe HTML')}
 append(...x){this.children.push(...x)}
 replaceChildren(...x){this._text='';this.children=x}
 addEventListener(k,v){this.handlers[k]=v}
}
const ids=['#summary','#results','#sysmon-file','#run-demo','#run-sysmon','#scenario-a','#scenario-b','#scenario-c','#stat-total','#stat-processed','#stat-excluded','#stat-detections'];
const elements=Object.fromEntries(ids.map(k=>[k,new Element()]));
const document={querySelector:k=>elements[k],createElement:()=>new Element()};
const reply=data=>({ok:true,status:200,json:async()=>data});
const window={prompt:()=> 'test-token'};
const fetch=async (url,options)=>{
 assert.equal(options.headers.Authorization,'Bearer test-token');
 if(url==='/data/demo_events.json') return reply({events:[{}, {}, {}]});
 if(url==='/api/v1/analyze') return reply({model_state:'semantic-baseline',
  detections:[{detection_id:'d1',status:'pending_review',technique:'T1',title:'test',score:50,source:'rule',host:'[HOST:1]',event_ids:['[EVENT:1]'],evidence:[]}],
  event_refs:[{input_index:0,event_id:'[EVENT:1]'},{input_index:1,event_id:'[EVENT:1]'},{input_index:2,event_id:'[EVENT:2]'}]});
 throw Error('unexpected URL '+url);
};
vm.runInNewContext(process.argv[1],{document,window,fetch,Map,String,Error,AbortController,encodeURIComponent});
(async()=>{
 await elements['#run-demo'].handlers.click();
 const card=elements['#results'].children.find(x=>String(x.className).startsWith('card '));
 assert.ok(card, 'detection card');
 assert.match(card.textContent,/입력 0 · 이벤트 ID \[EVENT:1\]/);
 assert.match(card.textContent,/입력 1 · 이벤트 ID \[EVENT:1\]/);
 assert.doesNotMatch(card.textContent,/입력 2 · 이벤트 ID/);
 assert.match(card.textContent,/가명처리된 메타데이터/);
 console.log('linked JSON events');
})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness, script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('linked JSON events', result.stdout)


if __name__ == '__main__':
    unittest.main()
