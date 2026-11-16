"""Exercise data-backed overview and experimental model results in the DOM."""
import shutil
import subprocess
import unittest


class ConsoleDesignUiTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_overview_and_shadow_use_actual_results_as_text(self):
        harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
class E {
  constructor(tag='div'){this.tag=tag;this.children=[];this.handlers={};this._text='';this.classList={add:()=>{}};this.style={}}
  set textContent(value){this._text=String(value);this.children=[]}
  get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
  get childNodes(){return this.children}
  append(...items){this.children.push(...items)}
  addEventListener(k,v){this.handlers[k]=v}
  setAttribute(k,v){this[k]=v}
}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));
const document={querySelector:q=>entries[q]||null,createElement:tag=>new E(tag)};
const window={},location={pathname:'/console'},code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
const ctx={document,window,location,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array};
vm.runInNewContext(code+`
 const sample={analyses:[{analyzed_at:'test',source_events:[{outcome:'failure'},{sysmon_event_id:3}],review_shadow:{state:'ready',fixture:true,current_order:['d'],proposed_order:['d'],events:[{event_id:'e',status:'ok',score:0.91}]}}],detections:[{detection_id:'d',title:'<img src=x onerror=alert(1)>',event_ids:['e']}]};
 view.append(topology(sample,{endpoints:[{host:'synthetic-host',endpoint_id:'device'}]}),renderShadow(sample,''));`,ctx);
const content=entries['#view'].textContent;
for(const text of ['synthetic-host','인증 이벤트 1건','Sysmon 연결 1건','별도 수집 미연동','의미는 아닙니다','합성 검증용','0.910','<img src=x onerror=alert(1)>'])assert(content.includes(text),text);
function walk(e){assert.notEqual(e.tag,'img');for(const c of e.children)walk(c)}walk(entries['#view']);
'''
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
