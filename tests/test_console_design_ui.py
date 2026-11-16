"""Exercise data-backed overview and experimental model results in the DOM."""
import shutil
import subprocess
import unittest


class ConsoleDesignUiTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_session_expiry_during_poll_redirects_without_exposing_server_text(self):
        harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');let timer,expired=false,redirect='';
class E{constructor(t='div'){this.tag=t;this.children=[];this._text='';this.value='';this.classList={add:()=>{}};this.style={};this.handlers={};this.id=''}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
get childNodes(){return this.children}append(...xs){this.children.push(...xs)}replaceChildren(...xs){this.children=xs;this._text=''}
addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this[k]=v}contains(x){return this===x||this.children.some(c=>c.contains(x))}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));
const document={activeElement:null,querySelector:q=>entries[q]||null,createElement:t=>new E(t)};
const fetch=async url=>expired?{status:401,ok:false,json:async()=>({detail:'synthetic-sensitive-cookie'})}:{ok:true,json:async()=>url.endsWith('/history')?{analyses:[],detections:[]}:url.endsWith('/endpoints')?{endpoints:[]}:url.endsWith('/collectors')?{collectors:[]}:{state:'disabled'}};
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
vm.runInNewContext(code,{document,window:{},location:{pathname:'/',assign:x=>redirect=x},fetch,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array,setInterval:f=>{timer=f;return 1}});
const tick=()=>new Promise(r=>setImmediate(r));
(async()=>{entries['#load'].handlers.click();await tick();expired=true;timer();await tick();assert.equal(redirect,'/login');assert(entries['#status'].textContent.includes('세션이 만료'));assert(!entries['#status'].textContent.includes('synthetic-sensitive-cookie'))})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_event_types_and_overview_use_full_history_for_link_scope(self):
        harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
class E{constructor(t='div'){this.tag=t;this.children=[];this._text='';this.classList={add:()=>{}};this.style={};this.handlers={}}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
get childNodes(){return this.children}append(...xs){this.children.push(...xs)}addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this[k]=v}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));
const document={querySelector:q=>entries[q]||null,createElement:t=>new E(t)};
const data={analyses:[{analysis_id:'new',source_events:[{event_id:'shared',sysmon_event_id:1,host:'fixture-host'},{event_id:'net',sysmon_event_id:3},{event_id:'auth',outcome:'failure'}],detection_ids:[]},...Array.from({length:4},(_,i)=>({analysis_id:'middle'+i,source_events:[],detection_ids:[]})),{analysis_id:'old',source_events:[{event_id:'shared'}],detection_ids:['d']}],detections:[{detection_id:'d',event_ids:['shared']}]};
const script=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
vm.runInNewContext(script+`\nrenderEvents(data,'');view.append(historyTable(data,'',5));`,{data,document,window:{},location:{pathname:'/console/events'},Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array});
const root=entries['#view'];for(const x of ['Sysmon 1 · 프로세스','Sysmon 3 · 네트워크','인증 실패','fixture-host'])assert(root.textContent.includes(x),x);
const history=root.children[1],tbody=history.children[0].children[1],first=tbody.children[0];assert.equal(first.children[3].textContent,'0');assert.equal(tbody.children.length,5);
'''
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_collector_draft_survives_automatic_refresh_after_blur(self):
        harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');let timer;
class E{constructor(t='div'){this.tag=t;this.children=[];this._text='';this.value='';this.classList={add:()=>{}};this.style={};this.handlers={};this.id=''}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
get childNodes(){return this.children}append(...xs){for(const x of xs){x.parent=this;this.children.push(x)}}replaceChildren(...xs){this.children=[];this._text='';this.append(...xs)}
addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this[k]=v}contains(x){return this===x||this.children.some(c=>c.contains(x))}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));const view=entries['#view'];
function walk(e,p){if(p(e))return e;for(const c of e.children){let x=walk(c,p);if(x)return x}return null}
const document={activeElement:null,querySelector:q=>entries[q]||(q.startsWith('#')?walk(view,e=>e.id===q.slice(1)):null),createElement:t=>new E(t)};
const fetch=async url=>({ok:true,json:async()=>url.endsWith('/history')?{analyses:[],detections:[]}:url.endsWith('/endpoints')?{endpoints:[]}:url.endsWith('/collectors')?{collectors:[]}:{state:'disabled'}});
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
vm.runInNewContext(code,{document,window:{},location:{pathname:'/'},fetch,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array,setInterval:f=>{timer=f;return 1}});
const tick=()=>new Promise(r=>setImmediate(r));
(async()=>{entries['#load'].handlers.click();await tick();let input=walk(view,e=>e.tag==='input'&&e.placeholder?.includes('수집기'));assert(input);input.value='synthetic-pc';input.handlers.input();document.activeElement=null;timer();await tick();input=walk(view,e=>e.tag==='input'&&e.placeholder?.includes('수집기'));assert.equal(input.value,'synthetic-pc')})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

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
