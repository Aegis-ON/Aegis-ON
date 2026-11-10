"""Console details must use fresh authenticated history and safe DOM text."""
import shutil
import subprocess
import unittest
from pathlib import Path

class ConsoleUiTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_detection_detail_refresh_and_filters(self):
        html = Path('static/console.html').read_text(encoding='utf-8')
        code = html.split('<script>', 1)[1].split('</script>', 1)[0]
        harness = r'''
const assert=require('assert'),vm=require('vm');
class E{constructor(tag='div'){this.tag=tag;this.children=[];this.handlers={};this._text='';this.value='';this.className='';this.attrs={};this.classList={add:()=>{}};this.style={};}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
get childNodes(){return this.children}append(...items){this.children.push(...items);if(this.tag==='select'&&!this.value&&this.children[0])this.value=this.children[0].value}
replaceChildren(...items){this._text='';this.children=items}addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this.attrs[k]=v}scrollIntoView(){}remove(){this.removed=true}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));
const document={querySelector:q=>entries[q]||null,createElement:tag=>new E(tag)};
const window={prompt:()=> 'temporary-token'};const location={pathname:'/console/detections'};
let host='old-sensitive-host',calls=0;
const fetch=async(url,opts)=>{assert.equal(opts.headers.Authorization,'Bearer temporary-token');calls++;let data={analyses:[{analysis_id:'a',analyzed_at:'2026-01-01T00:00:00Z',detection_ids:['d'],event_refs:[{input_index:0,event_id:'e'}]}],detections:[{detection_id:'d',technique:'T1105',title:'synthetic',source:'rule',score:58,host,event_ids:['e'],evidence:[],status:'pending_review'}]};return {ok:true,json:async()=>data}};
vm.runInNewContext(process.argv[1],{document,window,location,fetch,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array});
function walk(e,p){if(p(e))return e;for(const c of e.children){let x=walk(c,p);if(x)return x}return null}
(async()=>{entries['#load'].handlers.click();await new Promise(resolve=>setImmediate(resolve));let detail=walk(entries['#view'],e=>e.tag==='button'&&e.textContent.includes('synthetic'));assert(detail);host='[HOST:masked]';await detail.handlers.click();assert.equal(calls,2);assert(entries['#view'].textContent.includes('[HOST:masked]'));assert(!entries['#view'].textContent.includes('old-sensitive-host'));
let query=walk(entries['#view'],e=>e.tag==='input'&&e.placeholder==='기법 또는 탐지명');assert(query);query.value='not-found';query.handlers.input();assert(entries['#view'].textContent.includes('조건에 맞는 탐지가 없습니다.'));
})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness, code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_history_selection_clears_previous_detection(self):
        harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
let root;
class E{constructor(tag='div'){this.tag=tag;this.children=[];this.handlers={};this._text='';this.value='';this.className='';this.attrs={};this.classList={add:()=>{}};this.style={};this.id='';}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
get childNodes(){return this.children}append(...items){for(const x of items){x.parent=this;this.children.push(x)}if(this.tag==='select'&&!this.value&&this.children[0])this.value=this.children[0].value}
replaceChildren(...items){this._text='';this.children=[];this.append(...items)}addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this.attrs[k]=v}scrollIntoView(){}remove(){if(this.parent)this.parent.children=this.parent.children.filter(x=>x!==this)}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));root=entries['#view'];
function walk(e,p){if(p(e))return e;for(const c of e.children){let x=walk(c,p);if(x)return x}return null}
const document={querySelector:q=>entries[q]||(q.startsWith('#')?walk(root,e=>e.id===q.slice(1)):null),createElement:tag=>new E(tag)};
const window={prompt:()=> 'temporary-token'},location={pathname:'/console/history'};
const fetch=async()=>({ok:true,json:async()=>({analyses:[{analysis_id:'a',input_type:'json',detection_ids:['d1'],event_refs:[{event_id:'e1'}]},{analysis_id:'b',input_type:'json',detection_ids:['d2'],event_refs:[{event_id:'e2'}]}],detections:[{detection_id:'d1',title:'FIRST_FINDING',technique:'T1',source:'rule',score:50,host:'host1',event_ids:['e1'],evidence:[],status:'pending_review'},{detection_id:'d2',title:'SECOND_FINDING',technique:'T2',source:'rule',score:50,host:'host2',event_ids:['e2'],evidence:[],status:'pending_review'}]})});
const html=fs.readFileSync('static/console.html','utf8');let code=html.split('<script>')[1].split('</script>')[0];vm.runInNewContext(code,{document,window,location,fetch,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array});
(async()=>{entries['#load'].handlers.click();await new Promise(r=>setImmediate(r));await walk(root,e=>e.tag==='button'&&e.textContent==='a').handlers.click();await walk(root,e=>e.tag==='button'&&e.textContent.includes('FIRST_FINDING')).handlers.click();await walk(root,e=>e.tag==='button'&&e.textContent==='b').handlers.click();console.log('new analysis b:',root.textContent.includes('분석 b'));console.log('old finding detail still visible:',root.textContent.includes('FIRST_FINDING'));assert(root.textContent.includes('분석 b')&&!root.textContent.includes('FIRST_FINDING'));})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_changing_filter_clears_previous_detection(self):
        harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');let root;
class E{constructor(tag='div'){this.tag=tag;this.children=[];this.handlers={};this._text='';this.value='';this.className='';this.attrs={};this.classList={add:()=>{}};this.style={};this.id='';}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}get childNodes(){return this.children}append(...items){for(const x of items){x.parent=this;this.children.push(x)}if(this.tag==='select'&&!this.value&&this.children[0])this.value=this.children[0].value}replaceChildren(...items){this._text='';this.children=[];this.append(...items)}addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this.attrs[k]=v}scrollIntoView(){}remove(){if(this.parent)this.parent.children=this.parent.children.filter(x=>x!==this)}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));root=entries['#view'];function walk(e,p){if(p(e))return e;for(const c of e.children){let x=walk(c,p);if(x)return x}return null}
const document={querySelector:q=>entries[q]||(q.startsWith('#')?walk(root,e=>e.id===q.slice(1)):null),createElement:tag=>new E(tag)};const window={prompt:()=> 'temporary-token'},location={pathname:'/console/detections'};const fetch=async()=>({ok:true,json:async()=>({analyses:[{analysis_id:'a',analyzed_at:'2026-01-01T00:00:00Z',detection_ids:['d1'],event_refs:[{event_id:'e1'}]}],detections:[{detection_id:'d1',title:'FIRST_FINDING',technique:'T1',source:'rule',score:50,host:'host1',event_ids:['e1'],evidence:[],status:'pending_review'}]})});
const html=fs.readFileSync('static/console.html','utf8');vm.runInNewContext(html.split('<script>')[1].split('</script>')[0],{document,window,location,fetch,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array});
(async()=>{entries['#load'].handlers.click();await new Promise(r=>setImmediate(r));await walk(root,e=>e.tag==='button'&&e.textContent.includes('FIRST_FINDING')).handlers.click();let query=walk(root,e=>e.tag==='input'&&e.placeholder==='기법 또는 탐지명');query.value='nonexistent';query.handlers.input();console.log('empty result message:',root.textContent.includes('조건에 맞는 탐지가 없습니다.'));console.log('old finding detail still visible:',root.textContent.includes('FIRST_FINDING'));assert(root.textContent.includes('조건에 맞는 탐지가 없습니다.')&&!root.textContent.includes('FIRST_FINDING'));})().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_last_selected_detection_wins_out_of_order_responses(self):
        harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');let root;
class E{constructor(tag='div'){this.tag=tag;this.children=[];this.handlers={};this._text='';this.value='';this.className='';this.attrs={};this.classList={add:()=>{}};this.style={};this.id='';}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}get childNodes(){return this.children}append(...items){for(const x of items){x.parent=this;this.children.push(x)}if(this.tag==='select'&&!this.value&&this.children[0])this.value=this.children[0].value}replaceChildren(...items){this._text='';this.children=[];this.append(...items)}addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this.attrs[k]=v}scrollIntoView(){}remove(){if(this.parent)this.parent.children=this.parent.children.filter(x=>x!==this)}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));root=entries['#view'];function walk(e,p){if(p(e))return e;for(const c of e.children){let x=walk(c,p);if(x)return x}return null}
const document={querySelector:q=>entries[q]||(q.startsWith('#')?walk(root,e=>e.id===q.slice(1)):null),createElement:tag=>new E(tag)};const window={prompt:()=> 'temporary-token'},location={pathname:'/console/detections'};
const data={analyses:[{analysis_id:'a',analyzed_at:'2026-01-01T00:00:00Z',detection_ids:['d1','d2'],event_refs:[{event_id:'e1'},{event_id:'e2'}]}],detections:[{detection_id:'d1',title:'FIRST_FINDING',technique:'T1',source:'rule',score:50,host:'host1',event_ids:['e1'],evidence:[],status:'pending_review'},{detection_id:'d2',title:'SECOND_FINDING',technique:'T2',source:'rule',score:50,host:'host2',event_ids:['e2'],evidence:[],status:'pending_review'}]};
let waiters=[],calls=0;const reply=()=>({ok:true,json:async()=>data});const fetch=async()=>{if(calls++===0)return reply();return new Promise(resolve=>waiters.push(resolve));};
const html=fs.readFileSync('static/console.html','utf8');vm.runInNewContext(html.split('<script>')[1].split('</script>')[0],{document,window,location,fetch,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array});
(async()=>{entries['#load'].handlers.click();await new Promise(r=>setImmediate(r));const first=walk(root,e=>e.tag==='button'&&e.textContent.includes('FIRST_FINDING')).handlers.click();const second=walk(root,e=>e.tag==='button'&&e.textContent.includes('SECOND_FINDING')).handlers.click();waiters[1](reply());await second;waiters[0](reply());await first;let detail=walk(root,e=>e.id==='detail');console.log('last clicked second but detail is first:',detail.textContent.includes('FIRST_FINDING'));assert(detail.textContent.includes('SECOND_FINDING')); })().catch(e=>{console.error(e);process.exit(1)});
'''
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_live_polling_focus_error_and_recovery(self):
        harness = r"""
const assert=require('assert'),vm=require('vm'),fs=require('fs');let root,timer,calls=0,fail=false,total=0,delay=false,release;
class E{constructor(tag='div'){this.tag=tag;this.children=[];this.handlers={};this._text='';this.value='';this.className='';this.attrs={};this.classList={add:()=>{}};this.style={};this.id='';}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}get childNodes(){return this.children}append(...items){for(const x of items){x.parent=this;this.children.push(x)}if(this.tag==='select'&&!this.value&&this.children[0])this.value=this.children[0].value}replaceChildren(...items){this._text='';this.children=[];this.append(...items)}addEventListener(k,v){this.handlers[k]=v}setAttribute(k,v){this.attrs[k]=v}scrollIntoView(){}remove(){if(this.parent)this.parent.children=this.parent.children.filter(x=>x!==this)}contains(x){return this===x||this.children.some(c=>c.contains(x))}}
const entries=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));root=entries['#view'];
function walk(e,p){if(p(e))return e;for(const c of e.children){let x=walk(c,p);if(x)return x}return null}
const document={activeElement:null,querySelector:q=>entries[q]||(q.startsWith('#')?walk(root,e=>e.id===q.slice(1)):null),createElement:tag=>new E(tag)};
const window={prompt:()=> 'temporary-token'},location={pathname:'/',hash:''};
const fetch=async(url)=>{calls++;if(fail)throw new Error('network');if(delay&&url.endsWith('/endpoints'))await new Promise(r=>{release=r});let data=url.endsWith('/history')?{analyses:Array.from({length:total},(_,i)=>({analysis_id:'batch-'+i,event_refs:[],detection_ids:[]})),detections:[]}:url.endsWith('/endpoints')?{endpoints:[]}:url.endsWith('/collectors')?{collectors:[]}:{state:'disabled'};return {ok:true,json:async()=>data}};
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];vm.runInNewContext(code,{document,window,location,fetch,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array,setInterval:(f,ms)=>{assert.equal(ms,5000);timer=f;return 1}});
const tick=()=>new Promise(r=>setImmediate(r));
(async()=>{entries['#load'].handlers.click();await tick();assert(root.textContent.includes('저장된 분석0'));total=1;timer();await tick();assert(root.textContent.includes('저장된 분석1'));document.activeElement=walk(root,e=>e.tag==='button');assert(document.activeElement);let before=calls;timer();await tick();assert.equal(calls,before);assert(entries['#status'].textContent.includes('일시 중지'));document.activeElement=null;fail=true;timer();await tick();assert(entries['#status'].textContent.includes('재연결'));fail=false;timer();await tick();assert(entries['#status'].textContent.includes('복구됨'));delay=true;timer();await tick();let button=walk(root,e=>e.tag==='button'&&e.textContent==='batch-0');assert(button&&release);await button.handlers.click();assert(walk(root,e=>e.id==='history-detail'));release();await tick();assert(walk(root,e=>e.id==='history-detail'),'poll replaced open detail');})().catch(e=>{console.error(e);process.exit(1)});
"""
        result = subprocess.run(['node', '-e', harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__': unittest.main()
