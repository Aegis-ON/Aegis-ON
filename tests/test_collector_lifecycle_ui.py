"""Collector state and one-time-secret behavior under browser-style DOM events."""
import shutil
import subprocess
import unittest

class CollectorLifecycleUiTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_prior_report_error_and_one_time_secret_refresh_guard(self):
        script=r'''
const assert=require('assert'),fs=require('fs'),vm=require('vm');
class E{constructor(tag='div'){this.tag=tag;this.children=[];this.handlers={};this.style={};this.attrs={};this.classList={add(){}};this.value='';this.id='';this._text='';this.disabled=false}
set textContent(v){this._text=String(v);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
append(...x){for(const y of x){y.parent=this;this.children.push(y)}}get childNodes(){return this.children}replaceChildren(...x){this.children=[];this._text='';this.append(...x)}
setAttribute(k,v){this.attrs[k]=v}addEventListener(k,v){this.handlers[k]=v}remove(){if(this.parent)this.parent.children=this.parent.children.filter(x=>x!==this)}contains(x){return this===x||this.children.some(c=>c.contains(x))}scrollIntoView(){}}
const els=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));let view=els['#view'];
function walk(e,f){if(f(e))return e;for(const child of e.children){let found=walk(child,f);if(found)return found}return null}
const document={activeElement:null,querySelector:q=>els[q]||(q.startsWith('#')?walk(view,e=>e.id===q.slice(1)):null),createElement:t=>new E(t)};
let posts=0,gets=0,release,releaseHistory;const fetch=async(url)=>{if(url.endsWith('/reissue')){posts++;await new Promise(r=>release=r);return {ok:true,json:async()=>({collector_id:'pc-1',credential:'synthetic-once'})}}gets++;if(url.endsWith('/history'))await new Promise(r=>releaseHistory=r);let data=url.endsWith('/endpoints')?{endpoints:[]}:url.endsWith('/collectors')?{collectors:[]}:{analyses:[],detections:[]};return {ok:true,json:async()=>data}};
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
let copied='';const ctx={document,window:{confirm:()=>true,navigator:{clipboard:{writeText:async value=>{copied=value}}}},location:{pathname:'/console/endpoints'},Node:E,fetch,encodeURIComponent,decodeURIComponent,Date,Number,String,Array,Set};vm.createContext(ctx);vm.runInContext(code,ctx);
ctx.renderCollectors({collectors:[{collector_id:'pc-1',registered:true,credential_state:'revoked',credential_changed_at:'2026-11-10T10:00:00Z',last_heartbeat_at:'2026-11-10T09:00:00Z',reported_state:'running',last_error_code:'read_error',last_error_at:'2026-11-10T08:00:00Z'},{collector_id:'pc-2',registered:true,credential_state:'revoked'}]});
assert(view.textContent.includes('인증 변경 전 마지막 보고'));assert(view.textContent.includes('read_error · 2026-11-10T08:00:00Z (과거 보고)'));
(async()=>{let buttons=[];function collect(e){if(e.tag==='button'&&e.textContent==='재발급')buttons.push(e);for(const c of e.children)collect(c)}collect(view);let pending=ctx.refresh('session');assert(releaseHistory);let issuing=buttons[0].handlers.click();await ctx.refresh('session');assert.equal(gets,1);releaseHistory();await pending;release();await issuing;assert(!view.textContent.includes('synthetic-once'));let copy=walk(view,e=>e.tag==='button'&&e.textContent==='인증 정보 복사');await copy.handlers.click();assert.equal(copied,'synthetic-once');assert(els['#load'].disabled);assert(!view.children.some(e=>e.id==='detail'));await buttons[1].handlers.click();assert.equal(posts,1);const before=gets;await ctx.refresh('session');assert.equal(gets,before);assert(!view.textContent.includes('synthetic-once'));})().catch(e=>{console.error(e);process.exit(1)});
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
