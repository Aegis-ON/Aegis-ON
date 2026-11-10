"""The selected navigation label must follow the location, including back/forward."""
import shutil
import subprocess
import unittest
from pathlib import Path


class DashboardNavigationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_anchor_state_tracks_hash_changes(self):
        html = Path('static/index.html').read_text(encoding='utf-8')
        code = html.split('      const navLinks =', 1)[1].split('      const MAX_FILE_BYTES', 1)[0]
        code = 'const navLinks =' + code
        harness = r'''
const vm = require('vm'); const assert = require('assert');
const hashes=['#overview','#analysis','#result-section','#history'];
const links=hashes.map(href=>({href,active:false,aria:null,
  getAttribute:()=>href, classList:{toggle(_name,value){links.find(l=>l.href===href).active=value;}},
  setAttribute(_name,value){this.aria=value;}, removeAttribute(){this.aria=null;}}));
let handler; const document={querySelectorAll:()=>links};
const window={location:{hash:''},addEventListener:(name,fn)=>{assert.equal(name,'hashchange');handler=fn;}};
vm.runInNewContext(process.argv[1],{document,window,Array});
assert.deepStrictEqual(links.filter(l=>l.active).map(l=>l.href),['#overview']);
window.location.hash='#history';handler();
assert.deepStrictEqual(links.filter(l=>l.active).map(l=>l.href),['#history']);
assert.equal(links[3].aria,'location'); assert.equal(links[0].aria,null);
window.location.hash='#analysis';handler();
assert.deepStrictEqual(links.filter(l=>l.active).map(l=>l.href),['#analysis']);
'''
        result = subprocess.run(['node', '-e', harness, code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
