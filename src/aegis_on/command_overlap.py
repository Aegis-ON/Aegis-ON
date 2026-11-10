"""Candidate similarity audit: heuristics are not evidence of independence."""
from __future__ import annotations
import difflib
import json
import re
from pathlib import Path


def normalized(s): return ' '.join(s.casefold().split())

def template(s):
    s=normalized(s)
    s=re.sub(r'https?://\S+', '<url>', s)
    s=re.sub(r'[a-z]:\\[^\s\"\']+', '<path>', s)
    s=re.sub(r'/(?:[a-z0-9_.-]+/)+[a-z0-9_.-]+', '<path>', s)
    s=re.sub(r'\b\d+(?:\.\d+){0,3}\b','<n>',s)
    return s

def audit(new, old, pr4):
    prior=[('v2:'+c['id'],c['command']) for c in old['cases'] if isinstance(c.get('command'),str) and c['command'].strip()]
    for case in pr4['cases']:
        for event in case['events']:
            cmd=event.get('EventData',{}).get('CommandLine')
            if isinstance(cmd,str) and cmd.strip(): prior.append(('pr4:'+case['case_id'],cmd))
    results=[]
    for case in new['cases']:
        cmd=case.get('command')
        if not isinstance(cmd,str) or not cmd.strip() or len(cmd)>20000: continue
        exact=[ident for ident,text in prior if normalized(text)==normalized(cmd)]
        candidates=[(difflib.SequenceMatcher(None,template(cmd),template(text),autojunk=False).ratio(),ident) for ident,text in prior]
        score,ident=max(candidates) if candidates else (0.0,None)
        executable=cmd.strip().split()[0].casefold().removesuffix('.exe')
        same_tool=sorted({ident for ident,text in prior if text.strip().split()[0].casefold().removesuffix('.exe')==executable})
        results.append({'id':case['id'],'group':case['group'],'exact_matches':exact,'nearest_prior':ident,'template_similarity':round(score,4),'same_tool_prior_ids':same_tool})
    return results

if __name__=='__main__':
    def read(p): return json.loads(Path(p).read_text())
    print(json.dumps(audit(read('evaluation/command_holdout_v1.json'),read('evaluation/command_synthetic_v2.json'),read('evaluation/synthetic_v1.json')),ensure_ascii=False,indent=2))
