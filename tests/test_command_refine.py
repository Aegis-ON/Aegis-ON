import copy,json,unittest
from pathlib import Path
from aegis_on.command_refine import validate_development
from aegis_on.command_overlap import normalized

class RefinementDataTests(unittest.TestCase):
    def test_group_and_command_separation(self):
        dev=json.loads(Path('evaluation/command_refine_dev_v1.json').read_text())
        test=json.loads(Path('evaluation/command_refine_test_v1.json').read_text())
        self.assertTrue(validate_development(dev))
        self.assertFalse({c['group'] for c in dev['cases']} & {c['group'] for c in test['cases']})
        self.assertFalse({normalized(c['command']) for c in dev['cases']} & {normalized(c['command']) for c in test['cases']})
        d=copy.deepcopy(dev); d['cases'][-1]['group']=d['cases'][0]['group']
        with self.assertRaises(ValueError): validate_development(d)

    def test_no_exact_reuse_of_previous_cases(self):
        all_new=[]
        for file in ('evaluation/command_refine_dev_v1.json','evaluation/command_refine_test_v1.json'):
            all_new += [normalized(c['command']) for c in json.loads(Path(file).read_text())['cases']]
        self.assertEqual(len(all_new),len(set(all_new)))
        old=[]
        for file in ('evaluation/command_holdout_v1.json','evaluation/command_synthetic_v2.json'):
            old += [normalized(c['command']) for c in json.loads(Path(file).read_text())['cases'] if isinstance(c.get('command'),str) and c['command'].strip()]
        pr4=json.loads(Path('evaluation/synthetic_v1.json').read_text())
        old += [normalized(v) for c in pr4['cases'] for e in c['events'] if isinstance((v:=e.get('EventData',{}).get('CommandLine')),str) and v.strip()]
        self.assertFalse(set(old)&set(all_new))

if __name__=='__main__': unittest.main()
