import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from aegis_on.command_holdout import validate, evaluate
from aegis_on import command_holdout
from aegis_on.command_overlap import audit, executable_name

class CommandHoldoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads(Path('evaluation/command_holdout_v1.json').read_text())

    def test_dataset_metadata_and_unique_commands(self):
        self.assertTrue(validate(self.data))
        d=copy.deepcopy(self.data); d['cases'][1]['command']=d['cases'][0]['command']
        with self.assertRaises(ValueError): validate(d)
        d=copy.deepcopy(self.data); d['cases'][1]['id']=d['cases'][0]['id']
        with self.assertRaises(ValueError): validate(d)
        d=copy.deepcopy(self.data); d['cases'][0]['technique_candidates']=['T0000']
        with self.assertRaises(ValueError): validate(d)

    def test_common_set_unknown_and_failures_are_separate(self):
        class Fake:
            def predict(self,cmd):
                if not isinstance(cmd,str): return {'status':'invalid_input'}
                if not cmd.strip(): return {'status':'missing_command'}
                if len(cmd)>20000 or len(cmd.split())>128: return {'status':'too_long'}
                return {'status':'ok','score':0.7,'label':'review'}
        r=evaluate(self.data,Fake())
        self.assertEqual(r['cases'],40)
        self.assertEqual(r['scored_cases'],26)
        self.assertEqual(r['exclusions']['unknown_truth'],8)
        self.assertEqual(r['exclusions']['input_missing_command'],3)
        self.assertEqual(r['exclusions']['input_invalid_input'],1)
        self.assertEqual(r['exclusions']['input_too_long'],2)
        self.assertEqual(r['model_common']['tp'],12)
        self.assertEqual(r['model_common']['fp'],14)
        self.assertEqual(r['baseline_common']['support'],r['model_common']['support'])
        self.assertEqual(r['technique_candidate_binary_recall']['T1685.005']['denominator'],1)

    def test_bad_prediction_excluded_not_false_negative(self):
        class Bad:
            def predict(self,cmd): return {'status':'ok','score':float('nan'),'label':'review'}
        selected=copy.deepcopy(self.data); selected['cases']=[selected['cases'][0]]
        r=evaluate(selected,Bad())
        self.assertEqual(r['exclusions']['invalid_output'],1)
        self.assertEqual(r['model_common']['support'],0)
        self.assertIsNone(r['model_common']['precision']['value'])

    def test_rounded_threshold_preserves_product_label(self):
        class Boundary:
            def predict(self,cmd): return {'status':'ok','score':0.5,'label':'below_threshold'}
        selected=copy.deepcopy(self.data); selected['cases']=[selected['cases'][0]]
        r=evaluate(selected,Boundary())
        self.assertEqual(r['model_common']['support'],1)
        self.assertEqual(r['model_common']['tn'],1)

    def test_incorrect_boundary_status_is_reported(self):
        class Broken:
            def predict(self,cmd): return {'status':'ok','score':0.4,'label':'below_threshold'}
        selected=copy.deepcopy(self.data); selected['cases']=[next(r for r in self.data['cases'] if r['id']=='holdout-037')]
        r=evaluate(selected,Broken())
        self.assertEqual(r['expected_status_mismatches'][0]['id'],'holdout-037')
        self.assertEqual(r['expected_status_mismatches'][0]['actual'],'ok')

    def test_prior_datasets_have_no_exact_command_overlap(self):
        old=json.loads(Path('evaluation/command_synthetic_v2.json').read_text())
        pr4=json.loads(Path('evaluation/synthetic_v1.json').read_text())
        findings=audit(self.data,old,pr4)
        self.assertTrue(findings)
        self.assertFalse(any(r['exact_matches'] for r in findings))

    def test_same_executable_identified_with_quoted_windows_path(self):
        new={'cases':[{'id':'new','group':'g','command':'"C:\\Program Files\\bin\\cmd.exe" /c whoami'}]}
        old={'cases':[{'id':'old','command':'cmd /c whoami'}]}
        self.assertEqual(audit(new,old,{'cases':[]})[0]['same_tool_prior_ids'],['v2:old'])
        self.assertEqual(executable_name('/usr/bin/python --version'),'python')

    def test_output_hardlink_cannot_overwrite_frozen_dataset(self):
        with tempfile.TemporaryDirectory() as folder:
            data=Path(folder,'data.json'); out=Path(folder,'report.json')
            original=Path('evaluation/command_holdout_v1.json').read_bytes()
            data.write_bytes(original); os.link(data,out)
            with patch('sys.argv',['command_holdout','--dataset',str(data),'--output',str(out)]):
                with self.assertRaisesRegex(SystemExit,'Output must differ'):
                    command_holdout.main()
            self.assertEqual(data.read_bytes(),original)

if __name__=='__main__': unittest.main()
