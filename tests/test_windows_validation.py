import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.service import DetectionService
from test_sysmon_api import make_event
from aegis_on.windows_validation import compare, decode_payload, load_model, ORIGINAL


class FakeModel:
    def __init__(self, label='review'):
        self.label=label
        self.seen=[]
    def predict(self, text):
        self.seen.append(text)
        if not text: return {'status':'missing_command'}
        return {'status':'ok','label':self.label,'score':0.7}


class WindowsValidationTests(unittest.TestCase):
    def test_same_input_paired_counts_and_no_raw_data(self):
        process=make_event(1, 17); network=make_event(3, 18)
        process['System']['Computer']='PRIVATE-HOST'
        process['EventData']['CommandLine']='curl https://private.invalid/TOKEN123'
        original=FakeModel('review'); refined=FakeModel('below_threshold')
        result=compare({'events':[process,network]},original,refined,'synthetic')
        self.assertEqual(original.seen,refined.seen)
        self.assertEqual(result['processed'],2)
        self.assertEqual(result['paired_event1']['events'],1)
        self.assertEqual(result['paired_event1']['original'],1)
        self.assertEqual(result['paired_event1']['refined'],0)
        self.assertEqual(result['methods']['original']['missing_command'],1)
        self.assertEqual(result['cases'][1]['sysmon_event_id'],3)
        self.assertIsNone(result['cases'][1]['flags']['original'])
        encoded=json.dumps(result)
        for private in ('PRIVATE-HOST','TOKEN123','alice@example.org','192.0.2.9','198.51.100.1','curl'):
            self.assertNotIn(private,encoded)

    def test_batch_invalid_unsupported_and_empty(self):
        invalid=make_event(1); invalid['EventData'].pop('Image')
        unsupported=make_event(2)
        r=compare({'events':[invalid,unsupported]},FakeModel(),FakeModel(),'local-normal')
        self.assertEqual((r['invalid'],r['unsupported'],r['processed']),(1,1,0))
        self.assertEqual(r['paired_event1']['events'],0)
        self.assertEqual(r['methods']['original']['eligible'],0)
        with self.assertRaises(ValueError): compare({'events':[]},FakeModel(),FakeModel(),'other')

    def test_failure_is_not_a_negative_or_a_secret(self):
        class Bad:
            def predict(self,text): return {'status':'sensitive-exception'}
        result=compare({'events':[make_event()]},Bad(),FakeModel(),'synthetic')
        self.assertEqual(result['methods']['original']['invalid_output'],1)
        self.assertEqual(result['paired_event1']['events'],0)
        self.assertNotIn('sensitive-exception',json.dumps(result))

    def test_wrong_model_identity_and_missing_manifest_fail(self):
        with self.assertRaises(ValueError): load_model('path','',ORIGINAL)
        class Ready:
            state='ready';version='wrong'
        with patch('aegis_on.windows_validation.AttackModel.from_environment',return_value=Ready()):
            with self.assertRaises(ValueError): load_model('path','manifest',ORIGINAL)

    def test_rejects_duplicate_keys_nonfinite_and_oversize(self):
        for raw in (b'{"events":[{}],"events":[]}',b'{"events":[],"value":NaN}',b' '* (2 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError): decode_payload(raw)
        self.assertEqual(decode_payload(b'\xef\xbb\xbf{"events":[]}'),{'events':[]})

    def test_synthetic_fixture_api_pii_and_event_links(self):
        fixture=json.loads(Path('data/windows_validation_synthetic.json').read_text())
        old_service=api.service
        self.addCleanup(setattr,api,'service',old_service)
        api.service=DetectionService()
        with patch.dict('os.environ',{'AEGIS_API_TOKEN':'synthetic-token','AEGIS_ANALYST_NAME':'analyst'},clear=False):
            with TestClient(api.app, base_url='https://testserver') as client:
                self.assertEqual(client.post('/api/v1/sysmon/analyze',json=fixture).status_code,401)
                r=client.post('/api/v1/sysmon/analyze',json=fixture,headers={'Authorization':'Bearer synthetic-token'})
        self.assertEqual(r.status_code,200)
        self.assertNotIn('synthetic.user@example.invalid',r.text)
        self.assertNotIn('198.51.100.1',r.text)
        data=r.json(); self.assertEqual(data['summary']['processed'],5)
        source={s['input_index']:s['event_id'] for s in data['source_events']}
        self.assertTrue(data['pii']['findings'])
        self.assertTrue(all(f['event_id']==source[f['input_index']] for f in data['pii']['findings']))
        self.assertTrue(data['detections'])
        self.assertTrue(all(event_id in source.values() for d in data['detections'] for event_id in d['event_ids']))
        self.assertEqual(len(data['attack_model']['results']),len(source))
        self.assertEqual({result['input_index'] for result in data['attack_model']['results']},set(source))
        self.assertTrue(all(result['event_id']==source[result['input_index']] for result in data['attack_model']['results']))

if __name__=='__main__': unittest.main()

class ExporterPowerShellTests(unittest.TestCase):
    @unittest.skipUnless(__import__('shutil').which('pwsh'), 'PowerShell not installed')
    def test_syntax_and_existing_file_guard(self):
        import os, subprocess, tempfile
        from pathlib import Path
        script=Path('scripts/export_sysmon.ps1').resolve()
        syntax=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',
            '$null=[scriptblock]::Create([IO.File]::ReadAllText($env:AEGIS_SCRIPT))'],
            env={**os.environ,'AEGIS_SCRIPT':str(script)},capture_output=True)
        self.assertEqual(syntax.returncode,0,syntax.stderr.decode(errors='replace'))
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder,'existing.json'); target.write_text('unchanged')
            proc=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-File',str(script),
                '-OutputPath',str(target)],capture_output=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertEqual(target.read_text(),'unchanged')

    @unittest.skipUnless(__import__('shutil').which('pwsh'), 'PowerShell not installed')
    def test_oversized_export_is_not_written(self):
        import os, subprocess, tempfile
        from pathlib import Path
        script=Path('scripts/export_sysmon.ps1').resolve()
        # The mocked source is synthetic. No Windows event channel is accessed.
        command=r'''
function Get-WinEvent {
  param($FilterHashtable, $MaxEvents, $ErrorAction)
  for ($i=1; $i -le 900; $i++) {
    $event=[PSCustomObject]@{ ProviderName='Microsoft-Windows-Sysmon'; Id=1;
      TimeCreated=[DateTime]::UtcNow; MachineName='synthetic'; RecordId=$i;
      LogName='Microsoft-Windows-Sysmon/Operational' }
    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
      $payload='x' * 2500
      return "<Event><EventData><Data Name='Image'>cmd.exe</Data><Data Name='CommandLine'>$payload</Data></EventData></Event>"
    }
    $event
  }
}
& $env:AEGIS_SCRIPT -OutputPath $env:AEGIS_OUTPUT -MaxEvents 1000
'''
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder,'out.json')
            proc=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',command],
                env={**os.environ,'AEGIS_SCRIPT':str(script),'AEGIS_OUTPUT':str(target)},capture_output=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertFalse(target.exists())
