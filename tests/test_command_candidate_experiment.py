"""The comparison must fail closed on known data leakage."""
import copy
import json
from pathlib import Path
import pytest
from aegis_on.command_candidate_experiment import datasets


def test_synthetic_data_has_expected_separate_splits():
    parts = datasets('evaluation/command_refine_dev_v1.json', 'evaluation/command_refine_test_v1.json')
    assert {key:len(rows) for key, rows in parts.items()} == {'train':40, 'validation':16, 'test':24}


def test_exact_command_or_group_leakage_is_rejected(tmp_path):
    dev = json.loads(Path('evaluation/command_refine_dev_v1.json').read_text())
    test = json.loads(Path('evaluation/command_refine_test_v1.json').read_text())
    for kind in ('command', 'group', 'split'):
        corrupt = copy.deepcopy(test)
        if kind == 'split':
            corrupt['cases'][0]['split'] = 'train'
        else:
            corrupt['cases'][0][kind] = dev['cases'][0][kind]
        d, t = tmp_path/'dev.json', tmp_path/'test.json'
        d.write_text(json.dumps(dev)); t.write_text(json.dumps(corrupt))
        with pytest.raises(ValueError):
            datasets(d, t)
