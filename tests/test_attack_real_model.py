"""Opt-in integration with a separately prepared experimental model."""
import os
import unittest
from aegis_on.attack_model import AttackModel


@unittest.skipUnless(os.environ.get('AEGIS_ATTACK_INTEGRATION') == '1', 'real attack model opt-in')
class RealAttackModelTests(unittest.TestCase):
    def test_load_infer_and_reject_long_input(self):
        model = AttackModel.from_environment()
        self.assertEqual(model.state, 'ready')
        self.assertEqual(len(model.status()['artifacts_sha256']), 6)
        result = model.predict('whoami /groups')
        self.assertEqual(result['status'], 'ok')
        self.assertIn(result['label'], ('review', 'below_threshold'))
        self.assertEqual(model.predict('')['status'], 'missing_command')
        self.assertEqual(model.predict('word ' * 1000)['status'], 'too_long')
