"""Opt-in integration tests for explicitly provisioned official ONNX files.

Run with AEGIS_PII_INTEGRATION=1 and AEGIS_PII_MODEL_DIR set. These tests do
not download the model and are skipped in the ordinary offline test suite.
"""
import os
import unittest

from aegis_on.pii import MODEL_LABELS, PIIDetector, redact_spans


@unittest.skipUnless(os.environ.get('AEGIS_PII_INTEGRATION') == '1',
                     'real model integration is opt-in')
class RealPiiModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = PIIDetector.from_environment()
        if cls.detector.status()['state'] != 'ready':
            raise AssertionError('configured local model did not load and pass warmup')

    def test_official_model_inputs_outputs_and_unicode_offsets(self):
        model = self.detector._model
        self.assertEqual(model.input_names, {'input_ids', 'attention_mask', 'token_type_ids'})
        self.assertEqual(len(MODEL_LABELS), 37)
        texts = ['가상 이름 김민준 이메일 minjun@example.test 연락처 010-1234-5678',
                 'Synthetic user Jane Doe email jane@example.test phone 010-1234-5678']
        for text in texts:
            with self.subTest(language='ko' if text[0] == '가' else 'en'):
                spans = self.detector.find(text)
                self.assertTrue(any(span.source == 'model' for span in spans),
                                'real model returned no candidate for this synthetic input')
                self.assertTrue(all(0 <= span.start < span.end <= len(text) and text[span.start:span.end]
                                    for span in spans))
                display, masked = redact_spans(text, spans)
                self.assertTrue(masked)
                self.assertTrue(all(token in display for _, token in masked))

    def test_long_input_runs_across_multiple_windows(self):
        text = ('normal text ' * 140) + 'minjun@example.test' + (' normal text' * 140) + ' jane@example.test'
        model = self.detector._model
        ids = model.tokenizer(text, add_special_tokens=False, truncation=False)['input_ids']
        class RecordingSession:
            def __init__(self, wrapped):
                self.wrapped, self.windows = wrapped, []
            def run(self, outputs, feed):
                self.windows.append(feed['input_ids'][0].tolist())
                return self.wrapped.run(outputs, feed)
        original = model.session
        recorder = RecordingSession(original)
        model.session = recorder
        try:
            spans = self.detector.find(text)
        finally:
            model.session = original
        self.assertGreater(len(recorder.windows), 1, 'model must process multiple windows')
        step = max(1, model.capacity - min(128, model.capacity // 2))
        expected = []
        for start in range(0, len(ids), step):
            end = min(start + model.capacity, len(ids))
            expected.append(model.tokenizer.build_inputs_with_special_tokens(ids[start:end]))
            if end == len(ids):
                break
        self.assertEqual(recorder.windows, expected, 'all token windows, including the tail, must reach ONNX')
        self.assertEqual(len(spans), len(set(spans)), 'duplicate exact predictions')
        self.assertTrue(all(0 <= span.start < span.end <= len(text) for span in spans))
        self.assertTrue(any(span.source == 'regex' and text[span.start:span.end] == 'jane@example.test'
                            for span in spans), 'the tail must be processed')
        display, _ = self.detector.redact(text)
        self.assertNotIn('jane@example.test', display)
        self.assertNotIn('minjun@example.test', display)


if __name__ == '__main__':
    unittest.main()
