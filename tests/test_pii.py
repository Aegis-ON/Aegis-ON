import os
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import numpy as np
except ImportError:
    np = None

from aegis_on.pii import MODEL_LABELS, PIIDetector, Span, _LocalModel, _verify_model_files, redact_spans, regex_spans
from aegis_on.privacy import redact_text


class MockModel:
    def __init__(self, spans):
        self.spans = spans

    def find(self, text):
        return self.spans


class PIITests(unittest.TestCase):
    def test_default_is_disabled_and_regex_remains_available(self):
        with patch.dict(os.environ, {}, clear=True):
            detector = PIIDetector.from_environment()
        self.assertEqual(detector.status()["state"], "disabled")
        display, metadata = detector.redact("mail a@example.org")
        self.assertNotIn("a@example.org", display)
        self.assertEqual(metadata[0]["type"], "EMAIL")
        self.assertEqual(metadata[0]["source"], "regex")
        self.assertNotIn("a@example.org", str(metadata))

    def test_failed_initialization_is_generic_and_falls_back_to_regex(self):
        with patch.dict(os.environ, {"AEGIS_PII_MODEL_DIR": "/private/secret-directory"}):
            detector = PIIDetector.from_environment()
        self.assertEqual(detector.status()["state"], "error")
        self.assertNotIn("secret", str(detector.status()))
        self.assertEqual(detector.find("a@example.org")[0].label, "EMAIL")

    def test_configured_local_model_initialization_success_and_dependency_failure(self):
        with patch.dict(os.environ, {"AEGIS_PII_MODEL_DIR": "/local/model"}), \
             patch('aegis_on.pii._LocalModel', return_value=MockModel([])) as loader:
            detector = PIIDetector.from_environment()
            loader.assert_called_once_with('/local/model')
            self.assertEqual(detector.status()['state'], 'ready')
        with patch.dict(os.environ, {"AEGIS_PII_MODEL_DIR": "/private/secret"}), \
             patch('aegis_on.pii._LocalModel', side_effect=ModuleNotFoundError('secret path')):
            detector = PIIDetector.from_environment()
            self.assertEqual(detector.status()['state'], 'error')
            self.assertIn('dependencies', detector.status()['reason'])
            self.assertNotIn('secret', str(detector.status()))

    def test_graph_and_every_tokenizer_asset_must_match_revision_hashes(self):
        contents = {'config.json': b'config', 'tokenizer.json': b'tokenizer',
                    'tokenizer_config.json': b'tokenizer config', 'special_tokens_map.json': b'special',
                    'vocab.txt': b'vocabulary', 'onnx/model_quantized.onnx': b'graph'}
        hashes = {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()}
        graph_hash = hashes.pop('onnx/model_quantized.onnx')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in contents.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
            with patch('aegis_on.pii.MODEL_SHA256', graph_hash), patch('aegis_on.pii.MODEL_ASSET_SHA256', hashes):
                _verify_model_files(root)
                for name, value in contents.items():
                    with self.subTest(file=name):
                        (root / name).write_bytes(value + b'changed')
                        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                            _verify_model_files(root)
                        (root / name).write_bytes(value)

    def test_regex_offsets_and_compatible_ip_tokens(self):
        samples = ["host:2001:db8::1.", "mapped ::ffff:192.0.2.1 connected",
                   "https://[2001:db8::1]:8443 a@example.org 010-1234-5678",
                   "host 2001:0db8:0000:0000:0000:0000:0000:0001"]
        for text in samples:
            with self.subTest(text=text):
                spans = regex_spans(text)
                self.assertTrue(spans)
                for span in spans:
                    self.assertTrue(text[span.start:span.end])
                display, _ = PIIDetector().redact(text)
                if "::ffff:" not in text:
                    self.assertEqual(display, redact_text(text))
        text = "mapped ::ffff:192.0.2.1 connected"
        self.assertEqual([text[s.start:s.end] for s in regex_spans(text)], ["::ffff:192.0.2.1"])

    def test_mapped_ipv6_uses_ipv4_token_and_legacy_redaction_is_unchanged(self):
        detector = PIIDetector()
        mapped, _ = detector.redact("::ffff:192.0.2.1")
        ipv4, _ = detector.redact("192.0.2.1")
        self.assertEqual(mapped, ipv4)
        self.assertNotIn("192.0.2.1", redact_text("::ffff:192.0.2.1"))

    def test_overlap_union_preserves_all_sensitive_characters(self):
        text = "John a@example.org Doe"
        detector = PIIDetector(MockModel([Span(0, 10, "GIVENNAME", "model"), Span(15, 22, "SURNAME", "model")]))
        spans = detector.find(text)
        self.assertEqual({span.source for span in spans}, {"regex", "model"})
        display, merged = redact_spans(text, spans)
        self.assertEqual((merged[0][0].start, merged[0][0].end), (0, len(text)))
        self.assertEqual(merged[0][0].source, "regex")
        display, metadata = detector.redact(text)
        self.assertNotIn("John", display)
        self.assertNotIn("Doe", display)
        self.assertNotIn(text, str(metadata))

    def test_repeated_tokens_use_offsets_and_pseudonym_consistency(self):
        text = "Lee met Lee"
        detector = PIIDetector(MockModel([Span(0, 3, "SURNAME", "model"), Span(8, 11, "SURNAME", "model")]))
        display, metadata = detector.redact(text)
        self.assertEqual(metadata[0]["token"], metadata[1]["token"])
        self.assertEqual(display, metadata[0]["token"] + " met " + metadata[1]["token"])

    def test_inference_error_is_sanitized_and_sticky(self):
        class Broken:
            def find(self, text):
                raise ValueError("/sensitive/path " + text)
        detector = PIIDetector(Broken())
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, "^PII model inference failed$"):
                detector.redact("secret")
        self.assertEqual(detector.status()["state"], "error")
        self.assertNotIn("secret", str(detector.status()))

    def test_invalid_model_spans_fail_closed(self):
        detector = PIIDetector(MockModel([Span(0, 100, "GIVENNAME", "model")]))
        with self.assertRaises(RuntimeError):
            detector.find("abc")


class FakeTokenizer:
    def __call__(self, text, **kwargs):
        import re
        matches = list(re.finditer(r"\S+", text))
        return {"input_ids": [7 if m.group() == "target" else 1 for m in matches],
                "offset_mapping": [(m.start(), m.end()) for m in matches]}

    def prepare_for_model(self, ids, **kwargs):
        full = [101] + ids + [102]
        return {"input_ids": full, "attention_mask": [1] * len(full), "token_type_ids": [0] * len(full),
                "special_tokens_mask": [1] + [0] * len(ids) + [1]}


class FakeSession:
    def __init__(self):
        self.lengths = []

    def run(self, outputs, feed):
        ids = feed["input_ids"][0]
        self.lengths.append(len(ids))
        logits = np.zeros((1, len(ids), len(MODEL_LABELS)))
        logits[:, :, 0] = 1
        logits[0, ids == 7, 1] = 2
        return [logits]


class PositionTokenizer(FakeTokenizer):
    def __call__(self, text, **kwargs):
        encoded = super().__call__(text, **kwargs)
        encoded["input_ids"] = [1000 + i for i in range(len(encoded["input_ids"]))]
        return encoded


class PositionSession:
    """Synthetic BIO logits keyed by source token position and window start."""
    def __init__(self, labels, per_window=None):
        self.labels = labels
        self.per_window = per_window or {}

    def run(self, outputs, feed):
        ids = feed["input_ids"][0]
        window_start = int(ids[1]) - 1000
        labels = self.per_window.get(window_start, self.labels)
        logits = np.zeros((1, len(ids), len(MODEL_LABELS)))
        for i, token in enumerate(ids):
            label = labels.get(int(token) - 1000, "O")
            logits[0, i, MODEL_LABELS.index(label)] = 1
        return [logits]


@unittest.skipIf(np is None, "optional numpy dependency not installed")
class WindowTests(unittest.TestCase):
    def test_windowing_covers_tail_and_repeated_tokens(self):
        model = _LocalModel.__new__(_LocalModel)
        model.tokenizer = FakeTokenizer()
        model.np = np
        model.session = FakeSession()
        model.input_names = {"input_ids", "attention_mask", "token_type_ids"}
        model.output_name = "logits"
        model.capacity = 8
        text = " ".join(["x"] * 3 + ["target"] + ["x"] * 19 + ["target"])
        detector = PIIDetector(model)
        spans = detector.find(text)
        self.assertEqual([text[s.start:s.end] for s in spans], ["target", "target"])
        self.assertEqual(spans[-1].end, len(text))
        self.assertGreater(len(model.session.lengths), 1)
        self.assertLessEqual(max(model.session.lengths), 10)

    def make_position_model(self, labels, per_window=None):
        model = _LocalModel.__new__(_LocalModel)
        model.tokenizer = PositionTokenizer()
        model.np = np
        model.session = PositionSession(labels, per_window)
        model.input_names = {"input_ids", "attention_mask", "token_type_ids"}
        model.output_name = "logits"
        model.capacity = 126
        return model

    def test_complete_predictions_replace_both_left_and_right_window_fragments(self):
        words = ["x"] * 190
        words[62:65] = ["ALPHA", "BETA", "GAMMA"]
        words[124:127] = ["FIRST", "MIDDLE", "LAST"]
        text = " ".join(words)
        labels = {62: "B-GIVENNAME", 63: "I-GIVENNAME", 64: "I-GIVENNAME",
                  124: "B-GIVENNAME", 125: "I-GIVENNAME", 126: "I-GIVENNAME"}
        spans = PIIDetector(self.make_position_model(labels)).find(text)
        self.assertEqual([text[s.start:s.end] for s in spans], ["ALPHA BETA GAMMA", "FIRST MIDDLE LAST"])

    def test_uncovered_window_fragment_remains_available_for_redaction(self):
        words = ["x"] * 190
        words[124:127] = ["FIRST", "MIDDLE", "LAST"]
        text = " ".join(words)
        labels = {124: "B-GIVENNAME", 125: "I-GIVENNAME"}
        model = self.make_position_model({}, {0: labels})
        detector = PIIDetector(model)
        spans = detector.find(text)
        self.assertEqual([text[s.start:s.end] for s in spans], ["FIRST MIDDLE"])
        display, _ = detector.redact(text)
        self.assertNotIn("FIRST MIDDLE", display)

    def test_contained_and_overlapping_independent_predictions_are_preserved(self):
        words = ["x"] * 190
        words[70:74] = ["ONE", "TWO", "THREE", "FOUR"]
        text = " ".join(words)
        # Neither prediction touches a window edge; the two windows disagree.
        first = {70: "B-GIVENNAME", 71: "I-GIVENNAME", 72: "I-GIVENNAME"}
        second = {71: "B-GIVENNAME", 72: "I-GIVENNAME"}
        model = self.make_position_model({}, {0: first, 63: second})
        spans = PIIDetector(model).find(text)
        self.assertEqual([text[s.start:s.end] for s in spans], ["ONE TWO THREE", "TWO THREE"])
        # A partial overlap with neither containing the other is also retained.
        second[73] = "I-GIVENNAME"
        spans = PIIDetector(model).find(text)
        self.assertEqual([text[s.start:s.end] for s in spans], ["ONE TWO THREE", "TWO THREE FOUR"])

    def test_different_labels_and_still_incomplete_candidates_are_preserved(self):
        words = ["x"] * 190
        words[124:127] = ["FIRST", "MIDDLE", "LAST"]
        text = " ".join(words)
        first = {124: "B-SURNAME", 125: "I-SURNAME"}
        second = {124: "B-GIVENNAME", 125: "I-GIVENNAME", 126: "I-GIVENNAME"}
        model = self.make_position_model({}, {0: first, 63: second})
        spans = PIIDetector(model).find(text)
        self.assertEqual([(text[s.start:s.end], s.label) for s in spans],
                         [("FIRST MIDDLE", "SURNAME"), ("FIRST MIDDLE LAST", "GIVENNAME")])
        # A longer prediction that itself reaches a window edge is not complete.
        words = ["x"] * 190
        text = " ".join(words)
        first = {i: "I-GIVENNAME" for i in range(100, 126)}
        first[100] = "B-GIVENNAME"
        second = {i: "I-GIVENNAME" for i in range(100, 189)}
        second[100] = "B-GIVENNAME"
        spans = PIIDetector(self.make_position_model({}, {0: first, 63: second})).find(text)
        self.assertEqual(len(spans), 2)

    def test_incomplete_logits_fail_closed(self):
        class BadSession:
            def run(self, outputs, feed):
                return [np.zeros((1, 1, len(MODEL_LABELS)))]
        model = _LocalModel.__new__(_LocalModel)
        model.tokenizer = FakeTokenizer()
        model.np = np
        model.session = BadSession()
        model.input_names = {"input_ids"}
        model.output_name = "logits"
        model.capacity = 8
        detector = PIIDetector(model)
        with self.assertRaisesRegex(RuntimeError, "PII model inference failed"):
            detector.redact("target")


if __name__ == "__main__":
    unittest.main()
