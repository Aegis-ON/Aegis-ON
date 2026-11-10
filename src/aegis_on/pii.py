"""Optional, offline PII span detection and pseudonymization.

Model installation is explicit: point AEGIS_PII_MODEL_DIR at a local checkout
of the pinned repository revision. No model files are downloaded at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_left, bisect_right
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any

from .privacy import EMAIL_RE, PHONE_RE, IP_RE, IPV6_CANDIDATE_RE, _token

MODEL_REVISION = "3a1d4f61e156035a22d820b59c78e4d5e5cc6f6f"
MODEL_SHA256 = "8cb91734f9a559c8a2dd127484582b9bc7c43bae21cc44b6c893321030ae3de3"
# SHA-256 calculated from the files downloaded at MODEL_REVISION. The small
# files' Git blob IDs were also checked against Hugging Face revision metadata.
MODEL_ASSET_SHA256 = {
    "config.json": "704c0412effea86fca8f9dfc61c45b83ebba27a09dde1e697b29bfc2a9b835a3",
    "tokenizer.json": "68376ce5e989db0c0bdb282422a99e12e449c1f97a1a18daf705626db0d57b83",
    "tokenizer_config.json": "cbef04fcea9edfbabfe9d20fde7eda79a5a6932d057308bb2b021dd7afd5ccab",
    "special_tokens_map.json": "5d5b662e421ea9fac075174bb0688ee0d9431699900b90662acd44b2a350503a",
    "vocab.txt": "fe0fda7c425b48c516fc8f160d594c8022a0808447475c1a7c6d6479763f310c",
}
MODEL_TYPES = (
    "GIVENNAME", "SURNAME", "USERNAME", "EMAIL", "TELEPHONENUM", "DATEOFBIRTH",
    "CREDITCARDNUMBER", "IDCARD", "STREET", "CITY", "ZIPCODE", "BUILDINGNUM",
    "IP_ADDRESS", "PASSWORD", "ACCOUNTNUM", "DRIVERLICENSENUM", "TIME", "COMPANY",
)
MODEL_LABELS = ("O",) + tuple(f"{prefix}-{kind}" for kind in MODEL_TYPES for prefix in ("B", "I"))


def _verify_model_files(root: Path) -> None:
    """Verify the graph and tokenizer assets before loading any model files."""
    for name, expected in {"onnx/model_quantized.onnx": MODEL_SHA256, **MODEL_ASSET_SHA256}.items():
        with (root / name).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected:
            raise ValueError("local model file checksum mismatch")


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    label: str
    source: str


def regex_spans(text: str) -> list[Span]:
    """Find regex spans in original-text coordinates, including whole IPv6 addresses."""
    spans = [Span(m.start(), m.end(), label, "regex")
             for pattern, label in ((EMAIL_RE, "EMAIL"), (PHONE_RE, "TELEPHONENUM"))
             for m in pattern.finditer(text)]
    ipv6 = []
    for match in IPV6_CANDIDATE_RE.finditer(text):
        candidate = match.group().rstrip(".")
        start = match.start()
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            label, separator, address_text = candidate.partition(":")
            if not separator or re.fullmatch(r"[0-9a-fA-F]+", label):
                continue
            try:
                ipaddress.IPv6Address(address_text)
            except ValueError:
                continue
            start += len(label) + 1
        ipv6.append(Span(start, match.start() + len(candidate), "IP_ADDRESS", "regex"))
    spans.extend(ipv6)
    spans.extend(Span(m.start(), m.end(), "IP_ADDRESS", "regex") for m in IP_RE.finditer(text)
                 if not any(m.start() < s.end and s.start < m.end() for s in ipv6))
    return sorted(spans, key=lambda s: (s.start, s.end, s.label))


def _union(spans: list[Span]) -> list[Span]:
    # Never expose any part of overlapping evidence. Prefer the regex type when
    # it overlaps a model prediction; offsets always cover the full union.
    result: list[Span] = []
    for span in sorted(spans, key=lambda s: (s.start, s.end, s.source != "regex")):
        if result and span.start < result[-1].end:
            old = result[-1]
            chosen = span if span.source == "regex" and old.source != "regex" else old
            result[-1] = Span(old.start, max(old.end, span.end), chosen.label, chosen.source)
        else:
            result.append(span)
    return result


@dataclass(frozen=True)
class _WindowPrediction:
    span: Span
    token_start: int
    token_end: int
    window_start: int
    window_end: int
    total_tokens: int

    @property
    def left_cut(self) -> bool:
        return self.window_start > 0 and self.token_start == self.window_start

    @property
    def right_cut(self) -> bool:
        return self.window_end < self.total_tokens and self.token_end == self.window_end


def _discard_covered_window_fragments(predictions: list[_WindowPrediction], capacity: int) -> list[Span]:
    """Discard boundary fragments only when another window observes a full span.

    A prediction touching a non-document window edge is potentially incomplete.
    Keep it unless a same-label prediction, observed away from either window
    edge, contains it and extends across at least one of its cut edges. Other
    conflicting or contained predictions are intentionally kept for evaluation.
    """
    complete: dict[str, list[_WindowPrediction]] = {}
    for prediction in predictions:
        if not prediction.left_cut and not prediction.right_cut:
            complete.setdefault(prediction.span.label, []).append(prediction)
    indexes = {}
    for label, items in complete.items():
        items.sort(key=lambda p: p.token_start)
        indexes[label] = ([p.token_start for p in items], items)

    spans = []
    for partial in predictions:
        if not (partial.left_cut or partial.right_cut) or partial.span.label not in indexes:
            spans.append(partial.span)
            continue
        starts, items = indexes[partial.span.label]
        # A complete span can contain the fragment only if it starts within
        # one window's capacity. This bounds comparisons for long inputs.
        lo = bisect_left(starts, partial.token_start - capacity + 1)
        hi = bisect_right(starts, partial.token_start)
        covered = any(
            full.window_start != partial.window_start
            and full.token_end >= partial.token_end
            and ((partial.left_cut and full.token_start < partial.token_start)
                 or (partial.right_cut and full.token_end > partial.token_end))
            for full in items[lo:hi]
        )
        if not covered:
            spans.append(partial.span)
    return spans


class _LocalModel:
    def __init__(self, directory: str):
        # These imports are deliberately deferred, so the baseline works without
        # any of the optional packages installed.
        import numpy as np
        import onnxruntime as ort
        from transformers import AutoTokenizer

        root = Path(directory).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("invalid model directory")
        graph = root / "onnx" / "model_quantized.onnx"
        _verify_model_files(root)
        with (root / "config.json").open(encoding="utf-8") as stream:
            config = json.load(stream)
        labels = config["id2label"]
        if tuple(labels[str(i)] for i in range(37)) != MODEL_LABELS or len(labels) != 37:
            raise ValueError("model labels mismatch")
        if (config.get("model_type") != "bert" or config.get("max_position_embeddings") != 512
                or config.get("vocab_size") != 119547):
            raise ValueError("model configuration mismatch")
        self.tokenizer = AutoTokenizer.from_pretrained(str(root), local_files_only=True, use_fast=True, trust_remote_code=False)
        if (not self.tokenizer.is_fast or self.tokenizer.vocab_size != 119547
                or [self.tokenizer.pad_token_id, self.tokenizer.unk_token_id, self.tokenizer.cls_token_id,
                    self.tokenizer.sep_token_id, self.tokenizer.mask_token_id] != [0, 100, 101, 102, 103]):
            raise ValueError("fast tokenizer required")
        self.np = np
        self.session = ort.InferenceSession(str(graph), providers=["CPUExecutionProvider"])
        if self.session.get_providers() != ["CPUExecutionProvider"]:
            raise ValueError("CPU provider required")
        inputs = self.session.get_inputs()
        self.input_names = {entry.name for entry in inputs}
        if not {"input_ids", "attention_mask"}.issubset(self.input_names) or not self.input_names.issubset(
            {"input_ids", "attention_mask", "token_type_ids"}
        ) or any(entry.type != "tensor(int64)" for entry in inputs):
            raise ValueError("unsupported model inputs")
        outputs = self.session.get_outputs()
        if len(outputs) != 1 or outputs[0].type != "tensor(float)":
            raise ValueError("unsupported model outputs")
        self.output_name = outputs[0].name
        # The published tokenizer declares max_length=128; use this smaller
        # window rather than assuming the graph accepts all 512 positions.
        self.capacity = 128 - self.tokenizer.num_special_tokens_to_add(pair=False)
        if not 1 <= self.capacity <= 126:
            raise ValueError("unsupported tokenizer")
        # A ready state requires real local tokenization and ONNX inference.
        self.find("Aegis synthetic check.")

    def find(self, text: str) -> list[Span]:
        encoded = self.tokenizer(text, add_special_tokens=False, truncation=False, return_offsets_mapping=True)
        ids, offsets = encoded["input_ids"], encoded["offset_mapping"]
        if len(ids) != len(offsets):
            raise ValueError("tokenization incomplete")
        predictions_by_window: list[_WindowPrediction] = []
        step = max(1, self.capacity - min(128, self.capacity // 2))
        for start in range(0, len(ids), step):
            end = min(start + self.capacity, len(ids))
            prepared = self.tokenizer.prepare_for_model(ids[start:end], add_special_tokens=True,
                return_special_tokens_mask=True, return_attention_mask=True, return_token_type_ids=True,
                truncation=False)
            special = prepared["special_tokens_mask"]
            if len(special) > 512 or sum(1 for x in special if not x) != end - start:
                raise ValueError("tokenization incomplete")
            feed = {name: self.np.asarray([prepared[name]], dtype=self.np.int64) for name in self.input_names}
            result = self.session.run([self.output_name], feed)
            if len(result) != 1:
                raise ValueError("incomplete inference")
            logits = result[0]
            if logits.shape != (1, len(special), len(MODEL_LABELS)) or not self.np.isfinite(logits).all():
                raise ValueError("incomplete inference")
            predictions = logits.argmax(axis=-1)[0]
            token_index = start
            current: Span | None = None
            current_start = current_end = 0

            def save_current() -> None:
                if current is not None:
                    predictions_by_window.append(_WindowPrediction(
                        current, current_start, current_end, start, end, len(ids)))

            for is_special, prediction in zip(special, predictions):
                if is_special:
                    continue
                a, b = offsets[token_index]
                token_index += 1
                if not (0 <= a < b <= len(text)):
                    raise ValueError("invalid token offsets")
                label = MODEL_LABELS[int(prediction)]
                if label == "O":
                    if current:
                        save_current()
                        current = None
                    continue
                prefix, kind = label.split("-", 1)
                if current and prefix == "I" and current.label == kind and not text[current.end:a].strip():
                    current = Span(current.start, max(current.end, b), kind, "model")
                    current_end = token_index
                else:
                    if current:
                        save_current()
                    current = Span(a, b, kind, "model")
                    current_start, current_end = token_index - 1, token_index
            if current:
                save_current()
            if end == len(ids):
                break
        return _discard_covered_window_fragments(predictions_by_window, self.capacity)


class PIIDetector:
    """Regex baseline, optionally augmented by an explicitly configured local model.

    ``model`` is an injectable object with ``find(text) -> list[Span]``; it is
    useful for isolated tests. A request failure raises a sanitized RuntimeError.
    """
    def __init__(self, model: Any = None, *, state: str | None = None, reason: str | None = None,
                 salt: str = "aegis-on-demo"):
        self._model = model
        self._state = state or ("ready" if model is not None else "disabled")
        self._reason = reason or ("Local model ready" if model is not None else "Local model not configured")
        self._salt = salt
        self._runtime_failed = False

    @classmethod
    def from_environment(cls) -> "PIIDetector":
        directory = os.environ.get("AEGIS_PII_MODEL_DIR", "").strip()
        if not directory:
            return cls()
        try:
            return cls(_LocalModel(directory))
        except ModuleNotFoundError:
            return cls(state="error", reason="Optional PII dependencies unavailable; regex detection only")
        except (FileNotFoundError, NotADirectoryError):
            return cls(state="error", reason="Local model files unavailable; regex detection only")
        except ValueError:
            return cls(state="error", reason="Local model verification failed; regex detection only")
        except Exception:
            return cls(state="error", reason="Local model initialization failed; regex detection only")

    def status(self) -> dict[str, str]:
        return {"state": self._state, "reason": self._reason}

    def find(self, text: str) -> list[Span]:
        if self._runtime_failed:
            raise RuntimeError("PII model inference failed") from None
        spans = regex_spans(text)
        if self._model is not None:
            try:
                model_spans = self._model.find(text)
                if not isinstance(model_spans, list) or any(
                    not isinstance(s, Span) or s.source != "model" or s.label not in MODEL_TYPES
                    or not 0 <= s.start < s.end <= len(text) for s in model_spans
                ):
                    raise ValueError("invalid model output")
                spans.extend(model_spans)
            except Exception:
                self._state = "error"
                self._reason = "Local model inference failed"
                self._runtime_failed = True
                raise RuntimeError("PII model inference failed") from None
        # Keep source-specific predictions and their boundaries for evaluation;
        # identical overlapping-window predictions are duplicate observations.
        return sorted(set(spans), key=lambda s: (s.start, s.end, s.source, s.label))

    def redact(self, text: str) -> tuple[str, list[dict[str, str]]]:
        display, masked = redact_spans(text, self.find(text), salt=self._salt)
        return display, [{"type": span.label, "source": span.source, "token": token}
                         for span, token in masked]


def redact_spans(text: str, spans: list[Span], *, salt: str = "aegis-on-demo") -> tuple[str, list[tuple[Span, str]]]:
    """Redact already-detected spans in one pass, returning merged span/token pairs."""
    if any(not isinstance(s, Span) or s.source not in {"regex", "model"}
           or s.label not in MODEL_TYPES or not 0 <= s.start < s.end <= len(text) for s in spans):
        raise ValueError("Invalid PII spans")
    fragments, masked = [], []
    position = 0
    for span in _union(spans):
        raw = text[span.start:span.end]
        kind = {"TELEPHONENUM": "PHONE", "IP_ADDRESS": "IP"}.get(span.label, span.label)
        if span.label == "IP_ADDRESS":
            try:
                address = ipaddress.IPv6Address(raw)
                raw = str(address.ipv4_mapped or address)
            except ValueError:
                pass
        token = _token(kind, raw, salt)
        fragments.extend((text[position:span.start], token))
        masked.append((span, token))
        position = span.end
    fragments.append(text[position:])
    return "".join(fragments), masked
