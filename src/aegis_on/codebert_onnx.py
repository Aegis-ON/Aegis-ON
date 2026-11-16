from __future__ import annotations

from pathlib import Path
from typing import Final

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from .codebert_input import MAX_TOKENS

INPUT_NAMES: Final = ("input_ids", "attention_mask")
OUTPUT_NAME: Final = "logits"
THREADS: Final = 2


class ModelError(ValueError):
    pass


def runtime_tokenizer(path: Path) -> Tokenizer:
    tokenizer = Tokenizer.from_file(str(path))
    tokenizer.enable_truncation(max_length=MAX_TOKENS + 1)
    tokenizer.no_padding()
    return tokenizer


def make_feed(tokenizer: Tokenizer, command: str) -> dict[str, np.ndarray] | None:
    encoded = tokenizer.encode(command)
    if len(encoded.ids) > MAX_TOKENS:
        return None
    return {"input_ids": np.asarray([encoded.ids], dtype=np.int64),
            "attention_mask": np.asarray([encoded.attention_mask], dtype=np.int64)}


def open_session(graph: Path | bytes) -> ort.InferenceSession:
    options = ort.SessionOptions()
    options.intra_op_num_threads = THREADS
    options.inter_op_num_threads = 1
    runtime = ort.InferenceSession(str(graph) if isinstance(graph, Path) else graph,
                                   sess_options=options, providers=["CPUExecutionProvider"])
    inputs, outputs = runtime.get_inputs(), runtime.get_outputs()
    if (set(value.name for value in inputs) != set(INPUT_NAMES)
            or any(value.type != "tensor(int64)" or len(value.shape) != 2 for value in inputs)
            or len(outputs) != 1 or outputs[0].name != OUTPUT_NAME or outputs[0].type != "tensor(float)"
            or len(outputs[0].shape) != 2 or outputs[0].shape[1] != 2):
        raise ModelError("unexpected model input or output")
    return runtime


def infer_logits(runtime: ort.InferenceSession, feed: dict[str, np.ndarray]) -> np.ndarray:
    logits, = runtime.run([OUTPUT_NAME], feed)
    if logits.shape != (1, 2) or not np.isfinite(logits).all():
        raise ModelError("expected two finite logits")
    return logits


def review_probability(logits: np.ndarray) -> float:
    values = np.exp(logits - logits.max())
    return float(values[0, 1] / values.sum())
