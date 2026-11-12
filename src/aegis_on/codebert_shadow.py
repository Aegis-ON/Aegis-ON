from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from .codebert_input import MAX_COMMAND_CHARS, MAX_TOKENS, normalize_command
from .review_priority import RankingPolicy

if TYPE_CHECKING:
    from onnxruntime import InferenceSession
    from tokenizers import Tokenizer

LOGGER = logging.getLogger(__name__)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    schema_version: Literal[1] = Field(alias="schema")
    fixture: bool
    graph: Literal["codebert-fp32.onnx", "codebert-int8.onnx"]
    max_tokens: Literal[128]
    labels: list[str]
    files: dict[str, str]


class Prediction(TypedDict, total=False):
    status: str
    score: float


def _verified_bytes(path: Path, expected: str, maximum: int) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected):
        raise ValueError("unverified model artifact")
    return content


class ShadowModel:
    def __init__(
        self, *, state: str = "disabled", runtime: InferenceSession | None = None,
        tokenizer: Tokenizer | None = None, policy: RankingPolicy | None = None,
        manifest_sha256: str | None = None, graph_sha256: str | None = None, fixture: bool = False,
    ):
        self.state = state
        self.runtime = runtime
        self.tokenizer = tokenizer
        self.policy = policy or RankingPolicy()
        self.manifest_sha256 = manifest_sha256
        self.graph_sha256 = graph_sha256
        self.fixture = fixture

    @classmethod
    def from_environment(cls) -> ShadowModel:
        directory = os.environ.get("AEGIS_CODEBERT_SHADOW_DIR")
        if not directory:
            return cls()
        try:
            return cls._load(Path(directory), os.environ.get("AEGIS_CODEBERT_SHADOW_MANIFEST_SHA256", ""))
        except Exception as exc:  # noqa: BROAD_EXCEPT_OK
            LOGGER.warning("CodeBERT package unavailable (%s)", type(exc).__name__)
            return cls(state="error")

    @classmethod
    def _load(cls, root: Path, expected: str) -> ShadowModel:
        import onnx
        from onnx.external_data_helper import _get_all_tensors
        from tokenizers import Tokenizer

        from .codebert_onnx import open_session

        manifest = Manifest.model_validate_json(_verified_bytes(root / "manifest.json", expected, 32_768))
        if manifest.fixture and os.environ.get("AEGIS_CODEBERT_SHADOW_ALLOW_FIXTURE") != "1":
            raise ValueError("fixture package")
        if manifest.max_tokens != MAX_TOKENS or manifest.labels != ["benign", "review"]:
            raise ValueError("unexpected classifier configuration")
        files = manifest.files
        if set(files) != {manifest.graph, "tokenizer.json", "policy.json"}:
            raise ValueError("unexpected package files")
        graph = _verified_bytes(root / manifest.graph, files[manifest.graph], 750 * 1024**2)
        proto = onnx.load_model_from_string(graph)
        if any(tensor.external_data or tensor.data_location == onnx.TensorProto.EXTERNAL
               for tensor in _get_all_tensors(proto)):
            raise ValueError("external tensors are unsupported")
        del proto
        tokens = _verified_bytes(root / "tokenizer.json", files["tokenizer.json"], 16 * 1024**2)
        tokenizer = Tokenizer.from_str(tokens.decode("utf-8"))
        tokenizer.enable_truncation(max_length=MAX_TOKENS + 1)
        tokenizer.no_padding()
        policy = RankingPolicy.model_validate_json(_verified_bytes(root / "policy.json", files["policy.json"], 8192))
        model = cls(state="ready", runtime=open_session(graph), tokenizer=tokenizer, policy=policy,
                    manifest_sha256=expected, graph_sha256=files[manifest.graph], fixture=manifest.fixture)
        if model.predict("echo synthetic").get("status") != "ok":
            raise ValueError("model warmup failed")
        return model

    def predict(self, command: str, identities: tuple[str, ...] = ()) -> Prediction:
        if self.runtime is None or self.tokenizer is None:
            return {"status": "model_unavailable"}
        if len(command) > MAX_COMMAND_CHARS:
            return {"status": "too_long"}
        normalized = normalize_command(command, identities)
        if not normalized:
            return {"status": "missing_command"}
        try:
            from .codebert_onnx import infer_logits, make_feed, review_probability

            feed = make_feed(self.tokenizer, normalized)
            if feed is None:
                return {"status": "too_long"}
            return {"status": "ok", "score": review_probability(infer_logits(self.runtime, feed))}
        except Exception as exc:  # noqa: BROAD_EXCEPT_OK
            LOGGER.warning("CodeBERT inference failed (%s)", type(exc).__name__)
            return {"status": "inference_error"}
