from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Final, Protocol

from .privacy import redact_text

MAX_TOKENS: Final = 128
MAX_COMMAND_CHARS: Final = 20_000
BASE_REVISION: Final = "46c25bcc277a0ddc06c66439b04d5b61d3638ea3"
BASE_SHA256: Final = "b3a59026bf4955d5dbfae2ec74734b2d38c01049a84df1e8a12d78d0fd11bd75"
_HASHED_PII = re.compile(r"\[(EMAIL|PHONE|IP):[a-f0-9]{10}\]")
_SECRET_OPTION = re.compile(
    r"""(?ix)(?<!\w)([-/]{0,2}(?:password|passwd|pwd|token|api[-_]?key|client[-_]?secret|authorization)
    (?:\s*[:=]\s*|\s+))(?:"[^"]*"|'[^']*'|bearer\s+\S+|[^\s;&|]+)"""
)
_HOME = re.compile(r"(?i)([\\/](?:users|home)[\\/])[^\\/\r\n\x22]+?(?=[\\/\x22]|$)")
_GUID = re.compile(r"(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b")


class Encoder(Protocol):
    def encode(self, text: str, *, add_special_tokens: bool, truncation: bool, max_length: int) -> list[int]: ...


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def normalize_command(text: str, identities: tuple[str, ...] = ()) -> str:
    text = _SECRET_OPTION.sub(r"\1[SECRET]", text)
    text = _HOME.sub(r"\1[USER]", text)
    text = _GUID.sub("[ID]", text)
    for identity in identities:
        if identity and len(identity) <= len(text):
            text = re.sub(rf"(?<![\w.]){re.escape(identity)}(?![\w.])", "[IDENTITY]", text, flags=re.IGNORECASE)
    return _HASHED_PII.sub(r"[\1]", redact_text(text)).strip()


def token_ids(tokenizer: Encoder, command: str) -> list[int] | None:
    ids = tokenizer.encode(command, add_special_tokens=True, truncation=True, max_length=MAX_TOKENS + 1)
    return ids if len(ids) <= MAX_TOKENS else None
