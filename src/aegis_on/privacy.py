from __future__ import annotations

import hashlib
import re
from typing import Any

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b01[0-9]-?\d{3,4}-?\d{4}\b")
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")


def _token(kind: str, raw: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{raw}".encode()).hexdigest()[:10]
    return f"[{kind}:{digest}]"


def redact_text(value: str, *, salt: str = "aegis-on-demo") -> str:
    """Return a display-safe string without changing the locally retained evidence."""

    value = EMAIL_RE.sub(lambda match: _token("EMAIL", match.group(), salt), value)
    value = PHONE_RE.sub(lambda match: _token("PHONE", match.group(), salt), value)
    return IP_RE.sub(lambda match: _token("IP", match.group(), salt), value)


def redact_for_display(value: Any, *, salt: str = "aegis-on-demo") -> Any:
    if isinstance(value, str):
        return redact_text(value, salt=salt)
    if isinstance(value, list):
        return [redact_for_display(item, salt=salt) for item in value]
    if isinstance(value, dict):
        return {key: redact_for_display(item, salt=salt) for key, item in value.items()}
    return value
