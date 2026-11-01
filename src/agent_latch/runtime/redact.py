"""Hashing and redaction for anything the runtime writes to disk or stderr.

The trace never stores raw tool arguments or raw tool output: it keeps argument names, a SHA-256
of the full payload, and at most a short excerpt with secret-like values masked. The opt-in payloads
file stores payload values, but only after ``mask_value`` has masked and truncated them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

MASK = "[REDACTED]"

# Mapping keys whose string values are masked whole, whatever the value looks like.
_SECRET_KEY = re.compile(
    r"(?i)(api[_-]?key|secret|password|passwd|token|authorization|private[_-]?key|credential)"
)

# Key-value credentials, for example api_key="..." or "password": "...". The value group is masked.
_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|password|passwd|access[_-]?token|auth[_-]?token"
    r"|client[_-]?secret|private[_-]?key)\b['\"]?\s*[:=]\s*['\"]?(?P<value>[^'\"\s,;}]{4,})"
)
# Well-known token shapes that appear without a key name.
_TOKENS = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}"  # OpenAI / Anthropic style
    r"|gh[pousr]_[A-Za-z0-9]{20,}"  # GitHub
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"  # Slack
    r"|AKIA[0-9A-Z]{16}"  # AWS access key ID
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"  # JWT
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL
)


def canonical_json(value: Any) -> str:
    """Stable JSON text for hashing: sorted keys, no whitespace, non-JSON values as strings."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def payload_sha256(value: Any) -> str:
    text = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_bytes(value: Any) -> int:
    text = value if isinstance(value, str) else canonical_json(value)
    return len(text.encode("utf-8"))


def mask_secrets(text: str) -> str:
    text = _PEM.sub(MASK, text)
    text = _ASSIGNMENT.sub(lambda m: m.group(0).replace(m.group("value"), MASK), text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {MASK}", text)
    return _TOKENS.sub(MASK, text)


def mask_value(value: Any, max_chars: int) -> Any:
    """A JSON-ready copy of ``value`` with secrets masked and each string cut to ``max_chars``.

    Strings under a secret-like key (``api_key``, ``password``, ``token``, ...) are masked whole;
    other strings go through ``mask_secrets``. Masking runs before the cut, on the full string.
    """
    if isinstance(value, str):
        text = mask_secrets(value)
        if len(text) <= max_chars:
            return text
        return f"{text[:max_chars]}…[{len(text) - max_chars} more chars]"
    if isinstance(value, Mapping):
        return {
            str(key): MASK
            if isinstance(item, str) and item and _SECRET_KEY.search(str(key))
            else mask_value(item, max_chars)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [mask_value(item, max_chars) for item in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return mask_value(str(value), max_chars)


def excerpt(text: str, limit: int) -> str:
    """A short, single-line, secret-masked preview of ``text``; empty when ``limit`` is 0.

    Masking runs on a window a little longer than ``limit`` so a secret cut at the boundary is
    still recognized before the cut.
    """
    if limit <= 0 or not text:
        return ""
    window = mask_secrets(text[: limit + 200])
    flat = " ".join(window.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"
