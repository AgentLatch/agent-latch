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
# Masked-location kinds for the well-known token shapes, by matched prefix (checked in order).
_TOKEN_KINDS = (
    ("sk-", "token:openai"),
    ("github_pat_", "token:github"),
    ("gh", "token:github"),
    ("xox", "token:slack"),
    ("AKIA", "token:aws"),
    ("eyJ", "jwt"),
)


def _token_kind(matched: str) -> str:
    for prefix, kind in _TOKEN_KINDS:
        if matched.startswith(prefix):
            return kind
    return "token"


def value_kind(value: str) -> str | None:
    """The token shape of a whole value, or ``None`` when it has no recognized shape."""
    if _PEM.search(value):
        return "pem"
    match = _TOKENS.search(value)
    if match:
        return _token_kind(match.group(0))
    if _BEARER.search(value):
        return "bearer"
    return None


def canonical_json(value: Any) -> str:
    """Stable JSON text for hashing: sorted keys, no whitespace, non-JSON values as strings."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def payload_sha256(value: Any) -> str:
    text = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_bytes(value: Any) -> int:
    text = value if isinstance(value, str) else canonical_json(value)
    return len(text.encode("utf-8"))


def mask_secrets(text: str, kinds: list[str] | None = None) -> str:
    """``text`` with secret-like spans replaced by ``MASK``.

    With ``kinds``, the kind of every masked span (``pem``, ``assignment``, ``bearer``,
    ``token:github``, ``jwt``, ...) is appended to it. Kinds carry no masked value.
    """

    def note(kind: str) -> None:
        if kinds is not None:
            kinds.append(kind)

    def pem(m: re.Match[str]) -> str:
        note("pem")
        return MASK

    def assignment(m: re.Match[str]) -> str:
        note("assignment")
        return m.group(0).replace(m.group("value"), MASK)

    def bearer(m: re.Match[str]) -> str:
        note("bearer")
        return f"{m.group(1)} {MASK}"

    def token(m: re.Match[str]) -> str:
        note(_token_kind(m.group(0)))
        return MASK

    text = _PEM.sub(pem, text)
    text = _ASSIGNMENT.sub(assignment, text)
    text = _BEARER.sub(bearer, text)
    return _TOKENS.sub(token, text)


def _pointer_segment(key: Any) -> str:
    return str(key).replace("~", "~0").replace("/", "~1")


def mask_value(
    value: Any,
    max_chars: int,
    *,
    locations: list[dict[str, str]] | None = None,
    path: str = "$",
) -> Any:
    """A JSON-ready copy of ``value`` with secrets masked and each string cut to ``max_chars``.

    Strings under a secret-like key (``api_key``, ``password``, ``token``, ...) are masked whole;
    other strings go through ``mask_secrets``. Masking runs before the cut, on the full string.

    With ``locations``, one ``{"path", "kind"}`` entry per masked spot is appended to it: the
    JSON-pointer-like path of the string and the kind of secret the masking recognized
    (``key_name``, ``assignment``, ``token:github``, ``jwt``, ``pem``, ...). Entries hold only
    the kind and path, never any part of the masked value.
    """
    if isinstance(value, str):
        kinds: list[str] | None = [] if locations is not None else None
        text = mask_secrets(value, kinds)
        if kinds and locations is not None:
            locations.extend({"path": path, "kind": kind} for kind in dict.fromkeys(kinds))
        if len(text) <= max_chars:
            return text
        return f"{text[:max_chars]}…[{len(text) - max_chars} more chars]"
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            child = f"{path}/{_pointer_segment(name)}"
            if isinstance(item, str) and item and _SECRET_KEY.search(name):
                out[name] = MASK
                if locations is not None:
                    locations.append({"path": child, "kind": value_kind(item) or "key_name"})
            else:
                out[name] = mask_value(item, max_chars, locations=locations, path=child)
        return out
    if isinstance(value, list | tuple):
        return [
            mask_value(item, max_chars, locations=locations, path=f"{path}/{i}")
            for i, item in enumerate(value)
        ]
    if value is None or isinstance(value, bool | int | float):
        return value
    return mask_value(str(value), max_chars, locations=locations, path=path)


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
