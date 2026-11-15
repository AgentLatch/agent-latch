"""Hashing and redaction for anything the runtime writes to disk or stderr.

The trace never stores raw tool arguments or raw tool output: it keeps argument names, a SHA-256
of the full payload, and at most a short excerpt with secret-like values masked. The opt-in payloads
file stores payload values, but only after ``mask_value`` has masked and truncated them.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Any

MASK = "[REDACTED]"

# Cap for server-controlled identity strings (handshake name/title/version, protocol version).
# Same as ``gates.alr03.MAX_NAME_CHARS``.
MAX_IDENTITY_CHARS = 120

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
# "basic authentication" and similar are prose, not a credential. Only these exact words are
# exempt, so any other value after "Basic", lowercase or not, is still masked.
_BEARER = re.compile(
    r"(?i)\b(?!basic\s+(?:authentication|authorization|auth|access)\.?(?![A-Za-z0-9._~+/=-]))"
    r"(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
)
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


def safe_text(value: str, limit: int = MAX_IDENTITY_CHARS) -> str:
    """Cap ``value`` and show control/format characters as escapes (``\\x1b``, ``\\u200b``).

    For short, server-controlled strings that reach the trace and the terminal. Escaping instead
    of dropping keeps invisible-character tricks visible as evidence, while terminal escape
    sequences can no longer act on the operator's terminal.
    """
    return "".join(
        ch.encode("unicode_escape").decode("ascii") if unicodedata.category(ch)[0] == "C" else ch
        for ch in value[:limit]
    )


def unescape_text(value: str) -> str:
    """Inverse of ``safe_text`` for analysis: turn ``\\xNN``, ``\\uNNNN``, ``\\UNNNNNNNN`` back.

    The trace stores escaped identity strings, but a gate must compare what a reader would see,
    so an invisible character inside a name still counts toward similarity. Anything that is not
    a well-formed escape is left as it is. No regular expressions.
    """
    out: list[str] = []
    i, n = 0, len(value)
    while i < n:
        width = {"x": 2, "u": 4, "U": 8}.get(value[i + 1]) if value[i] == "\\" and i + 1 < n else None
        digits = value[i + 2 : i + 2 + width] if width else ""
        if width and len(digits) == width and all(c in "0123456789abcdefABCDEF" for c in digits):
            try:
                out.append(chr(int(digits, 16)))
                i += 2 + width
                continue
            except ValueError:
                pass
        out.append(value[i])
        i += 1
    return "".join(out)


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


def safe_segment(key: Any) -> str:
    """A path segment for ``key`` with any secret-like text in the key itself masked.

    A mapping key can carry a token (``{"ghp_...": 1}``). Paths are stored as location evidence,
    so the key is masked before it is used in one.
    """
    return _pointer_segment(mask_secrets(str(key)))


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
            raw_name = str(key)
            # A token-shaped key is masked in the output too, not only in the location path.
            name = mask_secrets(raw_name)
            if name in out:
                name = f"{name}#{len(out)}"
            child = f"{path}/{_pointer_segment(name)}"
            if isinstance(item, str) and item and _SECRET_KEY.search(raw_name):
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
