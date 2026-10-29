"""Canonical JSON bytes: the same value always hashes to the same digest.

Sorting keys and dropping whitespace means a field reorder in a serializer cannot look like
tampering, while any change to a value still does.
"""

from __future__ import annotations

import json
from typing import Any


def dumps(value: Any) -> bytes:
    """Stable UTF-8 bytes: sorted keys, no whitespace, no ASCII escaping."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
