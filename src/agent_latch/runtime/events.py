"""Runtime data types shared by the middleware, the trace log and, later, the detectors.

These follow the R1 runtime contract. ``ToolCall`` holds raw arguments in memory only; anything
written to disk goes through ``agent_latch.runtime.redact`` first.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


def utc_now() -> str:
    """Current time as ISO 8601 UTC with millisecond precision."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class ToolCall:
    session_id: str
    request_id: str
    client_id: str | None
    tool: str
    server: str
    arguments: Mapping[str, Any]
    timestamp: str


@dataclass(frozen=True)
class ToolOutput:
    texts: tuple[str, ...]
    structured: Any | None
    is_error: bool


@dataclass(frozen=True)
class ToolInfo:
    name: str
    server: str
    description: str
    input_schema: Mapping[str, Any]
