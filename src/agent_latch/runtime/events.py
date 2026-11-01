"""Runtime data types shared by the middleware, the trace log and, later, the detectors.

These follow the R1 runtime contract. ``ToolCall`` holds raw arguments in memory only; anything
written to disk goes through ``agent_latch.runtime.redact`` first.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

PAYLOAD_SCHEMA = "agentlatch.runtime.payload/1"


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
    # MCP tool annotations as the server declares them (readOnlyHint, destructiveHint, ...).
    annotations: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PayloadEvent:
    """One intercepted MCP message with its full payload, for the checks that will consume it.

    Payloads hold raw argument values and tool output, so a record lives in memory only. The one
    on-disk form, ``intercept.PayloadFile``, masks secret-like values first. Payload keys by kind:

    - ``tools/list`` response: ``tools`` (name, description, input_schema, annotations)
    - ``tools/call`` request: ``tool``, ``arguments``, ``tool_definition`` (from the last
      ``tools/list``, or ``None`` when the tool was not listed)
    - ``tools/call`` response: ``tool``, ``is_error``, ``content`` (text blocks), ``structured``,
      ``duration_ms``
    - ``tools/call`` error: ``tool``, ``error_type``, ``error_message``, ``duration_ms``
    - ``prompts/get`` request: ``prompt``, ``arguments``
    - ``prompts/get`` response: ``prompt``, ``messages`` (role, text)
    """

    record_id: str
    seq: int
    timestamp: str
    session_id: str
    request_id: str
    client_id: str | None
    server: str
    method: str
    stage: str
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PAYLOAD_SCHEMA,
            "record_id": self.record_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "client_id": self.client_id,
            "server": self.server,
            "method": self.method,
            "stage": self.stage,
            "payload": dict(self.payload),
        }
