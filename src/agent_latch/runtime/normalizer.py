"""MCP event normalizer: join a trace record and its payload record into one event.

The trace holds hashes, sizes and short excerpts (``metadata``); the opt-in payloads file holds the
full, masked payload. A normalized event carries both, plus where each came from, so every gate
gets the same JSON object whichever method it is looking at.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from agent_latch.runtime.events import PAYLOAD_SCHEMA
from agent_latch.runtime.trace import TRACE_SCHEMA

# Messages that also produce a payload record when ``--payloads`` is on.
PAYLOAD_METHODS = frozenset({"tools/list", "tools/call", "prompts/get"})

EventKey = tuple[str, str, str, str, str, str | None]

_REQUIRED_STRINGS = ("session_id", "request_id", "server", "method", "stage")
# Fields that the normalized event carries at top level; the rest of a trace record is metadata.
_TRACE_ENVELOPE = frozenset({"schema", "timestamp", *_REQUIRED_STRINGS, "tool", "prompt"})


def run_id_for(first_trace_line: str) -> str:
    """Stable run id: a hash of the first trace line, so restarts of the importer agree."""
    return hashlib.sha256(first_trace_line.strip().encode("utf-8")).hexdigest()[:16]


def is_trace_record(record: Any) -> bool:
    return (
        isinstance(record, dict)
        and record.get("schema") == TRACE_SCHEMA
        and all(isinstance(record.get(field), str) for field in _REQUIRED_STRINGS)
    )


def is_payload_record(record: Any) -> bool:
    return (
        isinstance(record, dict)
        and record.get("schema") == PAYLOAD_SCHEMA
        and isinstance(record.get("payload"), dict)
        and all(isinstance(record.get(field), str) for field in _REQUIRED_STRINGS)
    )


def _name(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def trace_key(record: Mapping[str, Any]) -> EventKey:
    """Identity of a trace record, matching ``payload_key`` of its payload record."""
    name = _name(record.get("tool")) or _name(record.get("prompt"))
    return (
        record["session_id"], record["request_id"], record["server"],
        record["method"], record["stage"], name,
    )


def payload_key(record: Mapping[str, Any]) -> EventKey:
    body = record["payload"]
    name = _name(body.get("tool")) or _name(body.get("prompt"))
    return (
        record["session_id"], record["request_id"], record["server"],
        record["method"], record["stage"], name,
    )


class MCPEventNormalizer:
    """Builds normalized events for one run from trace and payload records."""

    def __init__(self, run_id: str, *, trace_name: str, payloads_name: str | None = None) -> None:
        self.run_id = run_id
        self.trace_name = trace_name
        self.payloads_name = payloads_name

    def normalize(
        self,
        *,
        trace_line: int,
        trace: Mapping[str, Any],
        payload_line: int | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """One event. ``order`` is the trace line number; ``payload`` is ``None`` when absent."""
        has_payload = payload is not None and payload_line is not None
        return {
            "run_id": self.run_id,
            "order": trace_line,
            "timestamp": trace.get("timestamp"),
            "session_id": trace["session_id"],
            "request_id": trace["request_id"],
            "client_id": _name(payload.get("client_id")) if payload is not None else None,
            "server": trace["server"],
            "method": trace["method"],
            "stage": trace["stage"],
            "name": _name(trace.get("tool")) or _name(trace.get("prompt")),
            "trace": {"path": self.trace_name, "line": trace_line},
            "payloads": (
                {"path": self.payloads_name, "line": payload_line} if has_payload else None
            ),
            "metadata": {k: v for k, v in trace.items() if k not in _TRACE_ENVELOPE},
            "payload": dict(payload["payload"]) if payload is not None else None,
        }
