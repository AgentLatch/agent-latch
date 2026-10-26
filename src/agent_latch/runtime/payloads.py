"""Payload capture: turn each MCP message into a ``PayloadEvent`` and hand it to payload sinks.

The middleware calls the ``PayloadTap`` on the way in (before a request is forwarded) and on the
way out (before a result is returned). Each sink gets the full in-memory payload. Today the only
sink is the opt-in ``PayloadFile``; later the dispatcher that routes payloads to checks is a sink.

Named "payload" on purpose: ``agentlatch.runtime.event/1``, ``Interceptor`` and the events file
are reserved for runtime findings (epic AL-RUNTIME-01), which are a different record.

Monitor only: a failing sink is logged and skipped, and never stops the message.
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from agent_latch.runtime.events import PayloadEvent, ToolCall, ToolInfo, ToolOutput, utc_now
from agent_latch.runtime.redact import mask_value

log = logging.getLogger("agent_latch.runtime")

PayloadSink = Callable[[PayloadEvent], None]
DEFAULT_PAYLOAD_MAX_CHARS = 4000


class PayloadTap:
    """Builds payload records for tools/list, tools/call and prompts/get and passes them on.

    It remembers the last tool list per server, so a tools/call request record carries the
    called tool's description, input schema and annotations.
    """

    def __init__(self, sinks: Sequence[PayloadSink] = ()) -> None:
        self.sinks: list[PayloadSink] = list(sinks)
        self._seq = itertools.count(1)
        self._tools: dict[tuple[str, str], ToolInfo] = {}

    def tools_listed(
        self,
        *,
        session_id: str,
        request_id: str,
        client_id: str | None,
        server: str,
        tools: Sequence[ToolInfo],
    ) -> PayloadEvent:
        for tool in tools:
            self._tools[(server, tool.name)] = tool
        return self._emit(
            session_id, request_id, client_id, server, "tools/list", "response",
            {"tools": [_definition(tool) | {"name": tool.name} for tool in tools]},
        )

    def call_request(self, call: ToolCall) -> PayloadEvent:
        tool = self._tools.get((call.server, call.tool))
        return self._call(call, "request", {
            "tool": call.tool,
            "arguments": dict(call.arguments),
            "tool_definition": _definition(tool) if tool else None,
        })

    def call_response(
        self, call: ToolCall, output: ToolOutput, duration_ms: float
    ) -> PayloadEvent:
        return self._call(call, "response", {
            "tool": call.tool,
            "is_error": output.is_error,
            "content": list(output.texts),
            "structured": output.structured,
            "duration_ms": round(duration_ms, 1),
        })

    def call_error(
        self, call: ToolCall, error: BaseException, duration_ms: float
    ) -> PayloadEvent:
        return self._call(call, "error", {
            "tool": call.tool,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "duration_ms": round(duration_ms, 1),
        })

    def prompt_request(
        self,
        *,
        session_id: str,
        request_id: str,
        client_id: str | None,
        server: str,
        prompt: str,
        arguments: Mapping[str, Any],
    ) -> PayloadEvent:
        return self._emit(
            session_id, request_id, client_id, server, "prompts/get", "request",
            {"prompt": prompt, "arguments": dict(arguments)},
        )

    def prompt_response(
        self,
        *,
        session_id: str,
        request_id: str,
        client_id: str | None,
        server: str,
        prompt: str,
        roles: Sequence[str],
        texts: Sequence[str],
    ) -> PayloadEvent:
        messages = [{"role": role, "text": text} for role, text in zip(roles, texts, strict=True)]
        return self._emit(
            session_id, request_id, client_id, server, "prompts/get", "response",
            {"prompt": prompt, "messages": messages},
        )

    def _call(self, call: ToolCall, stage: str, payload: dict[str, Any]) -> PayloadEvent:
        return self._emit(
            call.session_id, call.request_id, call.client_id, call.server, "tools/call", stage,
            payload,
        )

    def _emit(
        self,
        session_id: str,
        request_id: str,
        client_id: str | None,
        server: str,
        method: str,
        stage: str,
        payload: dict[str, Any],
    ) -> PayloadEvent:
        record = PayloadEvent(
            record_id=uuid.uuid4().hex,
            seq=next(self._seq),
            timestamp=utc_now(),
            session_id=session_id,
            request_id=request_id,
            client_id=client_id,
            server=server,
            method=method,
            stage=stage,
            payload=payload,
        )
        for sink in self.sinks:
            try:
                sink(record)
            except Exception as error:  # noqa: BLE001 - a sink must never break the call
                log.warning("agent-latch-runtime: a payload sink failed (%s)", type(error).__name__)
        return record


class PayloadFile:
    """Payload sink that appends records as JSON lines to a file (mode 0600), values masked.

    Secret-like values are replaced by ``[REDACTED]`` and each string is cut to ``max_chars``.
    Masking is pattern-based and can miss unusual formats, so the file is still sensitive.
    """

    def __init__(self, path: Path, *, max_chars: int = DEFAULT_PAYLOAD_MAX_CHARS) -> None:
        self.path = path
        self.max_chars = max(1, max_chars)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._file: TextIO | None = os.fdopen(fd, "a", encoding="utf-8")

    def __call__(self, record: PayloadEvent) -> None:
        if self._file is None:
            return
        masked = mask_value(record.to_dict(), self.max_chars)
        self._file.write(json.dumps(masked, ensure_ascii=False) + "\n")
        self._file.flush()

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None


def _definition(tool: ToolInfo) -> dict[str, Any]:
    return {
        "description": tool.description,
        "input_schema": dict(tool.input_schema),
        "annotations": dict(tool.annotations),
    }
