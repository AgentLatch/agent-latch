"""Trace log: one redacted JSON line per MCP message seen by the runtime middleware.

The trace records traffic, not findings. It keeps argument names, sizes and SHA-256 hashes, plus a
short secret-masked excerpt of outputs; never raw argument values or full outputs.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from agent_latch.runtime.events import ToolCall, ToolInfo, ToolOutput, utc_now
from agent_latch.runtime.redact import excerpt, payload_bytes, payload_sha256

TRACE_SCHEMA = "agentlatch.runtime.trace/1"
DEFAULT_EXCERPT_CHARS = 200


class TraceLog:
    """Appends trace records to a JSONL file (mode 0600) and summarizes them on stderr.

    stdout is never written: in stdio mode it carries the MCP protocol.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        summary: TextIO | None = sys.stderr,
        excerpt_chars: int = DEFAULT_EXCERPT_CHARS,
    ) -> None:
        self.path = path
        self.summary = summary
        self.excerpt_chars = max(0, excerpt_chars)
        self._file: TextIO | None = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._file = os.fdopen(fd, "a", encoding="utf-8")

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def write(self, record: Mapping[str, Any]) -> dict[str, Any]:
        line = {"schema": TRACE_SCHEMA, "timestamp": utc_now(), **record}
        if self._file is not None:
            self._file.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")
            self._file.flush()
        if self.summary is not None:
            self.summary.write(f"agent-latch-runtime: {_summarize(line)}\n")
            self.summary.flush()
        return line

    # Record builders. Each returns the written record, which keeps tests simple.

    def tools_listed(
        self, *, session_id: str, request_id: str, server: str, tools: Sequence[ToolInfo]
    ) -> dict[str, Any]:
        return self.write({
            "session_id": session_id,
            "request_id": request_id,
            "server": server,
            "method": "tools/list",
            "stage": "response",
            "tools": [
                {
                    "name": tool.name,
                    "description_sha256": payload_sha256(tool.description),
                    "schema_sha256": payload_sha256(dict(tool.input_schema)),
                }
                for tool in tools
            ],
        })

    def call_request(self, call: ToolCall) -> dict[str, Any]:
        return self.write({
            **_call_fields(call),
            "stage": "request",
            "argument_names": sorted(call.arguments),
            "arguments_sha256": payload_sha256(dict(call.arguments)),
            "arguments_bytes": payload_bytes(dict(call.arguments)),
        })

    def call_response(self, call: ToolCall, output: ToolOutput, duration_ms: float) -> dict[str, Any]:
        text = "\n".join(output.texts)
        payload = {"texts": list(output.texts), "structured": output.structured}
        return self.write({
            **_call_fields(call),
            "stage": "response",
            "is_error": output.is_error,
            "content_items": len(output.texts),
            "output_bytes": payload_bytes(text),
            "output_sha256": payload_sha256(payload),
            "excerpt": excerpt(text, self.excerpt_chars),
            "duration_ms": round(duration_ms, 1),
        })

    def call_error(self, call: ToolCall, error: BaseException, duration_ms: float) -> dict[str, Any]:
        # Only the exception type: its message can echo argument values.
        return self.write({
            **_call_fields(call),
            "stage": "error",
            "error_type": type(error).__name__,
            "duration_ms": round(duration_ms, 1),
        })

    def prompts_listed(
        self, *, session_id: str, request_id: str, server: str, names: Sequence[str]
    ) -> dict[str, Any]:
        return self.write({
            "session_id": session_id,
            "request_id": request_id,
            "server": server,
            "method": "prompts/list",
            "stage": "response",
            "prompts": list(names),
        })

    def prompt_request(
        self,
        *,
        session_id: str,
        request_id: str,
        server: str,
        prompt: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self.write({
            "session_id": session_id,
            "request_id": request_id,
            "server": server,
            "method": "prompts/get",
            "stage": "request",
            "prompt": prompt,
            "argument_names": sorted(arguments),
            "arguments_sha256": payload_sha256(dict(arguments)),
        })

    def prompt_response(
        self,
        *,
        session_id: str,
        request_id: str,
        server: str,
        prompt: str,
        roles: Sequence[str],
        texts: Sequence[str],
    ) -> dict[str, Any]:
        text = "\n".join(texts)
        return self.write({
            "session_id": session_id,
            "request_id": request_id,
            "server": server,
            "method": "prompts/get",
            "stage": "response",
            "prompt": prompt,
            "message_count": len(roles),
            "roles": list(roles),
            "output_sha256": payload_sha256(list(texts)),
            "excerpt": excerpt(text, self.excerpt_chars),
        })


def _call_fields(call: ToolCall) -> dict[str, Any]:
    return {
        "session_id": call.session_id,
        "request_id": call.request_id,
        "server": call.server,
        "method": "tools/call",
        "tool": call.tool,
    }


def _summarize(record: Mapping[str, Any]) -> str:
    method, stage = record.get("method", "?"), record.get("stage", "?")
    if method == "tools/list":
        return f"tools/list -> {len(record.get('tools', []))} tool(s)"
    if method == "prompts/list":
        return f"prompts/list -> {len(record.get('prompts', []))} prompt(s)"
    name = record.get("tool") or record.get("prompt") or "?"
    if stage == "request":
        args = ", ".join(record.get("argument_names", [])) or "no arguments"
        return f"{method} {name} ({args})"
    if stage == "error":
        return f"{method} {name} -> error {record.get('error_type')} in {record.get('duration_ms')} ms"
    if method == "tools/call":
        status = "error result" if record.get("is_error") else "ok"
        return (
            f"{method} {name} -> {status}, {record.get('output_bytes')} B"
            f" in {record.get('duration_ms')} ms"
        )
    return f"{method} {name} -> {record.get('message_count')} message(s)"
