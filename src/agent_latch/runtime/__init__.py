"""AgentLatch runtime checks for live MCP tool traffic (preview).

Today this package records MCP traffic routed through ``agent-latch-runtime proxy`` and never
changes or blocks it. Detectors, the operator policy and enforcement are planned.

Importing this package must not import FastMCP: only ``middleware``, ``proxy`` and ``cli`` need
the optional ``[runtime]`` extra, so the pure modules stay testable without it.
"""

from __future__ import annotations

from agent_latch.runtime.events import ToolCall, ToolInfo, ToolOutput
from agent_latch.runtime.trace import TRACE_SCHEMA, TraceLog

__all__ = ["TRACE_SCHEMA", "ToolCall", "ToolInfo", "ToolOutput", "TraceLog"]
