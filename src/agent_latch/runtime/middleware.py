"""FastMCP middleware that records MCP traffic for AgentLatch runtime checks. Needs ``[runtime]``.

Monitor only: every message is passed through unchanged. If recording fails, the failure is
logged to stderr and the message still goes through; recording never breaks the agent's call.

With a ``PayloadTap``, each message also becomes a ``PayloadEvent`` with its full payload:
requests before they are forwarded, results before they are returned to the app.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from typing import Any

import mcp.types as mt
from fastmcp.prompts.base import Prompt, PromptResult
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult

from agent_latch.runtime.events import ToolCall, ToolInfo, ToolOutput, utc_now
from agent_latch.runtime.payloads import PayloadTap
from agent_latch.runtime.trace import TraceLog

log = logging.getLogger("agent_latch.runtime")


class AgentLatchMiddleware(Middleware):
    """Records tools/list, tools/call, prompts/list and prompts/get through a ``TraceLog``.

    An optional ``PayloadTap`` also gets tools/list, tools/call and prompts/get as payload records.
    """

    def __init__(
        self, trace: TraceLog, *, server: str, tap: PayloadTap | None = None
    ) -> None:
        self.trace = trace
        self.server = server
        self.tap = tap

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        session_id, request_id = _ids(context)
        infos = [
            ToolInfo(
                tool.name,
                self.server,
                tool.description or "",
                tool.parameters or {},
                _annotations(tool),
            )
            for tool in tools
        ]
        _record(lambda: self.trace.tools_listed(
            session_id=session_id, request_id=request_id, server=self.server, tools=infos
        ))
        tap = self.tap
        if tap is not None:
            _record(lambda: tap.tools_listed(
                session_id=session_id,
                request_id=request_id,
                client_id=_client_id(context),
                server=self.server,
                tools=infos,
            ))
        return tools

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        session_id, request_id = _ids(context)
        call = ToolCall(
            session_id=session_id,
            request_id=request_id,
            client_id=_client_id(context),
            tool=context.message.name,
            server=self.server,
            arguments=dict(context.message.arguments or {}),
            timestamp=utc_now(),
        )
        tap = self.tap
        _record(lambda: self.trace.call_request(call))
        if tap is not None:
            _record(lambda: tap.call_request(call))
        started = time.perf_counter()
        try:
            result = await call_next(context)
        except BaseException as error:
            elapsed = _ms_since(started)
            _record(lambda failure=error: self.trace.call_error(call, failure, elapsed))
            if tap is not None:
                _record(lambda failure=error: tap.call_error(call, failure, elapsed))
            raise
        elapsed = _ms_since(started)
        output = _tool_output(result)
        _record(lambda: self.trace.call_response(call, output, elapsed))
        if tap is not None:
            _record(lambda: tap.call_response(call, output, elapsed))
        return result

    async def on_list_prompts(
        self,
        context: MiddlewareContext[mt.ListPromptsRequest],
        call_next: CallNext[mt.ListPromptsRequest, Sequence[Prompt]],
    ) -> Sequence[Prompt]:
        prompts = await call_next(context)
        session_id, request_id = _ids(context)
        _record(lambda: self.trace.prompts_listed(
            session_id=session_id,
            request_id=request_id,
            server=self.server,
            names=[prompt.name for prompt in prompts],
        ))
        return prompts

    async def on_get_prompt(
        self,
        context: MiddlewareContext[mt.GetPromptRequestParams],
        call_next: CallNext[mt.GetPromptRequestParams, PromptResult],
    ) -> PromptResult:
        session_id, request_id = _ids(context)
        name = context.message.name
        arguments = dict(context.message.arguments or {})
        ids = {"session_id": session_id, "request_id": request_id, "server": self.server}
        tap = self.tap
        client_id = _client_id(context)
        _record(lambda: self.trace.prompt_request(**ids, prompt=name, arguments=arguments))
        if tap is not None:
            _record(lambda: tap.prompt_request(
                **ids, client_id=client_id, prompt=name, arguments=arguments
            ))
        result = await call_next(context)
        roles = [message.role for message in result.messages]
        texts = [_text(message.content) for message in result.messages]
        _record(lambda: self.trace.prompt_response(**ids, prompt=name, roles=roles, texts=texts))
        if tap is not None:
            _record(lambda: tap.prompt_response(
                **ids, client_id=client_id, prompt=name, roles=roles, texts=texts
            ))
        return result


def _record(write: Callable[[], Any]) -> None:
    try:
        write()
    except Exception as error:  # noqa: BLE001 - recording must never break the call
        log.warning("agent-latch-runtime: could not record a trace entry (%s)", type(error).__name__)


def _ids(context: MiddlewareContext[Any]) -> tuple[str, str]:
    ctx = context.fastmcp_context
    session_id, request_id = "stdio", ""
    if ctx is not None:
        try:
            session_id = ctx.session_id or session_id
        except RuntimeError:
            pass
        try:
            request_id = ctx.request_id
        except RuntimeError:
            pass
    return session_id, request_id


def _client_id(context: MiddlewareContext[Any]) -> str | None:
    ctx = context.fastmcp_context
    try:
        return ctx.client_id if ctx is not None else None
    except RuntimeError:
        return None


def _annotations(tool: Tool) -> dict[str, Any]:
    annotations = getattr(tool, "annotations", None)
    # by_alias gives the MCP wire names (readOnlyHint), not the SDK's field names (read_only_hint).
    if annotations is None:
        return {}
    return annotations.model_dump(by_alias=True, exclude_none=True)


def _text(block: Any) -> str:
    return getattr(block, "text", "") if getattr(block, "type", None) == "text" else ""


def _tool_output(result: ToolResult) -> ToolOutput:
    return ToolOutput(
        texts=tuple(_text(block) for block in result.content if getattr(block, "type", None) == "text"),
        structured=result.structured_content,
        is_error=result.is_error,
    )


def _ms_since(started: float) -> float:
    return (time.perf_counter() - started) * 1000
