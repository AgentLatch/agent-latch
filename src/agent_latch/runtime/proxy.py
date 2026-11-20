"""``agent-latch-runtime proxy``: one MCP server behind the AgentLatch middleware. Needs ``[runtime]``.

To the AI app the proxy is an MCP server; to the real server it is an MCP client. Both sides
speak normal MCP, so neither needs changes.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from fastmcp import FastMCP
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import ProxyClient

from agent_latch.runtime.middleware import AgentLatchMiddleware, listing_incomplete
from agent_latch.runtime.payloads import PayloadTap
from agent_latch.runtime.trace import TraceLog


class RecordingProxyClient(ProxyClient):
    """Observe protocol pages before FastMCP aggregates away their cursors."""

    async def list_tools(self, *args, **kwargs):
        parent = listing_incomplete.get()
        status = [False]
        token = listing_incomplete.set(status)
        try:
            return await super().list_tools(*args, **kwargs)
        finally:
            listing_incomplete.reset(token)
            if parent is not None:
                parent[0] |= status[0]

    async def list_tools_mcp(self, *args, **kwargs):
        result = await super().list_tools_mcp(*args, **kwargs)
        status = listing_incomplete.get()
        if status is not None:
            status[0] = result.next_cursor is not None
        return result


def build_proxy(
    *,
    name: str,
    trace: TraceLog,
    command: Sequence[str] = (),
    upstream_url: str | None = None,
    tap: PayloadTap | None = None,
) -> FastMCP:
    """Proxy to a server started from ``command`` (stdio) or reached at ``upstream_url``."""
    if bool(command) == bool(upstream_url):
        raise ValueError("give either a server command or an upstream URL, not both")
    if command:
        # The MCP SDK passes a child only a few safe variables by default. The app already chose
        # this process's environment for the server (its config's "env" block), so pass it on;
        # otherwise tokens such as GITHUB_TOKEN would never reach the real server.
        target: object = StdioTransport(
            command=command[0], args=list(command[1:]), env=dict(os.environ)
        )
    else:
        target = upstream_url
    # mode="auto" lets the upstream negotiate its own protocol version, as the gateway does.
    # identity="upstream" forwards the real server's name/version to the client (and so to the
    # recorded handshake), instead of the proxy hiding it behind its own identity.
    proxy = create_proxy(RecordingProxyClient(target, mode="auto"), name=name, identity="upstream")
    # First in the list = outermost. create_proxy already added its ProxyMetadataMiddleware, which
    # applies the upstream identity to the handshake result on the way out. AgentLatch must wrap
    # it, so the recorded handshake is the final result the client receives.
    proxy.middleware.insert(0, AgentLatchMiddleware(trace, server=name, tap=tap))
    return proxy
