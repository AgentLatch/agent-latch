"""``agent-latch-runtime proxy``: one MCP server behind the AgentLatch middleware. Needs ``[runtime]``.

To the AI app the proxy is an MCP server; to the real server it is an MCP client. Both sides
speak normal MCP, so neither needs changes.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack

from fastmcp import FastMCP
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy

from agent_latch.runtime.middleware import AgentLatchMiddleware
from agent_latch.runtime.payloads import PayloadTap
from agent_latch.runtime.trace import TraceLog


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
    proxy = create_proxy(target, name=name, mode="auto", identity="upstream")
    # First in the list = outermost. create_proxy already added its ProxyMetadataMiddleware, which
    # applies the upstream identity to the handshake result on the way out. AgentLatch must wrap
    # it, so the recorded handshake is the final result the client receives.
    proxy.middleware.insert(0, AgentLatchMiddleware(trace, server=name, tap=tap))
    return proxy


def build_mount_app(
    *,
    mounts: Mapping[str, str],
    trace: TraceLog,
    tap: PayloadTap | None = None,
) -> object:
    """One ASGI app that serves each upstream at ``/mcp/NAME``.

    Every upstream gets its own proxy (and so its own ``server`` name in the records), but all of
    them write to the same ``trace`` (and its ledger) and ``tap``. They share one process and one
    event loop, and the writes are synchronous, so the records form a single ordered chain.
    """
    apps = {
        name: build_proxy(name=name, trace=trace, upstream_url=url, tap=tap).http_app(
            path=f"/mcp/{name}"
        )
        for name, url in mounts.items()
    }

    async def lifespan(receive, send) -> None:
        await receive()  # lifespan.startup
        try:
            async with AsyncExitStack() as stack:
                for sub in apps.values():
                    await stack.enter_async_context(sub.router.lifespan_context(sub))
                await send({"type": "lifespan.startup.complete"})
                await receive()  # lifespan.shutdown
        except Exception as error:
            await send({"type": "lifespan.startup.failed", "message": str(error)})
            raise
        await send({"type": "lifespan.shutdown.complete"})

    async def app(scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            await lifespan(receive, send)
            return
        path = scope.get("path", "")
        for name, sub in apps.items():
            prefix = f"/mcp/{name}"
            if path == prefix or path.startswith(prefix + "/"):
                await sub(scope, receive, send)
                return
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})

    return app
