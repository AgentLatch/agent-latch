"""Bridge the gateway's tools into plain Python functions.

Some agent frameworks speak MCP directly (CrewAI, Claude Code, Cursor). Others
(BabyAGI, OpenAI Swarm, classic AutoGPT) only take ordinary Python callables.
This helper connects to the running gateway and hands you those callables, so
any Python agent can use the same tools.

    from bridge import GatewayTools

    tools = GatewayTools()            # connects to the local gateway over stdio
    print(tools.names())              # ['echo', 'utc_now', 'time_get_current_time', ...]
    print(tools.call("echo", text="hi"))
    fn = tools.function("echo")       # a normal callable: fn(text="hi")

The gateway stays the single controlled boundary: an agent can only use the
tools you enabled in servers.json and tools/. Keep it local and enable only
what a run needs.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Self

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

HERE = Path(__file__).resolve().parent


class GatewayTools:
    """A live connection to the gateway, exposing its tools as sync callables.

    Agent frameworks are usually synchronous, so this runs one background event
    loop and blocks each call on it. Use as a context manager, or call close().
    """

    def __init__(self, url: str | None = None, token: str | None = None, python: str | None = None):
        """Connect to the gateway.

        url:    the gateway's HTTP address, for example http://127.0.0.1:8765/mcp.
                Omit it to start the gateway over stdio from this folder.
        token:  value for MCP_GATEWAY_TOKEN, when the HTTP gateway requires one.
        python: python used for the stdio gateway (defaults to this interpreter).
        """
        if url:
            self._client = Client(url, auth=token)
        else:
            interpreter = python or str(HERE / ".venv" / "bin" / "python")
            if not Path(interpreter).exists():
                import sys

                interpreter = sys.executable
            self._client = Client(
                StdioTransport(command=interpreter, args=[str(HERE / "server.py")])
            )
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._run(self._client.__aenter__())
        self._tools = {tool.name: tool for tool in self._run(self._client.list_tools())}

    def _run(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def names(self) -> list[str]:
        """Return every tool name the gateway exposes."""
        return list(self._tools)

    def describe(self, name: str) -> str:
        """Return a tool's description (its first docstring line upstream)."""
        return (self._tools[name].description or "").strip()

    def call(self, name: str, **kwargs: Any) -> Any:
        """Call a tool by name with keyword arguments and return its result."""
        result = self._run(self._client.call_tool(name, kwargs))
        return result.data if result.data is not None else result.content

    def function(self, name: str) -> Callable[..., Any]:
        """Return a plain callable for one tool, to register with an agent framework."""
        if name not in self._tools:
            raise KeyError(f"no such tool: {name}. Available: {', '.join(self.names())}")

        def tool_fn(**kwargs: Any) -> Any:
            return self.call(name, **kwargs)

        tool_fn.__name__ = name
        tool_fn.__doc__ = self.describe(name)
        return tool_fn

    def functions(self) -> dict[str, Callable[..., Any]]:
        """Return every tool as a name -> callable mapping."""
        return {name: self.function(name) for name in self._tools}

    def close(self) -> None:
        """Disconnect from the gateway and stop the background loop."""
        try:
            self._run(self._client.__aexit__(None, None, None))
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


if __name__ == "__main__":
    # Smoke test: connect, list tools, and call echo.
    with GatewayTools() as gateway:
        print(f"{len(gateway.names())} tool(s): {', '.join(gateway.names())}")
        print("echo ->", gateway.call("echo", text="bridge works"))
