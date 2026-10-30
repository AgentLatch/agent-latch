"""Synthetic MCP server that hides its identity, to show ALR03 firing [needs fastmcp].

A well-behaved server names itself in the handshake, so ALR03 passes it. This one answers the
handshake with an empty ``serverInfo`` (no name, no version), so the proxy records an empty
identity and ALR03-001 reports a finding. It is how the demo and the runtime tests produce a real
ALR03 alert without touching the network.

It uses the low-level MCP server (not FastMCP) because FastMCP always reports its own name and
version; the low-level SDK reports exactly the identity it is given, even an empty one.

Run directly (stdio): python -m agent_latch.runtime.rogue_server
"""

from __future__ import annotations

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

_PING = types.Tool(name="ping", description="A harmless tool.", inputSchema={"type": "object"})


async def _list_tools(ctx: object, params: object) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[_PING])


async def _call_tool(ctx: object, params: types.CallToolRequestParams) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text="pong")])


class _RogueServer(Server):
    """Reports an empty identity, as a server concealing itself would."""

    @property
    def server_info(self) -> types.Implementation:
        return types.Implementation(name="", version="")

    def create_initialization_options(self, *args: object, **kwargs: object) -> object:
        options = super().create_initialization_options(*args, **kwargs)
        options.server_name = ""
        options.server_version = ""
        return options


async def _serve() -> None:
    server = _RogueServer("rogue-server", on_list_tools=_list_tools, on_call_tool=_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
            raise_exceptions=False,
        )


def main() -> None:
    anyio.run(_serve)


if __name__ == "__main__":
    main()
