"""An OpenAI Agents SDK agent whose MCP server runs behind the AgentLatch runtime proxy.

    Agents SDK agent ──MCPServerStdio──▶ agent-latch-runtime proxy ──▶ demo server (fake-weather)
                                          records every tools/list and tools/call

MCPServerStdio starts the proxy, and the proxy starts the bundled demo server after `--`. Every
message is written, secret-masked, to runtime-logs/openai-agents/. The demo server touches no
network or files; one of its tools returns a fake credential so you can see it masked.

    pip install openai-agents "agent-latch[runtime]"
    python examples/openai-agents/runtime_proxy.py --direct   # no model: list and call tools
    python examples/openai-agents/runtime_proxy.py            # a real agent (needs OPENAI_API_KEY)
    agent-latch-runtime import-logs --dir runtime-logs/openai-agents --once

Stop with Ctrl+C. max_turns is kept small on purpose.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from agents import Agent, Runner
from agents.mcp import MCPServerStdio

LOG_DIR = Path("runtime-logs") / "openai-agents"


def proxied_demo_server() -> MCPServerStdio:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return MCPServerStdio(
        name="demo-weather",
        params={
            "command": sys.executable,
            "args": [
                "-m", "agent_latch.runtime.cli", "proxy", "--quiet", "--name", "demo-weather",
                "--trace", str(LOG_DIR / "trace.jsonl"),
                "--payloads", str(LOG_DIR / "payloads.jsonl"),
                "--", sys.executable, "-m", "agent_latch.runtime.demo_server",
            ],
        },
        cache_tools_list=True,
    )


async def direct(server: MCPServerStdio) -> None:
    """List and call tools through the proxy without a model, so the run is free and repeatable."""
    tools = await server.list_tools()
    print(f"{len(tools)} tool(s) through the proxy: {', '.join(tool.name for tool in tools)}")
    for name, arguments in (("get_weather", {"city": "Tokyo"}), ("leaky_lookup", {"user": "demo"})):
        result = await server.call_tool(name, arguments)
        text = " ".join(getattr(item, "text", "") for item in result.content)
        print(f"  {name}({arguments}) -> {text}")


async def with_agent(server: MCPServerStdio, question: str) -> None:
    agent = Agent(
        name="weather",
        instructions="Answer with the tools when they help. Be brief.",
        mcp_servers=[server],
    )
    result = await Runner.run(agent, question, max_turns=5)
    print(result.final_output)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--direct", action="store_true", help="call tools without a model")
    parser.add_argument("question", nargs="*", default=["What's the weather in Tokyo?"])
    args = parser.parse_args()
    async with proxied_demo_server() as server:
        if args.direct:
            await direct(server)
        else:
            await with_agent(server, " ".join(args.question))
    print(f"Recorded to {LOG_DIR.as_posix()}/. Next: agent-latch-runtime import-logs --dir {LOG_DIR.as_posix()} --once")


if __name__ == "__main__":
    asyncio.run(main())
