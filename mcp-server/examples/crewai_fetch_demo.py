"""A real CrewAI agent that uses the time and fetch servers through the AgentLatch runtime proxy.

    CrewAI agent (real model) ──▶ agent-latch-runtime proxy ──▶ gateway ──▶ time, fetch servers
                                   records every tools/list,
                                   tools/call and prompts/get

time and fetch are the MCP project's reference servers (github.com/modelcontextprotocol/servers).
Both are on in servers.json and need no token. The task only reads: it checks the time in Tokyo
and summarizes one web page.

PREREQUISITES
  1. Gateway set up (SETUP.md), with uv installed for time and fetch, and a model key:
        cd mcp-server
        python set_token.py OPENAI_API_KEY        # model key for the agent
        python server.py --check                  # should list time_... and fetch_... tools
  2. The proxy running in front of the gateway (leave it running):
        /path/to/agent-latch/.venv/bin/agent-latch-runtime proxy --name gateway \\
          --http 127.0.0.1:8770 --payloads ~/agentlatch-payloads.jsonl -- \\
          .venv/bin/python server.py
  3. CrewAI installed in a SEPARATE environment:
        python3 -m venv crewai-env && source crewai-env/bin/activate
        pip install crewai "crewai-tools[mcp]" python-dotenv

RUN
        python examples/crewai_fetch_demo.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

MCP_DIR = Path(__file__).resolve().parent.parent
load_dotenv(MCP_DIR / ".env")

# "or": a blank KEY= line in .env loads as "", which should still mean the default.
PROXY_URL = os.environ.get("AGENTLATCH_PROXY_URL") or "http://127.0.0.1:8770/mcp"


def main() -> int:
    page = os.environ.get("FETCH_DEMO_URL") or "https://example.com"
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY is not set. Add it: python set_token.py OPENAI_API_KEY", file=sys.stderr)
        return 1
    try:
        from crewai import Agent, Crew, Task
        from crewai_tools import MCPServerAdapter
    except ImportError:
        print('CrewAI not installed. In a separate venv: pip install crewai "crewai-tools[mcp]"', file=sys.stderr)
        return 1

    model = os.environ.get("OPENAI_MODEL_NAME") or "gpt-4o-mini"
    server = {"url": PROXY_URL, "transport": "streamable-http"}
    print(f"Connecting through the AgentLatch proxy at {PROXY_URL} ... (model: {model})")
    try:
        with MCPServerAdapter(server) as tools:
            print("Tools the agent can see:", [t.name for t in tools])
            researcher = Agent(
                role="Researcher",
                goal="Answer questions using only the provided tools.",
                backstory="Careful analyst who checks facts with tools.",
                tools=tools,
                llm=f"openai/{model}",  # uses OPENAI_API_KEY and OPENAI_MODEL_NAME from .env
                max_iter=5,            # step cap: the agent cannot loop forever
                verbose=True,
            )
            task = Task(
                description=(
                    "Use the tools to answer two things: the current time in Asia/Tokyo, "
                    f"and a one-sentence summary of the web page {page}."
                ),
                expected_output="Two short lines: the Tokyo time, then the page summary.",
                agent=researcher,
            )
            result = Crew(agents=[researcher], tasks=[task]).kickoff()
            print("\nResult:\n", result)
    except Exception as exc:  # noqa: BLE001
        print(f"\nRun failed: {exc}", file=sys.stderr)
        print("Is the AgentLatch proxy running on port 8770 in front of the gateway?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
