"""A real CrewAI agent that sends a Slack message through the MCP gateway.

This is the "full live" run: a CrewAI agent (backed by a real model) connects to
the gateway, sees its tools, and decides to call slack_send_message itself.

PREREQUISITES
  1. Gateway running with your Slack token loaded:
        cd mcp-server
        python set_token.py SLACK_BOT_TOKEN      # paste your xoxb- token
        python set_token.py SLACK_CHANNEL        # e.g. #demo  (or edit .env)
        python server.py --http                  # leave this running
  2. A model key for the agent (CrewAI uses OpenAI by default):
        python set_token.py OPENAI_API_KEY       # paste your sk-... key
  3. CrewAI installed in a SEPARATE environment (keeps it off the gateway's deps):
        python3 -m venv crewai-env && source crewai-env/bin/activate
        pip install crewai "crewai-tools[mcp]" python-dotenv

RUN
        python examples/crewai_slack_demo.py

The agent posts a short, friendly message to your Slack channel.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

MCP_DIR = Path(__file__).resolve().parent.parent
load_dotenv(MCP_DIR / ".env")

GATEWAY_URL = f"http://127.0.0.1:{os.environ.get('MCP_GATEWAY_PORT', '8765')}/mcp"


def main() -> int:
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
    server = {"url": GATEWAY_URL, "transport": "streamable-http"}
    print(f"Connecting to the gateway at {GATEWAY_URL} ... (model: {model})")
    try:
        with MCPServerAdapter(server) as tools:
            print("Tools the agent can see:", [t.name for t in tools])
            messenger = Agent(
                role="Slack messenger",
                goal="Send one short, friendly greeting to the team's Slack channel.",
                backstory="You post concise updates to Slack using the available tools.",
                tools=tools,
                llm=f"openai/{model}",  # uses OPENAI_API_KEY and OPENAI_MODEL_NAME from .env
                max_iter=5,            # step cap: the agent cannot loop forever
                verbose=True,
            )
            task = Task(
                description=(
                    "Send a Slack message that says, in a friendly way, that this message "
                    "was sent by an AI agent through the MCP gateway. Keep it to one sentence."
                ),
                expected_output="Confirmation that the Slack message was sent.",
                agent=messenger,
            )
            result = Crew(agents=[messenger], tasks=[task]).kickoff()
            print("\nResult:\n", result)
    except Exception as exc:  # noqa: BLE001
        print(f"\nRun failed: {exc}", file=sys.stderr)
        print("Is the gateway running (python server.py --http) with your Slack token set?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
