# MCP gateway for live agent runs

One local MCP server that any agent can connect to. Behind it sit:

- **Your own tools**: Python functions in [`tools/`](tools/).
- **Any other MCP servers**: listed in [`servers.json`](servers.json), the same `mcpServers` format Claude Desktop and Cursor use.

Each agent connects to the gateway once and gets every tool. Tokens live in one git-ignored `.env` file.

```
your agent ──MCP──▶ gateway (server.py) ──▶ tools/*.py
                                         ├─▶ time    (uvx mcp-server-time)
                                         ├─▶ fetch   (uvx mcp-server-fetch)
                                         └─▶ …anything you add to servers.json
```

Everything runs on your machine. Today the gateway only forwards tool calls; it's separate from the AgentLatch scanner and doesn't change it. Runtime checks on the traffic passing through it are planned.

## Where to go next

| You want to… | Read |
|---|---|
| Set up the gateway, connect an agent (Claude Code, Claude Desktop, Cursor, Codex CLI, HTTP), or connect tools | [SETUP.md](SETUP.md): step by step, with what you should see at each step |
| Add a tool, tool server or environment variable to this repo | [CLAUDE.md](CLAUDE.md): standards and a checklist |
| Run a full open-source agent (CrewAI, ECC, BabyAGI, Swarm, AutoGPT) against it | [RUNNING_AGENTS.md](RUNNING_AGENTS.md), including [`bridge.py`](bridge.py) for agents that take plain Python tools |
| Test prompt injection against a live agent | [Injection lab](examples/injection_lab/README.md) (ASI01) |
| Use a point-and-click view | [Dashboard](#dashboard-ui) below |

## Quick start

Requires Python 3.11+ and, for the `time` and `fetch` examples, [uv](https://docs.astral.sh/uv/).

```sh
cd mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add tokens here later, only for the tools you use
python server.py --check      # lists every tool your agent will see
```

Then connect your agent with [SETUP.md Part 2](SETUP.md#part-2-connect-your-agent). In short:

- **stdio** (simplest): the agent starts the gateway itself, for example `claude mcp add agentlatch-gateway -- "$(pwd)/.venv/bin/python" "$(pwd)/server.py"`.
- **HTTP**: run `python server.py --http` once, and any number of agents connect to `http://127.0.0.1:8765/mcp`.

Tools from `servers.json` are prefixed with the server's name, for example `time_get_current_time`.

## Dashboard UI

A local web page with three buttons: run a static AgentLatch scan, check the gateway connection, and run tools with a live animation of the agent reaching the gateway and calling each tool.

```sh
# 1. Start the gateway (leave it running):
python server.py --http
# 2. In another terminal, make sure agent-latch is installed for the scan button:
#    from the repo root:  pip install -e ".[dev]"
# 3. Start the dashboard:
python ui/ui_server.py
```

Open http://127.0.0.1:8766. It drives the real scanner and the real gateway; nothing is mocked. If the gateway isn't running, panel 2 says so and tells you to start it. Set `AGENT_LATCH_CMD` if `agent-latch` isn't on your PATH.

## Safety notes

- Tools run with your user's permissions. An agent can do whatever its tools allow, so only enable what a run needs.
- HTTP mode listens on `127.0.0.1` only. If you widen that with `--host`, set `MCP_GATEWAY_TOKEN` ([how](SETUP.md#option-d-any-agent-over-http)).
- A local tool server only receives the variables listed in its `env` block in `servers.json`, not everything in `.env`.
- Never commit `.env`. Pin versions of servers you add.

Problems? See [If something goes wrong](SETUP.md#if-something-goes-wrong).
