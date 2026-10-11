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

Everything runs on your machine. It's separate from the AgentLatch scanner and doesn't change it.

- **New here?** Follow [SETUP.md](SETUP.md): step-by-step setup, connecting your agent, and connecting tools.
- **Adding a tool, tool server or token?** Follow the standards in [CLAUDE.md](CLAUDE.md).
- **Running a full open-source agent against it?** See [RUNNING_AGENTS.md](RUNNING_AGENTS.md) for CrewAI, ECC, BabyAGI, Swarm and AutoGPT, including [`bridge.py`](bridge.py) for agents that take plain Python tools.
- **Prefer a point-and-click view?** Run the [dashboard](#dashboard-ui) (`python ui/ui_server.py`).

## Quick start

Requires Python 3.11+. Check with `python3 --version`. If it's older (macOS often ships 3.9), use `python3.12` in place of `python3` below, or create the environment with `uv venv --python 3.12 .venv`. The `time` and `fetch` examples need [uv](https://docs.astral.sh/uv/) (`brew install uv`); without it they're skipped.

```sh
cd mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add tokens here later, only for the tools you use
python server.py --check      # lists every tool your agent will see
```

`--check` should end with something like:

```
5 tool(s) available:
  echo                   Return the text unchanged. Useful to check that an agent is connected.
  utc_now                Return the current UTC time in ISO 8601 format.
  time_get_current_time  Get current time in a specific timezone
  time_convert_time      Convert time between timezones
  fetch_fetch            Fetches a URL from the internet and optionally extracts its contents as markdown
```

Tools from `servers.json` are prefixed with the server's name, for example `time_get_current_time`.

## Connect your agent

There are two ways to connect:

- **stdio** (simplest): the agent starts the gateway itself.
- **HTTP**: you start the gateway once, and any number of agents connect to `http://127.0.0.1:8765/mcp`.

Run the commands below from the `mcp-server` folder, so `$(pwd)` fills in the right path.

### Claude Code

```sh
claude mcp add agentlatch-gateway -- "$(pwd)/.venv/bin/python" "$(pwd)/server.py"
```

Over HTTP (start `python server.py --http` first):

```sh
claude mcp add --transport http agentlatch-gateway http://127.0.0.1:8765/mcp
```

### Claude Desktop, Cursor, and other JSON-configured clients

Add this to `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop on macOS) or `~/.cursor/mcp.json` (Cursor), using your real path:

```json
{
  "mcpServers": {
    "agentlatch-gateway": {
      "command": "/path/to/agent-latch/mcp-server/.venv/bin/python",
      "args": ["/path/to/agent-latch/mcp-server/server.py"]
    }
  }
}
```

Run `pwd` in `mcp-server` to get the path. On Windows the Python path is `.venv\Scripts\python.exe`.

### Codex CLI

In `~/.codex/config.toml`:

```toml
[mcp_servers.agentlatch-gateway]
command = "/path/to/agent-latch/mcp-server/.venv/bin/python"
args = ["/path/to/agent-latch/mcp-server/server.py"]
```

### Any agent over HTTP

```sh
python server.py --http      # serves http://127.0.0.1:8765/mcp
```

Point any MCP-capable agent or framework at `http://127.0.0.1:8765/mcp`. From your own Python agent:

```python
import asyncio
from fastmcp import Client

async def main():
    async with Client("http://127.0.0.1:8765/mcp") as client:
        print([tool.name for tool in await client.list_tools()])
        result = await client.call_tool("echo", {"text": "hello"})
        print(result.data)

asyncio.run(main())
```

## Add tools

### Option 1: another MCP server, no code

Add an entry to `servers.json`. Both local programs and remote servers work:

```json
"my-local-server": {
  "description": "What it does (shown only to you).",
  "enabled": true,
  "command": "uvx",
  "args": ["some-mcp-server==1.2.3"],
  "env": {"SOME_API_KEY": "${SOME_API_KEY}"}
},
"my-remote-server": {
  "enabled": true,
  "url": "https://example.com/mcp",
  "headers": {"Authorization": "Bearer ${MY_SERVICE_TOKEN}"}
}
```

- `enabled: false` turns a server off without deleting it.
- Pin versions (`==1.2.3`, `@1.2.3`) so a new release can't change what runs.
- `servers.json` ships with `time` and `fetch` enabled. `git`, `filesystem` and `github` are there as switched-off examples.

### Option 2: your own Python tool

Copy [`tools/example_tools.py`](tools/example_tools.py) to a new file in `tools/` and add functions inside `register()`:

```python
def register(mcp) -> None:
    @mcp.tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b
```

- The function name becomes the tool name.
- The docstring is what the agent reads.
- The type hints become the input schema.

Restart the gateway to pick up the change.

## Tokens and secrets

All secrets go in `mcp-server/.env`, created from [`.env.example`](.env.example). Git ignores it.

1. Add the token to `.env`, for example `GITHUB_TOKEN=github_pat_...`.
2. Reference it in `servers.json` as `${GITHUB_TOKEN}`, in `env`, `headers`, `args` or `url`.
3. Set `"enabled": true` on that server and restart.

If a server's `${NAME}` is empty, the gateway skips that server and tells you which variable to set. The other servers keep working.

A local server only receives the variables you pass in its `env` block, not everything in `.env`.

### Protecting the gateway itself

In `--http` mode, set `MCP_GATEWAY_TOKEN` in `.env` to require a token. Agents then send it as `Authorization: Bearer <token>`:

- **Claude Code:** add `--header "Authorization: Bearer <token>"` to the `claude mcp add` command.
- **Python:** `Client("http://127.0.0.1:8765/mcp", auth="<token>")`.

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

## Troubleshooting

| Message | Fix |
|---|---|
| `skip github: set GITHUB_TOKEN in .env` | Add the token to `.env`, or leave the server off. |
| `skip time: 'uvx' is not installed` | Install uv, or Node.js for `npx` servers. |
| `skip git: disabled in servers.json` | Set `"enabled": true` if you want it. |
| A server's tools are missing | Check `logs/<name>.log`. Each local server's output goes there. |
| `address already in use` | Use another port: `python server.py --http --port 8877`. |

Run `python server.py --check` after any change to see exactly what loads.

## Safety notes

- Tools run with your user's permissions. An agent can do whatever its tools allow, so only enable what a run needs.
- HTTP mode listens on `127.0.0.1` only. If you widen that with `--host`, set `MCP_GATEWAY_TOKEN`.
- Never commit `.env`. Pin versions of servers you add.
