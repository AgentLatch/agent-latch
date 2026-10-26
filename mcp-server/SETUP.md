# Setup guide

Follow these steps in order. Each step tells you what you should see, so you know it worked.

- [Part 1: Set up the server](#part-1-set-up-the-server) (about 5 minutes, once)
- [Part 2: Connect your agent](#part-2-connect-your-agent)
- [Part 3: Connect tools to the server](#part-3-connect-tools-to-the-server)
- [Part 4: Watch a live agent run with AgentLatch](#part-4-watch-a-live-agent-run-with-agentlatch)
  - [4b. Claude Desktop on Windows, with the gateway in WSL](#4b-claude-desktop-on-windows-with-the-gateway-in-wsl)
- [If something goes wrong](#if-something-goes-wrong)

## Part 1: Set up the server

**1. Open a terminal in the `mcp-server` folder.**

```sh
cd path/to/agent-latch/mcp-server
```

**2. Check your Python version.**

```sh
python3 --version
```

✅ You need **3.11 or newer**. If it says 3.9 or 3.10, install a newer one with `brew install python@3.12`, then use `python3.12` in place of `python3` in the next step.

**3. Create a virtual environment and install the server.**

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

✅ Your prompt now starts with `(.venv)`. On Windows, activate with `.venv\Scripts\activate`.

**4. Create your private settings file.**

```sh
cp .env.example .env
```

✅ You now have a `.env` file. You'll add tokens to it in Part 3. Git ignores it, so it stays private.

**5. Install uv, so the example tools work.**

```sh
brew install uv
```

✅ `uvx --version` prints a version. If you'll use tool servers that start with `npx`, also run `brew install node`.

**6. Check that the server works.**

```sh
python server.py --check
```

✅ You should see:

```
5 tool(s) available:
  echo                   Return the text unchanged. ...
  utc_now                Return the current UTC time ...
  time_get_current_time  Get current time in a specific timezone
  time_convert_time      Convert time between timezones
  fetch_fetch            Fetches a URL from the internet ...
```

The first run takes a little longer while uv downloads the example tools. Lines like `skip git: disabled in servers.json` are normal.

## Part 2: Connect your agent

First, get the two paths you'll need. Run this in the `mcp-server` folder:

```sh
echo "$(pwd)/.venv/bin/python"
echo "$(pwd)/server.py"
```

Then follow the option for your agent. You only need one.

### Option A: Claude Code

**1. Add the server.** Run this in the `mcp-server` folder:

```sh
claude mcp add agentlatch-gateway -- "$(pwd)/.venv/bin/python" "$(pwd)/server.py"
```

**2. Check it.**

```sh
claude mcp list
```

✅ `agentlatch-gateway` shows as connected.

**3. Try it.** Start Claude Code and ask: *"Use the echo tool to say hello."* Type `/mcp` to see all the tools.

### Option B: Claude Desktop or Cursor

**1. Open the config file:**
- **Claude Desktop (macOS):** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Cursor:** `~/.cursor/mcp.json`

**2. Add the server,** using the two paths from above:

```json
{
  "mcpServers": {
    "agentlatch-gateway": {
      "command": "/your/path/to/mcp-server/.venv/bin/python",
      "args": ["/your/path/to/mcp-server/server.py"]
    }
  }
}
```

If the file already has an `mcpServers` section, add only the `"agentlatch-gateway": {...}` entry inside it. On Windows, the Python path is `...\mcp-server\.venv\Scripts\python.exe`. If the gateway lives in WSL and Claude Desktop on Windows, use [Part 4b](#4b-claude-desktop-on-windows-with-the-gateway-in-wsl) instead.

**3. Restart the app completely.**

✅ The gateway's tools appear in the app's tools or MCP list.

### Option C: Codex CLI

**1. Add this to `~/.codex/config.toml`:**

```toml
[mcp_servers.agentlatch-gateway]
command = "/your/path/to/mcp-server/.venv/bin/python"
args = ["/your/path/to/mcp-server/server.py"]
```

**2. Start Codex.**

✅ The tools appear when you list MCP tools.

### Option D: Any agent over HTTP

Use this when your agent connects to a URL, or when several agents share one gateway.

**1. Start the gateway and leave this terminal open:**

```sh
python server.py --http
```

✅ You see `[gateway] serving http://127.0.0.1:8765/mcp`.

**2. Point your agent at `http://127.0.0.1:8765/mcp`.** For Claude Code:

```sh
claude mcp add --transport http agentlatch-gateway http://127.0.0.1:8765/mcp
```

From your own Python code:

```python
import asyncio
from fastmcp import Client

async def main():
    async with Client("http://127.0.0.1:8765/mcp") as client:
        print([tool.name for tool in await client.list_tools()])
        print((await client.call_tool("echo", {"text": "hello"})).data)

asyncio.run(main())
```

**Optional: require a password.** Set `MCP_GATEWAY_TOKEN=some-long-random-text` in `.env` and restart the gateway. Agents then send it as `Authorization: Bearer some-long-random-text`:

- **Claude Code:** add `--header "Authorization: Bearer some-long-random-text"` to the `claude mcp add` command.
- **Python:** `Client(url, auth="some-long-random-text")`.

## Part 3: Connect tools to the server

After any change in this part:

1. Run `python server.py --check` to confirm what loads.
2. Restart the gateway. In Options A–C, the agent starts the gateway, so restart your agent.

### 3a. Turn on a tool server that's already listed

`servers.json` includes switched-off examples: `git`, `filesystem` and `github`.

**1.** Open `servers.json` and change `"enabled": false` to `"enabled": true` for the one you want.

**2.** Run `python server.py --check`.

✅ The new tools appear with the server's name in front of each tool's own name, for example `git_git_status`.

### 3b. Turn on a tool server that needs a token (GitHub example)

**1. Create a token.** On GitHub, go to Settings → Developer settings → Personal access tokens → Fine-grained tokens. Give it only the repositories and permissions you need.

**2. Add it to `.env`.** Either edit the file directly, or use the secure helper, which reads the value with hidden input (nothing shows on screen or in your shell history) and writes it for you:

```sh
python set_token.py GITHUB_TOKEN
```

Or edit `.env` by hand:

```sh
GITHUB_TOKEN=github_pat_your_token_here
```

**3.** In `servers.json`, set `"enabled": true` for `github`.

**4.** Run `python server.py --check`.

✅ You see GitHub tools prefixed `github_`. If you see `skip github: set GITHUB_TOKEN in .env`, the token is missing or `.env` wasn't saved.

### 3c. Add a new tool server

**1. Find the server's package name** and its current version in its README, for example on PyPI or npm.

**2. Add an entry to `servers.json`,** pinned to that exact version:

```json
"my-server": {
  "description": "What it does. Needs MY_SERVER_TOKEN in .env.",
  "enabled": true,
  "command": "uvx",
  "args": ["my-mcp-server==1.2.3"],
  "env": {"MY_SERVER_TOKEN": "${MY_SERVER_TOKEN}"}
}
```

For a hosted server, use `"url": "https://..."` and `"headers": {"Authorization": "Bearer ${MY_SERVER_TOKEN}"}` instead of `command`, `args` and `env`.

**3. If it needs a token:** add `MY_SERVER_TOKEN=` (empty) to `.env.example`, and the real value to your `.env`. Reference it as `${MY_SERVER_TOKEN}` in `env`, `headers`, `args` or `url`. A local server only receives the variables listed in its `env` block, not everything in `.env`.

Use `"enabled": false` to turn a server off without deleting it.

**4.** Run `python server.py --check`.

✅ The new tools appear prefixed `my-server_`.

### 3d. Write your own tool in Python

**1. Copy the example:**

```sh
cp tools/example_tools.py tools/my_tools.py
```

**2. Edit `tools/my_tools.py`.** Keep `register(mcp)`, and add your function inside it with a docstring and type hints:

```python
def register(mcp) -> None:
    @mcp.tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b
```

**3.** Run `python server.py --check`.

✅ `add` appears in the list.

Before you commit a new tool or server, follow the standards and checklist in [CLAUDE.md](CLAUDE.md).

## Part 4: Watch a live agent run with AgentLatch

A real CrewAI agent ([`examples/crewai_fetch_demo.py`](examples/crewai_fetch_demo.py)) uses the gateway's `time` and `fetch` tools through the AgentLatch runtime proxy. The proxy records every message, and `import-logs` shows each one as it happens. Monitor only: nothing is blocked or changed.

```
CrewAI agent ──▶ agent-latch-runtime proxy :8770 ──▶ gateway ──▶ time, fetch
                   │ writes runtime-logs/trace.jsonl and payloads.jsonl
                   ▼
            agent-latch-runtime import-logs ──▶ one line per event + runtime-logs/events.csv
                                                 optional --database runtime-logs/runtime.db
```

**Before you start:**

- Part 1 is done, and `python server.py --check` lists `time_...` and `fetch_...` tools.
- AgentLatch is installed with the runtime extra in the repo's own `.venv` (run this from the repo root, not `mcp-server`):

  ```sh
  python3 -m venv .venv && source .venv/bin/activate
  pip install -e ".[runtime]"
  ```

  ✅ `agent-latch-runtime demo` prints ten `#1 ... #10` event lines. That checks AgentLatch alone, with no model key and no gateway.
- CrewAI is installed in its **own** environment in `mcp-server`, so its packages never mix with the gateway's:

  ```sh
  python3 -m venv crewai-env && source crewai-env/bin/activate
  pip install crewai "crewai-tools[mcp]" python-dotenv
  ```

- A model key is in `.env`: `python set_token.py OPENAI_API_KEY`. The agent sends its prompts to OpenAI, so this run is not local-only.

Use three terminals. In each one, replace `~/projects/agent-latch` with your clone's path.

**1. Terminal 1: start the proxy.** It starts the gateway for you. Leave it open.

```sh
cd ~/projects/agent-latch/mcp-server
~/projects/agent-latch/.venv/bin/agent-latch-runtime proxy --name gateway --http 127.0.0.1:8770 \
  --trace ~/projects/agent-latch/runtime-logs/trace.jsonl \
  --payloads ~/projects/agent-latch/runtime-logs/payloads.jsonl \
  -- .venv/bin/python server.py
```

✅ You see `agent-latch-runtime: monitoring 'gateway' (preview; records traffic, never blocks)`.

**2. Terminal 2: start the importer before the agent.** It waits for the log files, then follows them and records each new event while the agent runs. Leave it open. Add `--database` when you want a local SQLite copy. Leave that flag off and only the CSV and JSONL files are written. Nothing is uploaded. What the file contains: [Store events in SQLite](../docs/runtime.md#store-events-in-sqlite).

```sh
cd ~/projects/agent-latch
source .venv/bin/activate
agent-latch-runtime import-logs --database runtime-logs/runtime.db
```

✅ You see `importing runtime-logs/trace.jsonl into runtime-logs/events.csv and runtime-logs/runtime.db with 1 gate(s); following new lines (Ctrl+C to stop)`. Without `--database` the `and runtime-logs/runtime.db` part is absent.

**3. Terminal 3: run the agent.**

```sh
cd ~/projects/agent-latch/mcp-server
source crewai-env/bin/activate
python examples/crewai_fetch_demo.py
```

✅ Terminal 3 ends with the Tokyo time and a one-line summary of the page. Terminal 1 prints a line per message. About two seconds behind the agent, Terminal 2 prints lines like:

```
agent-latch-runtime: #1 gateway: tools/list -> 5 tool(s) [payload]
agent-latch-runtime: #2 gateway: tools/call time_get_current_time (timezone) [payload]
agent-latch-runtime: #3 gateway: tools/call time_get_current_time -> ok, 120 B in 9.8 ms [payload]
```

**4. Look at the results.** Stop Terminals 1 and 2 with Ctrl+C, then from the repo root:

```sh
column -s, -t < runtime-logs/events.csv | less -S
```

✅ One row per message: method, tool, outcome, duration, whether a payload was joined, and a short redacted excerpt. For the full arguments and response of each message, open `runtime-logs/normalized.jsonl`. `runtime-logs/` is git-ignored. Its files can hold tool output, so keep them local.

**5. Optional: run 21 scenarios, some attack-shaped.** With Terminals 1 and 2 still running, in Terminal 3:

```sh
python examples/crewai_scenarios.py --list      # what each scenario sends and what to look for
python examples/crewai_scenarios.py --direct    # the 21 calls without a model: always all 21, no cost
python examples/crewai_scenarios.py --direct --only 21   # ALR04 schema-injection fixture only
python examples/crewai_scenarios.py             # a real agent decides each call (uses OPENAI_API_KEY)
```

The scenarios cover normal calls, tool errors, fake secrets in arguments and in a URL, fetches to cloud-metadata, localhost and `file://` addresses, injection-shaped text (shell, SQL, path traversal, "ignore your instructions"), an oversized argument, and one schema-injection fixture. They only use read-only tools (never `slack_send_message`), and all secrets are fake.

Scenario 21 calls `schema_fixture`. That tool's description tells the agent to read `~/.ssh/id_rsa`; the function itself returns a fixed string and reads nothing. ALR04 reports a finding when the tool list is recorded, as rule ALR04-004 in `runtime-logs/gate-results.csv`. Print that table with `agent-latch --runtime-result`. Restart the proxy after this tool is added so the gateway loads it. The list stays flagged until `mcp-server/tools/alr04_fixture_tools.py` is removed.

✅ Every scenario shows up in Terminal 2. Where to read each part:

| You want | Read |
|---|---|
| The prompt each scenario gave the agent, the calls it made and its answer | `runtime-logs/agent-runs.jsonl`, written by the script itself (the proxy never sees prompts to the model) |
| Each request's arguments, joined with its response, as the proxy saw them | `runtime-logs/normalized.jsonl`, one JSON object per event |
| A quick table of every event | `runtime-logs/events.csv` |
| The same events in SQLite, when Terminal 2 was started with `--database` | `runtime-logs/runtime.db` |

The fake key and password show as `[REDACTED]` in every file, `agent-runs.jsonl` included: the script masks its log and console output with the proxy's own redaction before writing, and refuses to run if it can't load it. Masking is pattern-based and can miss unusual secret formats, so keep `runtime-logs/` local and private.

**To run again from a clean log,** delete the folder first: `rm -rf runtime-logs/`, then start again from step 1.

> **Run `import-logs` from the repo root.** `runtime-logs/...` is relative to the folder you're in. Started from `mcp-server`, the importer watches `mcp-server/runtime-logs/`, which stays empty, and prints nothing. From anywhere, a full path also works: `--dir ~/projects/agent-latch/runtime-logs/claude-desktop`.

### 4b. Claude Desktop on Windows, with the gateway in WSL

Claude Desktop runs on Windows. The proxy and gateway stay in WSL, and Claude Desktop starts them through `wsl.exe`. No terminal is needed for the proxy: Claude Desktop starts and stops it.

**1. Open the config.** In Claude Desktop, go to **Settings → Developer → Edit Config**. Use this rather than looking for the file yourself: the Microsoft Store version keeps it in a hidden folder.

**2. Add the gateway entry.** If the file is empty, paste all of this. Otherwise add only the `"agentlatch-gateway": {...}` entry inside the existing `mcpServers`. Change `Ubuntu` if your distribution has another name (`wsl -l`), and `~/projects/agent-latch` if your clone is elsewhere.

```json
{
  "mcpServers": {
    "agentlatch-gateway": {
      "command": "wsl.exe",
      "args": [
        "-d", "Ubuntu", "-e", "bash", "-lc",
        "cd ~/projects/agent-latch && exec .venv/bin/agent-latch-runtime proxy --name gateway --trace runtime-logs/claude-desktop/trace.jsonl --payloads runtime-logs/claude-desktop/payloads.jsonl -- mcp-server/.venv/bin/python mcp-server/server.py"
      ]
    }
  }
}
```

`bash -lc` loads your login `PATH`, so the gateway finds `uvx` for the time and fetch tools. The logs go to their own folder, `runtime-logs/claude-desktop/`, so they don't mix with CrewAI runs.

**3. Restart Claude Desktop completely:** right-click its tray icon → **Quit**, then open it again. Closing the window is not enough.

✅ In **Settings → Developer**, `agentlatch-gateway` shows as running.

**4. Start the importer** in a WSL terminal, from the repo root:

```sh
cd ~/projects/agent-latch
source .venv/bin/activate
agent-latch-runtime import-logs --dir runtime-logs/claude-desktop --database runtime-logs/claude-desktop/runtime.db
```

Start this before you send Claude a message, so events are stored as they happen. Omit `--database` if you only want the CSV and JSONL files in `runtime-logs/claude-desktop/`.

**5. Ask Claude Desktop to use the tools,** and allow each call when it asks:

- "What time is it in Tokyo? Use the time tool."
- "Fetch https://example.com and summarize it."
- "Use the echo tool to repeat: my api key is sk-FAKE0123456789abcdefFAKE" (a fake key)

✅ The importer prints each call, for example:

```
agent-latch-runtime: #8 gateway: tools/call echo (text) [payload]
agent-latch-runtime: #9 gateway: tools/call echo -> ok, 41 B in 178.4 ms [payload]
```

In `runtime-logs/claude-desktop/normalized.jsonl` the echo request and response both show `my api key is [REDACTED]`.

**What to expect:**

- **Claude still sees the unmasked text.** The proxy is monitor-only: it passes traffic through unchanged and masks only what it writes to disk.
- **Your chat messages are not recorded.** They go from Claude Desktop to Anthropic, not through MCP. Only tool lists, tool calls and prompts pass the proxy. Never paste a real secret into the chat.
- **Claude may refuse attack-shaped requests,** such as fetching a cloud-metadata address. Nothing reaches the proxy then, so nothing is logged. Use `crewai_scenarios.py --direct` (step 5 of Part 4) for those tests.
- **`slack_send_message` posts to Slack for real.** Claude Desktop sees it, so deny it when asked, or remove the Slack tools from the gateway first.

## If something goes wrong

| You see | Do this |
|---|---|
| `python3: command not found`, or a version older than 3.11 | Install Python 3.12 (`brew install python@3.12`) and use `python3.12`. |
| `No module named fastmcp` | Activate the environment (`source .venv/bin/activate`), then `pip install -r requirements.txt`. |
| `skip <name>: set <VAR> in .env` | Add that variable to `.env`, or leave the server off. |
| `skip <name>: 'uvx' is not installed` | Run `brew install uv`. For `npx`, run `brew install node`. |
| `skip <name>: disabled in servers.json` | Normal. Set `"enabled": true` if you want that server. |
| A server is mounted but its tools are missing | Open `logs/<name>.log` to see that server's own error. |
| `address already in use` | Another gateway is running. Stop it, or use `--port 8877`. |
| The agent doesn't see new tools | Restart the agent, or the gateway in HTTP mode. |
| Part 4: `Is the AgentLatch proxy running on port 8770` | Start Terminal 1 first and wait for `monitoring 'gateway'`. |
| Part 4: `OPENAI_API_KEY is not set` | Run `python set_token.py OPENAI_API_KEY` in `mcp-server`. |
| Part 4: `agent-latch-runtime: command not found` | Use the full path `~/projects/agent-latch/.venv/bin/agent-latch-runtime`, or activate the repo's `.venv`. |
| Part 4: the importer prints nothing | It's watching another folder. Run `import-logs` from the repo root, or give a full path: `--dir ~/projects/agent-latch/runtime-logs/claude-desktop`. |
| Part 4b: `agentlatch-gateway` fails to start in Claude Desktop | Open **Settings → Developer** for the error. The full log is `mcp-server-agentlatch-gateway.log` in Claude's `logs` folder. Check the distribution name (`wsl -l`) and the clone path in the config. |
| Part 4b: the gateway starts but has no time or fetch tools | `uvx` isn't on the login `PATH`. In WSL, `bash -lc "command -v uvx"` must print a path. |
