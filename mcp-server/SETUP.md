# Setup guide

Follow these steps in order. Each step tells you what you should see, so you know it worked.

- [Part 1: Set up the server](#part-1-set-up-the-server) (about 5 minutes, once)
- [Part 2: Connect your agent](#part-2-connect-your-agent)
- [Part 3: Connect tools to the server](#part-3-connect-tools-to-the-server)
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

If the file already has an `mcpServers` section, add only the `"agentlatch-gateway": {...}` entry inside it. On Windows, the Python path is `...\mcp-server\.venv\Scripts\python.exe`.

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
