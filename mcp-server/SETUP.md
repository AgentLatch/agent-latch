# Setup guide

This guide gets the AgentLatch gateway running on your computer and connects an AI app or your own code to it. Follow the steps in order. Every step says what you should see, so you know it worked before you move on.

- [Before you start](#before-you-start): a few words you'll see, and how to use the terminal
- [Part 1: Set up the server](#part-1-set-up-the-server) (about 10 minutes, once)
- [Part 2: Connect your agent](#part-2-connect-your-agent)
- [Part 3: Connect tools to the server](#part-3-connect-tools-to-the-server)
- [If something goes wrong](#if-something-goes-wrong)

## Before you start

**Words you'll see:**

| Word | Meaning |
|---|---|
| **Tool** | Something an AI can ask to have done, like "get the time" or "fetch a web page". |
| **Gateway** | This folder's server (`server.py`). It holds the tools and decides which ones an AI is allowed to use. |
| **Agent** | The AI app or program that uses the tools: Claude Code, Claude Desktop, Cursor, or your own code. |
| **MCP** | The standard way agents and tool servers talk to each other. You don't need to know how it works. |
| **Terminal** | The window where you type commands. On Windows that's PowerShell; in VS Code or Cursor, use **Terminal → New Terminal**. |

**How to read the commands:**

- Type commands into the terminal and press Enter. Code in `json`, `js` or `python` blocks goes **in a file**, not the terminal.
- Where commands differ, this guide gives a **Windows (PowerShell)** version and a **macOS / Linux** version. Use the one for your computer.
- `path/to/` in a command is a placeholder. Replace it with the real folder on your computer, for example `C:\Users\you\Code\agent-latch`.
- If a path contains spaces, wrap it in quotes: `cd "C:\Users\you\My Code\agent-latch"`.
- Your terminal shows which folder you're in at the start of each line, for example `PS C:\Users\you\Code\agent-latch\mcp-server>`. Check it before running a command.

## Part 1: Set up the server

**1. Open a terminal in the `mcp-server` folder.**

Go to the `agent-latch` folder you cloned, then into `mcp-server`:

```sh
cd path/to/agent-latch/mcp-server
```

✅ The folder at the start of the line now ends in `mcp-server`. If you're already in `agent-latch`, `cd mcp-server` is enough.

**2. Check your Python version.**

Windows (PowerShell):

```powershell
py -3 --version
```

macOS / Linux:

```sh
python3 --version
```

✅ You need **3.11 or newer**. If Python is missing or older:

- **Windows:** `winget install Python.Python.3.12`, then close and reopen the terminal.
- **macOS:** `brew install python@3.12`, then use `python3.12` in place of `python3` in the next step.

**3. Create a virtual environment and install the server.**

A virtual environment (`.venv`) is a private copy of Python just for this folder, so the gateway's packages don't mix with anything else.

Windows (PowerShell):

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS / Linux:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

✅ Your prompt now starts with `(.venv)`, and the install ends with `Successfully installed ...`.

On Windows, if activating says *"running scripts is disabled on this system"*, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, answer `Y`, and activate again.

**4. Create your private settings file.**

```sh
cp .env.example .env
```

✅ You now have a `.env` file. You'll add tokens to it in Part 3. Git ignores it, so it stays private.

**5. Install uv, so the example tools work.**

The example tools `time` and `fetch` are downloaded and run by a program called uv.

- **Windows:** `winget install astral-sh.uv`, then close and reopen the terminal, go back to `mcp-server`, and activate `.venv` again.
- **macOS:** `brew install uv`

✅ `uvx --version` prints a version number.

**6. Check that the server works.**

```sh
python server.py --check
```

✅ You see a list of tools, including:

```
echo                   Return the text unchanged. ...
utc_now                Return the current UTC time ...
time_get_current_time  Get current time in a specific timezone
time_convert_time      Convert time between timezones
fetch_fetch            Fetches a URL from the internet ...
```

The first run takes a little longer while uv downloads the example tools. Lines like `skip git: disabled in servers.json` are normal.

## Part 2: Connect your agent

Most agents need two full paths: where the gateway's Python is, and where `server.py` is. Print them by running this in the `mcp-server` folder:

Windows (PowerShell). This prints them with forward slashes, ready to paste into a config file:

```powershell
(Resolve-Path .venv\Scripts\python.exe).Path -replace '\\', '/'
(Resolve-Path server.py).Path -replace '\\', '/'
```

macOS / Linux:

```sh
echo "$(pwd)/.venv/bin/python"
echo "$(pwd)/server.py"
```

✅ You see two lines, for example `C:/Users/you/Code/agent-latch/mcp-server/.venv/Scripts/python.exe` and `C:/Users/you/Code/agent-latch/mcp-server/server.py`. Keep them handy.

Then follow the option for your agent. You only need one.

| You're using | Option |
|---|---|
| Claude Code (in the terminal) | [A](#option-a-claude-code) |
| Claude Desktop or Cursor | [B](#option-b-claude-desktop-or-cursor) |
| Codex CLI | [C](#option-c-codex-cli) |
| Any agent that connects to a web address (URL) | [D](#option-d-any-agent-over-http) |
| Your own JavaScript or TypeScript code | [E](#option-e-your-own-javascript-or-typescript-code) |

### Option A: Claude Code

**1. Add the server.** Run this in the `mcp-server` folder, replacing the two paths with the ones you printed above:

```sh
claude mcp add agentlatch-gateway -- "PYTHON_PATH" "SERVER_PATH"
```

On macOS / Linux you can let the terminal fill them in: `claude mcp add agentlatch-gateway -- "$(pwd)/.venv/bin/python" "$(pwd)/server.py"`.

**2. Check it.**

```sh
claude mcp list
```

✅ `agentlatch-gateway` shows as connected.

**3. Try it.** Start Claude Code and ask: *"Use the echo tool to say hello."* Type `/mcp` to see all the tools.

### Option B: Claude Desktop or Cursor

**1. Open the app's config file** in any text editor. Create it if it doesn't exist.

| App | Windows | macOS |
|---|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `%USERPROFILE%\.cursor\mcp.json` | `~/.cursor/mcp.json` |

To open one quickly on Windows, paste its path into the File Explorer address bar.

If you installed Claude Desktop from the Microsoft Store, its config file may be in `%LOCALAPPDATA%\Claude-Data\claude_<letters>\claude_desktop_config.json` instead. The surest way to open the right file is in the app: **Settings → Developer → Edit config**.

**2. Add the server.** Paste this in, then replace the two paths with the ones you printed at the start of Part 2:

```json
{
  "mcpServers": {
    "agentlatch-gateway": {
      "command": "C:/Users/you/Code/agent-latch/mcp-server/.venv/Scripts/python.exe",
      "args": ["C:/Users/you/Code/agent-latch/mcp-server/server.py"]
    }
  }
}
```

Check these three things, because each one makes the app silently ignore the file:

- **Use forward slashes `/` in paths.** A single backslash (`C:\Users`) is invalid in a JSON file. Doubled backslashes (`C:\\Users`) also work.
- **Use the right Python path for your computer.** On Windows it ends in `.venv/Scripts/python.exe`; on macOS / Linux it ends in `.venv/bin/python`.
- **Don't add a second `mcpServers` section.** If the file already has one, add only the `"agentlatch-gateway": {...}` entry inside it, with a comma after the entry before it.

**3. Restart the app completely.** Closing the window isn't enough: the app keeps running in the system tray (the **^** arrow at the bottom-right of the Windows taskbar). Right-click its icon there and choose **Quit**, then open it again.

Claude Desktop also saves its own settings into the same config file while it runs, which can overwrite your edit. Quit the app fully **before** editing the file, then save, then open the app.

If the app installs an update while it's closed, it can take a minute or two before it opens again. Wait for it rather than reinstalling.

✅ The gateway's tools appear in the app's tools or MCP list. In Cursor, that's **Customize → MCPs**, where `agentlatch-gateway` shows under **Connected**. Ask *"What time is it in Tokyo?"* and the app should use `time_get_current_time`.

**Optional: also record every tool call.** AgentLatch's runtime proxy can sit between the app and the gateway and write each tool call to a log file. Without it, the app uses the gateway's tools, but nothing is recorded.

```
app ──▶ runtime proxy (records each call) ──▶ gateway ──▶ tools
```

1. Install the runtime proxy by following [Step 1 of the Claude Desktop guide](../docs/clients/claude-desktop.md#step-1-install-agentlatch). It goes in its own folder, `agentlatch-runtime` in your home folder, separate from the gateway's `.venv`.
2. Print the two extra paths you'll need: the runtime proxy program, and the log file it writes to.

   Windows (PowerShell):

   ```powershell
   (Resolve-Path "$HOME\agentlatch-runtime\Scripts\agent-latch-runtime.exe").Path -replace '\\', '/'
   "$HOME\agentlatch-trace.jsonl" -replace '\\', '/'
   ```

   macOS / Linux:

   ```sh
   echo "$HOME/agentlatch-runtime/bin/agent-latch-runtime"
   echo "$HOME/agentlatch-trace.jsonl"
   ```

   ✅ You see two lines, for example `C:/Users/you/agentlatch-runtime/Scripts/agent-latch-runtime.exe` and `C:/Users/you/agentlatch-trace.jsonl`. On Windows, if the first command says *"Cannot find path"*, the runtime proxy isn't installed yet: go back to step 1. The log file doesn't need to exist yet; the proxy creates it.

   You now have four paths: these two, plus the gateway's Python and `server.py` that you printed at the start of Part 2.

3. Quit the app completely (see step 3 above: from the system tray, not just the window). Then replace the `agentlatch-gateway` entry from step 2 with this one, putting your four paths in place of the examples:

   ```json
   "agentlatch-gateway": {
     "command": "C:/Users/you/agentlatch-runtime/Scripts/agent-latch-runtime.exe",
     "args": ["proxy", "--name", "claude-gateway", "--trace", "C:/Users/you/agentlatch-trace.jsonl", "--",
              "C:/Users/you/Code/agent-latch/mcp-server/.venv/Scripts/python.exe",
              "C:/Users/you/Code/agent-latch/mcp-server/server.py"]
   }
   ```

   This is only the entry, not the whole file: it goes **inside** the `"mcpServers": { ... }` section, as in step 2. If the file has nothing else in it, the whole file looks like this:

   ```json
   {
     "mcpServers": {
       "agentlatch-gateway": {
         "command": "...",
         "args": ["..."]
       }
     }
   }
   ```

   Pasting only the entry, without the outer `{ "mcpServers": { ... } }`, makes the file invalid, and the app silently ignores it.

   | Path | Goes in |
   |---|---|
   | Runtime proxy program | `"command"` |
   | Log file | After `"--trace",` |
   | Gateway's Python | After `"--",` |
   | `server.py` | Last |

   On macOS / Linux, the runtime proxy path ends in `bin/agent-latch-runtime`, and the gateway's Python ends in `.venv/bin/python`.

4. Save the file, then open the app again.

✅ The app uses the gateway's tools as before, and `agentlatch-trace.jsonl` gains a line for every tool call, marked `"server": "claude-gateway"`. [docs/runtime.md](../docs/runtime.md) explains what the log contains.

Don't confuse this with the runtime proxy setup in [docs/clients/](../docs/clients/). Those guides put the proxy in front of a **fake test server** (`fake_server.py`), whose tools, like `get_weather` and `leaky_lookup`, are made up on purpose. They're for testing the recorder, not for real use.

### Option C: Codex CLI

**1. Add this to `~/.codex/config.toml`,** with your two paths:

```toml
[mcp_servers.agentlatch-gateway]
command = "/your/path/to/mcp-server/.venv/bin/python"
args = ["/your/path/to/mcp-server/server.py"]
```

**2. Start Codex.**

✅ The tools appear when you list MCP tools.

### Option D: Any agent over HTTP

Use this when your agent connects to a web address (URL), or when several agents share one gateway.

**1. Start the gateway and leave this terminal open:**

```sh
python server.py --http
```

✅ You see `[gateway] serving http://127.0.0.1:8765/mcp`. The gateway runs until you close this terminal or press Ctrl+C.

**2. Point your agent at `http://127.0.0.1:8765/mcp`.** For Claude Code, in a second terminal:

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

From JavaScript, see [Option E](#option-e-your-own-javascript-or-typescript-code).

**Optional: require a password.** Set `MCP_GATEWAY_TOKEN=some-long-random-text` in `.env` and restart the gateway. Agents then have to send that password:

- **Claude Code:** add `--header "Authorization: Bearer some-long-random-text"` to the `claude mcp add` command.
- **Python:** `Client(url, auth="some-long-random-text")`.
- **JavaScript:** `GatewayTools.connect({ url, token: "some-long-random-text" })`.

### Option E: Your own JavaScript or TypeScript code

The [JS connector](js/README.md) lets a JavaScript program use the gateway's tools, and includes a demo where Claude uses them. Its README walks through setup step by step: installing Node.js, a first test, and adding it to your own code.

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
| `Cannot find path ... path\to\...` | `path/to/` is a placeholder. Replace it with your real folder (see [Before you start](#before-you-start)). |
| `python3: command not found`, `py` not recognized, or a version older than 3.11 | Install Python 3.12 (Windows: `winget install Python.Python.3.12`; macOS: `brew install python@3.12`), then open a new terminal. |
| `running scripts is disabled on this system` when activating | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, answer `Y`, then activate again. |
| `No module named fastmcp` | Activate the environment (Windows: `.venv\Scripts\Activate.ps1`; macOS / Linux: `source .venv/bin/activate`), then `pip install -r requirements.txt`. |
| A command isn't recognized right after you installed it | The terminal was opened before the install. Close the terminal and open a new one. In VS Code or Cursor, quit the whole app and reopen it. |
| `skip <name>: set <VAR> in .env` | Add that variable to `.env`, or leave the server off. |
| `skip <name>: 'uvx' is not installed` | Install uv (step 5 of Part 1). For servers that use `npx`, install Node.js. |
| `skip <name>: disabled in servers.json` | Normal. Set `"enabled": true` if you want that server. |
| A server is mounted but its tools are missing | Open `logs/<name>.log` to see that server's own error. |
| `address already in use` | Another gateway is running. Stop it, or use `--port 8877`. |
| Claude Desktop or Cursor doesn't show the gateway | Check the three things in [Option B step 2](#option-b-claude-desktop-or-cursor): forward slashes, the right Python path, one `mcpServers` section. Then quit and reopen the app. |
| The app shows other `agentlatch` tools, like `get_weather` or `leaky_lookup` | That's the AgentLatch test server used by the runtime proxy ([docs/runtime.md](../docs/runtime.md)), not this gateway. Its tools are fake on purpose. Add `agentlatch-gateway` as described in Option B. |
| The agent doesn't see new tools | Restart the agent, or the gateway in HTTP mode. |
