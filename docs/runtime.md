# Runtime proxy for MCP (preview)

`agent-latch-runtime proxy` sits between an AI app and one MCP server and records the traffic: the tool list, every tool call and result, and prompt templates. **Preview, monitor only:** it passes every message through unchanged and never blocks anything. Runtime detectors and opt-in blocking are planned.

```
AI app (MCP client) ──▶ agent-latch-runtime proxy ──▶ real MCP server
                         records each message
```

To the app, the proxy looks like an MCP server. To the real server, it looks like an MCP client. Neither needs changes.

## Install

Requires Python 3.11 or newer. Install it in its own virtual environment, pinned to a release tag. AgentLatch is **not on PyPI**, so don't run `pip install agent-latch`: a package with that name on PyPI would not be ours.

Linux, macOS and WSL:

```sh
python3 -m venv ~/agentlatch-runtime
source ~/agentlatch-runtime/bin/activate
python -m pip install "agent-latch[runtime] @ git+https://github.com/AgentLatch/agent-latch.git@v0.3.0"
agent-latch-runtime proxy --help
```

Windows PowerShell:

```powershell
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\Activate.ps1
python -m pip install "agent-latch[runtime] @ git+https://github.com/AgentLatch/agent-latch.git@v0.3.0"
agent-latch-runtime proxy --help
```

The `runtime` extra adds FastMCP; the scanner alone doesn't need it. From a clone of the repository, `python -m pip install -e ".[runtime]"` works too.

- **Keep MCP servers out of this environment.** Run them the usual way (`uvx`, `npx`, their own virtual environment). Installing a server into AgentLatch's environment can break it: FastMCP may need a newer MCP library than the server was written for.
- **Windows: keep the environment path short**, such as `$HOME\agentlatch-runtime`. FastMCP installs `pywin32`, whose deeply nested files can exceed Windows' 260-character path limit under a long folder (`WinError 206`). Alternatively, turn on long path support in Windows.

## Connect an app

Change the server's entry in the app's MCP config: the command becomes `agent-latch-runtime`, and the real server command moves after `--`.

Before:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github@<version>"]
    }
  }
}
```

After:

```json
{
  "mcpServers": {
    "github": {
      "command": "/full/path/to/.venv/bin/agent-latch-runtime",
      "args": [
        "proxy", "--name", "github", "--trace", "/full/path/to/agentlatch-trace.jsonl", "--",
        "npx", "-y", "@modelcontextprotocol/server-github@<version>"
      ]
    }
  }
}
```

- Use full paths: desktop apps often start servers with a different `PATH` and working directory. The command is the `agent-latch-runtime` inside your virtual environment: `~/agentlatch-runtime/bin/agent-latch-runtime`, or on Windows `C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe` (every `\` is written `\\` in JSON).
- Keep any `env` block as it was. The proxy passes its environment on to the real server.
- The config file is `.mcp.json` for Claude Code, `.cursor/mcp.json` for Cursor and `claude_desktop_config.json` for Claude Desktop. Restart the app afterwards.

**Remote server over HTTP.** Run the proxy as a local service and point the app at it:

```sh
agent-latch-runtime proxy --http 127.0.0.1:8770 --upstream-url https://tools.example.com/mcp
```

```json
{ "mcpServers": { "tools": { "type": "http", "url": "http://127.0.0.1:8770/mcp" } } }
```

The HTTP listener has no authentication, so it accepts loopback addresses only. Upstream servers that need auth headers aren't supported yet.

## Supported clients

Where an app's MCP client runs decides how it reaches the proxy:

- **Local apps** (Claude Desktop, Cursor, VS Code) run their MCP client on your PC. They start the proxy themselves over stdio, using the config change above. No network is involved.
- **Cloud apps** (ChatGPT, claude.ai in a browser) call tools from the vendor's servers. They can't start a program on your PC or reach `localhost`, so they need a tunnel or a public HTTPS server. For ChatGPT, OpenAI's Secure MCP Tunnel connects out from your PC, so nothing is made public.

| Client | Connection | Status | Setup guide |
|---|---|---|---|
| Claude Desktop | Local stdio | Tested on Windows, Oct 2026 | [docs/clients/claude-desktop.md](clients/claude-desktop.md) |
| ChatGPT (web) | OpenAI Secure MCP Tunnel | Tested on Windows with ChatGPT Plus, Oct 2026 | [docs/clients/chatgpt.md](clients/chatgpt.md) |
| Cursor | Local stdio (`~/.cursor/mcp.json`) | Tested on Windows, Oct 2026 | [docs/clients/cursor.md](clients/cursor.md) |
| GitHub Copilot in VS Code | Local stdio (`.vscode/mcp.json`, `"servers"` key) | Tested on Windows, VS Code 1.142, Oct 2026 | [docs/clients/vscode-copilot.md](clients/vscode-copilot.md) |
| Gemini in Google Antigravity | Local stdio (`~/.gemini/config/mcp_config.json`) | Tested on Windows, Oct 2026 | [docs/clients/antigravity.md](clients/antigravity.md) |
| OpenAI Codex app | Reuses the ChatGPT plugin (Secure MCP Tunnel) | Codex imports the ChatGPT account's plugins, so no separate setup is needed; it selected the AgentLatch plugin. A tool call through it is not yet verified | [docs/clients/chatgpt.md](clients/chatgpt.md#use-it-from-the-codex-app) |

Each guide uses the test server in `tests/runtime_fixtures/fake_server.py` and its own `--name` (for example `claude-weather`), so one trace file shows which client made each call.

Not supported, as of October 2026:

| Client | Reason |
|---|---|
| claude.ai in a browser, Gemini web app | Connect only to servers with a public URL. A public tunnel would expose the proxy's unauthenticated HTTP listener |
| Gemini CLI | Stopped serving free, AI Pro and Ultra users on 18 June 2026; Google moved them to Antigravity |
| Gemini desktop app | Custom MCP servers are only in testing, by URL |
| Microsoft Copilot (Windows app) | No support for adding MCP servers |
| Cloud agents (Cursor Cloud Agents, GitHub Copilot coding agent, Copilot Studio) | Run on the vendor's servers, so they can't start a local proxy |

## What gets recorded

With `--trace FILE`, each MCP message adds one JSON line (`"schema": "agentlatch.runtime.trace/1"`) to the file, created with mode `0600`. A one-line summary of each message also goes to stderr (turn it off with `--quiet`). Nothing is written to stdout, which carries the MCP protocol.

| Message | Recorded |
|---|---|
| `tools/list` | Tool names, and a SHA-256 of each description and input schema |
| `tools/call` request | Tool name, argument **names**, SHA-256 and size of the arguments |
| `tools/call` result | Error flag, size, SHA-256, duration, and a short excerpt |
| `tools/call` failure | Exception type and duration |
| `prompts/list`, `prompts/get` | Prompt names, argument names and hash, message roles, and a short excerpt |

Argument values and full outputs are never stored. The excerpt is at most `--excerpt-chars` characters (default 200; `0` turns it off), with secret-like values such as API keys, tokens and private keys replaced by `[REDACTED]`. Masking is pattern-based and can miss unusual formats, so treat the trace file as sensitive.

## Limits

- It sees only servers whose config entry goes through the proxy. Other servers, the app's built-in tools (for example Claude Code's shell and file edits) and the user's prompts to the model don't pass through it.
- It records traffic; it doesn't detect attacks or block calls yet. A quiet trace is not a security guarantee.
- Known issues: over HTTP, one tool call can also record an extra `tools/list` entry (FastMCP looks the tool up internally); and `session_id` can change between requests on the same connection (seen over both HTTP and stdio), so don't rely on it to group a session's calls yet.
