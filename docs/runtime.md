# Runtime proxy for MCP (preview)

`agent-latch-runtime proxy` sits between an AI app and one MCP server and records the traffic: the tool list, every tool call and result, and prompt templates. **Preview, monitor only:** it passes every message through unchanged and never blocks anything. Runtime detectors and opt-in blocking are planned.

```
AI app (MCP client) ──▶ agent-latch-runtime proxy ──▶ real MCP server
                         records each message
```

To the app, the proxy looks like an MCP server. To the real server, it looks like an MCP client. Neither needs changes.

## Install

```sh
python -m pip install "agent-latch[runtime]"
agent-latch-runtime proxy --help
```

The `runtime` extra adds FastMCP. A plain `pip install agent-latch` (the scanner) doesn't install it.

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

- Use full paths: desktop apps often start servers with a different `PATH` and working directory.
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
