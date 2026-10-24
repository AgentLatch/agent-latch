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

## What gets recorded

With `--trace FILE`, each MCP message adds one JSON line (`"schema": "agentlatch.runtime.trace/1"`) to the file, created with mode `0600`. A one-line summary of each message also goes to stderr (turn it off with `--quiet`). Nothing is written to stdout, which carries the MCP protocol.

| Message | Recorded |
|---|---|
| `tools/list` | Tool names, and a SHA-256 of each description and input schema |
| `tools/call` request | Tool name, argument **names**, SHA-256 and size of the arguments |
| `tools/call` result | Error flag, size, SHA-256, duration, and a short excerpt |
| `tools/call` failure | Exception type and duration |
| `prompts/list`, `prompts/get` | Prompt names, argument names and hash, message roles, and a short excerpt |

The trace never stores argument values or full outputs. The excerpt is at most `--excerpt-chars` characters (default 200; `0` turns it off), with secret-like values such as API keys, tokens and private keys replaced by `[REDACTED]`. Masking is pattern-based and can miss unusual formats, so treat the trace file as sensitive.

## Intercepted payloads (opt-in)

The trace says *that* a tool was called. Checking *what* was asked for (the command, path, URL or query, and what came back) needs the payload. The proxy turns each `tools/list`, `tools/call` and `prompts/get` message into a payload record with its full payload: requests before they are forwarded to the server, results before they go back to the app. Today the records are only written to a file. Runtime checks that read them are planned.

`--payloads FILE` writes each record as one JSON line (`"schema": "agentlatch.runtime.payload/1"`), in a file created with mode `0600`. **This file holds argument values and tool output**, so it is off by default:

| Message | Payload |
|---|---|
| `tools/list` response | Each tool's name, full description, input schema and annotations (`readOnlyHint`, `destructiveHint`, ...) |
| `tools/call` request | Tool name, argument values, and the tool's description, schema and annotations from the last `tools/list` (`null` if it was not listed) |
| `tools/call` response | Error flag, text content, structured content, duration |
| `tools/call` error | Exception type and message, duration |
| `prompts/get` request, response | Prompt name and argument values; the rendered messages (role and text) |

Every record also has `record_id`, `seq` (order within the proxy run), `timestamp`, `session_id`, `request_id` (pairs a request with its result), `client_id`, `server`, `method` and `stage`.

Before a record is written, string values under secret-like keys (`api_key`, `password`, `token`, ...) are replaced by `[REDACTED]`, other strings have secret-like values masked as in the trace, and each string is cut to `--payload-max-chars` characters (default 4000). Masking is pattern-based and can miss unusual formats: keep the payloads file local, private and short-lived. Nothing in it is sent anywhere.

## Try it without an app

```sh
agent-latch-runtime demo
```

This runs a bundled synthetic MCP server behind the proxy, lists its tools, calls three tools (one returns a fake credential, one fails), gets a prompt, then imports the logs and prints one line per event. Everything stays on your machine. The files land in `runtime-logs/demo/` and are replaced on each run: `trace.jsonl`, `payloads.jsonl`, `events.csv`, `normalized.jsonl` and `proxy.log` (the proxy's own messages).

## Import logs

`agent-latch-runtime import-logs` runs next to the proxy as a separate process. It reads the files the proxy already wrote, so it can neither slow down nor change the MCP flow. It follows the trace file (and the payloads file, if you have one) and, for each message:

1. **Normalizes** it: the trace record and its payload record are joined into one event (below).
2. **Shows** it: one line on stderr, one row in `events.csv`, and the full event (arguments, payload and response) in `normalized.jsonl`.
3. **Runs every installed gate** in turn on that event and appends one row per gate result to `gate-results.csv`. No gates ship yet, so this file is not created.

With no file options it reads and writes in `runtime-logs/`:

```sh
# Terminal 1: MCP traffic keeps flowing through the proxy.
agent-latch-runtime proxy --trace runtime-logs/trace.jsonl --payloads runtime-logs/payloads.jsonl -- npx -y @modelcontextprotocol/server-github

# Terminal 2: follow both logs (Ctrl+C to stop).
agent-latch-runtime import-logs
```

For a full live run with a real CrewAI agent and this repo's MCP gateway, follow [Part 4 of the gateway setup guide](../mcp-server/SETUP.md#part-4-watch-a-live-agent-run-with-agentlatch).

`--dir DIR` uses another folder. `--trace`, `--payloads`, `--events-csv` and `--output-csv` set single files. When `--trace` is given, payloads are read only if `--payloads` is given too; without them, gates see `payload: null` and only the trace `metadata`. `--normalized-out FILE` moves the full normalized events elsewhere. `--once` processes what the files hold now and exits. `--quiet` turns off the per-event lines. `--run-id` overrides the run id.

**events.csv.** One row per event: `run_id`, `order`, `timestamp`, `session_id`, `request_id`, `server`, `method`, `stage`, `name`, `outcome` (`ok`, `error result`, `error (Type)`, or empty for requests), `duration_ms`, `output_bytes`, `has_payload` and the trace's redacted `excerpt`. Argument values are never in it. Cells that a spreadsheet would run as a formula (starting with `=`, `+`, `-` or `@`) get a leading `'`.

**Normalized event.** Every gate gets this same object, whatever the method:

| Field | Meaning |
|---|---|
| `run_id`, `order` | `run_id` is a hash of the first trace line. `order` is the trace line number. Together they identify an event, and both are stable across restarts. |
| `timestamp`, `session_id`, `request_id`, `client_id`, `server`, `method`, `stage`, `name` | Common envelope. `name` is the tool or prompt name (`null` for list calls). `client_id` comes from the payload record. |
| `trace`, `payloads` | File name and line number of the source records. `payloads` is `null` when no payload record exists. |
| `metadata` | The rest of the trace record: hashes, sizes, excerpts, error flags and durations. |
| `payload` | The full masked payload (as in the payload table above), or `null`. |

A trace record waits for its payload record (matched on session, request, server, method, stage and name). In follow mode it moves on without it after 2 seconds. With `--once`, unmatched records go on without a payload at the end.

**Gates.** The importer discovers Python modules in `agent_latch.gates` in module-name order. A module exports a unique string `GATE_ID` and `evaluate(event)`, which returns `{"findings": [...]}`. Each gate gets its own copy of the event.

**gate-results.csv.** Columns are `run_id`, `order`, `gate_id`, `result_json`, and `result_json` always has the same shape: `{"gate_id":"...","status":"ok","findings":[],"error":null}`. If a gate raises, its row has `"status":"error"` and only the exception type in `error`; later gates still run.

Restarting the importer skips events and results already in its output files, so rows and lines are not repeated. Malformed lines are logged and skipped. The importer does not block or modify MCP traffic. Its output files can hold payload data, so keep them local and access-controlled (they are created with mode `0600`; `runtime-logs/` is in `.gitignore`).

## Limits

- It sees only servers whose config entry goes through the proxy. Other servers, the app's built-in tools (for example Claude Code's shell and file edits) and the user's prompts to the model don't pass through it.
- It records traffic; it doesn't detect attacks or block calls yet. A quiet trace is not a security guarantee.
- It sees MCP traffic only, not the agent's requests to its model, so it records what the agent did, not the prompt or reasoning behind it.
- Payload records cover `tools/list`, `tools/call` and `prompts/get`. Other MCP messages (`resources/list`, `resources/read`, `initialize`, notifications, sampling) pass through without a record, and `prompts/list` is only in the trace. Tool results keep text content only: image, audio and embedded-resource blocks are left out. A failed `prompts/get` writes no record.
- The payloads file is not rotated and grows with every message (each `tools/call` request repeats the tool's definition). Very large outputs are masked in full before they are cut, which costs CPU on multi-megabyte results.
- Known issues: over HTTP, one tool call can also record an extra `tools/list` entry (FastMCP looks the tool up internally); and `session_id` can change between requests on the same connection (seen over both HTTP and stdio), so don't rely on it to group a session's calls yet.
