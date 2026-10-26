# Runtime proxy for MCP (preview)

`agent-latch-runtime proxy` sits between an AI app and one MCP server and records the traffic: the tool list, every tool call and result, and prompt templates. **Preview, monitor only:** it passes every message through unchanged and never blocks anything. `import-logs` then runs ALR04, a preview check that reports findings for instruction-like content in tool definitions. The report lists findings only. Opt-in blocking is planned.

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
- Restart the app afterwards. The settings file depends on the app. The JSON shape above (`mcpServers`) is the same in each of these except VS Code, which uses `servers`:

| App | Settings file |
|---|---|
| Claude Code | `.mcp.json` in the project |
| Claude Desktop | **Settings → Developer → Edit Config**. The installer from claude.ai uses `%APPDATA%\Claude\claude_desktop_config.json` on Windows and `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS. The Microsoft Store build uses `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| GitHub Copilot in VS Code | `.vscode/mcp.json` in the folder you open, with a top-level `servers` key instead of `mcpServers`. Keep that file out of git; it holds paths on your machine |
| Gemini in Google Antigravity | `~/.gemini/config/mcp_config.json` (the `config` directory; a file directly under `.gemini` is not read) |

These local apps were connected on Windows in October 2026. The macOS and Linux paths are the same files with that system's home directory. Claude Desktop has no Linux build.

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

- **Local apps** (Claude Desktop, Cursor, VS Code, Antigravity) run their MCP client on your PC. They start the proxy themselves over stdio, using the config change above. No network is involved. Use a real server after `--`. A trace from that connection shows calls; a finding still needs [Import logs](#import-logs) with `--payloads`, because ALR04 reads tool definitions, not the text a tool returns.
- **ChatGPT on the web** calls tools from OpenAI's servers. It cannot start a program on your PC or reach `localhost`. OpenAI's Secure MCP Tunnel connects out from your PC, so the proxy's unauthenticated HTTP listener is not published. The steps are in [docs/clients/chatgpt.md](clients/chatgpt.md). That guide records a trace of the bundled practice server. It is not the findings path.

| Client | Connection | Status |
|---|---|---|
| Claude Desktop | Local stdio | Tested on Windows, Oct 2026. Settings file in the table above |
| Cursor | Local stdio | Tested on Windows, Oct 2026. `~/.cursor/mcp.json` |
| GitHub Copilot in VS Code | Local stdio | Tested on Windows, VS Code 1.142, Oct 2026. `.vscode/mcp.json`, `"servers"` key |
| Gemini in Google Antigravity | Local stdio | Tested on Windows, Oct 2026. `~/.gemini/config/mcp_config.json` |
| ChatGPT (web) | OpenAI Secure MCP Tunnel | Tested on Windows with ChatGPT Plus, Oct 2026. [Setup](clients/chatgpt.md) |
| OpenAI Codex app | Reuses the ChatGPT plugin | The plugin was selected. A tool call through it is not yet verified. [Notes](clients/chatgpt.md#use-it-from-the-codex-app) |

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
3. **Runs every installed gate** in turn on that event and appends one row per gate result to `gate-results.csv`. ALR04 ships with the package, so this file is created. It records findings and does not block or change the call.

With no file options it reads and writes in `runtime-logs/`:

```sh
# Terminal 1: MCP traffic keeps flowing through the proxy.
agent-latch-runtime proxy --trace runtime-logs/trace.jsonl --payloads runtime-logs/payloads.jsonl -- npx -y @modelcontextprotocol/server-github

# Terminal 2: follow both logs (Ctrl+C to stop).
agent-latch-runtime import-logs
```

For a full live run with a real CrewAI agent and this repo's MCP gateway, follow [Part 4 of the gateway setup guide](../mcp-server/SETUP.md#part-4-watch-a-live-agent-run-with-agentlatch).

`--dir DIR` uses another folder. `--trace`, `--payloads`, `--events-csv` and `--output-csv` set single files. When `--trace` is given, payloads are read only if `--payloads` is given too; without them, gates see `payload: null` and only the trace `metadata`. `--normalized-out FILE` moves the full normalized events elsewhere. `--database FILE` also stores each event in a local SQLite file (below); it is off unless you set it. `--once` processes what the files hold now and exits. `--quiet` turns off the per-event lines. `--run-id` overrides the run id.

**events.csv.** One row per event: `run_id`, `order`, `timestamp`, `session_id`, `request_id`, `server`, `method`, `stage`, `name`, `outcome` (`ok`, `error result`, `error (Type)`, or empty for requests), `duration_ms`, `output_bytes`, `has_payload` and the trace's redacted `excerpt`. Argument values are never in it. Cells that a spreadsheet would run as a formula (starting with `=`, `+`, `-` or `@`) get a leading `'`.

### Store events in SQLite

`--database FILE` also saves every normalized event in a local SQLite database, using Python's built-in `sqlite3` (nothing extra to install). The CSV and normalized JSONL outputs are unchanged. Without `--database`, nothing else changes, and nothing is uploaded.

```sh
agent-latch-runtime import-logs --database ./runtime.db
```

Each event is one row in the `events` table. `SQLiteEventStore` is the first destination behind the importer's `EventStore` contract (`open`, `save`, `close`). A later destination, such as a warehouse or an opt-in trace exporter, implements that same contract. This file is only the local one.

| Column | From the normalized event |
|---|---|
| `run_id`, `event_order` | `run_id`, `order` (the key: an event is stored once) |
| `timestamp`, `session_id`, `request_id`, `client_id`, `server`, `method`, `stage`, `name` | Same fields |
| `trace_path`, `trace_line` | `trace` |
| `payloads_path`, `payloads_line` | `payloads` (`NULL` when there is no payload record) |
| `metadata` | `metadata`, as JSON text |
| `payload` | `payload`, as JSON text (`NULL` without `--payloads`) |
| `imported_at` | When the importer stored the row (UTC) |

- **No duplicates.** Rows are keyed by `run_id` and `event_order` and saved with `INSERT OR IGNORE`, one transaction per pass. Importing the same files again, or restarting the importer, adds only events it has not stored yet.
- **Live.** Without `--once`, the importer keeps following the logs and saves new events within about a second. If a save fails (for example the database is locked by another program), it logs one warning, keeps the events and retries on the next pass. Events still waiting when it stops are saved on the next run, which re-reads the files.
- **Trace only.** Without `--payloads`, `payload`, `payloads_path` and `payloads_line` are `NULL` and `metadata` still holds the trace fields.
- **Schema.** The schema version is kept in `PRAGMA user_version`, and numbered migrations bring an older database up to date when it is opened, each in one transaction. A database from a newer AgentLatch, or a file that is not SQLite, is refused with exit code `2`.
- **Readable view.** `event_log` shows one line per event: `time`, `server`, `method`, `stage`, `tool_or_prompt`, `client_id`, `is_error`, `duration_ms`, the masked `excerpt` and `has_payload`.

Read it with Python:

```sh
python -c "import sqlite3; db = sqlite3.connect('runtime.db'); [print(r) for r in db.execute('select time, tool_or_prompt, stage, is_error, excerpt from event_log order by time desc limit 10')]"
```

**The database is sensitive.** With `--payloads` it holds tool arguments and outputs, masked by pattern only. A new database file is created with mode `0600` on macOS and Linux; on Windows it follows the folder's permissions, so keep it in your user folder. Keep it local and delete it when you no longer need it. The importer makes no network request for this store.

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

**ALR04 (preview).** The one gate that ships. It inspects tool definitions from `tools/list` responses and from the cached definition on a `tools/call` request: name, description, parameter schema, and metadata. It reports a finding for instruction-like content, including a definition that tells the agent to read a secret path such as `~/.ssh/id_rsa` (rule ALR04-004). Traffic that is not a tool definition produces no finding. Findings carry rule ids and the OWASP categories ASI01, ASI02, and ASI04. That mapping is context, not a claim those categories are fully covered. The rules can miss reworded instructions, and they do not look at tool results or what the agent does next. ALR04 never blocks a call.

**gate-results.csv.** Columns are `run_id`, `order`, `gate_id`, `result_json`, and `result_json` always has the same shape: `{"gate_id":"...","status":"ok","findings":[],"error":null}`. If a gate raises, its row has `"status":"error"` and only the exception type in `error`; later gates still run.

**Report.** From the repo root, after `import-logs` has written the CSV:

```sh
agent-latch --runtime-result
```

That prints the same kind of table as `agent-latch scan`: severity, rule, location, OWASP category, and the finding. It reads every gate in the file, not only ALR04, and it lists findings only. A finding that sets `path` and `line` uses that location. Otherwise, when `entity.tool` matches a function in the project path (the positional argument, default `.`), the location is that function's docstring line, for example `mcp-server/tools/alr04_fixture_tools.py:14`. A tool that comes from a mounted server and has no function in the project is shown as `server/tool #event`. `--plain` prints text instead of the table. `--fail-on` applies to these rows the same way it applies to a scan. The default CSV is `runtime-logs/gate-results.csv`; pass another file as `--runtime-result FILE`.

Restarting the importer skips events and results already in its output files, so rows and lines are not repeated. Malformed lines are logged and skipped. The importer does not block or modify MCP traffic. Its output files can hold payload data, so keep them local and access-controlled (they are created with mode `0600`; `runtime-logs/` is in `.gitignore`).

## Limits

- It sees only servers whose config entry goes through the proxy. Other servers, the app's built-in tools (for example Claude Code's shell and file edits) and the user's prompts to the model don't pass through it.
- It records traffic and runs ALR04 on tool definitions. It reports findings and does not block calls.
- It sees MCP traffic only, not the agent's requests to its model, so it records what the agent did, not the prompt or reasoning behind it.
- Payload records cover `tools/list`, `tools/call` and `prompts/get`. Other MCP messages (`resources/list`, `resources/read`, `initialize`, notifications, sampling) pass through without a record, and `prompts/list` is only in the trace. Tool results keep text content only: image, audio and embedded-resource blocks are left out. A failed `prompts/get` writes no record.
- The payloads file is not rotated and grows with every message (each `tools/call` request repeats the tool's definition). Very large outputs are masked in full before they are cut, which costs CPU on multi-megabyte results.
- Known issues: over HTTP, one tool call can also record an extra `tools/list` entry (FastMCP looks the tool up internally); and `session_id` can change between requests on the same connection (seen over both HTTP and stdio), so don't rely on it to group a session's calls yet.
