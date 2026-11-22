# Runtime proxy for MCP (preview)

`agent-latch-runtime proxy` sits between an AI app and one MCP server and records the traffic: the handshake, the tool list, every tool call and result, and prompt templates. **Preview, monitor only:** it passes every message through unchanged and never blocks anything. `import-logs` then runs the preview gates: ALR03 reports findings for endpoint identity (the handshake), ALR04 reports findings for instruction-like content in tool definitions, ALR05 reports findings for instruction-like content in tool results, and ALR10 reports findings for secret-like values crossing the tool boundary. The report lists findings only. Opt-in blocking is planned.

```
AI app (MCP client) ──▶ agent-latch-runtime proxy ──▶ real MCP server
                         records each message
```

To the app, the proxy looks like an MCP server. To the real server, it looks like an MCP client. Neither needs changes.

## Install

Requires Python 3.11 or newer. Install it from PyPI in its own environment, with the `runtime` extra. The package is `agentlatch-security`. The PyPI package named `agentlatch` is a separate project.

With [pipx](https://pipx.pypa.io):

```sh
pipx install "agentlatch-security[runtime]"
agent-latch-runtime proxy --help
```

Or in a virtual environment on Linux, macOS and WSL:

```sh
python3 -m venv ~/agentlatch-runtime
source ~/agentlatch-runtime/bin/activate
python -m pip install "agentlatch-security[runtime]"
agent-latch-runtime proxy --help
```

Windows PowerShell:

```powershell
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\Activate.ps1
python -m pip install "agentlatch-security[runtime]"
agent-latch-runtime proxy --help
```

The `runtime` extra adds FastMCP; the scanner alone doesn't need it. From a clone of the repository, `python -m pip install -e ".[runtime]"` works too.

Or use the container image `ghcr.io/agentlatch/agent-latch-runtime`; an app starts it with `docker run -i`. It holds no Node.js, so `npx` servers need a separate container or your own derived image. See [Container images](docker.md#runtime-image).

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

**Several remote servers, one proxy.** Repeat `--upstream-url` and give each a `NAME=`. One proxy then serves every server at `/mcp/NAME`, and all of them write to the same trace, payloads and ledger, so there is one ordered audit trail for the whole agent:

```sh
agent-latch-runtime proxy --http 127.0.0.1:8770 \
  --trace runtime-logs/trace.jsonl --payloads runtime-logs/payloads.jsonl \
  --ledger runtime-logs/trace.ledger.jsonl \
  --upstream-url fetch=https://a.example/mcp --upstream-url git=https://b.example/mcp
```

```json
{ "mcpServers": {
  "fetch": { "type": "http", "url": "http://127.0.0.1:8770/mcp/fetch" },
  "git":   { "type": "http", "url": "http://127.0.0.1:8770/mcp/git" }
} }
```

Each record's `server` field is the name you gave (`fetch`, `git`), so `import-logs`, `verify` and the report work unchanged. Names are 1 to 32 characters of `a-z`, `0-9`, `_` and `-`, must be unique, and `mcp` is reserved; anything else is a usage error (exit `2`). A value that starts with `http://` or `https://` is always a URL, so an `=` in its query string is never read as a name. A single bare `--upstream-url URL` works as before (served at `/mcp`, named by `--name`). With more than one server every one needs a name, `--name` does not apply, and `--http` is required. The proxy does not change tool names: each server's tools reach the app exactly as the server lists them.

**Limit:** several servers in one proxy must be remote URLs. A server started from a command (`uvx mcp-server-fetch`, `npx ...`) still needs its own proxy process (one trace and ledger per process). The same loopback-only, no-authentication rule applies.

## Supported clients

Where an app's MCP client runs decides how it reaches the proxy:

- **Local apps** (Claude Desktop, Cursor, VS Code, Antigravity) run their MCP client on your PC. They start the proxy themselves over stdio, using the config change above. No network is involved. Use a real server after `--`. A trace from that connection shows calls; a finding still needs [Import logs](#import-logs). ALR04 reads tool definitions and ALR05 reads tool results, so `--payloads` gives both gates the full text; without it, ALR05 has nothing to scan and reports one coverage record per run.
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

The trace never stores argument values or full outputs. The excerpt is at most `--excerpt-chars` characters (default 200; `0` turns it off), with secret-like values such as API keys, tokens and private keys replaced by `[REDACTED]`. Each record also carries `transport` (`stdio` or `http`), how the proxy reaches the upstream server; the ALR10 checks rate a secret sent to a remote (`http`) server higher. Masking is pattern-based and can miss unusual formats, so treat the trace file as sensitive.

## Intercepted payloads (opt-in)

The trace says *that* a tool was called. Checking *what* was asked for (the command, path, URL or query, and what came back) needs the payload. The proxy turns each `tools/list`, `tools/call` and `prompts/get` message into a payload record with its full payload: requests before they are forwarded to the server, results before they go back to the app. The records are written to a file. `import-logs` runs the ALR10 gate over them (secrets sent to a tool or returned by one), so without `--payloads` that gate can only report that it had nothing to check (`ALR10-R90`).

`--payloads FILE` writes each record as one JSON line (`"schema": "agentlatch.runtime.payload/1"`), in a file created with mode `0600`. **This file holds argument values and tool output**, so it is off by default:

| Message | Payload |
|---|---|
| `tools/list` response | Each tool's name, full description, input schema and annotations (`readOnlyHint`, `destructiveHint`, ...) |
| `tools/call` request | Tool name, argument values, and the tool's description, schema and annotations from the last `tools/list` (`null` if it was not listed) |
| `tools/call` response | Error flag, text content, structured content, duration |
| `tools/call` error | Exception type and message, duration |
| `prompts/get` request, response | Prompt name and argument values; the rendered messages (role and text) |

Every record also has `record_id`, `seq` (order within the proxy run), `timestamp`, `session_id`, `request_id` (pairs a request with its result), `client_id`, `server`, `method` and `stage`.

Before a record is written, string values under secret-like keys (`api_key`, `password`, `token`, ...) are replaced by `[REDACTED]`, other strings have secret-like values masked as in the trace, and each string is cut to `--payload-max-chars` characters (default 4000). When masking replaced anything, the payload carries a `masked` list of `{"path", "kind"}` entries naming where each secret-like value was (for example `$/arguments/api_key`) and what shape it had (`key_name`, `assignment`, `token:github`, `token:aws`, `jwt`, `pem`, `bearer`, ...). The entries hold only the kind and path, never any part of the value; the ALR10 checks read them, and records written before the list existed still import. Masking is pattern-based and can miss unusual formats: keep the payloads file local, private and short-lived. Nothing in it is sent anywhere.

## Try it without an app

```sh
agent-latch-runtime demo
```

This runs a bundled synthetic MCP server behind the proxy, lists its tools, calls five tools (one returns a fake credential, one fails, one returns a prompt-injection payload that ALR05 flags, and one returns ordinary cooking steps that correctly raise no finding), gets a prompt, then imports the logs and prints one line per event. Everything stays on your machine. The files land in `runtime-logs/demo/` and are replaced on each run: `trace.jsonl`, `payloads.jsonl`, `events.csv`, `normalized.jsonl`, `gate-results.csv`, `gate-results.sarif` and `proxy.log` (the proxy's own messages). Run `agent-latch --runtime-result runtime-logs/demo/gate-results.csv` afterwards to see the findings report.

`demo --scenario poisoned-output` runs a shorter session aimed at ALR05: one `fetch_page` call whose page hides an instruction in invisible Unicode tag characters and visibly steers the agent toward the sibling `send_email` tool. `ALR05-R02` (hidden content) and `ALR05-R03` (action steering) both fire on that one result.

```sh
agent-latch-runtime demo --scenario secret-leak
```

The `secret-leak` scenario shows the ALR10 checks instead: the client calls `search_issues` with an argument holding a GitHub-token-shaped fake value (ALR10-R01 fires), and the `read_config` tool returns a fake AWS key (ALR10-R02 fires). The report and the payload file show only `[REDACTED]`; every credential in the demo is fake.

## Import logs

`agent-latch-runtime import-logs` runs next to the proxy as a separate process. It reads the files the proxy already wrote, so it can neither slow down nor change the MCP flow. It follows the trace file (and the payloads file, if you have one) and, for each message:

1. **Normalizes** it: the trace record and its payload record are joined into one event (below).
2. **Shows** it: one line on stderr, one row in `events.csv`, and the full event (arguments, payload and response) in `normalized.jsonl`.
3. **Runs every installed gate** in turn on that event and appends one row per gate result to `gate-results.csv`. ALR03, ALR04, ALR05 and ALR10 ship with the package, so this file is created. They record findings and do not block or change the call. When the import ends (a `--once` run, or after you stop a following one), it also writes `gate-results.sarif` next to it; see below.

`--dir` names the run folder: the importer reads `trace.jsonl` and `payloads.jsonl` there and writes its outputs beside them. The proxy creates one folder per run (see [Default recording](#default-recording)) and prints it, so copy that path. Without `--dir` the importer reads `./runtime-logs/`, where `demo` and older setups write.

```sh
# Terminal 1: MCP traffic keeps flowing through the proxy. It prints the run folder.
agent-latch-runtime proxy --name github --record-payloads -- npx -y @modelcontextprotocol/server-github

# Terminal 2: follow the run's logs (Ctrl+C to stop). Use the folder the proxy printed.
agent-latch-runtime import-logs --dir ~/agent-latch/runtime-logs/github/20261122-074500
```

For a full live run with a real CrewAI agent and this repo's MCP gateway, follow [Part 4 of the gateway setup guide](../mcp-server/SETUP.md#part-4-watch-a-live-agent-run-with-agentlatch).

`--dir DIR` uses another folder. `--trace`, `--payloads`, `--events-csv` and `--output-csv` set single files. When `--trace` is given, payloads are read only if `--payloads` is given too; without them, gates see `payload: null` and only the trace `metadata`. `--normalized-out FILE` moves the full normalized events elsewhere. `--database FILE` also stores each event in a local SQLite file (below); it is off unless you set it. `--once` processes what the files hold now and exits. `--quiet` turns off the per-event lines. `--run-id` overrides the run id.

**events.csv.** One row per event: `run_id`, `order`, `timestamp`, `session_id`, `request_id`, `server`, `method`, `stage`, `name`, `outcome` (`ok`, `error result`, `error (Type)`, or empty for requests), `duration_ms`, `output_bytes`, `has_payload` and the trace's redacted `excerpt`. Argument values are never in it. Cells that a spreadsheet would run as a formula (starting with `=`, `+`, `-` or `@`) get a leading `'`.

### Store events in SQLite

`--policy FILE` hands operator policy (YAML or JSON) to the gates that read it. Today that is the ALR10 allowlist and the ALR03 suppressions. The file is trusted configuration: keep it outside the project being monitored. A file that cannot be read, or that is not a mapping, makes `import-logs` exit `2`.

```yaml
# policy.yaml
allowed_secret_tools:
  - {server: github, tool: search_issues}
```

```sh
agent-latch-runtime import-logs --policy ./policy.yaml
```

`--database FILE` also saves every normalized event in a local SQLite database, using Python's built-in `sqlite3` (nothing extra to install). The CSV and normalized JSONL outputs are unchanged. Without `--database`, nothing else changes, and nothing is uploaded.

```sh
agent-latch-runtime import-logs --database ./runtime.db
```

Each event is one row in the `events` table. `SQLiteEventStore` is the first destination behind the importer's `EventWriter` contract (`open`, `save`, `close`; `EventStore` is the older name for the same thing). Only `import-logs` holds a writer. Anything that merely shows events to an agent or a dashboard holds an `EventReader` instead (`SQLiteEventReader` for this file), which has no write methods and opens the file read-only. A later destination, such as a warehouse or an opt-in trace exporter, implements the same contract. This file is only the local one.

| Column | From the normalized event |
|---|---|
| `run_id`, `event_order` | `run_id`, `order` (the key: an event is stored once) |
| `timestamp`, `session_id`, `request_id`, `client_id`, `server`, `method`, `stage`, `name` | Same fields |
| `trace_path`, `trace_line` | `trace` |
| `payloads_path`, `payloads_line` | `payloads` (`NULL` when there is no payload record) |
| `metadata` | `metadata`, as JSON text |
| `payload` | `payload`, as JSON text (`NULL` without `--payloads`) |
| `imported_at` | When the importer stored the row (UTC) |
| `seal_seq`, `seal_prev`, `seal_digest` | The row's seal: its number in the chain, the previous row's digest, and its own digest. See [Keep the event store tamper-evident](#keep-the-event-store-tamper-evident) |

- **No duplicates, first write wins.** Rows are keyed by `run_id` and `event_order` and saved with `INSERT OR IGNORE`, one transaction per pass. Importing the same files again, or restarting the importer, adds only events it has not stored yet, and saving a key again with different content changes nothing.
- **Live.** Without `--once`, the importer keeps following the logs and saves new events within about a second. If a save fails (for example the database is locked by another program), it logs one warning, keeps the events and retries on the next pass. Events still waiting when it stops are saved on the next run, which re-reads the files.
- **Trace only.** Without `--payloads`, `payload`, `payloads_path` and `payloads_line` are `NULL` and `metadata` still holds the trace fields.
- **Schema.** The schema version is kept in `PRAGMA user_version`, and numbered migrations bring an older database up to date when it is opened, each in one transaction. A database from a newer AgentLatch, or a file that is not SQLite, is refused with exit code `2`. Version 3 adds the seal columns and seals the rows already stored, in `(run_id, event_order)` order; version 4 adds triggers that abort `UPDATE` and `DELETE`. **The upgrade is one way:** once a file is at version 3 or 4, an older AgentLatch refuses it. Keep a copy first if you may go back. The seal on an older row only vouches for it from the upgrade on: it cannot prove the row was not changed before.
- **Readable view.** `event_log` shows one line per event: `time`, `server`, `method`, `stage`, `tool_or_prompt`, `client_id`, `is_error`, `duration_ms`, the masked `excerpt` and `has_payload`.

Read it with Python:

```sh
python -c "import sqlite3; db = sqlite3.connect('runtime.db'); [print(r) for r in db.execute('select time, tool_or_prompt, stage, is_error, excerpt from event_log order by time desc limit 10')]"
```

### Keep the event store tamper-evident

Every row is sealed when it is saved: a SHA-256 over the event and its import time, chained to the row before it, computed by AgentLatch and not by the database. The newest seal can be published to an anchor outside the agent's reach, and then an edited, deleted, reordered or rebuilt store shows up. It is off unless you pass `--anchor`; the seals themselves are always written.

```sh
# Import, and publish the newest seal as the store grows (a new store creates the first point)
agent-latch-runtime import-logs --database ./runtime.db --anchor /safe/place/store-anchors.jsonl

# Check the store: every seal, the table layout, and the newest anchor point
agent-latch-runtime verify --database ./runtime.db --anchor /safe/place/store-anchors.jsonl

# Publish the head of a store that already has seals (the first point, or on purpose later)
agent-latch-runtime anchor --database ./runtime.db --to /safe/place/store-anchors.jsonl
```

`verify --database` reports the same six verdicts as the trace ledger and exits `0` for `intact` or `unanchored`, `1` for `tampered`, `deleted` or `rewritten`, and `2` for a usage error or a `missing` store: one with no rows and no anchor point to prove it ever held any (that is a store file that is absent, or one that exists but is empty; a store an anchor proves held rows is `deleted`, exit `1`). `import-logs` checks the store before it adds anything: a store that no longer matches its seals, its table layout or its anchor is refused with exit `1`, nothing is repaired or re-sealed, and no forged head is anchored, as long as the agent cannot write the store: keeping the store out of the agent's reach is what the guarantee rests on, because someone who can write it can append a correctly sealed row after the importer started, the importer will chain and anchor the next event onto it, and `verify` will accept the chain. Protect the trace and payload files the importer reads in the same way. Found at start, nothing is added; found while it runs, it stops before saving or publishing anything newer, and events it had already saved stay. A sealed store whose anchor file is missing is refused too, because that looks the same as a deleted anchor; restore the anchor or investigate first, and run `anchor --database` only if this store was never anchored. One anchor file per chain: a trace ledger and an event store number their records separately and cannot share a file.

To let an agent look at the store without ever holding its file, run `agent-latch-runtime audit-tool --database FILE`: an MCP server (stdio, needs the `[runtime]` extra) with two tools, `query_audit_log` (one SQL statement, up to 200 rows) and `recent_events`, built on the read-only reader. It exits `2` when the store is missing, not sealed yet, or newer than this AgentLatch. Run it where the agent cannot reach the file, for example in a container with the store's volume mounted read-only ([container layout](docker.md#keep-the-audit-store-out-of-the-agents-reach)).

Detection is not prevention. An agent that runs as the same operating-system user as the store can change the file and its permissions. The only thing that stops that is keeping the store and the anchor in another user or container, with mode `0600`, and never giving the agent their path. See [the event store in the ledger guide](ledger.md#the-event-store-gets-the-same-protection), [setup](ledger-setup.md#also-protect-the-event-store---database) and [the container layout](docker.md#keep-the-audit-store-out-of-the-agents-reach).

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

**ALR04 (preview).** The one gate that ships. It inspects tool definitions from `tools/list` responses and from the cached definition on a `tools/call` request: name, description, parameter schema, and metadata. It reports a finding for instruction-like content, including a definition that tells the agent to read a secret path such as `~/.ssh/id_rsa` (rule ALR04-004). Traffic that is not a tool definition produces no finding. Findings carry rule ids and the OWASP categories ASI01, ASI02, and ASI04. That mapping is context, not a claim those categories are fully covered. ALR04 never blocks a call.

Two evidence layers feed that report. The marker checks read the prose. A typed capability layer reads the schema and the `annotations` booleans (`readOnlyHint`, `destructiveHint`, `openWorldHint`), so a definition that declares itself read-only while exposing an upload target is a finding even though no sentence says so. A semantic layer frames each clause as actor, predicate, patient, sink, condition and modality, and reports behaviours the wording only implies ("operating notes take precedence", "logs stay internal", "preferred entry point") as review. The semantic layer never fails a tool on prose and never softens a marker finding, and a definition too large to frame fully is reported as incomplete coverage rather than cleared. Both layers can miss reworded or ambiguous definitions, and neither looks at tool results or what the agent does next.

**Reading ALR04 on its own.** `python -m agent_latch.gates.alr04 PATH` runs the gate over stored
`tools/list` payloads without the proxy: each file is one response, the table names severity,
rule, `tool@server` and the decision reason, and the command exits `1` when a tool fails. For a
recorded session, use the `gate-results.sarif` that `import-logs` writes. The labelled corpus the tests use is `tests/runtime_fixtures/alr04_unit/`, whose
payloads are synthetic and declare their expected outcome before the gate runs.
**ALR03 (preview).** Reads the connection handshake (`initialize` / `server/discover`), which the middleware records as an `initialize` event carrying the client and server name/version and the protocol version. It reports a finding when a server does not identify itself (rule ALR03-001), when a server's name or version changes versus an earlier connection in the same run (ALR03-002), and when a server's declared name or title is a look-alike of the proxy label or of a name seen earlier in the run (ALR03-003, typosquat/homoglyph impersonation — string similarity only: confusable folding, edit distance and bigram overlap; no regular expressions). It does not authenticate the transport (that is ALR12) or pin the tool list (ALR02), and identity is self-declared, so a PASS is not proof a server is trustworthy. Findings carry the OWASP categories ASI02, ASI03, ASI04, and ASI07. ALR03 never blocks a connection.

**ALR04 (preview).** It inspects tool definitions from `tools/list` responses and from the cached definition on a `tools/call` request: name, description, parameter schema, and metadata. It reports a finding for instruction-like content, including a definition that tells the agent to read a secret path such as `~/.ssh/id_rsa` (rule ALR04-004). Traffic that is not a tool definition produces no finding. Findings carry rule ids and the OWASP categories ASI01, ASI02, and ASI04. That mapping is context, not a claim those categories are fully covered. The rules can miss reworded instructions, and they do not look at tool results or what the agent does next. ALR04 never blocks a call.

**ALR05 (preview).** It inspects tool *results*: the text blocks and structured content of `tools/call` responses, and tool error messages. Three detectors share the text engine in `agent_latch/gates/_text.py` (also used by ALR04): `ALR05-R01` flags instruction-like text (override phrases, forged authority or conversation turns, concealment requests, instructions to read sensitive files), `ALR05-R02` flags hidden or encoded instructions (invisible or bidi characters, Unicode tag sequences, HTML comments, Base64/hex layers that decode to instruction-like text), and `ALR05-R03` flags output that steers the next action (naming another tool of the same server, sending data somewhere, opening a URL). Each finding records whether the tool is expected to return outside content (`openWorldHint`, or a name like `fetch_page`) as `outside_content_context`. A server declares both, so that context never skips a check and never lowers a finding: severity follows the outcome alone. Ordinary instructions in benign data (a recipe's steps, a CLI's manual) do not raise a finding on their own, and one weak signal alone cannot reach FAIL. Payload records exist only with `--payloads`; without them the gate emits one coverage record per run (`ALR05-R90`), and output cut by `--payload-max-chars` gets one coverage record per tool. The proxy sits between the app and the server, so it cannot show whether the output later reached a model or was fenced as data — a finding is a review signal about suspicious untrusted output, never a claim that an injection succeeded. The static rule AG003 checks the code side of the same gate. Findings carry the OWASP category ASI01 as context, not as a coverage claim. ALR05 never blocks a call.

**ALR10 (preview).** It watches secrets crossing the tool boundary on `tools/call` payload records. `ALR10-R01` reports a secret-like value sent to a tool in the request arguments; `ALR10-R02` reports one coming back in the tool's output (text content, structured content or an error message); `ALR10-R90` is a coverage record when a tool call has no payload record (the proxy ran without `--payloads`), because the gate then cannot check it. The gate works on **masked** payloads by design: the proxy replaces secrets with `[REDACTED]` before writing, so the gate never sees a raw secret and nothing it writes can leak one. Its evidence is the masking itself, the `masked` path-and-kind list described above; older records fall back to the `[REDACTED]` markers, which are reported as `INCONCLUSIVE` at `low` severity because a bare marker may also be ordinary text (a redacted legal document, a log line) and is never a FAIL. Severity is `high` for a token-shaped secret (`sk-`, `ghp_`, `AKIA…`, a JWT, a PEM key, a bearer header) in an argument or in tool output, and `high` for any secret sent to a remote (HTTP upstream) server; that remote escalation applies to requests only, so a key-name secret returned by a remote server is `medium`, like one returned by a local server. A secret under a key name sent to a local server is `medium`. A tool that looks like an authentication tool (named `login`/`auth`, or with a password parameter in its schema) is noted in the finding but never downgraded, because a server declares its own tool names and schemas; to expect a credential sent to such a tool, add it to the operator allowlist below. An operator allowlist, `allowed_secret_tools: [{server, tool}]` in a policy file you pass with `import-logs --policy FILE` (YAML or JSON; trusted configuration only, never a file from the monitored project), turns an expected pair into `PASS` with a note. Without `--policy` nothing is allowed. Metadata read from the payload file is treated as untrusted: a masking kind that is not one of the known kinds is reported as `unknown`, never copied into a finding. Findings carry OWASP category ASI03. Blind spots: secrets the masking patterns do not recognize (the same limit as the proxy's masking), secrets split across fields, and encoded secrets. On a small separate validation set (`tests/runtime_fixtures/alr10_heldout.json`, written after the patterns and not used to tune them; 48 synthetic cases) it flagged 7 of 12 secrets in requests and 8 of 10 in tool output, with no false positives in either direction. The misses were credentials inside URLs, GitLab, Stripe-style and Google API keys, npm tokens, and environment-style names with a prefix such as `AWS_SECRET_ACCESS_KEY` or `DB_PASSWORD`. These numbers come from a small hand-written set, so treat them as a regression check and not as a measure of real traffic. ALR10 never blocks a call and does not clear a tool.

**gate-results.sarif.** Every `import-logs` run writes this SARIF 2.1.0 file next to `gate-results.csv` (or next to the `--output-csv` file, with the `.sarif` extension), so it always exists: with no findings it has an empty `results` list. It holds every finding in the CSV, from all gates (ALR03, ALR04, ALR05 and ALR10), for GitHub code scanning, GitLab or a dashboard, and it is rewritten from the whole CSV each time, so it matches the CSV. A following importer also refreshes it when the logs go quiet (and every few seconds under steady traffic), so a hard kill leaves a recent file. A runtime finding has no source file, so a result has a logical location (`server/tool`) and a `partialFingerprints` entry (`agentLatchRuntimeFinding/v1`). The fingerprint is built from the rule, the server and tool, the tool-definition hash (when the gate has one) and the message, never from the event order, so the same finding keeps its identity from one session to the next. `level` follows the severity (`critical` and `high` are `error`, `medium` is `warning`, `low` and `info` are `note`). The file is created with mode `0600` like the CSV, because its messages and evidence come from the same findings. It lists findings only and does not clear a tool.

**gate-results.csv.** Columns are `run_id`, `order`, `gate_id`, `result_json`, and `result_json` always has the same shape: `{"gate_id":"...","status":"ok","findings":[],"error":null}`. If a gate raises, its row has `"status":"error"` and only the exception type in `error`; later gates still run.

**Report.** From the repo root, after `import-logs` has written the CSV:

```sh
agent-latch --runtime-result
```

That prints the same kind of table as `agent-latch scan`: severity, rule, location, OWASP category, and the finding. It reads every gate in the file, not only ALR04, and it lists findings only. A finding that sets `path` and `line` uses that location. Otherwise, when `entity.tool` matches a function in the project path (the positional argument, default `.`), the location is that function's docstring line, for example `mcp-server/tools/alr04_fixture_tools.py:14`. A tool that comes from a mounted server and has no function in the project is shown as `server/tool #event`. `--plain` prints text instead of the table. `--fail-on` applies to these rows the same way it applies to a scan. The default CSV is `runtime-logs/gate-results.csv`; pass another file as `--runtime-result FILE`.

Restarting the importer skips events and results already in its output files, so rows and lines are not repeated. Malformed lines are logged and skipped. The importer does not block or modify MCP traffic. Its output files can hold payload data, so keep them local and access-controlled (they are created with mode `0600`; `runtime-logs/` is in `.gitignore`).

### Send events to a connector (optional)

A connector is a separate package that sends the normalized events somewhere other than the built-in files: a database, another live system or an archive (design: [connectors.md](connectors.md)). **Nothing is discovered, imported or sent unless you name a connector.** `--database` is unchanged and does not use connectors. No connector package ships with AgentLatch yet; this is the configuration and the command line they plug into.

```sh
agent-latch-runtime connectors                       # list installed types; imports nothing
agent-latch-runtime import-logs \
  --connector pg=postgres \
  --connector-option pg.dsn=env:AGENTLATCH_PG_DSN \
  --connector-option pg.table=agent_events
```

- `--connector [NAME=]TYPE` selects an installed connector (repeatable). `NAME` defaults to `TYPE`, and two names let you run two of one type.
- `--connector-option NAME.KEY=VALUE` sets one value for a selected connector (repeatable). `--connector-config FILE` reads the same settings from a TOML file (`[connectors.NAME]` with `type = "..."`); options on the command line override the file. Both are trusted operator configuration: never a file from the monitored project.
- **Secrets.** Write a secret as `env:VARNAME`. The core reads the variable, so the value is never on the command line, in the process list or in output. Option values are never printed, and anything a connector says is scrubbed of the secret values the core resolved. A variable that is not set is an error that names the variable.
- **Payloads stay off.** A connector gets events with `payload` set to `null` unless you pass `NAME.payloads=true` for that connector. Other options every connector takes: `max_batch_events` (default 500), `max_pending_batches` (default 100) and `timeout` (seconds, default 10, enforced by the connector).
- **Errors you can act on.** An unknown type lists what is installed. A package that cannot be imported, a connector API outside the supported range (the message says whether to upgrade AgentLatch or the connector), a bad option, or two packages registering one type each exit `2` before any file is opened.
- **Delivery.** Events go to each connector in batches of at most `max_batch_events`, after every pass over the logs. A temporary failure keeps the batch and retries after 1, 2, 4 ... up to 60 seconds. A refused batch is saved to `DIR/NAME.rejected.jsonl` (mode `0600`) and skipped. A connector that fails in another way is turned off for the rest of the run and every other output continues; events that arrive after that count as dropped, so `--once` still exits `2`. If a refused batch cannot be saved to that file, it stays queued and that connector stops. The waiting queue holds `max_pending_batches` batches. The limit applies to what still has to wait after the write attempts, and the oldest is dropped when it is full.
- **Exit code.** With `--once`, events that were not delivered, were rejected or were dropped exit `2` after the final summary. Rebuild the gap by running `import-logs --once` again with the same input and connector settings: events are keyed by run and order, so a destination can merge duplicates. Following (no `--once`) ends with Ctrl+C and exit `0`, after a summary line per connector.

### Restarting the importer

A restarted `import-logs` skips every event whose gate rows are already in `gate-results.csv`.
Gates that keep state between events, such as ALR03, therefore do not see those earlier events
again. ALR03's identity baseline lives only in memory for one importer run (its
`cross_run_baseline` check already reports `PARTIAL` for this reason), so after a restart the first
handshake the importer evaluates, possibly one recorded while it was stopped, becomes the new
baseline, and an identity change across the stop can be missed. This is a property of any importer
restart. To check the whole recording again with fresh gate state, run one extra pass over the same
kept log files, with outputs that do not exist yet so nothing is skipped:

```bash
agent-latch-runtime import-logs --once --dir RECHECK_DIR \
  --trace PATH/trace.jsonl --payloads PATH/payloads.jsonl --run-id RUN_ID
```

`RECHECK_DIR` is a new, empty folder that only you can read, outside any source repository. `--dir`
sends every output of this pass there: events, gate results, and `normalized.jsonl`, which holds
full arguments, payloads and responses, so treat the folder as sensitive. Leave out `--database`
and any `--connector`, so the pass only evaluates gates. Review the findings with
`agent-latch --runtime-result RECHECK_DIR/gate-results.csv`, then delete the folder. The importer
you restarted keeps running unchanged.

Two limits apply to this re-check:

- **It needs the payloads.** ALR03 reads a server's identity from the `initialize` handshake
  payload. Without `payloads.jsonl` (the proxy was started without `--payloads`, or the file was
  not kept), ALR03 reports `INCONCLUSIVE` with `payload_unavailable` and cannot detect an identity
  change, in the re-check or anywhere else.
- **It does not repair the live importer.** The re-check runs in its own process with its own
  baseline. The restarted importer keeps the baseline it built from the first handshake it
  evaluated, so later identity changes are judged against that baseline, not the one from the
  re-check.

**Log rotation has no documented procedure for the runtime as a whole.** Rotating the proxy's log
files touches the trace, the payloads file, the audit ledger and its anchor, and the state the
runtime gates keep. Until a procedure is documented, do not rotate or move the log files while the
proxy or a follow-mode importer is running, and follow `docs/ledger-operations.md` ("Retention and
rotation") for the ledger.

## Default recording

The proxy records a trace and seals it into a ledger **by default**, with no flags. Every run gets its own folder:

```
~/agent-latch/runtime-logs/<server name>/<YYYYMMDD-HHMMSS>/trace.jsonl
                                                          /trace.ledger.jsonl
```

The root is in your home folder, so it does not depend on where an MCP client happened to start the proxy, and it is outside any project, so the files are not committed by accident. The timestamp is UTC, taken when the proxy starts (a second run in the same second gets a `-2` suffix). Because a run never reuses a folder, two proxies never share a hash chain, and each run has its own ledger and its own anchor. The proxy prints the exact folder, with a ready-to-copy `import-logs` command, on stderr at startup, and the folder again on exit.

**The run is imported for you when the proxy stops.** The proxy cannot know when an agent has finished, only when it is stopped (Ctrl+C or shutdown). At that point it runs the same one-shot import as `import-logs --once` over its own run folder and prints where everything is:

```
agent-latch-runtime: run folder: /home/you/agent-latch/runtime-logs/duckduckgo/20261122-074500
agent-latch-runtime: 14 event(s), 2 finding(s) (ALR05-R90 x1, ALR10-R01 x1); ledger unanchored
agent-latch-runtime: results: .../gate-results.csv  .../gate-results.sarif
agent-latch-runtime: to view the results, copy and paste:
RUN=/home/you/agent-latch/runtime-logs/duckduckgo/20261122-074500
/home/you/venv/bin/agent-latch --runtime-result "$RUN/gate-results.csv" --ledger "$RUN/trace.ledger.jsonl"
column -s, -t < "$RUN/events.csv" | less -S
agent-latch-runtime: anchor it (to a path the agent cannot write): agent-latch-runtime anchor --ledger ... --to <anchor file>
```

The block under "copy and paste" has no prefix, so you can paste it into a shell as is. The `agent-latch` path is the install the proxy runs from, so it works even when that install's `bin` folder is not on your `PATH`.

It only reads the run's own trace and payloads, runs after traffic has stopped, and never changes the proxy's exit code: a failed import prints a warning with the `import-logs` command to run by hand. `--no-import` turns it off (only the run folder is printed), and `--quiet` imports without printing. It does not help when an MCP client kills the proxy outright (for example Claude Desktop stopping a stdio server), because no output is seen then; use `import-logs --dir` for those runs. The ledger verdict is `unanchored` until you run `anchor`: the proxy cannot publish an anchor somewhere your agent cannot write.

Importing by hand, for runs that were not imported (or to import again), needs the run named, because nothing is guessed:

```sh
RUN=~/agent-latch/runtime-logs/duckduckgo/20261122-074500
agent-latch-runtime import-logs --dir "$RUN" --once
agent-latch --runtime-result "$RUN/gate-results.csv" --ledger "$RUN/trace.ledger.jsonl"
```

If you point `import-logs --dir` at a folder of runs (or give no `--dir` while runs exist in the home folder), it lists the runs it found, newest last, and exits `2`. `agent-latch-runtime verify ~/agent-latch/runtime-logs --all` checks every ledger below a folder in one go.

- `--log-dir DIR` moves the root (runs are then `DIR/<name>/<timestamp>`). `--trace FILE` and `--ledger FILE` set exact paths and skip the per-run folder (a trace alone gets `TRACE.ledger.jsonl` beside it).
- `--no-ledger` records the trace without sealing it. `--no-trace` records nothing (and so no ledger). Combining an opt-out with its own path flag is an error (exit `2`).
- **Payloads stay opt-in**: `--record-payloads` writes `payloads.jsonl` into the run folder, where `import-logs --dir` finds it with no extra flag; `--payloads FILE` sets another path (then pass the same file to `import-logs --payloads`). They cannot be combined. The file is opt-in because the file holds masked tool arguments and outputs and is sensitive. Without it, gates that read payloads, such as ALR10, have nothing to inspect.
- If a *default* location cannot be written, the proxy warns and keeps running without recording. An explicitly given path that cannot be opened is still a configuration error.
- Giving `--trace` and `--ledger` the same files for two proxies at once can break the chain, and verification then reports a false gap. The per-run default folders avoid this.
- Old habit, still valid: `--trace runtime-logs/trace.jsonl --payloads runtime-logs/payloads.jsonl --ledger runtime-logs/trace.ledger.jsonl` writes exactly there, and `import-logs` with no `--dir` reads `./runtime-logs/`.

## Tamper-evident audit ledger (preview)

A trace file is only evidence if nobody can quietly rewrite it. The ledger (on by default, or `--ledger FILE`) seals every trace record into a local hash chain, and `anchor` publishes one short digest where the agent cannot write, so an edit, a deletion or a full rebuild shows up when you verify. Until you anchor it, the verdict is `unanchored`.

```sh
agent-latch-runtime proxy -- <server command>      # prints the run folder, shown as $RUN below

agent-latch-runtime anchor --ledger "$RUN/trace.ledger.jsonl" --to /mnt/audit/anchors.jsonl
agent-latch-runtime verify --ledger "$RUN/trace.ledger.jsonl" \
  --trace "$RUN/trace.jsonl" --anchor /mnt/audit/anchors.jsonl
```

`agent-latch --runtime-result FILE --ledger "$RUN/trace.ledger.jsonl" --anchor /mnt/audit/anchors.jsonl` prints the verdict as the first thing in the report, in bold in a terminal (add `--database FILE [--database-anchor PATH]` for the event store's verdict too; the findings are listed by gate):

```
AUDIT TRAIL TAMPERED — a record was altered; the log cannot be trusted.
  #2: the block's digest does not match its content
```

The verdicts are `intact`, `unanchored`, `tampered`, `deleted`, `rewritten` and `missing`. A failed trail exits `1` even with `--fail-on none`; a missing ledger at a path you gave exits `2`. It is off unless you pass `--ledger`, it never blocks a call, it uses the standard library only, and it makes no network request. `--ledger` requires `--trace`.

Start here: [the audit ledger](ledger.md) (the model and the verdicts), [setup](ledger-setup.md) (ten minutes, including where to put the anchor), [reference](ledger-reference.md) (formats and API) and [operations](ledger-operations.md) (schedule, retention, incidents). The gate is `ALR15`.

## Limits

- It sees only servers whose config entry goes through the proxy. Other servers, the app's built-in tools (for example Claude Code's shell and file edits) and the user's prompts to the model don't pass through it.
- It records traffic and runs the bundled gates: ALR03 on the handshake, ALR04 on tool definitions and ALR10 on tool-call payloads. It reports findings and does not block calls.
- The audit ledger proves a log was not changed after it was recorded. It says nothing about whether what was recorded was safe, and a chain without an anchor cannot catch a full rewrite. See [the audit ledger](ledger.md).
- It sees MCP traffic only, not the agent's requests to its model, so it records what the agent did, not the prompt or reasoning behind it.
- Payload records cover `initialize` (the handshake), `tools/list`, `tools/call` and `prompts/get`. Other MCP messages (`resources/list`, `resources/read`, notifications, sampling) pass through without a record, and `prompts/list` is only in the trace. Tool results keep text content only: image, audio and embedded-resource blocks are left out. A failed `prompts/get` writes no record.
- The payloads file is not rotated and grows with every message (each `tools/call` request repeats the tool's definition). Very large outputs are masked in full before they are cut, which costs CPU on multi-megabyte results.
- Known issues: over HTTP, one tool call can also record an extra `tools/list` entry (FastMCP looks the tool up internally); and `session_id` can change between requests on the same connection (seen over both HTTP and stdio), so don't rely on it to group a session's calls yet.
