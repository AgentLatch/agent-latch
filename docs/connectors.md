# Log connectors: design (draft)

> **Status: draft for review.** This document proposes how AgentLatch sends runtime events to
> other destinations. Nothing here is implemented yet except what is marked **today**. The
> existing SQLite store and the `--database` flag stay exactly as they are (see
> [Keeping today's behavior untouched](#7-keeping-todays-behavior-untouched)).

## 1. Background: what exists today

The runtime proxy writes `trace.jsonl` (and, with `--payloads`, `payloads.jsonl`).
`agent-latch-runtime import-logs` reads those files, joins each trace record with its payload
record (`MCPEventNormalizer`), and writes one **normalized event** to several outputs:
`events.csv`, `normalized.jsonl`, the gate results, and, with `--database FILE`, a local SQLite
file.

The importer talks to the database only through one contract, `EventStore`, in
`src/agent_latch/runtime/importer.py`:

```python
class EventStore(Protocol):
    path: Path | None
    def open(self) -> None: ...
    def save(self, events: list[dict[str, Any]], /) -> int: ...   # returns new events; OSError on failure
    def close(self) -> None: ...
```

How it behaves **today**:

- `open()` runs before any other output is opened. If it fails, `import-logs` exits `2`.
- After each pass over the log files, every new event is copied into a waiting list and handed
  to `save()` as one batch, which is one SQLite transaction.
- If `save()` raises `OSError` while following, the batch stays in the waiting list. The importer
  warns once and retries on the next pass. When the save succeeds again, it says
  "database reachable again".
- With `--once`, a final failed save raises and the command exits `2`.
- A restart is safe because rows are keyed by `(run_id, order)` and inserted with
  `INSERT OR IGNORE`.

This document extends that model to other destinations without changing it.

## 2. Three kinds of connector

A **connector** is any destination for normalized events that is not one of the built-in files.
There are three kinds. They share one lifecycle but promise different things.

| | **Store** | **Exporter** | **Archive** |
|---|---|---|---|
| Plain meaning | A database you query later | Forwards events to another live system | Long-term, write-once copy |
| Examples | SQLite (today), PostgreSQL, DuckDB | OpenTelemetry, Splunk HEC, a webhook | Folder of `.jsonl.gz` files, S3 bucket |
| Keeps the data? | Yes, and can read it back | No, the other system keeps it | Yes, but it is not meant for queries |
| Duplicate handling | **Must** ignore an event it already has (`run_id`, `order`) | Sends `batch_id` and event keys so the receiver can drop duplicates | Same batch, same object name, so a retry overwrites identical bytes |
| Typical failure | Database locked or unreachable | Network down, rate limited | Disk full, bucket permission |
| Gets payloads by default? | Yes, if it is local | **No**, unless the operator opts in | **No**, unless the operator opts in |
| Network use | Only if it is a remote database | Always | Only if it is remote |

Rules of thumb:

- If the operator will run queries against it, it is a **store**.
- If something else receives the data and AgentLatch forgets it, it is an **exporter**.
- If its purpose is retention or audit and it is written once, it is an **archive**.

An archive is **not** the tamper-evident ledger (`ALR15`). The ledger proves the trace was not
edited. An archive only keeps a copy. An archive can also store the ledger file, but it never
replaces verification.

## 3. The contract in code

A new module, `src/agent_latch/runtime/connectors.py`, holds the contract. It uses the standard
library only and imports no connector package.

```python
CONNECTOR_API = 1                       # contract version; see section 6
ENTRY_POINT_GROUP = "agent_latch.connectors"
BATCH_SCHEMA = "agentlatch.runtime.batch/1"
EVENT_SCHEMA = "agentlatch.runtime.event/1"

ConnectorKind = Literal["store", "exporter", "archive"]


@dataclass(frozen=True)
class ConnectorContext:
    """What AgentLatch tells a connector when it is created."""
    name: str                 # the name the operator chose, e.g. "pg" or "otel"
    log_dir: Path             # runtime-logs/ folder, for any local state the connector needs
    agentlatch_version: str
    connector_api: int        # CONNECTOR_API of the running core


class Connector(Protocol):
    kind: ConnectorKind
    connector_api: int                   # the contract version this connector was written for
    path: Path | None                    # local file it writes, or None (used for the
                                         # "all outputs are different files" check)
    accepts_payloads: bool               # whether it was configured to receive payloads

    def open(self) -> None: ...
    def write(self, batch: EventBatch, /) -> int: ...   # number of events accepted
    def close(self) -> None: ...


# A connector package exposes one factory per connector through an entry point.
ConnectorFactory = Callable[[Mapping[str, str], ConnectorContext], Connector]
```

The existing `EventStore` is unchanged and remains the store contract the importer already uses.
A small adapter, `StoreConnector(store: EventStore)`, lets a store take part in the new loop
without any change to the store:

```python
class StoreConnector:
    kind = "store"
    connector_api = CONNECTOR_API
    accepts_payloads = True
    def __init__(self, store: EventStore) -> None: self.store = store; self.path = store.path
    def open(self) -> None: self.store.open()
    def write(self, batch: EventBatch) -> int: return self.store.save(list(batch.events))
    def close(self) -> None: self.store.close()
```

The adapter exists so that new store packages can be written against `EventStore`. The
`--database` path itself does **not** go through the adapter (see section 7).

## 4. Lifecycle

Every connector goes through the same six steps. The importer drives them, and the connector
never starts work by itself.

```
 discover ──▶ create ──▶ open ──▶ write, write, write … ──▶ close
 (entry       (factory     (once,      (once per importer        (always, also
  point)       + config)    before      pass, in order)           after errors)
                            other files)
```

1. **Discover.** The importer lists the entry points in the group `agent_latch.connectors`
   without importing them. It loads **only** the connectors the operator named with
   `--connector`. Installing a connector package does nothing by itself. Nothing is sent
   anywhere unless the operator asks for it on the command line.
2. **Create.** The importer calls `factory(options, context)`. The factory validates its options
   and returns a connector. **No I/O is allowed here.** Invalid options raise
   `ConnectorConfigError`, and the command exits `2` before any file is opened. The importer
   then checks `connector.connector_api` against what it supports (section 6).
3. **Open.** `open()` runs once, after the `--database` store is opened and before
   `events.csv` and the other files. This keeps today's rule that a bad destination leaves no
   other file open.
   - `ConnectorConfigError` (for example wrong credentials, or a missing table it may not create)
     makes the command exit `2`.
   - `ConnectorUnavailable` (for example the server is not up yet) does not stop the importer.
     The connector stays "not open" and the importer retries `open()` on the backoff schedule in
     section 5.
4. **Write.** After each pass over the log files, the importer builds the new events into one or
   more batches (section 4.1). It calls `write(batch)` on each connector in the order given on
   the command line. Connectors are independent: each has its own queue of waiting batches, so a
   slow or broken one never holds back another, the CSVs, the gates, or the proxy.
   `write` must either accept the whole batch or raise. It must not accept half of a batch.
5. **Flush.** Connectors that buffer internally (for example an exporter sending in the
   background) must deliver everything they have accepted before `close()` returns.
6. **Close.** `close()` is called exactly once in the importer's `finally` block, even after
   errors and on Ctrl+C. An exception from `close()` is logged as a warning and never hides the
   original error.

Threading: the importer calls a connector from one thread only, so connectors need no locks.
Each call must finish within the connector's own `timeout` option (default 10 seconds). The
importer does not wrap calls in threads, so a connector that ignores its timeout would stall
only the importer process, never the MCP traffic. Our own `ALR08-S01` rule exists for exactly
this, and connector code must pass the self-scan.

### 4.1 Event batch format

```python
@dataclass(frozen=True)
class EventBatch:
    schema: str               # "agentlatch.runtime.batch/1"
    event_schema: str         # "agentlatch.runtime.event/1"
    batch_id: str             # f"{run_id}:{first_order}-{last_order}", stable across retries
    run_id: str
    created_at: str           # UTC, ISO 8601 with milliseconds and "Z"
    events: tuple[dict[str, Any], ...]   # deep copies, sorted by "order"
```

Rules:

- **One run per batch.** A batch never mixes `run_id`s.
- **Size.** At most `max_batch_events` events (default 500, configurable per connector). A larger
  pass is split into several batches.
- **Frozen once tried.** After a batch is handed to `write()`, it is never changed. A retry sends
  the identical batch with the same `batch_id`, and new events go into the next batch. This lets
  exporters and archives deduplicate by `batch_id`. (The `--database` store keeps its current
  merge-and-retry behavior, which is safe because SQLite ignores duplicate keys.)
- **Each event** is the normalized event that every gate and `normalized.jsonl` already see:

  | Field | Type | Notes |
  |---|---|---|
  | `run_id` | str | Hash of the first trace line. Same for the whole run. |
  | `order` | int | Trace line number. `(run_id, order)` is the event's unique key. |
  | `timestamp` | str \| null | From the trace record |
  | `session_id`, `request_id`, `server`, `method`, `stage` | str | |
  | `client_id` | str \| null | From the payload record, if any |
  | `name` | str \| null | Tool or prompt name |
  | `trace` | `{path, line}` | Where the record came from |
  | `payloads` | `{path, line}` \| null | |
  | `metadata` | object | Hashes, sizes, excerpt, duration, error flags |
  | `payload` | object \| null | Full masked payload (only with `--payloads`) |

- **Payloads are removed unless allowed.** If `connector.accepts_payloads` is false, the importer
  sets `payload` to `null` in that connector's copy before `write`. Exporters and archives default
  to `false`. The operator turns it on per connector with `--connector-option NAME.payloads=true`.
  Payloads are masked, but they still hold tool arguments and outputs, so sending them off the
  machine must be a deliberate choice.
- **Additive changes only** within `/1`. New optional fields may appear, and connectors must
  ignore fields they do not know. Removing or renaming a field means `/2` and a new
  `CONNECTOR_API` (section 6).

## 5. Error behavior

Connectors raise one of three exceptions, defined in `connectors.py`:

| Exception | Meaning | What the importer does |
|---|---|---|
| `ConnectorConfigError(ValueError)` | Can never work as configured | At create or open: exit `2` with the message. During `write`: treated as a bug (last row). |
| `ConnectorUnavailable(OSError)` | Temporary: network, lock, rate limit, disk full | Keeps the batch, warns **once**, retries with backoff. Logs "reachable again" when it recovers. Same idea as today's SQLite retry. |
| `ConnectorRejected(Exception)` | The destination refused **this** batch for good (for example HTTP 400) | Does not retry. Writes the batch to `runtime-logs/<name>.rejected.jsonl` (mode `0600`), warns, and moves on. |
| Any other exception | A bug in the connector | Warns with the exception type only, **disables that connector** for the rest of the run, keeps every other output going. |

`ConnectorUnavailable` subclasses `OSError` on purpose, so the existing store contract ("raise
`OSError` when the batch was not stored") is already a special case of it.

**Backoff.** Retries wait 1 s, then 2, 4, 8 … up to 60 s between attempts, per connector. They
never block the importer's normal pass, which keeps running every 0.1 s for the other outputs.

**Bounded memory.** Each connector holds at most `max_pending_batches` waiting batches (default
100). When that is full, the **oldest** batch is dropped. The connector warns with a running
count, and the final summary line reports it. Nothing is lost for good: every event can be
rebuilt from the trace files, and all three kinds deduplicate. So the fix is to run
`import-logs --once --connector NAME` again once the destination is back.

**Never in the request path.** No connector error can reach the proxy. The importer is a separate
process that only reads log files (see `docs/runtime.md`).

**Messages.** Warnings name the connector and the exception type and message. They never print
option values, payloads or event contents. Connector authors must not put secrets in exception
messages.

**Exit codes for `import-logs`** (unchanged values: `0` and `2`):

- `2`: a config error at create or open, or an unknown connector name or API version.
- With `--once`, also `2` when any connector still has undelivered batches at the end, or
  rejected or dropped any. This matches today, where a final failed database save exits `2`.
- Follow mode ends on Ctrl+C with `0`, as today, after a final summary that lists undelivered,
  rejected and dropped counts per connector.

## 6. Registration, configuration and versioning

### 6.1 How a package registers

A connector package declares an entry point in its own `pyproject.toml`:

```toml
[project.entry-points."agent_latch.connectors"]
postgres = "agentlatch_connector_postgres:create"
```

`create` is the `ConnectorFactory`. The entry point name (`postgres`) is the **type** the
operator selects. Two installed packages may not register the same type, and the importer exits
`2` if they do rather than picking one. `agent-latch-runtime connectors` lists the installed
types with their package version and `CONNECTOR_API`, without loading them.

### 6.2 How configuration reaches a connector

Configuration comes from the operator's command line or the operator's own file. It never comes
from the scanned project or the MCP traffic.

```bash
agent-latch-runtime import-logs \
  --connector pg=postgres \
  --connector-option pg.dsn=env:AGENTLATCH_PG_DSN \
  --connector-option pg.table=agent_events
```

- `--connector [NAME=]TYPE` (repeatable). `NAME` defaults to `TYPE`. It allows two instances of
  one type (for example two webhooks).
- `--connector-option NAME.KEY=VALUE` (repeatable). Every value is a string, and the factory
  parses and validates it.
- `--connector-config FILE` reads the same settings from a TOML file (stdlib `tomllib`):

  ```toml
  [connectors.pg]
  type = "postgres"
  dsn = "env:AGENTLATCH_PG_DSN"
  table = "agent_events"
  ```

  Command-line options override file values.
- **Secrets.** A value written as `env:VARNAME` is read from the environment by the core before
  it reaches the factory. Command-line flags are visible in process lists, so connector docs must
  show secrets only as `env:` references. The core never logs option values. `connectors` and
  error messages show `KEY=***` for every option.
- **Options every connector gets** (handled by the core, not the connector): `payloads`
  (default `false` for exporters and archives), `max_batch_events`, `max_pending_batches`,
  `timeout`.

### 6.3 Where connector code lives

Connectors are **separate packages kept in this repository**, in one top-level folder:

```
connectors/
  README.md                         # list of connectors, how to add one
  _template/                        # copy this to start a new connector
  jsonl-archive/                    # first reference connector: stdlib only, local files
    pyproject.toml                  # name = "agentlatch-connector-jsonl-archive"
    README.md
    CHANGELOG.md
    src/agentlatch_connector_jsonl_archive/__init__.py
    tests/
  postgres/                         # later
  otel/                             # later
```

Why one folder rather than separate repositories or the main package:

- **Separate.** Each has its own `pyproject.toml`, dependencies, tests and PyPI package. The core
  package (`agentlatch-security`) never includes them, so vendor clients (`psycopg`, `boto3`,
  OpenTelemetry SDK) never become core dependencies. `connectors/` is outside `src/`, so the core
  wheel and the Docker build context (an allow-list) do not pick it up.
- **One folder.** A change to the contract and the fixes to every connector land in one pull
  request, and CI tests every connector against the core in the same commit. Separate repositories
  would let them drift apart silently.
- CI adds one job per connector folder: install the core from the checkout, install the
  connector, run its tests and `ruff`, and run the self-scan on it. Tests make no network calls.
  Remote connectors use fakes.

### 6.4 Versioning

Three version numbers, each with one job:

| What | Example | Changes when |
|---|---|---|
| **Core version** | `agentlatch-security 0.6.0` | As today. |
| **Contract version** `CONNECTOR_API` | `1` | Only on a **breaking** change to `Connector`, `EventBatch` or the event schema. Adding an optional field or method does **not** change it. |
| **Connector version** (SemVer, per package) | `agentlatch-connector-postgres 1.2.0` | Independently, whenever that connector changes. |

Rules:

- Each connector sets `connector_api = 1` and depends on the first core release that ships that
  contract: `dependencies = ["agentlatch-security>=0.6"]`.
- The core supports the current `CONNECTOR_API` and the one before it. For a connector outside
  that range, `import-logs` exits `2` and says which side to upgrade.
- A connector's **major** version goes up when it moves to a new `CONNECTOR_API` or changes the
  meaning of an existing option.
- Release tags are `connector-<type>-vX.Y.Z` (for example `connector-postgres-v1.2.0`), so they
  never collide with core tags (`vX.Y.Z`). A separate workflow, `publish-connectors.yml`,
  publishes the matching folder with Trusted Publishing and checks that the tag matches that
  folder's `pyproject.toml`. The existing `publish.yml` stays core-only.
- Naming: PyPI `agentlatch-connector-<type>`, import `agentlatch_connector_<type>`, entry point
  `<type>`.

## 7. Keeping today's behavior untouched

These stay byte-for-byte or behavior-for-behavior the same, and the implementation PR adds tests
that prove it:

- `src/agent_latch/runtime/sqlite_store.py` is not edited. Its schema version and migrations do
  not change.
- `EventStore` keeps its name, methods and meaning. `RuntimeLogImporter(store=...)` keeps
  working, and existing callers need no change.
- `--database FILE` keeps its flag, help text, startup message, retry-and-warn behavior and exit
  codes. It is **not** rewritten as `--connector sqlite`. Connectors are an additional,
  separate list (`RuntimeLogImporter(..., connectors=[...])`), run after the store in each pass.
- A run with no `--connector` makes no new imports, loads no entry points, and writes no new
  files. Its output is identical to today's.
- `import agent_latch.runtime` still imports no optional dependency. `connectors.py` is standard
  library only.
- No new core runtime dependency.
- Every existing test passes unchanged.

## 8. What this is not

- Not real-time blocking. Connectors observe, like the gates. They never approve or refuse
  traffic.
- Not a replacement for the ledger (`ALR15`). Sending events to a store or archive does not prove
  they were not edited.
- Gate results and ledger files are out of scope for `CONNECTOR_API = 1`. They can be added later
  as optional batch types without breaking version 1.

## 9. Proposed rollout

1. Merge this document (this PR).
2. Add `runtime/connectors.py`, the importer's `connectors=` list, the CLI flags and the
   `connectors` listing, plus tests with an in-memory fake connector for every error path.
3. Add `connectors/_template` and `connectors/jsonl-archive`, the first real connector. It is
   local and stdlib-only, so it proves the contract with no network behavior.
4. Add network connectors (PostgreSQL, OpenTelemetry), each documented as opt-in network
   behavior.

## 10. Open questions for review

1. Is a default of 100 pending batches per connector right? That is up to 50,000 events in
   memory.
2. Should `--once` exit `1` rather than `2` when a connector fails? This draft keeps `2` to match
   the current database behavior.
3. Should a later contract version carry gate results (findings) to exporters, so a dashboard sees
   alerts and not only raw events?
