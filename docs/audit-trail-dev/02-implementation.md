# 02 · Implementation map

How the pieces fit, the rules that must stay true, and how to extend them. Read the code beside this:
every section names the file.

## The data flow

```
trace.jsonl + payloads.jsonl
        │  (the importer re-reads these on every start)
        ▼
RuntimeLogImporter ──audit before the first save──► refuse: StoreTampered / StoreRefused (exit 1)
        │ normalize → _unsaved
        ▼
SQLiteEventStore.save()   one BEGIN IMMEDIATE transaction:
        │                  read newest seal → for each event: seal it, INSERT OR IGNORE,
        │                  advance the head only when a row was really inserted
        ▼
events table (+ seal_seq, seal_prev, seal_digest)
        │
        └─► importer publishes the head to the anchor file (≤ every 5 s, and at exit)
```

## The seal (`ledger/event_seal.py`)

```text
event_sha256 = SHA-256( canonical_json({"event": event, "imported_at": imported_at}) )
seal_digest  = SHA-256( b"agentlatch.runtime.store-seal/1\x00" +
                        canonical_json({"prev": …, "seq": …, "event_sha256": …}) )
```

Invariants (a test or a reviewer should be able to point at each):

1. **The event that is sealed is the event that is read back.** `save()` seals
   `row_to_event(event_to_row(event, …))`, never the caller's object, so a JSON round trip cannot make a
   good row look edited. If you change `row_to_event`, you change every stored seal: that needs a new
   seal schema (`…store-seal/2`), not an edit.
2. **`imported_at` is sealed.** Otherwise the import time could be edited unnoticed.
3. **Own domain tag.** A store seal can never be mistaken for a trace-ledger block (`chain.DOMAIN`).
4. **The database never computes a seal.** Nothing here may call a SQL function to hash.
5. **Numbers are given only to rows that are really inserted.** A duplicate key leaves the head
   unchanged (`cursor.rowcount == 1`), or the chain would have a hole.
6. **The writer holds the write lock while it reads the head** (`BEGIN IMMEDIATE`), so a second writer
   waits instead of forking the chain.

`walk_chain` collects problems instead of stopping at the first, and names each kind:
`deleted` (a gap), `reordered` (a repeated or out-of-order number, or a broken `prev`), `edited` (the
recomputed digest differs), `added` (a row with no valid seal).

## The verdict (`ledger/verify.py`)

`status_for(kinds, anchored=…)` is the only place a set of issues becomes a verdict, shared by the trace
ledger and the store:

```
edited | malformed | added  → tampered
deleted                     → deleted        (so deleting a row is not hidden by the trigger you dropped to do it)
reordered | schema          → tampered
rewritten                   → rewritten
no anchor | unanchored      → unanchored
otherwise                   → intact
```

`anchor_point_issues(seq, digest, head_seq=…, digest_at_seq=…)` compares a published point with a chain.
`verify_ledger` and `verify_store` both call it. If you change the order above, the trace ledger's tests
(`tests/test_ledger.py`) must still pass untouched.

## The anchor (`ledger/anchor.py`)

`AnchorPoint` gained three **optional** fields: `source`, `schema_sha256`, `schema_version`. They are
written only when set, so a trace-ledger point is byte-identical to before and an older reader ignores
them. `FileAnchor.publish` refuses a point whose `source` differs from the file's newest point: two
chains number their records separately and cannot share a file. Keep that check; the importer, the
`anchor` command and `verify` all rely on it.

## The store (`sqlite_store.py`)

- **Migration 3** adds the three columns, a unique index on `seal_seq`, and seals every existing row in
  `(run_id, event_order)` order (never rowid, which `VACUUM` can renumber). It runs before the triggers
  exist, because it must `UPDATE`.
- **Migration 4** creates `BEFORE UPDATE` and `BEFORE DELETE` triggers that `RAISE(ABORT)`. They stop
  careless SQL only: whoever can write the file can drop them, and the seal plus the schema check catch
  that. Nothing may rely on them.
- **The schema fingerprint** is a SHA-256 over every row of `sqlite_master` (type, name, table, SQL).
  The *expected* value is computed by running the current `MIGRATIONS` against an in-memory database, so
  adding a migration updates it automatically. Never hard-code it.
- **`SQLiteEventReader`** opens with `mode=ro`, sets `PRAGMA query_only=ON`, and installs an authorizer
  that allows only `SELECT`, `READ`, `FUNCTION` and `RECURSIVE`. `ATTACH`, `PRAGMA`, `DROP`, `ALTER`,
  `DELETE`, `UPDATE`, `INSERT` and `CREATE` are refused. It never migrates; an older file is refused with
  "not sealed yet". It is built with `check_same_thread=False` and a lock, because an MCP server runs a
  sync tool on a worker thread.

### Adding a migration

Append a function to `MIGRATIONS`; never edit a shipped one. If it touches `events`, remember the
triggers: an `UPDATE` or `DELETE` inside a migration after version 4 will abort. Drop and recreate the
trigger inside the same migration, or avoid `UPDATE`. Then update the schema expectations in
`tests/test_audit_store.py` (the column list lives in `test_runtime_importer.py`).

## The importer (`importer.py`)

- `EventWriter` and `EventReader` are the two contracts. `EventStore` is kept as an alias of the writer,
  so existing code and docs keep working.
- **Audit before writing** (`_audit_store`): recompute the chain and the schema, compare with the newest
  anchor point. A store without `sealed_rows` (a minimal writer) is skipped, which is what keeps the
  older importer tests meaning what they meant.
- **A store ahead of its anchor** (a crash between save and publish): the rows past the anchor go into
  `_tail`. Each is compared with the event the logs rebuild (`as_stored`); a difference, or a row with no
  log line, raises `StoreTampered`. Only when `_tail` is empty may the importer publish. That guard is
  tested by `test_9_a_forged_row_is_never_anchored_even_when_new_events_arrive`: remove it and a forged
  row gets anchored.
- **Publishing** is throttled to `ANCHOR_INTERVAL_SECONDS` (5 s) while following, forced when the run
  ends, and attempted once more on Ctrl+C.
- **The first anchor**: an empty store creates it; a sealed store with no anchor is refused
  (`StoreRefused`). `anchor --database` is the deliberate way.

## The commands (`cli.py`)

| Command | Behaviour to keep |
|---|---|
| `import-logs … --database F --anchor A` | `--anchor` needs `--database` (exit 2). `StoreIntegrityError` → exit **1**, anything else as before → 2 |
| `anchor --database F --to A` | Verifies the store (and any earlier point) first and refuses a failing one (exit 1). An anchor file that holds a ledger's points is a configuration error (exit 2), not a store failure |
| `verify --database F [--anchor A]` | Uses the **read-only reader**. A missing file is `deleted` with an anchor point, otherwise exit 2. An unsealed (older) file is exit 2 |
| `verify PATH` on a SQLite file | Refused, exit 2, pointing at `--database` |

Exit codes are a contract with CI: `0` pass, `1` the trail or store cannot be trusted, `2` a usage or
configuration error. Do not change them.

## Adding a new kind of store

1. Implement the writer contract (`open`, `save`, `close`; a key saved again keeps the first write).
2. Keep the three seal values with each row; implement `head()`, `as_stored()`, `sealed_rows()`,
   `schema_sha256()`, `expected_schema_sha256()` and `schema_version()`.
3. Add a test module that calls `assert_store_is_append_only(make_store, tamper)` from
   `tests/store_contract.py`.
4. Select it with a flag on `import-logs`, never by default. A store that sends events off the machine is
   new network behaviour: opt-in, documented, and not a required dependency.

Notes for databases other than SQLite are in [ledger-reference.md](../ledger-reference.md#adding-another-event-store).
