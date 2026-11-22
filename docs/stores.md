# Event store packages (`--store`)

`import-logs --database FILE` keeps the sealed events in a local SQLite file. A **store package** keeps
the same sealed events somewhere else and is chosen with `--store TYPE` instead. Every command that
works with `--database` works the same way with `--store`, running the same code:

| Command | With `--database FILE` | With `--store TYPE` |
|---|---|---|
| Import, seal and anchor | `import-logs --database FILE --anchor PATH` | `import-logs --store TYPE --store-option ... --anchor PATH` |
| Verify | `verify --database FILE --anchor PATH` | `verify --store TYPE --store-option ... --anchor PATH` |
| Publish the head | `anchor --database FILE --to PATH` | `anchor --store TYPE --store-option ... --to PATH` |
| Read-only tool for an agent | `audit-tool --database FILE` | `audit-tool --store TYPE --store-option ...` |
| Report with the verdict banner | `agent-latch --runtime-result CSV --database FILE --database-anchor PATH` | `agent-latch --runtime-result CSV --store TYPE --store-option ... --database-anchor PATH` |
| List what is installed | | `agent-latch-runtime stores` |

`--database` is unchanged, needs no package, and stays the default. A run uses one store: `--database`
and `--store` together exit `2`.

## What stays the same

A store package does not change what AgentLatch checks. With `--store`:

- every event is sealed (`ledger/event_seal.py`) when it is saved, and a key saved again keeps the
  first write;
- before anything is added, `import-logs` checks every seal, the store's layout and every anchor
  point, and refuses a changed store with exit `1`, without repairing or re-sealing it;
- `--anchor` publishes the newest seal while the store grows, and rows left past the anchor by a
  crash are kept only if the trace and payload files rebuild them exactly;
- `verify` prints the same six verdicts with the same exit codes (`0` intact or unanchored, `1`
  tampered, deleted or rewritten, `2` nothing to verify or a setup error);
- a store that cannot be reached is retried while following, and with `--once` a final failed save
  exits `2`, as with `--database`;
- payloads are stored whenever the importer has them, as with `--database`.

The anchor is still a file (`--anchor PATH`), and the trace ledger (`proxy --ledger`) is still a file
beside the trace. A store package keeps only the sealed events.

## Options and secrets

`--store-option KEY=VALUE` (repeatable) passes one setting to the store. Write a secret as
`env:VARNAME`: AgentLatch reads the variable, so the value never appears on the command line or in
output, and anything the store reports is scrubbed of it. An unknown type lists what is installed. A
package that cannot be loaded, a store API it does not support, or an option it refuses exits `2`
before anything is opened. Which options a store takes is documented by its package.

## Connectors that ask for seals

A connector can set `wants_seals = True`. With a sealed store (`--database` or `--store`), it then
receives each event once the store has saved it, with one extra field:

```json
"seal": {"seq": 12, "prev": "<digest of seal 11>", "digest": "<digest of seal 12>"}
```

`seal` is `null` if the store could not return it. Without a store, such a connector receives events
as soon as they are read, without the field. Every other connector is unchanged. This is an additional
optional field, so `CONNECTOR_API` stays `1` (see [connectors.md](connectors.md)).

## Writing a store package

A package registers a factory in the entry point group `agent_latch.stores`:

```toml
[project.entry-points."agent_latch.stores"]
mystore = "my_package:create"
```

```python
def create(options: Mapping[str, str], context: StoreContext) -> StoreBackend: ...
```

The factory validates its options and does no input or output; it raises `StoreConfigError` for a
setting that can never work. The backend it returns has:

| Member | What it is |
|---|---|
| `store_api` | `1` (`runtime/stores.py`, `STORE_API`) |
| `name` | a short display name without secrets or `/`; used in messages and anchor points |
| `writer()` | the sealed writer, for `import-logs` only |
| `reader()` | a view that cannot change the store, for `verify`, `anchor`, `audit-tool` and the report |

The **writer** implements `EventWriter` (`runtime/importer.py`: `path`, `open`, `save`, `close`) and
`event_seal.SealedSource` (`sealed_rows`, `schema_sha256`, `expected_schema_sha256`,
`schema_version`), plus `head`, `as_stored`, `seals_after`, `seal_digest_at` and, for connectors that
ask, `seals_for`. Optionally `stored_version()` reads the schema version without changing anything, so
a lowered version is reported as tampering, and `name` names its anchor points when `path` is `None`.
Define these on the class: the importer checks the class, not `__getattr__`. `save` seals each row with
`next_seal` inside the same transaction as the insert, and raises `OSError` when the batch was not
stored. `open` raises `ValueError` for a store that can never be used (exit `2`).

The **reader** has the same read methods and no way to write. Optionally `exists()` says, before
`open`, whether there is a store at all (so a removed store with an anchor is `deleted`, not a setup
error); `query(sql)` gives `audit-tool` its `query_audit_log` tool; `recent_events(limit)` answers
`recent_events` (otherwise it is built from `sealed_rows`).

`tests/store_contract.py` (`assert_store_is_append_only`) proves the writer keeps first writes and that
edits, deletions and swaps are named. The rules for a store that is not SQLite are in
[ledger-reference.md](ledger-reference.md#adding-another-event-store).

## What it does not change

- The seal still has no key: the anchor, kept out of the agent's reach, is what proves a rebuilt store.
- Keeping the agent away from the store (another container, another account, no credentials) is
  still what prevents a change; the seals only detect one. See [docker.md](docker.md).
