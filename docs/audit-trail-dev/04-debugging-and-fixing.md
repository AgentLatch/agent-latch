# 04 · Debugging and fixing

First decide which of two situations you are in. They need opposite reactions.

- **A developer problem**: a test fails, or a command misbehaves while you build. Debug it; fix the code.
- **An operator problem**: a real store was refused, or `verify` says `tampered`, `deleted` or
  `rewritten`. **Do not fix the file.** Freeze it, record it, classify it. The runbook is
  [ledger-operations.md](../ledger-operations.md#when-import-logs-refuses-the-event-store).

## Look inside a store (read-only)

Always use the reader, so looking can never change anything.

```sh
python -I - runtime.db <<'EOF2'
import sys
from agent_latch.runtime.sqlite_store import SQLiteEventReader
r = SQLiteEventReader(sys.argv[1]); r.open()
print("schema version", r.schema_version(), "head", r.head())
print("schema ok:", r.schema_sha256() == r.expected_schema_sha256())
for row in r.query("SELECT seal_seq, run_id, event_order, name, substr(seal_digest,1,12) AS seal FROM events ORDER BY seal_seq LIMIT 20"):
    print(row)
print(r.query("SELECT type, name FROM sqlite_master"))          # tables, view, triggers, indexes
r.close()
EOF2
agent-latch-runtime verify --database runtime.db --anchor store-anchors.jsonl
tail -n 3 store-anchors.jsonl                                    # the newest anchor points
```

`verify` prints up to five problems. To see all of them from Python, call
`verify_store(reader, name="x")` and print `result.issues`.

## Symptom → cause → fix

| You see | Most likely cause | Fix |
|---|---|---|
| `SQLite objects created in a thread can only be used in that same thread` from a tool | A reader opened on one thread and used on another (FastMCP runs sync tools on a worker thread) | Already handled: the reader uses `check_same_thread=False` and a lock. If you built your own connection, do the same |
| A migration test fails with `events are append-only` | A migration after version 4 runs `UPDATE` or `DELETE` on `events` | Drop and recreate the trigger inside that migration, or avoid the statement |
| `test_migrations_create_and_keep_the_schema` fails on the column list | You added a column | Update the expected list in `test_runtime_importer.py`, and add a migration; never edit migration 1 |
| `verify` says `tampered` / "table layout … differ" on a store nobody touched | `MIGRATIONS` changed but the file is at the old version, or a manual migration was run | `verify` reads the file with the current expectation; open it once with `import-logs --database` to upgrade, or restore |
| `verify` says `tampered` right after you changed `row_to_event` or `event_to_row` | The sealed event is no longer what is read back | You changed what every seal covers. Revert, or introduce `…store-seal/2` with a migration that reseals under an explicit, documented rule |
| `import-logs` exits 1 "no matching trace record" after you rotated or moved the trace | Rows past the anchor can no longer be rebuilt from the logs | Restore the trace and payload files the rows came from. If they are truly gone, this is correct: keep the store as evidence and start a new store and anchor |
| `import-logs` exits 1 "anchor … missing or empty" on a store you just upgraded | An older store sealed on upgrade has no anchor yet | Run `anchor --database FILE --to PATH` once, deliberately |
| `anchor --database` exits 2 "holds points for another source" | The anchor file belongs to a trace ledger | Use a separate anchor file per ledger and per store |
| `verify` exits 2 "not sealed yet" | The file is an older database and the reader never upgrades | Run `import-logs --database FILE` once (back it up first: the upgrade is one way) |
| `verify` exits 2 "newer than this AgentLatch supports" | The file was written by a newer AgentLatch | Upgrade AgentLatch. Do not point an old version at a new store |
| A test passes but a mutation does not fail it | A hole in the test | Add a test that fails on the mutation (see [03](03-testing.md#rigour-break-it-on-purpose-mutation-checks)) |
| `test_8_second_os_user_is_denied` skips locally | You are not root and `AGENTLATCH_SECOND_USER` is unset | Set it ([01](01-setup.md#the-second-user-test-test-8)); CI sets `AGENTLATCH_REQUIRE_SECOND_USER` so a skip there is a failure |
| Test 8 fails with `allowed` for `read_store` | The store folder or the file is more open than `0755`/`0600`, or the child runs as the same user | Check `stat`; the test asserts the modes. Check which user the child really runs as |
| Test 8 fails on `control_write` | The child could not act at all (cannot execute Python, cannot enter the folder) | The test is vacuous if the child cannot even write the world-writable control file; fix the interpreter path or folder mode |
| `ruff` fails on import order after an edit | New imports | `ruff check --fix .` |

## Common pitfalls (each one has bitten this design)

- **`INSERT OR IGNORE` ignores every uniqueness conflict**, including the unique index on `seal_seq`. A
  row silently dropped for that reason has `rowcount == 0`, so the head does not advance and the next
  `verify` still sees a consistent chain. Never replace the `rowcount` check with `total_changes`.
- **A trigger is not protection.** If a test only passes because a trigger blocked the attacker, the test
  is testing the wrong thing. Attack tests drop the triggers first.
- **A "careful attacker" restores the layout.** Drop the triggers, edit rows, reseal, recreate the
  triggers. Only the anchor, and the trace for rows past it, can tell. Test against that attacker too.
- **Do not publish while rows past the anchor are unverified.** `_publish` returns early while `_tail` is
  non-empty. Removing that lets a forged row be anchored.
- **Ordering rows by rowid is wrong.** Always `(run_id, event_order)` for sealing older rows and
  `seal_seq` afterwards.
- **A shared anchor file is a bug**, not a convenience. The two chains number records separately.
- **The seal has no key.** Anyone with the code can compute a valid seal. That is why an anchor outside
  the agent's reach matters. An optional HMAC is a possible follow-up, not a fix to slip into this change.

## Docker Desktop and mounted folders

Whether a mounted host folder shows up as owned by the Mac user (and so is writable by an agent running
as that user) is **not proven by any test here**; CI runs on Linux. Check by hand:

```sh
docker run --rm -v agentlatch-data:/data ghcr.io/agentlatch/agent-latch-runtime:<version> demo      # named volume
docker run --rm --entrypoint ls -v "$PWD/store:/data" ghcr.io/agentlatch/agent-latch-runtime:<version> -ln /data
ls -ln store
```

If the host folder is owned by you and writable by you, an agent running as you can change it: use a
named volume, or put the store on a machine the agent cannot log in to.

## When you must change the design

Stop and check these before you merge. Each is a promise to operators.

- A seal input changed: every existing store would fail verification. It needs a new schema string and a
  migration, and the release notes must say so.
- The upgrade is one way: version 3 and 4 databases are refused by older AgentLatch. Release notes say so.
- An exit code changed: CI and the GitHub Action depend on `0`, `1`, `2`.
- A new place the agent could write: the plan's "honest boundary" must still be true. Nothing in the
  database stops an agent that holds the file, and the docs must not claim it does.
- Version bump: both `pyproject.toml` and `src/agent_latch/__init__.py`, release notes in
  `docs/release-notes/`, version references in `README.md`, `docs/ci.md`, `llms.txt`. If dependencies
  change, run `scripts/update-docker-locks.sh`. This work changes none and does not bump the version;
  releasing is a separate step for whoever cuts the release.
