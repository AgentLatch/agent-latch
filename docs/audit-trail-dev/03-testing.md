# 03 · Testing

Run everything, run the new tests alone, then try to break the protections on purpose.

## Run it

```sh
python -m pytest -q                              # every test, old and new
python -m pytest tests/test_audit_store.py -v    # the audit-store tests, named
ruff check .
agent-latch scan . --fail-on high --project-ignores --plain
```

CI runs the suite on Python 3.11, 3.12, 3.13 and 3.14. Locally you probably have one; the code uses only
the standard library and `from __future__ import annotations`, so nothing is version-specific. The
runtime job also runs `tests/test_audit_store.py` with FastMCP installed, so test 7 runs there and not
only on your machine.

## Regression: the old behaviour must still hold

The change touches the importer, the CLI, the store, the verifier and the anchor, so check each thing it
could have broken:

| Thing that must not change | Proven by |
|---|---|
| The trace ledger's verdicts, anchors and report | `tests/test_ledger.py` passes **unmodified** (the verdict logic was moved, not changed) |
| The importer, the CSV and JSONL outputs, restart behaviour | `tests/test_runtime_importer.py`. One assertion changed on purpose: the `events` table now has three more columns |
| The proxy, the middleware and the demo | `tests/test_runtime_middleware.py`, `tests/test_runtime.py` |
| An importer given a store that does not seal rows | The flaky and broken stores in `test_runtime_importer.py` |
| An anchor point for a trace ledger | `test_anchor_points_without_the_new_fields_are_unchanged` (same keys, same bytes) |
| Scanner rules, SARIF, GATES.md | `tests/test_scanner.py`, `tests/test_alr04.py` |
| Exit codes `0`/`1`/`2` | The CLI tests, and the table in `ledger-reference.md` |

If an existing test needs changing, stop and ask whether you changed behaviour you did not mean to. The
one expected change is the `events` column list.

## The test plan (`tests/test_audit_store.py`)

| # | Test | Proves |
|---|---|---|
| 1 | `test_1_sealed_import_verifies_intact` | The real pipeline makes a sealed store; verify says `intact`; re-importing adds nothing |
| 2 | `test_2_writer_keeps_the_first_write_and_triggers_stop_sql` | First write stays (shared contract); plain `UPDATE`/`DELETE` abort |
| 3 | `test_3_reader_has_no_way_to_write` | Twelve write statements are refused by the reader; the store still verifies |
| 4 | `test_4_direct_tampering_is_named_and_import_refuses` (edit, delete, swap) | `verify` exits 1; `import-logs` exits 1 and adds nothing |
| 5 | `test_5_*` (drop table, cut rows, forged row, rewritten seals, deleted file) | `deleted`, `deleted`, caught by import, `rewritten`, `deleted` (or exit 2 with no anchor) |
| 6 | `test_6_version_2_database_is_upgraded_and_sealed` | An older database is upgraded, sealed, unchanged, and later edits are caught |
| 7 | `test_7_agent_tool_through_the_proxy_cannot_change_the_store` | An MCP client sends raw write SQL through the proxy; every attempt fails; attempts are in the trace |
| 8 | `test_8_second_os_user_is_denied` | Another OS user is denied read, write, chmod, delete and anchor-append; a control file proves the child can act when allowed |
| 9 | `test_9_*` (four cases) | A crash is recovered; a changed, an extra, or a forged-but-new row is refused and the anchor does not move |
| 10 | `test_10_*` | First anchor for a new store only; a sealed store with no anchor is refused; `anchor` refuses a failing store |
| 11 | `test_11_schema_changes_are_caught` (add column, edit view, drop trigger) | Layout changes are `tampered` though no row changed |
| 12 | `test_12_*` | A database is never read as a ledger; one anchor file per chain |
| — | `test_seal_*`, `test_walk_chain_*`, `test_store_seals_use_their_own_domain_*` | The seal is deterministic, covers every field, and has its own domain |

### What each attacker is allowed to do

Tests model attackers honestly. `_connect_as_attacker` drops the triggers first (the trigger is a speed
bump, not a wall). `_reseal_all` recomputes every seal and `_cover_tracks` puts the triggers back: a
careful attacker. Against that attacker only the anchor (and, for rows past it, the trace) can tell. If
you write a new attack test, decide which attacker it is and say so in a comment.

## Rigour: break it on purpose (mutation checks)

A test that cannot fail proves nothing. After any change to a protection, switch it off and confirm a
test notices. This is the recipe used for this work; run it from the repository root.

```sh
mutate() {  # name file old new
  cp "$2" /tmp/backup.py
  python3 - "$2" "$3" "$4" <<'PY'
import sys; p, o, n = sys.argv[1:4]; s = open(p).read(); assert o in s; open(p, "w").write(s.replace(o, n, 1))
PY
  echo "[$1] -> $(python -m pytest -q -x tests 2>&1 | tail -1)"; cp /tmp/backup.py "$2"
}
mutate "reader allows every statement" src/agent_latch/runtime/sqlite_store.py \
  "return sqlite3.SQLITE_OK if action in _READ_ONLY_ACTIONS else sqlite3.SQLITE_DENY" "return sqlite3.SQLITE_OK"
mutate "importer skips the pre-save check" src/agent_latch/runtime/importer.py \
  "            self._audit_store()" "            pass"
mutate "schema check disabled" src/agent_latch/runtime/ledger/event_seal.py \
  "    actual = source.schema_sha256()" "    return []"
mutate "seal ignores imported_at" src/agent_latch/runtime/ledger/event_seal.py \
  'dumps({"event": event, "imported_at": imported_at})' 'dumps({"event": event})'
mutate "tail rows not compared" src/agent_latch/runtime/importer.py \
  "            if dumps(as_stored(event)) != dumps(stored):" "            if False:"
mutate "publish while ahead" src/agent_latch/runtime/importer.py \
  "not self._dirty or self._tail:" "not self._dirty:"
git diff --stat   # nothing left behind: the source files must be unchanged by the loop
```

Each line must report at least one `failed`. A line that says `passed` is a hole in the tests: this is
how the forged-row-while-new-events-arrive test was found. Test 8 has its own check: delete the
`kwargs.update(user=…)` line in the test (so the child stays root) and it must fail.

## Real-environment checks the tests cannot do

- **Docker Desktop and mounted folders.** CI runs on Linux. Run the container with a named volume, then
  with a mounted host folder, and check `ls -ln` and what a second user can do. Record what you saw.
- **The Docker smoke step.** Run the command in [01-setup.md](01-setup.md#docker) against a built image.
- **Windows.** File modes follow the folder's permissions; test 8 skips there. Say so in a PR.

## Before you open the PR

- [ ] `python -m pytest -q` and `ruff check .` pass; the self-scan exits `0`
- [ ] The mutation loop reports a failure for every protection you touched, and leaves no diff
- [ ] No new dependency; no network call in a test; synthetic fixtures only
- [ ] Docs updated in the same change (`runtime.md`, `ledger*.md`, `docker.md`, `AGENTS.md`)
- [ ] The PR description maps each acceptance criterion to the test that proves it:

| Criterion | Proven by |
|---|---|
| 1. Plan approved before code | The plan document, approved by the reviewer |
| 2. Append-only policy and triggers for the event store | Tests 2, 4, 6, 11; migration 4 |
| 3. The agent execution layer cannot delete, update or drop | Tests 3, 7 (reader refuses every write), test 8 (the OS refuses another user) |
| 4. An automated integration test proves tampering is blocked | `tests/test_audit_store.py` in CI (runtime job and the second-user step) |
