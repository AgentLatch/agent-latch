# Sealed audit store: developer guide

Everything a developer needs to build on, test, debug and fix the immutable audit trail for the
runtime event store (`import-logs --database`). For what the feature is and how an operator uses it,
read [ledger.md](../ledger.md#the-event-store-gets-the-same-protection) and
[ledger-setup.md](../ledger-setup.md#also-protect-the-event-store---database). This folder is for the
person changing the code.

| Guide | Read it when |
|---|---|
| [01-setup.md](01-setup.md) | You are starting: environment, branch, baseline, the second-user test |
| [02-implementation.md](02-implementation.md) | You are changing the code: what lives where, the invariants, how to extend it |
| [03-testing.md](03-testing.md) | You are proving a change: the test plan, mutation checks, regression, CI |
| [04-debugging-and-fixing.md](04-debugging-and-fixing.md) | Something fails: symptom to cause to fix, and what never to do |
| [05-claude-desktop-test.md](05-claude-desktop-test.md) | You want to see an agent try to delete its traces, with Claude Desktop as the agent, on your Mac's Python |
| [attack_tool.py](attack_tool.py) | You want the tool's refusals proven without relying on a model's willingness: sends 17 write statements over a real MCP session |
| [06-docker-test.md](06-docker-test.md) | The same test the way it should be deployed: the store and anchor in Docker volumes, the agent holding only a read-only tool. Start here |

## The change in one paragraph

Every row of the SQLite event store is sealed when it is saved: a SHA-256 over the event and its
import time, chained to the row before it, computed in Python and not by the database. The newest seal
is published to an anchor file outside the agent's reach. `verify --database` recomputes every seal and
the table layout and reports the six ALR15 verdicts; `import-logs` runs the same check before it adds
anything and refuses (exit `1`) a store that fails it. The reader that tools hold opens the file
read-only and refuses every statement but a read. Keeping the store in another OS user or container is
what actually stops a change; the seals detect one.

## Where the code is

| What | Where |
|---|---|
| The seal, the chain walk, the schema check, `verify_store` | `src/agent_latch/runtime/ledger/event_seal.py` |
| Shared verdict (`status_for`) and anchor comparison | `src/agent_latch/runtime/ledger/verify.py` |
| Optional anchor fields (`source`, `schema_sha256`, `schema_version`), one-chain-per-file rule | `src/agent_latch/runtime/ledger/anchor.py` |
| Migrations 3 (seal) and 4 (triggers), `SQLiteEventStore`, `SQLiteEventReader` | `src/agent_latch/runtime/sqlite_store.py` |
| `EventWriter` / `EventReader`, the pre-save check, crash recovery, publishing | `src/agent_latch/runtime/importer.py` |
| `import-logs --anchor`, `anchor --database`, `verify --database`, `audit-tool` | `src/agent_latch/runtime/cli.py` |
| One read-only look at a store (`check_store`), the `ALR15-R02` finding | `src/agent_latch/runtime/store_check.py` |
| The store verdict and `ALR15-R02` in `agent-latch --runtime-result` (by gate, SARIF) | `src/agent_latch/runtime/results.py` |
| The read-only MCP tool an agent gets (`audit-tool`) | `src/agent_latch/runtime/audit_tool.py` |
| Tests | `tests/test_audit_store.py`, `tests/store_contract.py`, `tests/runtime_fixtures/audit_reader_server.py` |
| CI | `.github/workflows/tests.yml` (second-user step, runtime job), `.github/workflows/images.yml` (sealed-store smoke) |

## Rules this work follows (from AGENTS.md)

- No new dependency: the standard library only.
- No network, no telemetry. Tests use synthetic fixtures.
- Never edit a shipped migration; append one.
- No secret values in evidence, messages or reports.
- Docs change in the same change as behaviour.
- Never commit to `main`; work on a feature branch and open a PR.
