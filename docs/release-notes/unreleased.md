# Unreleased

Changes since v0.5.1. These move into the next release's notes when it is tagged.

## Runtime proxy: trace and ledger are on by default

`agent-latch-runtime proxy` now records a trace and seals it into a tamper-evident ledger without any flags. Behavior change: after upgrading, a proxy started with no `--trace` writes files where it used to write nothing.

- **Where.** Each run gets its own folder, `~/agent-latch/runtime-logs/<server name>/<YYYYMMDD-HHMMSS>/` (UTC), holding `trace.jsonl` and `trace.ledger.jsonl`. The home folder does not depend on where an MCP client starts the proxy, and it is outside any project. A run never reuses a folder, so two proxies never share a hash chain. The proxy prints the folder at startup and on exit.
- **Opt-outs.** `--no-ledger` records the trace unsealed. `--no-trace` records nothing. `--log-dir DIR` moves the root. `--trace FILE` and `--ledger FILE` still set exact paths; a `--trace` alone now also gets `TRACE.ledger.jsonl` beside it. Contradictory flags (`--no-trace` with `--trace` or `--ledger`, `--no-ledger` with `--ledger`) exit `2`.
- **Payloads stay opt-in.** `--record-payloads` (new) writes `payloads.jsonl` into the run folder, so `import-logs --dir` finds it; `--payloads FILE` still sets another path. The file holds masked tool arguments and outputs and is sensitive. Without it, ALR10 has nothing to read.
- **Fails open on defaults only.** If a default location cannot be written, the proxy warns and keeps serving. A path you gave explicitly that cannot be opened still exits `2`.
- **`import-logs --dir` names one run.** Pointing it at a folder of runs (or giving no `--dir` while runs exist in the home folder) lists them and exits `2`; nothing is guessed. With no `--dir` and no runs, it still reads `./runtime-logs/`, where `demo` and older setups write.

- **The proxy imports its run when it stops.** It runs the same one-shot import as `import-logs --once` over its run folder (`events.csv`, `gate-results.csv`, `gate-results.sarif`) and prints the folder, a findings summary, the ledger verdict and the report and anchor commands. It never changes the exit code (a failure prints a warning with the manual command). `--no-import` turns it off; `--quiet` imports silently. `import-logs --once` on a folder with no `trace.jsonl` now exits `2` instead of doing nothing.

Existing commands with explicit `--trace`, `--payloads` and `--ledger` paths keep working unchanged.
