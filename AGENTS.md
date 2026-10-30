# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Project overview

**AgentLatch** is a local-first, static security scanner for AI-agent projects. It checks:

- Python agent source code (AST-based rules, tool/approval analysis, prompts written in code, and a small intra-file taint analysis),
- prompts in any YAML file (for example CrewAI `config/agents.yaml`) and prompt template files (`.prompt`, `.prompty`, `.j2`, `.jinja`, `.jinja2`, and `.md`/`.txt` under a `prompts/` folder),
- optionally, agent manifests (`agent-manifest.yaml`) declaring tools, permissions, auth, and prompts, plus the prompt files they reference,
- optionally, pinned Python dependencies via `pip-audit` (`--dependencies`).

It reports findings as a terminal table / plain text, JSON, or SARIF, and runs as a CLI, a pre-commit hook, or a composite GitHub Action. Findings map to the OWASP Top 10 for Agentic Applications (informational only).

Status: **early proof of concept (v0.4.0)**. Never overstate coverage. A clean scan is not a security guarantee, and docs and messages must say so.

## Design principle: the scanned project is untrusted

AgentLatch is often run on agents someone else wrote, so nothing inside the scanned project may weaken the scan.

- **A manifest is optional and self-declared.** Every rule except `MAN*` must work from source and prompt files alone. Manifest findings are added to source findings (`findings.dedupe` merges overlaps) and must never suppress, downgrade, or skip a source check. Example: a manifest that says `requires_approval: true` does not silence `AG004` on the matching code.
- **In-project suppressions are off by default.** `.agent-latch-ignore`, `[tool.agent-latch] exclude`, and inline `# agent-latch: ignore` comments are written by the project author, so they apply only with `--project-ignores` (Action input `project-ignores`, an interactive prompt that defaults to No). The operator's `--exclude` and an explicit `--ignore-file` always apply. Any new suppression source that lives in the scanned project must be gated by `--project-ignores`.
- **Scan everything by default.** The walker visits every folder and checks every text file for secrets. It skips only `.git`, real installed environments (`rules.is_installed_environment`: `pyvenv.cfg`, `.tox` environments, `node_modules` with a package-manager marker), symlinks, binary files, and files over 1 MB. Never skip a folder by name alone, because a project could then hide code in a folder called `venv`.
- New rules should prefer evidence from code (what a tool actually calls) over declarations (what a manifest or docstring claims).

## Primary scope: OWASP Top 10 for Agentic Applications 2026

**The current focus is building security checks for the OWASP Top 10 for Agentic Applications 2026 only.** The reference document is `OWASP-Top-10-for-Agentic-Applications-2026-12.6-1.pdf` in the repository root.

- Every new rule must map to at least one ASI category below. Defer general Python/web security checks that don't map to one, and don't treat them as priorities.
- The shared category list is `ASI_CATEGORIES` in `src/agent_latch/owasp.py`. It is the single source of IDs and names, taken from the PDF's table of contents. Rules emit only IDs in `Finding.owasp`, and reports look up names from `owasp.py`. Never hard-code category names anywhere else in code.
- When you add a rule, also add its categories to `RULE_CATEGORIES` in `owasp.py`. A test checks every `Finding(...)` against that table and fails on any unknown ID.
- Every report (terminal, text, JSON `owasp_agentic`, SARIF `owaspAgenticCoverage`) shows an ASI01–ASI10 summary. Categories without rules appear as `no checks yet`, so they are never mistaken for clean results.
- Prefer filling uncovered categories (ASI06, ASI07, ASI10, then deepening ASI08 and ASI09) over adding more rules to categories that are already covered.
- The mapping is informational. Never claim OWASP compliance, certification, or endorsement.
- The PDF is an OWASP publication. Don't copy large passages into code or docs. Paraphrase it and link to https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/.

| ID | Category | Gates | Current rules |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | `ALR01`, `ALR04`, `ALR05` | `AG003`, `PRM001`, `PRM002`, `ALR01-S01` |
| ASI02 | Tool Misuse and Exploitation | `ALR02`, `ALR03`, `ALR04`, `ALR06`, `ALR07`, `ALR09`, `ALR12` | `PY001`, `PY002`, `PY003`, `AG001`, `AG002`, `AG004`, `AG005`, `AG006`, `MAN001`, `MAN002`, `MAN003`, `ALR06-S02`, `ALR12-S01` |
| ASI03 | Identity and Privilege Abuse | `ALR03`, `ALR07`, `ALR09`, `ALR10` | `AG001`, `AG004`, `AG005`, `SEC001`, `MAN001`, `MAN002`, `MAN003`, `ALR03-S01` |
| ASI04 | Agentic Supply Chain Vulnerabilities | `ALR02`, `ALR03`, `ALR04`, `ALR10`, `ALR11` | `SEC001`, `DEP001`, `ALR11-S01` |
| ASI05 | Unexpected Code Execution (RCE) | `ALR06`, `ALR07`, `ALR09` | `PY001`, `PY002`, `AG002`, `AG004`, `AG005`, `AG006`, `MAN001`, `ALR06-S01`, `ALR06-S02` |
| ASI06 | Memory & Context Poisoning | `ALR13` | `ALR13-S01`, `ALR13-S02` (partial) |
| ASI07 | Insecure Inter-Agent Communication | `ALR03`, `ALR12` | `ALR03-S01`, `ALR12-S01` (partial) |
| ASI08 | Cascading Failures | `ALR08` | `AG007`, `ALR08-S01`, `ALR08-S02` (partial) |
| ASI09 | Human-Agent Trust Exploitation | `ALR09` | `AG004`, `AG006`, `MAN001` (partial) |
| ASI10 | Rogue Agents | `ALR14` | `ALR14-S01`, `ALR14-S02`, `ALR14-S03` (partial) |

Keep this table up to date whenever a rule is added or its OWASP mapping changes.

### Gates

A gate is a security outcome (for example `ALR09` Human approval for sensitive actions). Every detector, a static rule or a runtime check, belongs to exactly one gate. `src/agent_latch/catalog.py` is the single source for gates (`GATES`, which groups each gate's detectors as `(id, mode, reason)`), detector-to-gate assignments with the reason (`DETECTORS`, derived from those groups), and framework references per gate: OWASP IDs from `owasp.py` and EU AI Act articles (`EU_AI_ACT_ARTICLES`). ISO/IEC 42001 is not mapped yet.

- A detector's OWASP IDs must be a subset of its gate's. A test checks this, and that every rule in `RULE_CATEGORIES` and every ALR04 rule ID has a gate (or is listed in `DIAGNOSTICS`).
- `docs/GATES.md` is generated: `python -I -m agent_latch.catalog > docs/GATES.md`. A test fails when it is out of date.
- Framework mappings are informational. Never claim compliance with the EU AI Act, ISO/IEC 42001 or OWASP.
- `agent_latch/gates/` holds runtime gate plugins only (one module per gate, `GATE_ID` = the gate ID). Keep the catalog out of that package: the importer loads every module in it as a plugin.

## Repository layout

```
src/agent_latch/
  __init__.py     # __version__ (keep in sync with pyproject.toml)
  cli.py          # argparse + rich CLI, interactive mode, exit codes, report dispatch
  findings.py     # Finding dataclass; dedupe() for merging findings; is_test_path() for test-file severity
  rules.py        # PY*/AG001/AG002/SEC001 rules, project walker, prompt-file scan, pip-audit integration
  agent_code.py   # manifest-free agent checks: prompts in code/YAML (PRM*), AG004, AG005
  oversight.py    # AG006 human approval disabled (ASI09), AG007 unbounded agent loops (ASI08)
  memory.py       # ALR13: untrusted memory writes (ASI06), memory shared across sessions
  endpoints.py    # ALR12-S01 plaintext endpoints, ALR03-S01 server bound to all interfaces (ASI07)
  resilience.py   # ALR08-S01 missing timeout, ALR08-S02 unbounded retry (ASI08)
  rogue.py        # ALR14: self-modification, persistence, runtime installs (ASI10)
  sandbox.py      # ALR06 unsafe deserialization and unsandboxed code, ALR11-S01 trust_remote_code
  astutil.py      # cached ast.walk shared by the rule modules
  taint.py        # AG003/ALR13-S01: untrusted web/HTTP/tool output flowing into messages or memory
  prompts.py      # PRM001/PRM002/ALR01-S01 text checks shared by code, YAML, prompt files, manifests
  yamlload.py     # line-aware YAML loading (SafeLoader subclass)
  manifest.py     # Manifest loading and MAN* rules; PRM* on manifest prompts
  owasp.py        # ASI01–ASI10 category IDs/names, rule→category map, coverage summary
  catalog.py      # gates ALR01–ALR14, detector→gate map, EU AI Act refs; renders docs/GATES.md
  suppress.py     # .agent-latch-ignore, inline ignores, pyproject excludes
  report.py       # text, JSON, and SARIF renderers; severity ordering
  action_summary.py # GitHub Action job summary and SARIF URI rewrite (python -I -m agent_latch.action_summary)
  gates/          # runtime gate plugins discovered by the importer (monitor only, never block)
    __init__.py
    alr04.py      # ALR04: instruction-like content in MCP tool definitions (preview; reports findings only)
  runtime/        # MCP traffic recording (preview, monitor only; `[runtime]` extra). Logs go to runtime-logs/, not here.
    events.py     # ToolCall, ToolOutput, ToolInfo, PayloadEvent (agentlatch.runtime.payload/1)
    redact.py     # hashes, secret masking, short excerpts, mask_value for the opt-in payloads file
    trace.py      # TraceLog: one redacted JSONL record per MCP message (agentlatch.runtime.trace/1)
    payloads.py   # PayloadTap: full-payload records to sinks; PayloadFile (opt-in --payloads, masked)
    normalizer.py # MCPEventNormalizer: joins a trace record and its payload record into one event
    importer.py   # RuntimeLogImporter: tails logs, writes events, runs gates; optional EventStore
    sqlite_store.py # SQLiteEventStore: first EventStore, local SQLite via stdlib sqlite3 (`--database`)
    results.py    # agent-latch --runtime-result: findings table from gate-results.csv, for every gate
    middleware.py # AgentLatchMiddleware: FastMCP middleware that records traffic [needs fastmcp]
    proxy.py      # build_proxy: one MCP server (stdio command or URL) behind it [needs fastmcp]
    demo_server.py # synthetic MCP server for `demo` and the runtime tests [needs fastmcp]
    demo.py       # `demo`: drives demo_server through the proxy, then imports the logs [needs fastmcp]
    cli.py        # agent-latch-runtime console script (`proxy`, `import-logs`, `demo`)
tests/test_scanner.py          # scanner unit tests (synthetic fixtures via tmp_path)
tests/test_runtime.py          # runtime tests that need no FastMCP
tests/test_runtime_importer.py # normalizer, importer and import-logs CLI tests (no FastMCP)
tests/test_runtime_middleware.py # proxy and demo end-to-end tests (skipped without the [runtime] extra)
tests/test_alr04.py            # ALR04 baseline against the synthetic normalized events
tests/test_runtime_results.py  # runtime findings report, including a later gate's path and line
tests/runtime_fixtures/        # demo-server wrapper, plus the ALR04 event dataset and expected outcomes
examples/vulnerable-agent/     # deliberately insecure demo project + expected SARIF
scripts/agentlatch-chatgpt.ps1 # one-command ChatGPT tunnel setup and start (Windows); .sh for macOS/Linux
docs/                          # getting-started, agent-manifest, ci, RULES, release notes, brand assets
action.yml                     # composite GitHub Action (isolated venv, SARIF path rewrite, summary)
.pre-commit-hooks.yaml         # pre-commit hook definition (`agent-latch scan --fail-on high`)
.agent-latch-ignore            # suppressions for the repo's own self-scan
.github/workflows/tests.yml    # CI: tests + ruff (py3.11–3.14), runtime tests, action smoke test, self-scan
.github/workflows/code-quality.yml # CI: ruff check across the repo, npm audit --audit-level=high for web/
.github/workflows/publish.yml  # PyPI release via Trusted Publishing (on GitHub release; manual run → TestPyPI)
MANIFEST.in                    # sdist extras (test fixtures the shipped tests read)
llms.txt                       # LLM-oriented project summary
```

## Setup, test, lint

Python 3.11+ is required. The repo uses a local `.venv`.

```sh
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev,audit,runtime]"
python -m pytest          # run all tests
ruff check .              # lint (line-length 100, target py311)
```

Always run both `pytest` and `ruff check .` before you finish a change. CI runs them on Python 3.11, 3.12, 3.13, and 3.14.

Manual smoke test against the demo project:

```sh
cd examples/vulnerable-agent
agent-latch scan --config agent-manifest.yaml
agent-latch scan --format sarif --output agent-latch.sarif
```

## CLI reference

```
agent-latch [scan] [path] [--config MANIFEST] [--exclude PATH]... [--ignore-file FILE]
            [--project-ignores] [--dependencies] [-i/--interactive]
            [--format text|json|sarif] [--output FILE] [--plain] [--min-severity LEVEL]
            [--fail-on none|low|medium|high|critical]
            [--runtime-result [CSV]] [-V]

agent-latch-runtime proxy [--name NAME] [--trace FILE] [--excerpt-chars N]
            [--payloads FILE] [--payload-max-chars N] [--quiet]
            [--http HOST:PORT] (--upstream-url URL | -- SERVER COMMAND...)
agent-latch-runtime import-logs [--dir DIR] [--trace FILE] [--payloads FILE]
            [--events-csv FILE] [--output-csv FILE] [--normalized-out FILE]
            [--database FILE] [--run-id ID] [--once] [--quiet]
agent-latch-runtime demo [--dir DIR]
```

`agent-latch-runtime proxy` is a preview: it records MCP traffic and never blocks (see `docs/runtime.md`). It exits `2` on a configuration error. It never writes to stdout, which carries the MCP protocol in stdio mode. `import-logs` runs in parallel as a separate process: it only reads the proxy's log files, prints one line per event, writes `events.csv` and `gate-results.csv` (ALR04 is installed) under the ignored `runtime-logs/` folder by default, and never blocks or changes traffic. ALR04 reports findings only; the runtime report does not clear a tool. `demo` records a session with the bundled synthetic server into `runtime-logs/demo/` and imports it, so the pipeline can be checked with one command.

`--database FILE` is the operator's choice of a local store. It saves each normalized event in a SQLite file (`SQLiteEventStore`) and is off when omitted. The importer talks to that file only through the `EventStore` contract in `importer.py` (`open`, `save`, `close`). SQLite is the first implementation, using the standard-library `sqlite3` module, so it adds no dependency and makes no network request. A later destination (a warehouse or an opt-in trace exporter) implements the same contract and is selected the same way: by a flag on `import-logs`, not by a default. The database can hold payload data, so a new file is created with mode `0600` where the platform supports it. Keep it local. Do not add a vendor client as a required dependency.

Exit codes are `0` for passed, `1` for findings at or above `--fail-on` (unknown severity fails closed), and `2` for a scan or configuration error. The GitHub Action relies on these values, so do not change them.

## Rules

| ID | Gate | Where | Detects |
|---|---|---|---|
| `PY001` | `ALR06` | `rules.py` | `eval()` / `exec()` |
| `PY002` | `ALR06` | `rules.py` | `subprocess.*(..., shell=True)` |
| `PY003` | `ALR12` | `rules.py` | literal `verify=False` |
| `AG001` | `ALR07` | `rules.py` | CrewAI `Agent(allow_delegation=True)` |
| `AG002` | `ALR06` | `rules.py` | LangChain `create_pandas_dataframe_agent` |
| `AG003` | `ALR05` | `taint.py` | web/HTTP/tool output flowing unfenced into LLM messages |
| `AG004` | `ALR09` | `agent_code.py` | model-exposed tool that runs commands, writes files/DB, sends email or HTTP writes, with no approval gate |
| `AG005` | `ALR07` | `agent_code.py` | unrestricted built-in tool (`ShellTool`, `PythonREPLTool`, unscoped `FileManagementToolkit`, ...) |
| `AG006` | `ALR09` | `oversight.py` | human approval disabled (`human_input_mode="NEVER"` with code execution, `auto_approve=True`, ...) |
| `AG007` | `ALR08` | `oversight.py` | agent loop without an effective limit (`max_iterations=None`, huge limits, endless `while True`) |
| `SEC001` | `ALR10` | `rules.py` | credential-like quoted assignments (value redacted) |
| `DEP001` | `ALR11` | `rules.py` | `pip-audit` advisories in `requirements*.txt` |
| `MAN001` | `ALR09` | `manifest.py` | high-risk tool capability without an approval gate |
| `MAN002` | `ALR07` | `manifest.py` | wildcard tool permissions |
| `MAN003` | `ALR03` | `manifest.py` | remote tool endpoint without auth |
| `PRM001` | `ALR01` | `prompts.py` (via `agent_code.py`, `rules.py`, `manifest.py`) | prompt-injection signatures in prompts |
| `PRM002` | `ALR01` | `prompts.py` (via `agent_code.py`, `rules.py`, `manifest.py`) | user-input placeholder in a system prompt |
| `ALR01-S01` | `ALR01` | `prompts.py` | invisible, bidi, or zero-width characters in a prompt |
| `ALR03-S01` | `ALR03` | `endpoints.py` | agent or MCP server bound to every interface |
| `ALR06-S01` | `ALR06` | `sandbox.py` | unsafe deserialization (`yaml.load`, `pickle`, `torch.load`, dangerous loader options) |
| `ALR06-S02` | `ALR06` | `sandbox.py` | model-written code runs without a sandbox |
| `ALR08-S01` | `ALR08` | `resilience.py` | outbound HTTP call without a timeout |
| `ALR08-S02` | `ALR08` | `resilience.py` | retry without a limit |
| `ALR11-S01` | `ALR11` | `sandbox.py` | `trust_remote_code=True` on a model or dataset loader |
| `ALR12-S01` | `ALR12` | `endpoints.py` | plaintext `http://` or `ws://` endpoint |
| `ALR13-S01` | `ALR13` | `memory.py` | web/tool output written to memory without validation |
| `ALR13-S02` | `ALR13` | `memory.py` | memory shared across sessions (module-level store) |
| `ALR14-S01` | `ALR14` | `rogue.py` | agent writes to its own prompts or settings |
| `ALR14-S02` | `ALR14` | `rogue.py` | agent installs persistence on the host |
| `ALR14-S03` | `ALR14` | `rogue.py` | agent installs packages at runtime |

Full behavior and blind spots: `docs/RULES.md`.

### Adding or changing a rule

1. Pick its gate in `catalog.GATES` (add a gate only for a new outcome) and give it a stable, unique ID named after that gate: `ALRnn-Snn` for a static rule, `ALRnn-Rnn` for a runtime check (matching `suppress._RULE_ID`), plus a focused title. Existing `AGENTLATCH-XXX000` IDs keep their names. Never reuse or renumber an existing ID.
2. Make it work without a manifest unless it is a `MAN*` rule (see the design principle above).
3. Emit a `findings.Finding` with `rule_id`, `title`, `severity`, `message`, `path` (relative POSIX), `line`, `column`, `owasp` (ASI IDs only), `confidence`, and concise `evidence`. Register the rule in `owasp.RULE_CATEGORIES` and in `catalog.DETECTORS` with its gate and a one-line reason. Its OWASP IDs must fit inside the gate's.
4. **Never put secret values in evidence, messages, or reports.**
5. Add a positive test and, where relevant, a negative (non-finding) test in `tests/test_scanner.py` using `tmp_path` fixtures.
6. Document the rule in `docs/RULES.md` and in the rule tables in `README.md` and this file (with its gate), and regenerate `docs/GATES.md`.
7. If the demo project should show it, update `examples/vulnerable-agent/` (code, README, and `agent-latch.sarif`).
8. Make sure the repo's own self-scan (`agent-latch scan . --fail-on high --project-ignores`) still passes. Add any intentional test fixtures to `.agent-latch-ignore` instead of weakening rules.

## Conventions

- Keep runtime dependencies minimal: `rich`, `rich-argparse`, `PyYAML`. `pip-audit` is an optional `[audit]` extra, and pinned `fastmcp` is the optional `[runtime]` extra (`import agent_latch.runtime` must not import it). Do not add new runtime dependencies without strong justification.
- Use `from __future__ import annotations`, type hints, and `pathlib.Path` throughout. Use frozen dataclasses for value types.
- Rules are static heuristics. Parse with `ast` and never import or execute scanned code. Load YAML only with `yaml.SafeLoader` (see `manifest._LineLoader`).
- The project walker (`rules.iter_project_files` / `scan_project`) visits every folder and every text file (see the design principle above). By file type: `.py` gets source, agent, and prompt rules; `.yaml`/`.yml` (except manifests, which `manifest.py` handles) gets YAML prompt checks; prompt templates (`rules.PROMPT_SUFFIXES`, and `.md`/`.txt` under a `prompts/` folder) get prompt rules; every text file gets `SEC001`. Keep these limits intentional and documented in `docs/getting-started.md`.
- Noisy rules report findings in test files at low severity instead of dropping them, so real problems in tests stay visible: `SEC001` itself, and `findings.TEST_DEMOTED_RULES` (`PY001`, `AG004`, `AG006`, `AG007`, `ALR14-S01`) through `demote_test_findings`.
- `--min-severity` filters what is reported, never what fails: the CLI rejects a `--min-severity` above `--fail-on`, keeps unknown severity, and every report counts hidden findings.
- Use `astutil.walk` instead of `ast.walk` for whole-file or whole-function traversals; every rule walks the same tree.
- Sort findings deterministically (path, line, rule ID) so reports and SARIF stay stable.
- People read rule IDs short with their gate (`catalog.display_id`: `PY001 (ALR06)`) in the terminal, text report and job summary. SARIF `ruleId` and JSON `rule_id` keep the full ID (`AGENTLATCH-PY001`) because code-scanning alert history is keyed on it; JSON and SARIF also carry `gate` and the short ID. Do not change the full IDs.
- Suppressions are handled in `suppress.py`: `.agent-latch-ignore` (path / rule / `path:line`), inline `# agent-latch: ignore[RULE]`, and `[tool.agent-latch] exclude` in `pyproject.toml`, all applied only with `--project-ignores`, plus `--exclude` and `--ignore-file`, which always apply. Reports must state how many findings were suppressed. This repo's own self-scan, pre-commit hook, and CI job pass `--project-ignores`.
- When the CLI writes a report to a file or stdout, send human-facing summaries to stderr so machine-readable output stays clean.

## Privacy and security constraints

- Scans must stay local. Do not add LLM calls, telemetry, or uploads.
- The only network use is the opt-in `--dependencies` audit, which sends package names and versions. Any new network behavior must be opt-in and documented. `--database` is local SQLite and must stay that way. A destination that sends events off the machine is new network behavior: opt-in, documented, and not a required dependency.
- Tests must make no network calls. Mock `subprocess` for `pip-audit`.
- Use synthetic fixtures only. Never commit real secrets or proprietary code.
- Report vulnerabilities in AgentLatch itself as described in `SECURITY.md`.

## GitHub Action and pre-commit

- `action.yml` installs AgentLatch into an isolated venv under `$RUNNER_TEMP`, runs a SARIF scan, rewrites SARIF URIs to be repo-relative and writes the job summary (`agent_latch.action_summary`), optionally uploads to code scanning, and then enforces `fail-on`.
- The Action's working directory is the scanned (untrusted) repository. Always run Python there with `-I` (isolated mode), so it cannot import modules planted in the repo, and never use `python -` or `python -c` without `-I`. Escape all scanned-project text (paths, evidence, messages) before writing it into the Markdown job summary.
- Outputs: `sarif-file`, `finding-count`, `exit-code`. The CI `action-smoke-test` job asserts on these outputs and on the SARIF URI for `examples/vulnerable-agent/agent-manifest.yaml`.
- `.pre-commit-hooks.yaml` exposes hook id `agent-latch` and passes `--fail-on high --project-ignores` (pre-commit runs on the user's own repo).
- The Action's `project-ignores` input defaults to `"false"`, because pull requests can edit ignore files. The self-scan job sets it to `"true"`.

## Prior art

Before building a check, look at how established open-source tools handle it. Borrow ideas and test cases, not code. Check each project's license before reusing anything.

- General SAST: Semgrep (rule-as-data YAML patterns), Bandit (Python AST plugins), and Gitleaks / TruffleHog (secret detection).
- Agent- and MCP-specific: Snyk `agent-scan` (MCP servers, agent skills), SPLX `agentic-radar` (workflow graphs for LangGraph, CrewAI, n8n, and OpenAI Agents), and `agent-audit` (OWASP Agentic-mapped rules, MCP config auditing).
- Runtime red-teaming tools such as garak, promptfoo, and `agentic_security` test model behavior. They complement AgentLatch's static scope rather than replacing it.

## Releasing

- Bump the version in **both** `pyproject.toml` and `src/agent_latch/__init__.py`.
- Add `docs/release-notes/vX.Y.Z.md`, and update version references in `README.md`, `docs/ci.md`, and `llms.txt` (for example `AgentLatch/agent-latch@vX.Y.Z` and `agentlatch-security==X.Y.Z`).
- The package is published to PyPI as `agentlatch-security` (PyPI rejects `agent-latch` as too similar to an unrelated `agentlatch` project). The commands stay `agent-latch` and `agent-latch-runtime`, and the import stays `agent_latch`. It is published by `.github/workflows/publish.yml` using Trusted Publishing (no API token). Run it manually first to publish to TestPyPI and check `pipx install` from there. Publishing a GitHub release tagged `vX.Y.Z` then uploads to PyPI; the workflow fails if the tag does not match both version files.
- PyPI versions cannot be replaced or reused, even after deletion, so fix problems with a new patch release.

## Documentation map

- `README.md`: overview, quick start, FAQ, limitations, roadmap
- `docs/getting-started.md`: install (incl. Windows), options, ignores, output formats, exit codes, troubleshooting
- `docs/agent-manifest.md`: manifest schema and checks
- `docs/ci.md`: pre-commit, GitHub Action inputs and outputs, other CI
- `docs/RULES.md`: per-rule detection, OWASP mapping, blind spots
- `docs/GATES.md`: gates, their detectors and framework references (generated from `catalog.py`)
- `docs/runtime.md`: runtime proxy for MCP (preview, monitor only): install, connecting an app, supported clients, what is recorded, limits
- `docs/clients/chatgpt.md`: ChatGPT reaches the proxy through OpenAI's Secure MCP Tunnel. Local apps use the config change in `docs/runtime.md`
- `mcp-server/SETUP.md`: the only place with step-by-step gateway setup and agent connection instructions, including starting `import-logs --database` before a live CrewAI or Claude Desktop run; `mcp-server/README.md` is an overview that links to it
- `CONTRIBUTING.md`, `SECURITY.md`, `llms.txt`

When behavior changes, update the relevant docs in the same change.
