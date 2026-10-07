# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Project overview

**AgentLatch** is a local-first, static security scanner for AI-agent projects. It checks:

- Python agent source code (AST-based rules, tool/approval analysis, prompts written in code, and a small intra-file taint analysis),
- prompts in any YAML file (for example CrewAI `config/agents.yaml`) and prompt template files (`.prompt`, `.prompty`, `.j2`, `.jinja`, `.jinja2`, and `.md`/`.txt` under a `prompts/` folder),
- optionally, agent manifests (`agent-manifest.yaml`) declaring tools, permissions, auth, and prompts, plus the prompt files they reference,
- optionally, pinned Python dependencies via `pip-audit` (`--dependencies`).

It reports findings as a terminal table / plain text, JSON, or SARIF, and runs as a CLI, a pre-commit hook, or a composite GitHub Action. Findings map to the OWASP Top 10 for Agentic Applications (informational only).

Status: **early proof of concept (v0.2.1)**. Never overstate coverage. A clean scan is not a security guarantee, and docs and messages must say so.

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

| ID | Category | Current rules |
|---|---|---|
| ASI01 | Agent Goal Hijack | `AG003`, `PRM001`, `PRM002` |
| ASI02 | Tool Misuse and Exploitation | `PY001`, `PY002`, `PY003`, `AG001`, `AG002`, `AG004`, `AG005`, `AG006`, `MAN001`, `MAN002`, `MAN003` |
| ASI03 | Identity and Privilege Abuse | `AG001`, `AG004`, `AG005`, `SEC001`, `MAN001`, `MAN002`, `MAN003` |
| ASI04 | Agentic Supply Chain Vulnerabilities | `SEC001`, `DEP001` |
| ASI05 | Unexpected Code Execution (RCE) | `PY001`, `PY002`, `AG002`, `AG004`, `AG005`, `AG006`, `MAN001` |
| ASI06 | Memory & Context Poisoning | none yet |
| ASI07 | Insecure Inter-Agent Communication | none yet |
| ASI08 | Cascading Failures | `AG007` (partial) |
| ASI09 | Human-Agent Trust Exploitation | `AG004`, `AG006`, `MAN001` (partial) |
| ASI10 | Rogue Agents | none yet |

Keep this table up to date whenever a rule is added or its OWASP mapping changes.

## Repository layout

```
src/agent_latch/
  __init__.py     # __version__ (keep in sync with pyproject.toml)
  cli.py          # argparse + rich CLI, interactive mode, exit codes, report dispatch
  findings.py     # Finding dataclass; dedupe() for merging findings; is_test_path() for test-file severity
  rules.py        # PY*/AG001/AG002/SEC001 rules, project walker, prompt-file scan, pip-audit integration
  agent_code.py   # manifest-free agent checks: prompts in code/YAML (PRM*), AG004, AG005
  oversight.py    # AG006 human approval disabled (ASI09), AG007 unbounded agent loops (ASI08)
  astutil.py      # cached ast.walk shared by the rule modules
  taint.py        # AG003: untrusted web/HTTP/tool output flowing into LLM messages
  prompts.py      # PRM001/PRM002 text checks shared by code, YAML, prompt files, and manifests
  yamlload.py     # line-aware YAML loading (SafeLoader subclass)
  manifest.py     # Manifest loading and MAN* rules; PRM* on manifest prompts
  owasp.py        # ASI01–ASI10 category IDs/names, rule→category map, coverage summary
  suppress.py     # .agent-latch-ignore, inline ignores, pyproject excludes
  report.py       # text, JSON, and SARIF renderers; severity ordering
  action_summary.py # GitHub Action job summary and SARIF URI rewrite (python -I -m agent_latch.action_summary)
tests/test_scanner.py          # all unit tests (synthetic fixtures via tmp_path)
examples/vulnerable-agent/     # deliberately insecure demo project + expected SARIF
docs/                          # getting-started, agent-manifest, ci, RULES, release notes, brand assets
action.yml                     # composite GitHub Action (isolated venv, SARIF path rewrite, summary)
.pre-commit-hooks.yaml         # pre-commit hook definition (`agent-latch scan --fail-on high`)
.agent-latch-ignore            # suppressions for the repo's own self-scan
.github/workflows/tests.yml    # CI: tests + ruff (py3.11–3.14), action smoke test, self-scan
llms.txt                       # LLM-oriented project summary
```

## Setup, test, lint

Python 3.11+ is required. The repo uses a local `.venv`.

```sh
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev,audit]"
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
            [--fail-on none|low|medium|high|critical] [-V]
```

Exit codes are `0` for passed, `1` for findings at or above `--fail-on` (unknown severity fails closed), and `2` for a scan or configuration error. The GitHub Action relies on these values, so do not change them.

## Rules

| ID | Where | Detects |
|---|---|---|
| `AGENTLATCH-PY001` | `rules.py` | `eval()` / `exec()` |
| `AGENTLATCH-PY002` | `rules.py` | `subprocess.*(..., shell=True)` |
| `AGENTLATCH-PY003` | `rules.py` | literal `verify=False` |
| `AGENTLATCH-AG001` | `rules.py` | CrewAI `Agent(allow_delegation=True)` |
| `AGENTLATCH-AG002` | `rules.py` | LangChain `create_pandas_dataframe_agent` |
| `AGENTLATCH-AG003` | `taint.py` | web/HTTP/tool output flowing unfenced into LLM messages |
| `AGENTLATCH-AG004` | `agent_code.py` | model-exposed tool that runs commands, writes files/DB, sends email or HTTP writes, with no approval gate |
| `AGENTLATCH-AG005` | `agent_code.py` | unrestricted built-in tool (`ShellTool`, `PythonREPLTool`, unscoped `FileManagementToolkit`, ...) |
| `AGENTLATCH-AG006` | `oversight.py` | human approval disabled (`human_input_mode="NEVER"` with code execution, `auto_approve=True`, ...) |
| `AGENTLATCH-AG007` | `oversight.py` | agent loop without an effective limit (`max_iterations=None`, huge limits, endless `while True`) |
| `AGENTLATCH-SEC001` | `rules.py` | credential-like quoted assignments (value redacted) |
| `AGENTLATCH-DEP001` | `rules.py` | `pip-audit` advisories in `requirements*.txt` |
| `AGENTLATCH-MAN001` | `manifest.py` | high-risk tool capability without an approval gate |
| `AGENTLATCH-MAN002` | `manifest.py` | wildcard tool permissions |
| `AGENTLATCH-MAN003` | `manifest.py` | remote tool endpoint without auth |
| `AGENTLATCH-PRM001` | `prompts.py` (via `agent_code.py`, `rules.py`, `manifest.py`) | prompt-injection signatures in prompts |
| `AGENTLATCH-PRM002` | `prompts.py` (via `agent_code.py`, `rules.py`, `manifest.py`) | user-input placeholder in a system prompt |

Full behavior and blind spots: `docs/RULES.md`.

### Adding or changing a rule

1. Give it a stable, unique ID (`AGENTLATCH-XXX000`, matching `suppress._RULE_ID`) and a focused title. Never reuse or renumber an existing ID.
2. Make it work without a manifest unless it is a `MAN*` rule (see the design principle above).
3. Emit a `findings.Finding` with `rule_id`, `title`, `severity`, `message`, `path` (relative POSIX), `line`, `column`, `owasp` (ASI IDs only), `confidence`, and concise `evidence`. Register the rule in `owasp.RULE_CATEGORIES`.
4. **Never put secret values in evidence, messages, or reports.**
5. Add a positive test and, where relevant, a negative (non-finding) test in `tests/test_scanner.py` using `tmp_path` fixtures.
6. Document the rule in `docs/RULES.md` and in the rule tables in `README.md` and this file.
7. If the demo project should show it, update `examples/vulnerable-agent/` (code, README, and `agent-latch.sarif`).
8. Make sure the repo's own self-scan (`agent-latch scan . --fail-on high --project-ignores`) still passes. Add any intentional test fixtures to `.agent-latch-ignore` instead of weakening rules.

## Conventions

- Keep runtime dependencies minimal: `rich`, `rich-argparse`, `PyYAML`. `pip-audit` is an optional `[audit]` extra. Do not add new runtime dependencies without strong justification.
- Use `from __future__ import annotations`, type hints, and `pathlib.Path` throughout. Use frozen dataclasses for value types.
- Rules are static heuristics. Parse with `ast` and never import or execute scanned code. Load YAML only with `yaml.SafeLoader` (see `manifest._LineLoader`).
- The project walker (`rules.iter_project_files` / `scan_project`) visits every folder and every text file (see the design principle above). By file type: `.py` gets source, agent, and prompt rules; `.yaml`/`.yml` (except manifests, which `manifest.py` handles) gets YAML prompt checks; prompt templates (`rules.PROMPT_SUFFIXES`, and `.md`/`.txt` under a `prompts/` folder) get prompt rules; every text file gets `SEC001`. Keep these limits intentional and documented in `docs/getting-started.md`.
- Noisy rules report findings in test files at low severity instead of dropping them, so real problems in tests stay visible: `SEC001` itself, and `findings.TEST_DEMOTED_RULES` (`PY001`, `AG004`, `AG006`, `AG007`) through `demote_test_findings`.
- `--min-severity` filters what is reported, never what fails: the CLI rejects a `--min-severity` above `--fail-on`, keeps unknown severity, and every report counts hidden findings.
- Use `astutil.walk` instead of `ast.walk` for whole-file or whole-function traversals; every rule walks the same tree.
- Sort findings deterministically (path, line, rule ID) so reports and SARIF stay stable.
- Suppressions are handled in `suppress.py`: `.agent-latch-ignore` (path / rule / `path:line`), inline `# agent-latch: ignore[RULE]`, and `[tool.agent-latch] exclude` in `pyproject.toml`, all applied only with `--project-ignores`, plus `--exclude` and `--ignore-file`, which always apply. Reports must state how many findings were suppressed. This repo's own self-scan, pre-commit hook, and CI job pass `--project-ignores`.
- When the CLI writes a report to a file or stdout, send human-facing summaries to stderr so machine-readable output stays clean.

## Privacy and security constraints

- Scans must stay local. Do not add LLM calls, telemetry, or uploads.
- The only network use is the opt-in `--dependencies` audit, which sends package names and versions. Any new network behavior must be opt-in and documented.
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
- Add `docs/release-notes/vX.Y.Z.md`, and update version references in `README.md`, `docs/ci.md`, and `llms.txt` (for example `AgentLatch/agent-latch@vX.Y.Z`).

## Documentation map

- `README.md`: overview, quick start, FAQ, limitations, roadmap
- `docs/getting-started.md`: install (incl. Windows), options, ignores, output formats, exit codes, troubleshooting
- `docs/agent-manifest.md`: manifest schema and checks
- `docs/ci.md`: pre-commit, GitHub Action inputs and outputs, other CI
- `docs/RULES.md`: per-rule detection, OWASP mapping, blind spots
- `CONTRIBUTING.md`, `SECURITY.md`, `llms.txt`

When behavior changes, update the relevant docs in the same change.
