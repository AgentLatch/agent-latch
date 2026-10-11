# Getting started

This guide covers installing AgentLatch, running scans, reading results, and the optional dependency audit.

- [Install](#install)
- [Run a scan](#run-a-scan)
- [Command reference](#command-reference)
- [Ignoring false positives and known findings](#ignoring-false-positives-and-known-findings)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Dependency audit](#dependency-audit)
- [Troubleshooting](#troubleshooting)

## Install

Requires Python 3.11 or newer. Install AgentLatch in its own virtual environment, not into the project you are scanning.

### Linux, macOS, and WSL

```sh
git clone https://github.com/AgentLatch/agent-latch.git
cd agent-latch
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

On a fresh Ubuntu or WSL install you may first need `sudo apt install -y python3 python3-venv git`.

### Windows PowerShell

```powershell
git clone https://github.com/AgentLatch/agent-latch.git
Set-Location agent-latch
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

### Optional extras

| Extra | Install | Adds |
|---|---|---|
| `audit` | `python -m pip install -e ".[audit]"` | `pip-audit`, needed for `--dependencies` |
| `dev` | `python -m pip install -e ".[dev]"` | `pytest` and `ruff` for contributing |

### Using AgentLatch from any folder

The `agent-latch` command is available wherever its virtual environment is active. In a new terminal:

```sh
source ~/path/to/agent-latch/.venv/bin/activate
```

Or skip activation with an alias in `~/.bashrc`:

```sh
echo 'alias agent-latch="$HOME/path/to/agent-latch/.venv/bin/agent-latch"' >> ~/.bashrc
source ~/.bashrc
```

Check the install with `agent-latch --version`.

## Run a scan

```sh
# Scan the current directory
agent-latch scan

# Scan another project, by absolute or relative path
agent-latch scan ~/projects/my-agent
agent-latch scan ../my-agent

# Scan a single file
agent-latch scan ~/projects/my-agent/agent.py

# Audit an agent manifest's tools and prompts as well (see agent-manifest.md)
agent-latch scan --config agent-manifest.yaml
```

The `scan` verb is optional: `agent-latch ~/projects/my-agent` does the same thing. To scan a folder literally named `scan`, write `./scan`.

### Guided mode

```sh
agent-latch --interactive
```

The wizard asks for a target, asks whether to run the networked dependency audit (default **No**), shows findings in a table, and offers JSON or SARIF export. It uses `agent-manifest.yaml` from the target automatically and asks whether to apply the project's own ignore file and inline comments (default **No**); for a manifest elsewhere, use `--config` on the command line instead.

### Scan many agents at once

```sh
for d in ~/projects/agents/*/; do agent-latch scan "$d"; done
```

### What gets scanned

| Files | Checks |
|---|---|
| `*.py` | Source rules (`PY*`, `AG*`), prompts written in code (`PRM*`), and secrets (`SEC001`) |
| `*.yaml`, `*.yml` | Prompt-like keys such as `system_prompt`, `instructions`, `goal`, `backstory`, `prompt` (`PRM*`), and secrets |
| `*.prompt`, `*.prompty`, `*.j2`, `*.jinja`, `*.jinja2`, and `*.md`/`*.txt` inside a `prompts/` folder | Prompt rules (`PRM*`) and secrets |
| `*.toml`, `*.txt`, `.env*` | Secrets (`SEC001`) |
| `agent-manifest.yaml` in the target directory, and prompt files it references | Manifest rules (`MAN*`) and prompt rules (`PRM*`); referenced prompt files are also checked for secrets |
| `requirements*.txt` | Dependency advisories (`DEP001`), only with `--dependencies` |

No manifest is needed: every folder under the target is walked, and the `AG*` and `PRM*` checks run on source and prompt files directly. A manifest adds the `MAN*` checks; it can add findings but never hides them, so a misleading manifest cannot make a project look cleaner. Every other text file (JSON, JavaScript, shell scripts, Markdown, and so on) is checked for secrets (`SEC001`). Skipped: `.git`; installed environments, meaning a folder containing `pyvenv.cfg`, a `.tox` folder of such environments, or a `node_modules` folder with a package-manager marker such as `.package-lock.json`; symlinks, which can point outside the project; binary files; and files over 1 MB. A folder that is only *named* `venv` or `node_modules` is still scanned, so a project cannot hide code by naming a folder that way. See [RULES.md](RULES.md) for what each rule detects and misses.

## Command reference

```text
agent-latch [scan] [path] [options]
```

| Option | Description |
|---|---|
| `path` | Directory or file to scan. Default: current directory. |
| `--config MANIFEST` | Agent manifest to audit. Default: `agent-manifest.yaml` in the target directory (or, for a file target, its folder), if present. |
| `--exclude PATH` | Skip findings under a path or glob, relative to the target. Repeatable. See [Ignoring false positives](#ignoring-false-positives-and-known-findings). |
| `--ignore-file FILE` | File of accepted findings. Default: `.agent-latch-ignore` in the target directory (or, for a file target, its folder), if present. |
| `--project-ignores` | Apply suppressions that live in the scanned project: its `.agent-latch-ignore`, `[tool.agent-latch] exclude`, and inline ignore comments. Off by default, because the project's author controls them. Use it only for your own code. `--exclude` and an explicit `--ignore-file` always apply. |
| `--dependencies` | Audit `requirements*.txt` with pip-audit. Contacts an advisory service. |
| `-i`, `--interactive` | Guided terminal scanner. |
| `--format {text,json,sarif}` | Report format. Default: `text`. |
| `--min-severity {info,low,medium,high,critical}` | Report only findings at or above this severity. Default: `info` (everything). Hidden findings are counted in the report, and unknown-severity findings are always shown. It cannot be above `--fail-on`, so it never hides a finding that would fail the scan. |
| `--output FILE` | Write the report to a file instead of the terminal. |
| `--plain` | Plain-text report even in a terminal. |
| `--fail-on {none,low,medium,high,critical}` | Exit 1 when a finding at or above this severity exists. Default: `none`. |
| `-V`, `--version` | Print the version. |

## Ignoring false positives and known findings

Test fixtures, demos, and vendored code often contain risky patterns on purpose, and heuristics sometimes flag safe code. Record accepted findings instead of turning rules off everywhere. Every report states how many findings were suppressed, so nothing disappears silently.

**Suppressions inside the project are off by default.** The `.agent-latch-ignore` file, `pyproject.toml` excludes, and inline comments are written by whoever controls the project, so AgentLatch applies them only when you add `--project-ignores`. Use that flag for your own repositories; leave it off for agents you did not write and for pull requests from others. `--exclude` and `--ignore-file` come from you, so they always apply.

| Method | Best for |
|---|---|
| [`.agent-latch-ignore` file](#the-agent-latch-ignore-file) | The project's list of known findings and false positives, reviewed like code. **Recommended.** |
| [Inline comment](#inline-ignore-comments) | A single accepted line, documented right next to the code. |
| [`--exclude` / `pyproject.toml`](#excluding-paths-from-the-command-line-or-pyprojecttoml) | Quick path exclusions for one run, or projects that already centralise settings in `pyproject.toml`. |

### The `.agent-latch-ignore` file

Create `.agent-latch-ignore` in the root of the project you scan. AgentLatch applies it when you scan with `--project-ignores`. To use a file of your own instead, pass `--ignore-file path/to/file`, which always applies.

```gitignore
# .agent-latch-ignore — known and accepted AgentLatch findings.
# Give every entry a reason so reviewers know why it is safe.

# 1. PATH: ignore every finding in a file or directory
examples/
vendor/*.py

# 2. RULE PATH: ignore one rule in matching files
SEC001 tests/fixtures/fake_keys.py       # fake keys used by redaction tests
AG003 agents/summarizer/*.py             # output is rendered to the user, never fed to tools

# 3. RULE PATH:LINE: ignore one specific known finding
PY002 scripts/deploy.py:42               # fixed command string, no user input
```

| Entry | Suppresses |
|---|---|
| `PATH` | All findings in that file, or under that directory. |
| `RULE PATH` | Only that rule's findings in matching files. |
| `RULE PATH:LINE` | Only that rule's finding on that exact line. |

Format rules:

- Paths are relative to the scan target. A path without wildcards matches that file or everything under that directory; with `*`, `?`, or `[` it is a glob.
- Rules can be written short (`SEC001`) or in full (`AGENTLATCH-SEC001`), in any case.
- `#` starts a comment, at the start of a line or after whitespace. Blank lines are ignored.
- A line number always needs a rule. Line entries stop matching when the code moves, so prefer `RULE PATH` unless you want the entry to be re-reviewed after edits.
- A malformed line stops the scan with exit code 2 and points at the line, so a typo cannot quietly disable checks.

Commit the file and review changes to it in pull requests. Adding an entry is a security decision.

### Inline ignore comments

Put a comment on the line AgentLatch reports. Name the rule and give a reason:

```python
eval(expression)  # agent-latch: ignore[PY001] -- input is a validated arithmetic expression
```

```yaml
capabilities: [shell]  # agent-latch: ignore[MAN001] -- runs only in an isolated sandbox
```

Separate several rules with commas: `ignore[PY001,PY002]`. A bare `# agent-latch: ignore` suppresses every rule on that line, including future ones, so prefer naming the rule.

### Excluding paths from the command line or pyproject.toml

For one run, `--exclude` takes a path or glob and can be repeated:

```sh
agent-latch scan . --exclude tests/ --exclude "scripts/*.py"
```

For projects that keep settings in `pyproject.toml`:

```toml
[tool.agent-latch]
exclude = ["tests/", "examples/", "vendor/*.py"]
```

### How the sources combine

With `--project-ignores`, all sources apply together: the ignore file, `pyproject.toml` excludes, `--exclude`, and inline comments. Without it, only `--exclude` and an explicit `--ignore-file` apply. The ignore file and `pyproject.toml` are read only from the scan target directory, so scanning a subfolder directly (for example `agent-latch scan examples/vulnerable-agent`) does not apply the parent project's entries.

## Output formats

| Format | When to use it |
|---|---|
| `text` in a terminal | Colour table, sorted by severity. The default when you run it yourself. |
| `text` when piped, with `--output`, or with `--plain` | Plain text for logs and scripts. |
| `json` | Machine-readable report for your own tooling. |
| `sarif` | Standard static-analysis format; GitHub code scanning and many IDEs import it. |

```sh
agent-latch scan --format json --output report.json
agent-latch scan --format sarif --output results.sarif
```

Each finding includes a rule ID, severity, confidence, file, line, column, OWASP Agentic Top 10 mapping, a message, and evidence. Detected secret values are redacted from evidence. Reports still contain file paths and code context, so review them before sharing.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed and nothing met the `--fail-on` threshold. |
| `1` | At least one finding at or above `--fail-on`. Unknown-severity dependency findings also count. |
| `2` | Scan error: missing target, missing or invalid manifest, invalid `.agent-latch-ignore` or `[tool.agent-latch]` settings, or dependency audit failure. |

When the scan exits `1`, it prints the findings that caused the failure (severity, rule, `path:line`, and title) to stderr, so JSON or SARIF on stdout stays valid:

```text
✗ Failing (exit 1): 3 finding(s) at or above --fail-on high
  HIGH     AGENTLATCH-MAN001  agent-manifest.yaml:29  High-risk tool without human approval
  HIGH     AGENTLATCH-MAN002  agent-manifest.yaml:40  Tool grants wildcard permissions
  HIGH     AGENTLATCH-PY002   tools.py:10             Subprocess uses shell=True
```

## Dependency audit

```sh
python -m pip install -e ".[audit]"   # once
agent-latch scan ~/projects/my-agent --dependencies
```

The audit uses [pip-audit](https://github.com/pypa/pip-audit) on `requirements*.txt` files. It does not yet read `pyproject.toml` dependencies or lockfiles.

**Privacy:** package names and versions from those files are sent to pip-audit's vulnerability service (PyPI by default). Your source code is not uploaded, and no packages are installed or resolved (`--no-deps --disable-pip`). Requirements therefore need exact pins (`package==1.2.3`). Check your organisation's policy before querying private package names.

**Severity:** pip-audit does not provide a normalised severity, so dependency findings show as `UNKNOWN` rather than an invented rating. With any `--fail-on` other than `none`, they fail closed. Advisory data changes over time, so repeat scans can return different results.

## Troubleshooting

| Problem | Fix |
|---|---|
| `agent-latch: command not found` | Activate the virtual environment or use the alias above. |
| `unrecognized arguments: --config-manifest.yaml` | Put a space after `--config`: `--config agent-manifest.yaml`. |
| No colour table | Output is piped or redirected. Run it directly in a terminal without `--output` or `--plain`. |
| Fewer findings than expected | Dependency findings need `--dependencies`; `MAN*` findings need an `agent-manifest.yaml`; Markdown prompts are scanned only inside a `prompts/` folder. |
| Accepted findings in `.agent-latch-ignore` still reported | Project suppressions are off by default; add `--project-ignores` for your own repository. |
| Findings in tests or demo code you wrote on purpose | Exclude those paths or add an inline ignore. See [Ignoring false positives](#ignoring-false-positives-and-known-findings). |
| `Manifest error: invalid YAML` | Fix the YAML syntax at the line shown. |
| `Configuration error: ... exclude ... must be a list of strings` | Write `exclude = ["tests/"]`, not `exclude = "tests/"`. |
| `Dependency audit error` | Install the `audit` extra, pin exact versions, and check network access. |
