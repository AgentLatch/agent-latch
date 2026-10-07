# pre-commit and CI

Run AgentLatch automatically: locally before each commit, and on every push or pull request.

- [pre-commit hook](#pre-commit-hook)
- [GitHub Actions](#github-actions)
- [Other CI systems](#other-ci-systems)
- [Choosing a threshold](#choosing-a-threshold)

## pre-commit hook

1. Install [pre-commit](https://pre-commit.com) once: `pip install pre-commit`.
2. Add `.pre-commit-config.yaml` to the root of the repository you want to protect:

   ```yaml
   repos:
     - repo: https://github.com/AgentLatch/agent-latch
       rev: v0.2.1
       hooks:
         - id: agent-latch
   ```

3. Enable it: `pre-commit install`.
4. Try it on all files: `pre-commit run agent-latch --all-files`.

Examples in this guide pin release `v0.2.1`. Check the [releases page](https://github.com/AgentLatch/agent-latch/releases) for the latest version; `pre-commit autoupdate` bumps `rev` for you.

The hook runs `agent-latch scan --fail-on high --project-ignores` and blocks the commit when a high or critical finding exists. It runs when Python, YAML, Markdown, or text files change, and scans the whole repository, not only staged files.

### Customise

Setting `args` replaces the defaults, so always include `--fail-on`, and `--project-ignores` if you keep an `.agent-latch-ignore`:

```yaml
      - id: agent-latch
        args: [--fail-on, medium, --project-ignores, --config, agent/agent-manifest.yaml]
```

To bypass the hook for one commit: `git commit --no-verify`. Use it sparingly.

## GitHub Actions

This repository is also a GitHub Action. Add `.github/workflows/agent-latch.yml` to your repository:

```yaml
name: agent-latch
on: [push, pull_request]

permissions:
  contents: read
  security-events: write  # needed to upload results to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AgentLatch/agent-latch@v0.2.1
        with:
          fail-on: high
```

The action:

1. Installs AgentLatch in an isolated virtual environment.
2. Scans and writes a SARIF report.
3. Prints findings in the log and adds a findings table to the job summary.
4. Uploads the SARIF report to GitHub code scanning, so findings appear in the Security tab and on pull requests.
5. Fails the job when a finding meets `fail-on`.

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory or file to scan, relative to the repository root. |
| `config` | empty | Agent manifest. Empty means auto-detect `agent-manifest.yaml` in `path`. |
| `fail-on` | `high` | `none`, `low`, `medium`, `high`, or `critical`. |
| `min-severity` | `info` | Report only findings at or above `info`, `low`, `medium`, `high`, or `critical`. Hidden findings are counted in the job summary. Must not be above `fail-on`. |
| `project-ignores` | `"false"` | `"true"` applies the repository's own `.agent-latch-ignore`, `pyproject.toml` excludes, and inline ignore comments. A pull request can edit these, so enable it only where you trust the authors, or protect those files with CODEOWNERS. |
| `dependencies` | `"false"` | `"true"` also audits `requirements*.txt`; sends package names and versions to PyPI's advisory service. |
| `sarif-file` | `agent-latch.sarif` | Where to write the SARIF report. |
| `upload-sarif` | `"true"` | `"false"` skips the code scanning upload. |
| `python-version` | `3.12` | Python used to run AgentLatch. |

### Outputs

| Output | Description |
|---|---|
| `finding-count` | Number of findings. |
| `sarif-file` | Path to the SARIF report. |
| `exit-code` | `0` passed, `1` findings at or above `fail-on`, `2` scan error. |

The job summary starts with a pass/fail headline and finding counts by severity, rule, and OWASP ASI category, then lists the blocking findings, with the rest collapsed. The step log stays short; the full list is in the SARIF report.

### Examples

Scan one agent folder with its manifest and audit dependencies:

```yaml
      - uses: AgentLatch/agent-latch@v0.2.1
        with:
          path: agents/support-bot
          config: agents/support-bot/agent-manifest.yaml
          dependencies: "true"
```

Report without failing the build, then act on the result:

```yaml
      - uses: AgentLatch/agent-latch@v0.2.1
        id: agentlatch
        with:
          fail-on: none
      - run: echo "AgentLatch found ${{ steps.agentlatch.outputs.finding-count }} issue(s)"
```

### Notes

- Linux and macOS runners are supported; Windows runners are not.
- Uploading to code scanning is free for public repositories. Private repositories need GitHub Advanced Security; otherwise set `upload-sarif: "false"`.
- Pull requests from forks get a read-only token and may not be able to upload results; use `upload-sarif: "false"` for those runs if the upload fails.

## Other CI systems

AgentLatch is a normal command-line tool, so any CI system can run it. Fail on the exit code and keep the report as an artifact. A GitLab CI example:

```yaml
agent-latch:
  image: python:3.12
  script:
    - pip install "git+https://github.com/AgentLatch/agent-latch.git@v0.2.1"
    - agent-latch scan --fail-on high --plain --project-ignores
    - agent-latch scan --format sarif --output agent-latch.sarif
  artifacts:
    when: always
    paths: [agent-latch.sarif]
```

## Known findings and false positives

The pre-commit hook always reads `.agent-latch-ignore` from the scanned directory. The GitHub Action reads it only with `project-ignores: "true"`, and other CI needs `--project-ignores`. With those set, one committed file keeps local and CI results consistent:

```gitignore
examples/                          # deliberately insecure demo
SEC001 tests/test_redaction.py     # fake keys used by tests
```

Treat changes to that file as security decisions and review them in pull requests. Anyone who can edit it, or add an inline `# agent-latch: ignore` comment, can hide a finding, which is why it is off by default. See [Ignoring false positives](getting-started.md#ignoring-false-positives-and-known-findings) for the full format and the other options.

## Choosing a threshold

| `--fail-on` | Good for |
|---|---|
| `none` | Trying AgentLatch out; reporting only. |
| `high` | Recommended starting point. Blocks shell/code execution, wildcard permissions, unapproved high-risk tools, and hardcoded secrets. |
| `medium` | Stricter. Also blocks prompt-injection signals and unauthenticated remote tools, which are lower-confidence heuristics. |

Start with `high`, review the medium findings by hand, and tighten once the baseline is clean.
