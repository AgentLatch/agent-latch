# AgentLatch — Local-First AI Agent Security Scanner

**Find selected security risks in AI-agent projects before you run or deploy them.** AgentLatch is an open-source, local-first AI agent security scanner that checks Python source and supported configuration files, optionally audits pinned Python dependencies, and reports evidence in your terminal, JSON, or SARIF.

![Example AgentLatch scan showing detected security findings](docs/assets/gent-latch-scan-example.png)

> **Project status: early proof of concept.** AgentLatch is not a complete vulnerability scanner, runtime protection system, security score, or certification. A clean scan means only that the enabled checks did not report a finding.

AgentLatch aims to make AI-agent security checks approachable for developers working with agentic AI. The first version focuses on a small, explainable set of static checks. Framework integrations, runtime authorization, policy enforcement, and evaluations are future layers—not capabilities this scanner currently provides.

## Quick start

Requires Python 3.11+. Install AgentLatch in its own virtual environment (Windows: see [Getting started](docs/getting-started.md#windows-powershell)):

```sh
git clone https://github.com/AgentLatch/agent-latch.git
cd agent-latch
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e .
```

Scan an agent project:

```sh
agent-latch scan /path/to/my-agent
```

Try it on the bundled, deliberately insecure example:

```sh
cd examples/vulnerable-agent
agent-latch scan --config agent-manifest.yaml
```

More ways to run it:

```sh
agent-latch scan --config agent-manifest.yaml        # audit declared tools and prompts
agent-latch scan . --dependencies                    # add known-vulnerability checks (sends package names to PyPI)
agent-latch scan . --fail-on high                    # exit 1 on high-severity findings, for CI
agent-latch scan . --exclude tests/                  # skip a path for one run
agent-latch scan . --format sarif --output results.sarif
agent-latch --interactive                            # guided mode
```

Block risky changes automatically with the [pre-commit hook](docs/ci.md#pre-commit-hook) or the [GitHub Action](docs/ci.md#github-actions):

```yaml
- uses: AgentLatch/agent-latch@v0.1.0
  with:
    fail-on: high
```

## Documentation

| Guide | Covers |
|---|---|
| [Getting started](docs/getting-started.md) | Install on Linux, macOS, WSL, and Windows; scanning; options; [ignoring false positives with `.agent-latch-ignore`](docs/getting-started.md#ignoring-false-positives-and-known-findings); output formats; exit codes; dependency audit; troubleshooting |
| [Agent manifests](docs/agent-manifest.md) | Declaring agents, tools, permissions, and prompts in `agent-manifest.yaml`, and what is checked |
| [pre-commit and CI](docs/ci.md) | pre-commit hook, GitHub Action inputs and outputs, other CI systems, choosing a threshold |
| [Detection rules](docs/RULES.md) | What every rule detects, its OWASP mapping, and its known blind spots |
| [Vulnerable example](examples/vulnerable-agent) | A demo project and the findings it should produce |

## Why AgentLatch?

AI agents combine model-generated decisions with tools, credentials, code execution, and external data. Traditional code and dependency checks are useful, but they do not by themselves explain agent-specific risks. AgentLatch is a small starting point: run selected checks locally, inspect the exact file and evidence, and map relevant findings to OWASP Agentic Top 10 categories.

The goal is to grow in layers:

1. **Now — local scanner:** focused source-pattern checks, optional Python dependency advisories, and portable reports.
2. **Next — broader static and evaluation checks:** more tested rules, framework adapters, and reproducible security test cases.
3. **Later — runtime controls:** a separate policy and audit layer for agent actions, with explicit adapters and enforcement boundaries.

These layers will remain clearly distinguished: detecting a risky pattern is not the same as testing agent behavior, and neither alone guarantees runtime enforcement.

## What it checks today

| Rule | Detection | OWASP Agentic mapping |
|---|---|---|
| `AGENTLATCH-PY001` | Direct Python `eval()` and `exec()` calls | ASI05 Unexpected Code Execution; ASI02 Tool Misuse & Exploitation |
| `AGENTLATCH-PY002` | `subprocess.*(..., shell=True)` calls | ASI05 Unexpected Code Execution; ASI02 Tool Misuse & Exploitation |
| `AGENTLATCH-PY003` | Calls with a literal `verify=False` argument | ASI02 Tool Misuse & Exploitation |
| `AGENTLATCH-AG001` | CrewAI `Agent(..., allow_delegation=True)` review hint | ASI02 Tool Misuse & Exploitation; ASI03 Identity & Privilege Abuse |
| `AGENTLATCH-AG002` | LangChain `create_pandas_dataframe_agent(...)` code-execution capability | ASI05 Unexpected Code Execution; ASI02 Tool Misuse & Exploitation |
| `AGENTLATCH-AG003` | Web-search, web-loader, or HTTP output flowing unfenced into an LLM message (indirect prompt injection) | ASI01 Agent Goal Hijack |
| `AGENTLATCH-SEC001` | Credential-like quoted assignments; matched value is redacted | ASI03 Identity & Privilege Abuse; ASI04 Agentic Supply Chain Vulnerabilities |
| `AGENTLATCH-DEP001` | Known advisory for a package in an audited requirements file | ASI04 Agentic Supply Chain Vulnerabilities |
| `AGENTLATCH-MAN001` | Manifest tool with a high-risk capability and no human-approval gate | ASI02 Tool Misuse & Exploitation; ASI05 / ASI03 |
| `AGENTLATCH-MAN002` | Manifest tool with wildcard permissions | ASI02 Tool Misuse & Exploitation; ASI03 Identity & Privilege Abuse |
| `AGENTLATCH-MAN003` | Manifest tool calling a remote endpoint without authentication | ASI03 Identity & Privilege Abuse; ASI02 Tool Misuse & Exploitation |
| `AGENTLATCH-PRM001` | Prompt-injection signatures in manifest prompts and prompt templates | ASI01 Agent Goal Hijack |
| `AGENTLATCH-PRM002` | User-input placeholder interpolated into a system prompt | ASI01 Agent Goal Hijack |

Rule behavior and known blind spots are documented in [docs/RULES.md](docs/RULES.md). OWASP mappings are informational references, not an OWASP endorsement or certification.

## Reports and data handling

- Scans run locally. They do not call an LLM or upload your source code.
- The one exception is the opt-in dependency audit (`--dependencies`), which sends package names and versions to an advisory service. See [Dependency audit](docs/getting-started.md#dependency-audit).
- Detected secret values are redacted from evidence, but reports still include paths, line numbers, and code context. Review them before sharing.
- Common environment/build directories, symlinks, and files over 1 MB are skipped.

## Important limitations

- Rules are static heuristics: aliases, wrappers, dynamic imports, generated code, non-Python languages, and runtime behavior can be missed.
- Findings can be false positives. A code-pattern match is not proof that an attacker can exploit it.
- No findings does not mean the agent is secure. AgentLatch inspects only prompts declared in an agent manifest and does not inspect model behavior, deployment configuration, live tool calls, or complete transitive dependency state.
- OWASP category IDs help organize selected findings; the mapping is not a compliance assessment, OWASP affiliation, or certification.
- AgentLatch currently scans projects; it is **not** a Python runtime library that intercepts agent actions and does not yet enforce policies.

## Development and tests

```sh
python -m pip install -e ".[dev,audit]"
python -m pytest
ruff check .
```

Tests use synthetic fixtures and mock the dependency-audit subprocess, so they make no network calls. See [CONTRIBUTING.md](CONTRIBUTING.md) for writing new rules.

## Roadmap

The longer-term direction is a layered AI-agent security toolkit. Each layer should have its own stated coverage and tests:

- **Scanner (current):** expand well-scoped rules, language support, dependency manifest support, and SARIF quality.
- **Evaluation (planned):** reproducible test cases for selected agent security behaviors, with transparent methodology and no single opaque “safe” score.
- **Runtime policy and audit (planned, separate component):** authorize, deny, or require approval for tool actions through explicit, framework-specific adapters. Controls only protect execution paths that cannot bypass enforcement.
- **Marketplace and hosted scanning (future, not implemented):** require explicit consent, minimal repository access, retention/deletion policy, tenant isolation, and security review before accepting private source code.

The project will not claim to be an industry standard or a universal security guarantee. Interoperability, independent review, transparent tests, and community adoption must come before such claims.

## Contributing and security reports

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and rule authoring, and [SECURITY.md](SECURITY.md) for responsible vulnerability reporting. Please submit synthetic test fixtures rather than real secrets or confidential source code.

## Name and standards references

AgentLatch is an independent open-source project. It references selected categories from the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) where useful. OWASP is not affiliated with or endorsing AgentLatch.
