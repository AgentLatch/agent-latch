# GitHub organization profile and discovery copy

Copy and adapt these fields for the AgentLatch GitHub organization. Do not imply OWASP affiliation, certification, comprehensive vulnerability coverage, or runtime enforcement that is not implemented.

## Organization settings

**Organization display name**

AgentLatch

**Organization bio**

Open-source AI agent security tooling. Scan agent code, tool manifests, and prompts for prompt injection and over-privileged tools; evaluations and runtime controls are planned.

**Organization description / tagline**

Practical, transparent security tools for AI-agent developers. Scan selected risks locally today; help shape evaluations and runtime policy controls for tomorrow.

**Website**

https://github.com/AgentLatch/agent-latch

**Location**

Leave blank unless the project has a real public location to list.

**Social links**

Add only official accounts controlled by the project maintainers. Do not create placeholder links.

## Repository “About” fields

**Repository name**

`agent-latch`

**Description**

Local-first AI agent security scanner. Finds prompt injection, over-privileged tools, and secrets in agent code, manifests, and prompts. CLI, pre-commit, GitHub Action, SARIF.

**Suggested topics**

`ai-agent-security` `agentic-ai` `ai-security` `llm-security` `prompt-injection` `security-scanner` `static-analysis` `sast` `sarif` `owasp-agentic-top-10` `langchain` `langgraph` `crewai` `github-actions` `pre-commit-hook` `python`

GitHub allows up to 20 topics. Set them under the repository's **About** gear icon.

Only add topics that accurately describe the code in this repository. Avoid `runtime-security` until runtime enforcement is implemented.

## Organization profile README draft

GitHub displays an organization profile README from a public repository named `.github`, at `profile/README.md`. Copy this draft there after creating that repository.

---

# AgentLatch

### Open-source security tooling for AI-agent developers

AgentLatch is building practical, transparent security tooling for AI agents. The first release is a **local-first AI agent security scanner**. It checks Python agent code, agent manifests, and prompt templates for risks such as prompt injection, over-privileged tools, unauthenticated tool endpoints, and hardcoded secrets, and optionally audits Python dependencies. It runs as a CLI, a pre-commit hook, or a [GitHub Action](https://github.com/marketplace/actions/agentlatch-scan), and reports evidence in the terminal, JSON, and SARIF, with informational mappings to OWASP Agentic Top 10 categories.

> Early proof of concept: AgentLatch does not find every vulnerability, guarantee that an agent is secure, or provide a security certification. It is independent of OWASP and is not endorsed by OWASP.

## Start here

- **Scanner:** [AgentLatch/agent-latch](https://github.com/AgentLatch/agent-latch)
- **Issues and ideas:** [Open an issue](https://github.com/AgentLatch/agent-latch/issues)
- **Contributing:** See the repository's `CONTRIBUTING.md` and `SECURITY.md`.

## Current and planned layers

- **Available now:** Python source checks (including indirect prompt injection data flow), agent manifest and prompt template checks, optional `pip-audit` checks for `requirements*.txt`, text/JSON/SARIF reports, a pre-commit hook, and a GitHub Action.
- **Planned:** broader framework and language coverage, reproducible agent-security evaluations, and a separate runtime policy/audit layer with explicit adapters.

Static findings, behavioral evaluations, and runtime enforcement are different capabilities. Each will have separately documented coverage and limitations.

## Principles

- Local-first scanning; scanned source is not uploaded by the CLI.
- Explicit consent before optional networked dependency auditing.
- Evidence and limitations alongside every finding.
- No claim of complete coverage, OWASP affiliation, or certification.

Contributions, rule tests, independent reviews, and careful reports of false positives are welcome.

---

## Search/discovery guidance

Use these terms naturally and consistently in the public README and repository description: **AI agent security**, **AI agent security scanner**, **agentic AI security**, **LLM security**, **prompt injection**, **indirect prompt injection**, **OWASP Top 10 for Agentic Applications**, **LangChain / LangGraph / CrewAI security**, **GitHub Action**, and **SARIF**. AI answer engines favour pages that answer a concrete question in plain sentences, so keep the README FAQ and `llms.txt` accurate as features change. Keep the repository title and the first README heading aligned. Avoid keyword stuffing and avoid promising an “AI agent security score” until a tested, transparent scoring methodology exists.
