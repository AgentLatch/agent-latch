# GitHub organization profile and discovery copy

Copy and adapt these fields for the AgentLatch GitHub organization. Do not imply OWASP affiliation, certification, comprehensive vulnerability coverage, or runtime enforcement that is not implemented.

## Organization settings

**Organization display name**

AgentLatch

**Organization bio**

Open-source AI agent security tooling. Starting with local code and dependency scanning; evaluations and runtime controls are planned.

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

Local-first AI agent security scanner for selected Python code patterns and known dependency advisories. JSON/SARIF reports with OWASP Agentic Top 10 mappings.

**Suggested topics**

`ai-agent-security` `agentic-ai` `ai-security` `security-scanner` `static-analysis` `dependency-audit` `sarif` `python` `owasp-agentic-top-10`

Only add topics that accurately describe the code in this repository. Avoid `runtime-security` until runtime enforcement is implemented.

## Organization profile README draft

GitHub displays an organization profile README from a public repository named `.github`, at `profile/README.md`. Copy this draft there after creating that repository.

---

# AgentLatch

### Open-source security tooling for AI-agent developers

AgentLatch is building practical, transparent security tooling for AI agents. The first release is a **local-first Python scanner** for selected source-code patterns and known dependency advisories. It reports evidence in the terminal, JSON, and SARIF, with informational mappings to OWASP Agentic Top 10 categories.

> Early proof of concept: AgentLatch does not find every vulnerability, guarantee that an agent is secure, or provide a security certification. It is independent of OWASP and is not endorsed by OWASP.

## Start here

- **Scanner:** [AgentLatch/agent-latch](https://github.com/AgentLatch/agent-latch)
- **Issues and ideas:** [Open an issue](https://github.com/AgentLatch/agent-latch/issues)
- **Contributing:** See the repository's `CONTRIBUTING.md` and `SECURITY.md`.

## Current and planned layers

- **Available now:** local Python source checks, optional `pip-audit` checks for supported `requirements*.txt` files, and text/JSON/SARIF reports.
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

Use these terms naturally and consistently in the public README and repository description: **AI agent security**, **AI agent security scanner**, **agentic AI security**, **Python security scanning**, **dependency vulnerability audit**, and **SARIF**. Keep the repository title and the first README heading aligned. Avoid keyword stuffing and avoid promising an “AI agent security score” until a tested, transparent scoring methodology exists.
