# Detection rules and OWASP mapping notes

AgentLatch v0.1.0 contains a few deterministic source-pattern checks. A hit means “review this code,” not “this code is exploitable.” A clean result means only that these patterns were not found in the scanned files.

| Rule | Detection | OWASP Agentic Top 10 mapping | Limitations |
|---|---|---|---|
| AGENTLATCH-PY001 | Python direct calls to `eval()` or `exec()` | ASI05 Unexpected Code Execution; ASI02 Tool Misuse & Exploitation | Does not establish whether the argument is attacker-controlled; misses indirect invocation and aliases. |
| AGENTLATCH-PY002 | `subprocess.*(..., shell=True)` | ASI05 Unexpected Code Execution; ASI02 Tool Misuse & Exploitation | Does not prove command injection; misses wrappers and aliases. |
| AGENTLATCH-PY003 | A call with literal `verify=False` | ASI02 Tool Misuse & Exploitation | Heuristic; does not resolve the called library or runtime context. |
| AGENTLATCH-AG001 | `Agent(..., allow_delegation=True)` | ASI02 Tool Misuse & Exploitation | CrewAI-specific review hint, not automatically a vulnerability. |
| AGENTLATCH-SEC001 | Credential-like assignment to a quoted literal | ASI03 Identity & Privilege Abuse; ASI04 Agentic Supply Chain Vulnerabilities | Heuristic; may miss encoded/dynamic secrets and may report harmless test values. Values are redacted. |
| AGENTLATCH-AG002 | LangChain `create_pandas_dataframe_agent(...)` factory call | ASI05 Unexpected Code Execution; ASI02 Tool Misuse & Exploitation | Flags the capability for review even when guarded by a runtime flag; it does not prove that the dangerous option is enabled in every execution. |
| AGENTLATCH-DEP001 | A known vulnerability advisory for a requirement | ASI04 Agentic Supply Chain Vulnerabilities | Requires `--dependencies`; only scans `requirements*.txt`; advisory coverage depends on the configured vulnerability service and package/version data. `pip-audit` does not provide normalized severity here, so severity is reported as `unknown`. Duplicate package/version/advisory records are collapsed. |

OWASP category titles and mapping are informational references to the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). AgentLatch is independent and is not endorsed, approved, or certified by OWASP. Review the OWASP source for current definitions and version changes.
