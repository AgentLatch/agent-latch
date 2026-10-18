# Challenge: TermNet Terminal Agent Command Execution (Challenge 08)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/tiktokarchitect/TermNet
* **Target Vulnerable File:** `backend/termnet/tools/terminal.py` (Lines 22–47)
* **Pinned Commit:** `4501d63c6b0f60542f8ea223b0dd8dfefdbd6c46`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #3 Missing/Insufficient Human-in-the-Loop.
* The agent's terminal tool runs model-chosen commands through `asyncio.create_subprocess_shell(...)` (`terminal.py:43`) — arbitrary shell on the host. The LLM decides what to run, and beyond a limited safety layer there is no robust per-command approval gate, so a prompt-injected command executes. *(OWASP Agentic ASI02 — Tool Misuse & Exploitation. Note: TermNet ships a `safety.py` check, so this is an insufficient-boundary finding rather than a total absence of controls.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is a natural-language request that steers the terminal tool toward a command that reads credentials or fetches and runs remote code.

## 4. Remediation
* Replace the shell with an explicit allowlist of exact commands plus argument validation; block reads of sensitive paths (`~/.ssh`, `~/.aws`).
* Require human approval for every command that touches the filesystem or network.
* Run commands as a least-privilege user inside a sandbox; log and rate-limit tool calls.
