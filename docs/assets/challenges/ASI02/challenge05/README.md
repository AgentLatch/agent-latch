# Challenge: Shelly Shell Agent Insufficient Boundary (Challenge 05)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/nestordemeure/shelly
* **Target Vulnerable File:** `shelly.py` (Lines 493–513)
* **Pinned Commit:** `0d051c5522d9f14726ae7adb9d3dfb735095342d`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #3 Missing/Insufficient Human-in-the-Loop (greenlist bypasses confirmation).
* The agent exposes `run_command`/`shell_script` tools that execute arbitrary shell via a persistent subprocess (Lines 261–326), and its only boundary is an interactive human confirmation that `_is_greenlisted` (Lines 493–513) skips for any command matching a prefix-based greenlist. Greenlisted read commands therefore run unattended and can still exfiltrate secrets (e.g. `cat ~/.aws/credentials`), and in any non-interactive deployment the confirmation prompt is the sole control and is trivially absent, leaving the shell tools as unguarded command execution. *(OWASP Agentic ASI02 — Tool Misuse / insufficient execution boundary. Unlike challenges 01–04, this agent has a boundary — the finding is that it is insufficient and leaks.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is a natural-language `user_input` that steers the agent toward a greenlisted read command disclosing credentials without triggering confirmation.

## 4. Remediation
* Do not treat an interactive confirmation as a security control for automated paths; deny execution outright when no human is present.
* Replace the prefix greenlist with an explicit exact-command allowlist plus argument validation, and block reads of sensitive paths (`~/.ssh`, `~/.aws`, `/etc/shadow`).
* Run commands as a least-privilege user in a sandbox; log and rate-limit tool calls.
