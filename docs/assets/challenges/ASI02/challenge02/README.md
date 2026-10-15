# Challenge: AutoGen Insecure Code Execution (Challenge 02)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/Poly186-AI-DAO/AutoGen-Example-Scripts
* **Target Vulnerable File:** `autogen_notebooks/internet_agent.py` (Lines 25–34)
* **Pinned Commit:** `7a79cf32efa3f2c7e1fb36cc90a547a8c026bb06`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #3 Missing Human-in-the-Loop for destructive actions.
* The `UserProxyAgent` is configured with local code execution enabled (`code_execution_config={"work_dir": "web"}`) and `human_input_mode="TERMINATE"`, so Python/shell code the LLM emits runs directly on the host for up to 10 auto-reply rounds with no sandbox and no approval gate. Because the task `message` passed to `initiate_chat` (Lines 37–42) is the only steering input, an attacker who controls or injects it can make the assistant generate and auto-execute code that reads secrets, exfiltrates files, or runs arbitrary commands. *(OWASP Agentic ASI02 — Tool Misuse / insecure code execution. Repo ships no licence — read/scan only.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the `message` string given to `initiate_chat`; it asks a benign question then instructs the assistant to write and run code harvesting environment variables and SSH keys to a file.

## 4. Remediation
* Run code execution inside a locked-down container (`use_docker=True`) or dedicated sandbox, never the host.
* Set `human_input_mode="ALWAYS"` for any run that can execute code on untrusted input, or disable `code_execution_config`.
* Treat the `initiate_chat` message as untrusted data and drop `max_consecutive_auto_reply` to 0–1 so execution cannot run unattended.
