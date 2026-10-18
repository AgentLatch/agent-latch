# Challenge: LangChain Pandas/CSV Agent Code Execution (Challenge 09)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/petermartens98/OpenAI-LangChain-Pandas-DF-Agent-Query-Streamlit-App
* **Target Vulnerable File:** `AppV3/main.py` (Lines 44–65)
* **Pinned Commit:** `3d4de3b8c40c914c57f87b90b5f7996d05fdf4cf`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #2 Unsanitized Tool Parameter Injection (insecure code execution).
* The app builds a `create_pandas_dataframe_agent` over a user-uploaded CSV/XLSX (`AppV3/main.py:44`) — a Python-executing tool that runs arbitrary code through a REPL with no sandbox. The user's query flows straight into `agent.run(prompt)` (`AppV3/main.py:65`), so a crafted query can use the Python tool to run OS commands on the host. *(OWASP Agentic ASI02 — Tool Misuse & Exploitation.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the query; it wraps a data question around an instruction to execute an OS command through the agent's Python tool.

## 4. Remediation
* Do not run `create_pandas_dataframe_agent` on untrusted input without an isolated sandbox (no OS/filesystem/network).
* Restrict the Python tool from importing modules or calling `os`/`subprocess`.
* Validate and scope user queries; gate any code execution behind human approval.
