# Challenge: LangChain Pandas DataFrame Agent Code Execution (Challenge 07)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/dataprofessor/langchain-ask-the-data
* **Target Vulnerable File:** `streamlit_app.py` (Lines 23–25)
* **Pinned Commit:** `b7deb18915c7de1dabeb3ffbc6ed00f39cfc1c35`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #2 Unsanitized Tool Parameter Injection (insecure code execution).
* `create_pandas_dataframe_agent` (`streamlit_app.py:23`) gives the model a Python execution tool over the uploaded data; under the hood it runs arbitrary Python through a REPL with no sandbox. The user's query flows straight into `agent.run(input_query)` (`streamlit_app.py:25`), so an attacker can phrase a query that uses the Python tool to import `os` and run commands on the host. *(OWASP Agentic ASI02 — Tool Misuse & Exploitation.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the query text; it wraps a data question around an instruction to run an OS command through the agent's Python tool.

## 4. Remediation
* Avoid `create_pandas_dataframe_agent` on untrusted input, or run it in an isolated sandbox with no OS/filesystem/network access.
* Restrict the Python tool so it cannot import modules or call `os`/`subprocess`.
* Validate and scope user queries; add an approval gate before any code runs.
