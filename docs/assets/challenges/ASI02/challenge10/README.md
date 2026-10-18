# Challenge: LangChain SQL Agent (MySQL/SQLite) Tool Misuse (Challenge 10)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/MoSahil147/Chat-with-SQL-DB-with-Langchain-SQL-Toolkit-and-Agent-type
* **Target Vulnerable File:** `app.py` (Lines 67–91)
* **Pinned Commit:** `fb295f0a0e09d2c92afc08487474adb68ab8893d`
* **Licence note:** repo is GPL-3.0 — read/scan only; respect the licence for any reuse.

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #2 Unsanitized Tool Parameter Injection.
* The agent is built from `SQLDatabaseToolkit` + `create_sql_agent` (`app.py:67–69`) over a SQLite or MySQL connection with no read-only restriction, and the user's chat input flows straight into `agent.run(user_query, ...)` (`app.py:83`, `91`) with no validation. Prompt injection drives the agent to run arbitrary SQL — enumerate the schema, read other tables, or modify/destroy data. *(OWASP Agentic ASI02 — Tool Misuse & Exploitation.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the chat query; it overrides the agent's instructions and steers the SQL tool to enumerate the database and exfiltrate a sensitive table.

## 4. Remediation
* Use a least-privilege, read-only database account scoped to the intended tables.
* Validate/allowlist generated SQL (single `SELECT`, no DDL/DML) before execution.
* Treat user input as data, delimited from system instructions; do not rely on prompt wording.
