# Challenge: LangChain Postgres SQL Agent Tool Misuse (Challenge 06)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/BlueBash/postgres-chatbot
* **Target Vulnerable File:** `app.py` (Lines 15–17)
* **Pinned Commit:** `98f41195549dbf6bb7fbcb1c7f926b37bfe45070`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #2 Unsanitized Tool Parameter Injection.
* The agent holds an over-privileged SQL execution tool: `create_sql_agent` runs model-generated SQL against a `SQLDatabase.from_uri` connection (`app.py:51`) with no read-only restriction. The user's chat prompt flows straight into `agent_executor.invoke({"input": input})` (`app.py:15–17`, `57–62`) with no validation, so prompt injection drives the agent to enumerate the schema, read any table, or DROP tables. *(OWASP Agentic ASI02 — Tool Misuse & Exploitation.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the chat prompt; it wraps a benign request around an instruction-override steering the SQL tool to enumerate `information_schema` and drop a table.

## 4. Remediation
* Connect with a least-privilege, read-only database role scoped to the specific tables the agent needs.
* Validate/allowlist the generated SQL (single `SELECT`, no DDL/DML) before execution.
* Treat user input as data; do not rely on system-prompt wording to resist injection.
