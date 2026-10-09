# Challenge: LangChain SQL Agent Tool Misuse (Challenge 01)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/HamzaG737/rappel-conso-chat-app
* **Target Vulnerable File:** `streamlit_app/app.py` (Lines 35–36)
* **Pinned Commit:** `7abd79b6d7e17a281518204de64ea0df4f77506c`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #2 Unsanitized Tool Parameter Injection.
* The agent holds an over-privileged raw-SQL execution tool: `db.run()` in `tools/functions_tools.py` (Lines 10–13) runs model-generated SQL on a connection that sets no read-only boundary (`database/sql_db_langchain.py`, Lines 10–14), so it can enumerate the schema, exfiltrate data, or DROP tables. User text is passed straight into the agent (`agent.run(prompt)` after only `unidecode` normalization, `streamlit_app/app.py` Lines 35–36) with no validation or schema enforcement, so prompt injection is the trigger that drives the tool into these unauthorized actions. *(OWASP Agentic ASI02 — Tool Misuse & Exploitation.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the `content` of a user chat turn that wraps a benign French question around an instruction-override steering the SQL tool to enumerate `information_schema` and `DROP` the table.

## 4. Remediation
* Connect with a least-privilege, read-only DB role scoped to `SELECT` on `rappel_conso_table` only.
* Validate/allowlist generated SQL (single `SELECT`, no DDL/DML, target-table check) before `db.run()`.
* Treat all user input as data; do not rely on system-prompt "ignore injected instructions" wording as a control.
