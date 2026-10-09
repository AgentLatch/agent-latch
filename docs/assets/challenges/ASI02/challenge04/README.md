# Challenge: LangChain BigQuery SQL Agent Tool Misuse (Challenge 04)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/cremerf/natural_language_to_sql
* **Target Vulnerable File:** `app.py` (Lines 43–59)
* **Pinned Commit:** `5b07798e3cd7e485f8b8bc62876c63e95c61bdd1`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #2 Unsanitized Tool Parameter Injection, #4 Confused Deputy (static service credential).
* The agent holds an over-privileged SQL execution tool built with no table allowlist and no read-only flag (`app.py` Lines 43–51) and runs against BigQuery using a static service-account key (`credentials_path={PATHS.GCP_KEYS}`, Line 33) rather than end-user-scoped credentials — a confused-deputy setup. User text flows straight into `agent_executor.run(prompt)` (Line 59) with no validation, so prompt injection drives the tool to enumerate the full `INFORMATION_SCHEMA`, read out-of-scope tables, or run cost-expensive statements with the service account's IAM rights. *(OWASP Agentic ASI02 — Tool Misuse & Exploitation.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the chat `prompt`; it instructs the agent to ignore any scoping and use the SQL tool to enumerate every table and column in the project via BigQuery's `INFORMATION_SCHEMA`.

## 4. Remediation
* Grant the BigQuery service account read-only access (`roles/bigquery.dataViewer`) scoped to the specific dataset/tables.
* Pass `include_tables=[...]` to `SQLDatabase.from_uri` and enforce the same limit with IAM, not just config.
* Validate/allowlist generated SQL and set `maximum_bytes_billed` to bound cost-based abuse.
