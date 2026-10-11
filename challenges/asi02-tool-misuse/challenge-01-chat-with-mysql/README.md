# Challenge: Chat-with-MySQL — Unrestricted SQL Execution (Challenge 01)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/alejandro-ao/chat-with-mysql
* **Target Vulnerable File:** src/app.py (Lines 53–84, execution at Line 74)

## 2. What is the Vulnerability?
* The agent converts the user's chat message into a SQL query and then runs it
  directly against the database with `db.run(...)` and no restriction to read-only
  statements. A user can therefore phrase a request that makes the model generate a
  destructive or data-exfiltrating query, which the agent executes with the full
  privileges of the connected database account.

## 3. Explain It Like I'm New
* Think of a translator who turns your English into commands and hands them straight
  to a robot that obeys instantly, no questions asked. Normally you say "how many
  customers do we have?" But if you get the translator to produce "delete everything"
  or "read the passwords table," the robot just does it. The agent translates your
  words into SQL and runs whatever comes out — it never stops to ask "is this query
  actually allowed?"
