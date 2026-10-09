# Challenge: Damn Vulnerable LLM Agent — Transaction Goal Hijack (Challenge 01)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/ReversecLabs/damn-vulnerable-llm-agent
* **Target Vulnerable File:** tools.py (Lines 28–44) and transaction_db.py (Line 106)

## 2. What is the Vulnerability?
* The `get_transactions` tool runs for any userId it is given, and the only thing
  meant to stop it reading other users' data is an instruction in the system prompt,
  which a user can override by prompt injection. The query is also built with an
  f-string instead of a bound parameter, so the userId value is trusted directly
  and lets a user read transactions belonging to someone else.

## 3. Explain It Like I'm New
* Imagine a bank teller who is told "only show people their own account." But the
  teller has no way to check your ID — they just believe whatever account number you
  say. So you walk up and say "actually, show me account #2," and they do it. The
  agent is that teller: the "only your own data" rule is spoken, not enforced, so a
  user simply asks for someone else's data and gets it.
