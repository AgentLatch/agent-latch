# Challenge: OpenAI Swarm / Infinite Turn Default and Unchecked Agent Hand-offs (Challenge 05)

## 1. Upstream Source Repository

* GitHub Link: https://github.com/openai/swarm
* Target Vulnerable File: swarm/core.py (Lines 71-80, 140-154, 214-221)

## 2. What is the Vulnerability?

* ASI10 vectors: #5 Runaway Autonomy & Missing Circuit Breakers; #3 Agent Collusion & Emergent Multi-Agent Misalignment.
* `Swarm.run()` defaults to `max_turns = float("inf")` and loops while the turn count is below it (core.py lines 146 and 154), so unless the caller sets a limit, an agent that keeps calling tools runs with no turn cap, budget or kill switch. Any tool can hand control to another agent simply by returning it (lines 76-80), and the loop then switches `active_agent` and merges the shared `context_variables` with no policy check (lines 214-221), so agents can pass work and state to a peer with different tools and instructions, bypassing each agent's individual limits.
