# Challenge: CrewAI / Unchecked Delegation and Persistent Trained Instructions (Challenge 04)

## 1. Upstream Source Repository

* GitHub Link: https://github.com/crewAIInc/crewAI
* Target Vulnerable File: lib/crewai/src/crewai/tools/agent_tools/base_agent_tools.py (Lines 110-120); lib/crewai/src/crewai/agent/core.py (Lines 1430-1449)

## 2. What is the Vulnerability?

* ASI10 vectors: #3 Agent Collusion & Emergent Multi-Agent Misalignment; #4 Persistent Malicious Backdoors in Agent Runtime.
* The delegation tools turn one agent's free-text request into a new Task and run it with the chosen coworker's own tools (base_agent_tools.py lines 110-120), with no independent policy check on what is delegated, so an agent can hand a restricted action to a teammate whose tools allow it. Outside training runs, `_use_trained_data` loads a local trained-data pickle (path overridable by an environment variable) and appends its suggestions under "You MUST follow these instructions" to that role's task prompt (core.py lines 1430-1449) with no provenance or integrity check, so a modified training file persistently steers the agent across all future runs.
