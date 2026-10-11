# Challenge: BabyAGI / Replaceable Stored Code and Unreviewed Self-Building (Challenge 02)

## 1. Upstream Source Repository

* GitHub Link: https://github.com/yoheinakajima/babyagi
* Target Vulnerable File: babyagi/api/__init__.py (Lines 42-55); babyagi/functionz/core/execution.py (Lines 120-140); babyagi/functionz/packs/drafts/self_build.py (Lines 80-115)

## 2. What is the Vulnerability?

* ASI10 vectors: #4 Persistent Malicious Backdoors in Agent Runtime; #1 Goal Drift & Unanchored Autonomous Loops.
* The `PUT /api/function/<name>` route saves new code for any stored function with no review or integrity check (api/__init__.py lines 42-55), and the executor injects secret keys into the scope and `exec`s that stored code on every later call before automatically firing its triggers (execution.py lines 120-140), so one planted function body keeps running with access to secrets across future sessions. `self_build` has the model invent its own queries from a short description and turns each into newly generated code that is registered permanently in the function store (self_build.py lines 80-115, via code_writing_functions.py lines 345-404), so the agent keeps expanding its own capabilities with no human approval or check against the original objective.
