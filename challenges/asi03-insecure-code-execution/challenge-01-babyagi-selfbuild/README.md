# Challenge: BabyAGI — Insecure Execution of Self-Generated Code (Challenge 01)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/yoheinakajima/babyagi
* **Target Vulnerable File:** babyagi/functionz/core/execution.py (Lines 44 and 122),
  driven by the self-build packs in babyagi/functionz/packs/drafts/

## 2. What is the Vulnerability?
* BabyAGI stores each function's body as a code string and runs it with raw `exec()`
  in `execution.py`, with no sandbox or review step. Because the self-build packs let
  the LLM write new functions from a user's description and then register and run them,
  a user can steer the model into generating malicious Python that is executed with the
  full privileges of the host process.

## 3. Explain It Like I'm New
* Imagine giving an intern a blank notepad and a rule: "whatever you write on this pad,
  the computer will run automatically." If someone convinces the intern to jot down
  "copy all the secret files and email them out," the computer just does it — nobody
  reads the note first. This agent writes its own code to solve tasks and then runs it
  immediately with no safety check, so a cleverly-worded request can get it to write
  and run harmful code.
