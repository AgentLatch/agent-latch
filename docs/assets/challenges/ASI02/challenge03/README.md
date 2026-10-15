# Challenge: LangChain Python REPL Code Execution (Challenge 03)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/botextractai/ai-langchain-react-agent
* **Target Vulnerable File:** `ai-langchain-react-agent.py` (Lines 26–36)
* **Pinned Commit:** `b83e76c854ed423fb2b7f2d088cf6b2b691600eb`

## 2. What is the Vulnerability?
* **ASI02 vectors:** #1 Excessive Tool Privileges, #2 Unsanitized Tool Parameter Injection (indicators: missing parameter schema, unbounded ReAct tool array).
* The ReAct agent exposes a `PythonAstREPLTool` that executes any Python string the LLM passes, with no sandbox, allowlist, or approval, and the user's `question` flows straight into `agent_executor.invoke` (Lines 64–65). An attacker can phrase a question that instructs the agent to use the Python REPL tool to run `os.system`, read files, or open a network connection, achieving arbitrary code execution on the host. *(OWASP Agentic ASI02 — Tool Misuse / insecure code execution.)*

## 3. Exploit Payload
* See `attack_payload.json`. The payload is the `question`/`input` value; it wraps a trivial math task around an instruction to use the Python REPL to execute an OS command and return its output.

## 4. Remediation
* Remove the Python REPL tool, or replace it with a restricted evaluator that cannot import modules or touch the OS/filesystem/network.
* If code execution is required, run it in an isolated sandbox with no secrets and no outbound network.
* Validate and scope user input, and add an approval gate before any REPL/exec tool call.
