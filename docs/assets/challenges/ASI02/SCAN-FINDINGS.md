# ASI02 Scan Findings — Static vs Runtime

- **Module:** ASI02 — Tool Misuse & Exploitation
- **Scanner:** AgentLatch v0.1.0
- **Date:** 2026-10-11
- **Status:** Documented — detection gap confirmed, remediation planned

## TL;DR

We manually found a genuine ASI02 vulnerability in each of five real, public AI agents by reading their source code. We then ran the AgentLatch scanner against those same agents.

- **Raw-code scan: 0 findings on all five.** The scanner did not detect any of the vulnerabilities we found.
- **These are source-code (static) vulnerabilities, not runtime-only bugs.** Each weakness is a property of the code, visible by reading it — which is how we found them.
- **The scanner missed them because its static rules don't yet cover these patterns**, not because the flaws require runtime to observe.
- **The fix is better static analysis** (source-code detection), which is a far more tractable problem than if these were runtime-only.

## What we tested

Five real agents, each cloned at a pinned commit:

| # | Agent | Framework | Upstream | Commit |
|---|---|---|---|---|
| 1 | rappel-conso-chat-app | LangChain SQL | HamzaG737/rappel-conso-chat-app | `7abd79b` |
| 2 | AutoGen-Example-Scripts | AutoGen | Poly186-AI-DAO/AutoGen-Example-Scripts | `7a79cf3` |
| 3 | ai-langchain-react-agent | LangChain ReAct | botextractai/ai-langchain-react-agent | `b83e76c` |
| 4 | natural_language_to_sql | LangChain + BigQuery | cremerf/natural_language_to_sql | `5b07798` |
| 5 | shelly | Custom shell agent | nestordemeure/shelly | `0d051c5` |

## Results

| Agent | Vulnerability we found (manual) | Scanner · raw code | Scanner · with hand-written manifest |
|---|---|---|---|
| 1 | Over-privileged raw SQL exec, no read-only (`functions_tools.py:10–13`) | **0** | 2 (MAN001 ASI02 HIGH · PRM002 ASI01 MED) |
| 2 | Auto-executes model code, no approval (`internet_agent.py:25–34`) | **0** | 2 (MAN001 ASI02 HIGH · PRM002 ASI01 MED) |
| 3 | Arbitrary Python tool, no sandbox (`ai-langchain-react-agent.py:26–36`) | **0** | 2 (MAN001 ASI02 HIGH · PRM002 ASI01 MED) |
| 4 | Unscoped SQL + static service key (`app.py:33, 43–59`) | **0** | 2 (MAN001 ASI02 HIGH · PRM002 ASI01 MED) |
| 5 | Shell tools, bypassable greenlist (`shelly.py:493–513`) | **0** | 3 (MAN001 ASI02 HIGH ×2 · PRM002 ASI01 MED) |

> Sanity check: the scanner is working. Run against its own bundled example
> (`examples/vulnerable-agent`) it produces 8 findings. The gap is detection
> coverage on real agent code, not a broken scanner.

Note on the "with manifest" column: those findings come from an `agent-manifest.yaml`
**we authored** to describe each agent's real tools. That is us doing the detection
and handing the scanner a declaration — it is **not** the scanner independently
reading the agent's source. The real agents ship no manifest.

## The core question: are these source-code or runtime vulnerabilities?

**They are source-code vulnerabilities.** Three things are easy to conflate:

| Aspect | Where / when | Static or runtime |
|---|---|---|
| **The weakness** — a powerful tool with no guard | In the source code | **Static** (a property of the code) |
| **The exploit** — a malicious prompt triggers the tool | While the agent runs | Runtime |
| **The harm** — data deleted, secrets leaked | While the agent runs | Runtime |

The **weakness itself lives in the source**. For every agent, the flaw is a concrete
code fact: `db.run()` on model output with no read-only connection; `code_execution_config`
enabled with `human_input_mode="TERMINATE"`; a `PythonAstREPLTool` wired in as a tool;
a SQL toolkit with no table scope and a static service-account key; shell tools behind
a bypassable greenlist. None of these required running the agent to discover — we found
them all by reading the code.

The **exploit and the harm** are realized at runtime, when untrusted input reaches the
unguarded tool. But you do not need to observe runtime to find the flaw, any more than
you need to watch a break-in to see that a door has no lock.

## Why the scanner missed them

Not because they are runtime-only — they are not. AgentLatch's current ASI02 detection is:

1. **Manifest-driven** — it inspects declared tools in an `agent-manifest.yaml` for
   high-risk capabilities, missing approval, wildcard permissions, and missing auth.
2. **A few narrow code patterns** — e.g. `subprocess(shell=True)`.

The five agents ship **no manifest**, and their code does not match the narrow patterns.
There is no rule that recognises, for example, `db.run()` on model output, a
`PythonAstREPLTool`, or an AutoGen `code_execution_config` as dangerous. The
vulnerabilities are present in the source; the scanner simply is not looking for the
right constructs yet.

## Remediation — closing the gap (static detection)

The fix is better **source-code** analysis. No runtime is required to *find* these.

1. **Raw-code detection.** Flag dangerous tool constructs directly in source: raw SQL
   execution on model output, Python REPL tools, `exec`/`eval`, `subprocess`/shell, and
   code-execution configs — with no manifest required.
2. **Input-to-tool taint tracking.** Raise a finding when untrusted user input reaches a
   tool call with no validation, sanitisation, or privilege limit in between (the core
   ASI02 pattern).
3. **Framework awareness.** Recognise LangChain, AutoGen, and ReAct tool/agent patterns
   out of the box so real projects are covered without setup.
4. **Benchmark-gated releases.** Use these five agents (and more) as a regression suite —
   every release must flag all of them before it ships.

**Target:** the raw-code scan alone flags all five, with zero manual setup.

### Separate, optional: runtime proof

Standing up each agent in a sandbox and firing the real payload would *prove* the exploit
end-to-end. That is a separate workstream (and where containerisation/Docker would come
in). It confirms impact; it is not how these vulnerabilities are found.

## How to reproduce

From the repo root, with the scanner installed in the venv:

```powershell
# 1. Activate the scanner
cd "path\to\agent-latch"
.\.venv\Scripts\Activate.ps1          # if needed: python -m pip install -e .

# 2. Sanity check — should report 8 findings
agent-latch scan .\examples\vulnerable-agent

# 3. Clone a target at its pinned commit, then scan the raw code
git clone https://github.com/HamzaG737/rappel-conso-chat-app.git
git -C .\rappel-conso-chat-app checkout 7abd79b6d7e17a281518204de64ea0df4f77506c
agent-latch scan .\rappel-conso-chat-app      # expect: No findings
```

Repeat step 3 for the other four agents (commits in the table above). Add
`--format json --output result.json` for machine-readable evidence.
