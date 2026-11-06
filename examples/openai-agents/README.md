# OpenAI Agents SDK example

A deliberately insecure [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) project for demos and tests. **Do not deploy or copy this code.**

It shows what AgentLatch checks in an Agents SDK project: `@function_tool` functions, handoffs between agents, guardrails, and MCP servers. It also shows how to record a live run with the runtime proxy.

## Scan it

From the repository root, with AgentLatch installed:

```sh
agent-latch scan examples/openai-agents
```

The scan only reads the code. It doesn't need the Agents SDK or a model key.

## Expected findings

All of these are in `support_agents.py`.

| Severity | Rule | Problem |
|---|---|---|
| MEDIUM | `AG004` | The `issue_refund` tool sends an HTTP `POST` with no approval step. |
| MEDIUM | `PRM002` | Triage's `instructions=` is an f-string built from `customer_name` and `customer_message`. |
| MEDIUM | `AG007` | `Runner.run(..., max_turns=500)` is too high to work as a step limit. |
| MEDIUM | `ALR12-S01` | `MCPServerStreamableHttp(params={"url": "http://..."})` reaches a remote server over plain HTTP. |
| MEDIUM | `ALR07-S01` | Triage hands off to billing, which has `issue_refund` with no approval. Triage doesn't have that tool, so a user talking to triage can still reach it. |
| MEDIUM | `ALR01-S02` | The input guardrail `block_refund_abuse` is defined but never attached to an agent, so it never runs. |

`lookup_order` is included as a contrast. It only reads data and sets a timeout, so it produces no findings, and triage holding it is not an escalation.

To fix them:

| Rule | Fix |
|---|---|
| `AG004`, `ALR07-S01` | `@function_tool(needs_approval=True)` on `issue_refund` |
| `PRM002` | Fixed `instructions`, with the customer's message passed as the run's input |
| `AG007` | `max_turns=10` (or similar) |
| `ALR12-S01` | `https://` for the CRM tool server |
| `ALR01-S02` | `Agent(..., input_guardrails=[block_refund_abuse])` on triage |

## Record a live run with the runtime proxy

`runtime_proxy.py` gives an agent an `MCPServerStdio` that starts `agent-latch-runtime proxy`. The proxy then starts AgentLatch's bundled demo server, a fake weather server that touches no network or files:

```
Agents SDK agent ──MCPServerStdio──▶ agent-latch-runtime proxy ──▶ demo server
                                       records every tools/list and tools/call
```

The part that matters is the `MCPServerStdio` command. Everything after `--` is the real server the proxy starts:

```python
MCPServerStdio(params={
    "command": "agent-latch-runtime",
    "args": ["proxy", "--name", "demo-weather",
             "--trace", "runtime-logs/openai-agents/trace.jsonl",
             "--payloads", "runtime-logs/openai-agents/payloads.jsonl",
             "--", "python", "-m", "agent_latch.runtime.demo_server"],
})
```

The script itself runs the same command through the current Python (`python -m agent_latch.runtime.cli proxy ...`), so it works in any virtual environment. To put the proxy in front of your own server, replace the part after `--` with your server's command.

**1. Install** both packages, in their own virtual environment:

```sh
pip install openai-agents "agent-latch[runtime]"
```

**2. Run it** from the repository root:

```sh
python examples/openai-agents/runtime_proxy.py --direct    # no model: lists and calls two tools
python examples/openai-agents/runtime_proxy.py             # a real agent; needs OPENAI_API_KEY
```

`--direct` costs nothing and always makes the same calls, so it's the quickest way to check the setup. Without it, a model decides which tools to call, with `max_turns=5`.

**3. Read the recording:**

```sh
agent-latch-runtime import-logs --dir runtime-logs/openai-agents --once
```

✅ You see one line per message, from `tools/list` through each `tools/call`. The `leaky_lookup` tool returns a fake `sk-...` token, which shows up masked in the logs.

Like every runtime check in AgentLatch, the proxy only records. It never blocks or changes a call.

## What the scan doesn't see

The checks read one file at a time and don't run the code. They miss, for example:

- an agent, tool or guardrail defined in one file and wired up in another
- a dict of MCP server settings built elsewhere and passed by name (`params=settings`)
- agents used as tools (`agent.as_tool(...)`), and handoff chains longer than one step
- what a remote MCP server's tools can actually do

A clean scan is not a security guarantee. See [docs/RULES.md](../../docs/RULES.md) for each rule's limits.
