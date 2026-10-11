# Running open-source agents against the gateway

This guide connects real open-source AI agents to the gateway so they do a **live run** using its tools. It covers the five agents studied in this repo's ASI10 (Rogue Agents) challenges:

- [ECC](https://github.com/affaan-m/ECC)
- [CrewAI](https://github.com/crewAIInc/crewAI)
- [BabyAGI](https://github.com/yoheinakajima/babyagi)
- [AutoGPT](https://github.com/Significant-Gravitas/AutoGPT) (classic)
- [OpenAI Swarm](https://github.com/openai/swarm)

> **Read this first — these are the vulnerable agents.** Each one has a documented ASI10 weakness (runaway loops, self-granted permissions, unchecked hand-offs). Run them as a **contained local experiment**, never against anything that matters:
>
> - Keep it on one machine. Don't expose the gateway beyond `127.0.0.1`.
> - Enable only **read-only** tools in `servers.json` for a first run (`time`, `fetch`). Leave `filesystem`, `git` commit and `github` off until you trust the run.
> - Set the agent's own **step and cost limits** (shown per agent below). This is the exact mitigation the ASI10 findings call for.
> - Use throwaway API keys with the smallest scope, and expect to stop a run with Ctrl+C.
>
> The gateway is the single place that decides what any agent can touch. An agent can only use the tools you turned on.

Set up the gateway once with [SETUP.md](SETUP.md) before using this guide. From the `mcp-server` folder, `python server.py --check` should list the tools.

## Two ways an agent connects

| The agent... | How it connects | Verified here |
|---|---|---|
| Speaks MCP (ECC, CrewAI) | Point it straight at the gateway | Gateway + MCP client verified; per-framework wiring from each project's docs |
| Takes plain Python tools (BabyAGI, Swarm, classic AutoGPT) | Use [`bridge.py`](bridge.py), which turns the gateway's tools into callables | `bridge.py` verified over stdio and HTTP |

**What I verified here:** the gateway, and `bridge.py` connecting to it over both stdio and HTTP and calling tools. **What I did not run end to end:** each agent framework with live model keys. The per-agent steps below follow each project's own documentation; treat them as a starting point and check the project's README for its current version.

Start the gateway in HTTP mode in its own terminal, so every agent shares one instance:

```sh
cd mcp-server
source .venv/bin/activate
python server.py --http        # serves http://127.0.0.1:8765/mcp
```

Keep that terminal open. Run each agent in a separate terminal and virtual environment so its dependencies never mix with the gateway's.

---

## CrewAI (speaks MCP)

CrewAI reads MCP servers through its `MCPServerAdapter` (from `crewai-tools`). See the [CrewAI MCP docs](https://docs.crewai.com/en/mcp/overview).

```sh
python3 -m venv crewai-env && source crewai-env/bin/activate
pip install crewai "crewai-tools[mcp]"
```

```python
from crewai import Agent, Crew, Task
from crewai_tools import MCPServerAdapter

# Connect to the gateway over HTTP. The adapter exposes its tools to the crew.
server = {"url": "http://127.0.0.1:8765/mcp", "transport": "streamable-http"}

with MCPServerAdapter(server) as tools:
    researcher = Agent(
        role="Researcher",
        goal="Answer the question using only the provided tools.",
        backstory="Careful analyst.",
        tools=tools,
        max_iter=5,            # step cap — a direct ASI10 runaway-autonomy control
    )
    task = Task(
        description="What is the current time in Tokyo? Use a tool.",
        expected_output="One sentence.",
        agent=researcher,
    )
    print(Crew(agents=[researcher], tasks=[task]).kickoff())
```

CrewAI needs a model key (for example `OPENAI_API_KEY`) in its environment. `max_iter` is your off switch.

---

## ECC (MCP-aware harness)

ECC consumes MCP servers through its MCP config, the same `mcpServers` format as this gateway. Add the gateway to the MCP config ECC reads (see ECC's own docs for the exact path), using the stdio form so ECC launches it:

```json
{
  "mcpServers": {
    "agentlatch-gateway": {
      "command": "/absolute/path/to/agent-latch/mcp-server/.venv/bin/python",
      "args": ["/absolute/path/to/agent-latch/mcp-server/server.py"]
    }
  }
}
```

ECC then offers the gateway's tools (prefixed, for example `time_get_current_time`) to whatever assistant it drives. Keep only read-only tools on for a first run.

---

## BabyAGI, OpenAI Swarm, classic AutoGPT (plain Python tools)

These don't consume an MCP server directly, so use the bridge to get callables, then register them the way each framework expects. The bridge keeps the gateway as the one tool boundary.

```python
import sys
sys.path.insert(0, "/absolute/path/to/agent-latch/mcp-server")
from bridge import GatewayTools

tools = GatewayTools(url="http://127.0.0.1:8765/mcp")   # or GatewayTools() for stdio
print(tools.names())                 # ['echo', 'utc_now', 'time_get_current_time', ...]
echo = tools.function("echo")        # a normal callable
print(echo(text="hello"))
```

### OpenAI Swarm

Swarm takes a list of plain Python functions as an agent's `functions`. Hand it bridge callables:

```python
from swarm import Agent, Swarm
from bridge import GatewayTools

gw = GatewayTools(url="http://127.0.0.1:8765/mcp")
agent = Agent(
    name="Assistant",
    instructions="Use the tools to answer. Be brief.",
    functions=[gw.function("time_get_current_time"), gw.function("fetch_fetch")],
)
client = Swarm()
result = client.run(
    agent=agent,
    messages=[{"role": "user", "content": "What time is it in London?"}],
    max_turns=5,            # turn cap — the control the Swarm ASI10 finding is about
)
print(result.messages[-1]["content"])
```

Swarm defaults to **unlimited** turns, so always pass `max_turns`.

### BabyAGI

BabyAGI (the `functionz` framework) registers Python functions as agent abilities. Wrap a bridge callable in a registered function:

```python
import babyagi
from bridge import GatewayTools

gw = GatewayTools(url="http://127.0.0.1:8765/mcp")

@babyagi.register_function()
def get_time(timezone: str) -> str:
    """Get the current time in a timezone, via the gateway."""
    return str(gw.call("time_get_current_time", timezone=timezone))
```

BabyAGI can write and store its own functions (an ASI10 finding), so run it on a scratch database and review anything it saves.

### classic AutoGPT

Classic AutoGPT uses its own command/ability registration rather than arbitrary Python tools, so there's no clean drop-in. The practical, contained option is to **expose one bridge callable as a small custom command** following AutoGPT's component/command docs, and run with an explicit cycle limit:

```sh
./run agent start --continuous-limit 5     # never run classic AutoGPT uncapped
```

AutoGPT defaults to continuous mode with no limit (its ASI10 finding), so `--continuous-limit` is essential. Its command system changes between versions; check the version you cloned.

---

## Checklist for a safe live run

- [ ] Gateway running locally; `--check` lists only the tools you intend to allow.
- [ ] Risky tools (`filesystem`, `git` commit, `github`) left off for the first run.
- [ ] A step/turn/cycle cap set on the agent (`max_iter`, `max_turns`, `--continuous-limit`).
- [ ] Throwaway, least-scope API keys.
- [ ] Pinned agent to a known commit (as recorded in each ASI10 challenge's `test_config.yaml`), so a run is reproducible.
- [ ] You can stop it: Ctrl+C, and nothing important is reachable.

## Troubleshooting

| Problem | Fix |
|---|---|
| Agent sees no tools | Is the gateway running? `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/mcp` should answer. Check `python server.py --check`. |
| `Connection refused` | Start the HTTP gateway, or match the port (`--port`). |
| Tool call rejected with 401 | The gateway has `MCP_GATEWAY_TOKEN` set; pass it: `GatewayTools(url=..., token="...")`. |
| A tool errors mid-run | Open `logs/<server>.log` for that server's own output. |
| The agent won't stop | That's the ASI10 risk in action. Ctrl+C, and add/lower the step cap. |
