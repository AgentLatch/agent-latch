# GitHub Copilot in VS Code

Route GitHub Copilot's MCP tool calls in VS Code through `agent-latch-runtime proxy`. VS Code starts the proxy itself over stdio, so no tunnel, API key or open terminal is needed.

**Tested:** VS Code 1.142 on Windows 11 with GitHub Copilot Chat (built in), Agent mode, October 2026, using a workspace `.vscode/mcp.json`.

```
┌──── GitHub cloud ───────┐       ┌──────────────────────── Your PC ─────────────────────────┐
│ Copilot model           │◀─────▶│ VS Code ──stdio──▶ agent-latch-runtime ──stdio──▶        │
│ (decides to call a tool)│ chat  │ (MCP client)       proxy (records)        MCP server     │
└─────────────────────────┘       └──────────────────────────────────────────────────────────┘
```

VS Code is the MCP client: it runs on your PC and starts the proxy when you start the server. The Copilot coding agent on GitHub.com runs in the cloud instead, so it can't start a local proxy.

## Requirements

| Item | Details |
|---|---|
| VS Code | 1.102 or newer. Copilot Chat is built in to current versions |
| GitHub Copilot | Signed in through the Copilot icon in the status bar. Use Copilot Chat **inside VS Code** (`Ctrl+Alt+I`), not Copilot on github.com: the web chat runs in GitHub's cloud and can't reach a local server. MCP tools only run in **Agent** mode |
| AgentLatch | Installed from a clone with the `runtime` extra |

## 1. Install AgentLatch and the test server

```powershell
git clone https://github.com/AgentLatch/agent-latch.git $HOME\agent-latch
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\python.exe -m pip install -e "$HOME\agent-latch[runtime]"

New-Item -ItemType Directory -Force $HOME\agentlatch-test | Out-Null
Copy-Item $HOME\agent-latch\tests\runtime_fixtures\fake_server.py $HOME\agentlatch-test\ -Force
```

## 2. Add the proxy to the workspace config

Create `.vscode/mcp.json` in the folder you open in VS Code, replacing `<you>` with your user name. VS Code uses a top-level `"servers"` key, not `"mcpServers"`, and every `\` is written `\\` in JSON.

```json
{
  "servers": {
    "agentlatch": {
      "type": "stdio",
      "command": "C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe",
      "args": [
        "proxy", "--name", "copilot-weather",
        "--trace", "C:\\Users\\<you>\\agentlatch-trace.jsonl",
        "--",
        "C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\python.exe",
        "C:\\Users\\<you>\\agentlatch-test\\fake_server.py"
      ]
    }
  }
}
```

A workspace config applies only to that folder. To make the server available in every folder, run **MCP: Open User Configuration** from the Command Palette and add the same `"agentlatch"` entry there.

If the folder is a git repository, this file contains your local paths. Keep it out of commits, for example by adding `.vscode/mcp.json` to `.git/info/exclude`.

## 3. Start the server

VS Code doesn't start a new server on its own. Open `.vscode/mcp.json` and click **Start** above `"agentlatch"`, or run **MCP: List Servers** from the Command Palette (`Ctrl+Shift+P`), choose `agentlatch` and **Start Server**.

The server shows as **Running** with 4 tools. If it fails, choose **Show Output** to see the proxy's log.

## 4. Test

Watch the trace in any terminal:

```powershell
Get-Content $HOME\agentlatch-trace.jsonl -Wait -Tail 20
```

Open Copilot Chat (`Ctrl+Alt+I`), switch the mode to **Agent**, and check that `agentlatch` is ticked under the tools icon. Ask for each tool and allow the call when Copilot asks:

| Prompt | Trace shows |
|---|---|
| Use the agentlatch get_weather tool for London | `"server": "copilot-weather"`, a `request` with `argument_names: ["city"]`, and a `response` with the weather text |
| Use the agentlatch leaky_lookup tool for user alice | An excerpt containing `token=[REDACTED]`. Copilot itself shows the fake token, because the proxy only monitors |
| Use the agentlatch broken_tool tool with reason test | A response with `"is_error": true`, or an `error` stage |
| Use the agentlatch echo_injection tool for Paris | The injected instruction in the excerpt. Copilot should not act on it |

VS Code lists the tools again after each call, so the trace has an extra `tools/list` record after every `tools/call`. This is expected.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Chat says you need to upgrade for Agent mode | You may be using Copilot on github.com. Open Copilot Chat inside VS Code (`Ctrl+Alt+I`) instead. If VS Code shows it too, check you are signed in, choose a model without a premium label, and check your monthly usage in the Copilot status menu |
| The tools icon doesn't list `agentlatch` | The server isn't started. Start it from `mcp.json` or **MCP: List Servers** |
| The server fails to start | Choose **Show Output**. Usually a path is wrong; check each file exists |
| The tools are missing in another folder | `.vscode/mcp.json` applies only to its own folder. Use the user configuration instead |

## Wrap your own server

Put the proxy in front of any server in `mcp.json`: the command becomes `agent-latch-runtime.exe`, the server's own command and arguments move after `--` in `args`, and any `env` block stays as it was. See [Connect an app](../runtime.md#connect-an-app). Connect only servers you trust.
