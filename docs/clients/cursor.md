# Cursor

Route Cursor's MCP tool calls through `agent-latch-runtime proxy`. Cursor starts the proxy itself over stdio, so no tunnel, API key or open terminal is needed.

**Tested:** Cursor desktop on Windows 11, October 2026, with the global config file.

```
┌──── Cursor cloud ───────┐       ┌──────────────────────── Your PC ─────────────────────────┐
│ AI model                │◀─────▶│ Cursor ──stdio──▶ agent-latch-runtime ──stdio──▶         │
│ (decides to call a tool)│ chat  │ (MCP client)      proxy (records)        MCP server      │
└─────────────────────────┘       └──────────────────────────────────────────────────────────┘
```

Cursor's MCP client runs in the desktop app on your PC. It reads `mcp.json` when it starts, launches the proxy, and stops it when it closes. Cursor Cloud Agents run on Cursor's servers instead, so they can't start a local proxy.

## 1. Install AgentLatch and the test server

Install the runtime from a clone, so the test MCP server in `tests/runtime_fixtures/` is available:

```powershell
git clone https://github.com/AgentLatch/agent-latch.git $HOME\agent-latch
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\python.exe -m pip install -e "$HOME\agent-latch[runtime]"

New-Item -ItemType Directory -Force $HOME\agentlatch-test | Out-Null
Copy-Item $HOME\agent-latch\tests\runtime_fixtures\fake_server.py $HOME\agentlatch-test\ -Force
```

## 2. Add the proxy to Cursor's config

Cursor reads MCP servers from two places:

| File | Applies to |
|---|---|
| `~/.cursor/mcp.json` (`C:\Users\<you>\.cursor\mcp.json`) | Every project. Used in this guide |
| `.cursor/mcp.json` in a project folder | Only that project |

Create or edit `C:\Users\<you>\.cursor\mcp.json`, replacing `<you>` with your user name. If the file already has `"mcpServers"`, add only the `"agentlatch"` block inside it. Every `\` is written `\\` in JSON.

```json
{
  "mcpServers": {
    "agentlatch": {
      "type": "stdio",
      "command": "C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe",
      "args": [
        "proxy", "--name", "cursor-weather",
        "--trace", "C:\\Users\\<you>\\agentlatch-trace.jsonl",
        "--",
        "C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\python.exe",
        "C:\\Users\\<you>\\agentlatch-test\\fake_server.py"
      ]
    }
  }
}
```

Or let PowerShell write it with your paths filled in (this replaces the file, so only use it if you have no other servers in it):

```powershell
$entry = [ordered]@{ mcpServers = [ordered]@{ agentlatch = [ordered]@{
  type    = "stdio"
  command = "$HOME\agentlatch-runtime\Scripts\agent-latch-runtime.exe"
  args    = @("proxy", "--name", "cursor-weather", "--trace", "$HOME\agentlatch-trace.jsonl", "--",
              "$HOME\agentlatch-runtime\Scripts\python.exe", "$HOME\agentlatch-test\fake_server.py")
} } }
New-Item -ItemType Directory -Force $HOME\.cursor | Out-Null
[IO.File]::WriteAllText("$HOME\.cursor\mcp.json", ($entry | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
```

**Use full paths.** Cursor's docs list `${userHome}` as a variable for `command` and `args`, but on Windows a config using it failed with `The filename, directory name, or volume label syntax is incorrect.` Full paths worked.

## 3. Check that Cursor connected

Cursor reloads `mcp.json` when it changes; restart it if nothing happens. Open **Customize → MCPs** in the sidebar (or **Cursor Settings → Tools & MCP**):

- A green dot next to `agentlatch` means it connected, and the test server's 4 tools are listed.
- A red dot with **Error - Show Output** opens the server's log. See [Troubleshooting](#troubleshooting).

Cursor writes the proxy's stderr to the log, so normal lines such as `agent-latch-runtime: tools/list -> 4 tool(s)` appear with an `[error]` label. They are not errors.

## 4. Test

Watch the trace in any terminal:

```powershell
Get-Content $HOME\agentlatch-trace.jsonl -Wait -Tail 20
```

Open chat (`Ctrl+L`) in **Agent** mode, ask for each tool, and click **Run** when Cursor asks to approve the call:

| Prompt | Trace shows |
|---|---|
| Use the agentlatch get_weather tool for London | `"server": "cursor-weather"`, a `request` with `argument_names: ["city"]`, and a `response` with the weather text |
| Use the agentlatch leaky_lookup tool for user alice | An excerpt containing `token=[REDACTED]`. Cursor itself shows the fake token, because the proxy only monitors |
| Use the agentlatch broken_tool tool with reason test | A response with `"is_error": true`, or an `error` stage |
| Use the agentlatch echo_injection tool for Paris | The injected instruction in the excerpt. Cursor should not act on it |

Naming the server ("the agentlatch … tool") stops the model from answering another way, such as by searching the web.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Red dot; the log shows `The filename, directory name, or volume label syntax is incorrect.` | A path is invalid on Windows. Replace any `${userHome}` with the full path, and check each file exists |
| Red dot; the log shows `Connection closed` with a Python error | The proxy started but the server failed. Run the same command in a terminal to see the error |
| A path contains a space | Cursor is reported to split the command at spaces on Windows. Move the files to a folder without spaces, such as `C:\agentlatch` |
| The tools don't appear in chat | Switch chat to Agent mode, and check `agentlatch` is enabled in Customize → MCPs |

The full log is in `%APPDATA%\Cursor\logs\<session>\mcp-server-user-agentlatch.log`, or in Cursor's **Output** panel under **MCP: user-agentlatch**.

## Wrap your own server

Put the proxy in front of any server in `mcp.json`: the command becomes `agent-latch-runtime.exe`, the server's own command and arguments move after `--` in `args`, and any `env` block stays as it was. See [Connect an app](../runtime.md#connect-an-app). Connect only servers you trust.

To turn AgentLatch off without deleting it, use the toggle next to `agentlatch` in Customize → MCPs.
