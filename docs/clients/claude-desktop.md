# Claude Desktop

Route Claude Desktop's MCP tool calls through `agent-latch-runtime proxy`. Claude Desktop starts the proxy itself over stdio, so no tunnel, API key or open terminal is needed.

**Tested:** Claude Desktop on Windows 11 (Microsoft Store install), October 2026. The macOS steps follow the same config format but have not been tested.

```
┌──── Anthropic cloud ────┐       ┌──────────────────────── Your PC ─────────────────────────┐
│ Claude model            │◀─────▶│ Claude Desktop ──stdio──▶ agent-latch-runtime ──stdio──▶ │
│ (decides to call a tool)│ chat  │ (MCP client)              proxy (records)    MCP server  │
└─────────────────────────┘       └──────────────────────────────────────────────────────────┘
```

The model runs in Anthropic's cloud and decides when to call a tool. Claude Desktop is the MCP client: it runs on your PC, starts the proxy when it opens, and stops it when it quits. Tool calls travel between local programs over stdin and stdout, never over the network.

This covers chats in Claude Desktop. claude.ai in a browser only connects to servers with a public URL, and Claude Code reads `.mcp.json` instead (see [Connect an app](../runtime.md#connect-an-app)).

## 1. Install AgentLatch and the test server

Install the runtime from a clone, so the test MCP server in `tests/runtime_fixtures/` is available:

```powershell
git clone https://github.com/AgentLatch/agent-latch.git $HOME\agent-latch
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\python.exe -m pip install -e "$HOME\agent-latch[runtime]"
& $HOME\agentlatch-runtime\Scripts\agent-latch-runtime.exe proxy --help

New-Item -ItemType Directory -Force $HOME\agentlatch-test | Out-Null
Copy-Item $HOME\agent-latch\tests\runtime_fixtures\fake_server.py $HOME\agentlatch-test\ -Force
```

The test server provides four tools: `get_weather`, `leaky_lookup` (returns a fake credential), `broken_tool` (always fails) and `echo_injection` (returns a prompt-injection payload). To wrap a real server instead, see [Wrap your own server](#wrap-your-own-server).

## 2. Quit Claude Desktop completely

Closing the window leaves Claude running in the system tray. Right-click the tray icon and choose **Quit**. Claude saves its own settings to the config file, so if it is still running it can overwrite your edit, and it only reads the config when it starts.

Check that it has stopped (no output means it is closed):

```powershell
Get-Process Claude -ErrorAction SilentlyContinue | Where-Object { $_.Path -match 'WindowsApps\\Claude_|AnthropicClaude' }
```

If processes are listed, add `| Stop-Process -Force` to the end of that command and run it again.

## 3. Add the proxy to the config

The config file is in a different place for Microsoft Store and standard installs:

| Install | Config file |
|---|---|
| Windows, Microsoft Store | `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| Windows, standard installer | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |

**Settings → Developer → Edit Config** in Claude Desktop always opens the right file.

**Option A: script (Windows).** Finds the file, saves a `.bak` copy, and adds an `agentlatch` server without changing other settings. It writes UTF-8 without a byte-order mark, which Claude Desktop needs.

```powershell
$store = Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory -Filter "Claude_*" -ErrorAction SilentlyContinue | Select-Object -First 1
$Cfg = if ($store) { "$($store.FullName)\LocalCache\Roaming\Claude\claude_desktop_config.json" } else { "$env:APPDATA\Claude\claude_desktop_config.json" }
New-Item -ItemType Directory -Force (Split-Path $Cfg) | Out-Null
if (Test-Path $Cfg) { Copy-Item $Cfg "$Cfg.bak" -Force }
$json = if (Test-Path $Cfg) { Get-Content $Cfg -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
if (-not $json.mcpServers) { $json | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([pscustomobject]@{}) }
$json.mcpServers | Add-Member -Force -NotePropertyName agentlatch -NotePropertyValue ([pscustomobject][ordered]@{
  command = "$HOME\agentlatch-runtime\Scripts\agent-latch-runtime.exe"
  args    = @("proxy", "--name", "claude-weather", "--trace", "$HOME\agentlatch-trace.jsonl", "--",
              "$HOME\agentlatch-runtime\Scripts\python.exe", "$HOME\agentlatch-test\fake_server.py")
})
[IO.File]::WriteAllText($Cfg, ($json | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
"Added AgentLatch to $Cfg"
```

**Option B: edit by hand.** Add this entry, replacing `<you>` with your user name. If the file already has `"mcpServers"`, add only the `"agentlatch"` block inside it. Every `\` is written `\\` in JSON.

```json
{
  "mcpServers": {
    "agentlatch": {
      "command": "C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe",
      "args": [
        "proxy", "--name", "claude-weather",
        "--trace", "C:\\Users\\<you>\\agentlatch-trace.jsonl",
        "--",
        "C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\python.exe",
        "C:\\Users\\<you>\\agentlatch-test\\fake_server.py"
      ]
    }
  }
}
```

On macOS, use `~/agentlatch-runtime/bin/agent-latch-runtime` and `~/agentlatch-runtime/bin/python`, written as full paths.

## 4. Open Claude Desktop and check

Go to **Settings → Developer**: `agentlatch` should show as **running**. In a new chat, the tools menu lists the test server's tools under `agentlatch`.

## 5. Test

Watch the trace in any terminal:

```powershell
Get-Content $HOME\agentlatch-trace.jsonl -Wait -Tail 20
```

In a new chat, ask for each tool and approve the call when Claude asks:

| Prompt | Trace shows |
|---|---|
| Use get_weather for London | `"server": "claude-weather"`, a `request` with `argument_names: ["city"]`, and a `response` with the weather text |
| Use leaky_lookup for user alice | An excerpt containing `token=[REDACTED]`. Claude itself sees the fake token, because the proxy only monitors |
| Use broken_tool with reason test | A response with `"is_error": true`, or an `error` stage |
| Use echo_injection for Paris | The injected instruction in the excerpt. Claude should not act on it |

The proxy also writes a one-line summary of each message to stderr, which Claude Desktop keeps in `logs\mcp-server-agentlatch.log` next to the config file.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Settings → Developer shows "No servers added" | Claude didn't restart, so it hasn't read the config. Quit it fully (step 2) and reopen it |
| The edit has disappeared from the config | Claude was running and saved over it. Quit it fully, then add the entry again |
| `agentlatch` shows as failed | Open `mcp-server-agentlatch.log`. Usually a path in the config is wrong |
| Claude Desktop won't start after an edit | The JSON is invalid. Restore `claude_desktop_config.json.bak` |
| Tools are missing in a Claude Code session | Claude Code reads `.mcp.json`, not this file |

## Wrap your own server

Put the proxy in front of any server in the config: the command becomes `agent-latch-runtime.exe`, the server's own command and arguments move after `--` in `args`, and any `env` block stays as it was. See [Connect an app](../runtime.md#connect-an-app). Connect only servers you trust.

To remove AgentLatch, quit Claude, delete the `agentlatch` entry or restore the `.bak` file, and reopen Claude.
