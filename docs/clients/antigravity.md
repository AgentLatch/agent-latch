# Gemini in Google Antigravity

Route Gemini's MCP tool calls in Google Antigravity through `agent-latch-runtime proxy`. Antigravity starts the proxy itself over stdio, so no tunnel, API key or open terminal is needed.

**Tested:** Antigravity desktop on Windows 11, signed in with a personal Google account, October 2026, using the global config file.

```
┌──── Google cloud ───────┐       ┌──────────────────────── Your PC ─────────────────────────┐
│ Gemini model            │◀─────▶│ Antigravity ──stdio──▶ agent-latch-runtime ──stdio──▶    │
│ (decides to call a tool)│ chat  │ (MCP client)           proxy (records)        MCP server │
└─────────────────────────┘       └──────────────────────────────────────────────────────────┘
```

Antigravity is the MCP client: it runs on your PC and starts the proxy from its config. Google moved free, AI Pro and Ultra users from Gemini CLI to Antigravity on 18 June 2026, so this guide uses Antigravity. The Gemini web app only connects to servers by URL and can't start a local proxy.

## 1. Install AgentLatch and the test server

```powershell
git clone https://github.com/AgentLatch/agent-latch.git $HOME\agent-latch
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\python.exe -m pip install -e "$HOME\agent-latch[runtime]"

New-Item -ItemType Directory -Force $HOME\agentlatch-test | Out-Null
Copy-Item $HOME\agent-latch\tests\runtime_fixtures\fake_server.py $HOME\agentlatch-test\ -Force
```

Install Antigravity from [antigravity.google](https://antigravity.google) and sign in with your Google account.

## 2. Add the proxy to Antigravity's config

Antigravity reads MCP servers from two places ([Antigravity MCP docs](https://antigravity.google/docs/mcp)):

| File | Applies to |
|---|---|
| `~/.gemini/config/mcp_config.json` (`C:\Users\<you>\.gemini\config\mcp_config.json`) | Every workspace. Used in this guide |
| `.agents/mcp_config.json` in a workspace folder | Only that workspace |

Create or edit the global file, replacing `<you>` with your user name. If it already has `"mcpServers"`, add only the `"agentlatch"` block inside it. Every `\` is written `\\` in JSON.

```json
{
  "mcpServers": {
    "agentlatch": {
      "command": "C:\\Users\\<you>\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe",
      "args": [
        "proxy", "--name", "gemini-weather",
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
  command = "$HOME\agentlatch-runtime\Scripts\agent-latch-runtime.exe"
  args    = @("proxy", "--name", "gemini-weather", "--trace", "$HOME\agentlatch-trace.jsonl", "--",
              "$HOME\agentlatch-runtime\Scripts\python.exe", "$HOME\agentlatch-test\fake_server.py")
} } }
New-Item -ItemType Directory -Force $HOME\.gemini\config | Out-Null
[IO.File]::WriteAllText("$HOME\.gemini\config\mcp_config.json", ($entry | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
```

Antigravity's docs don't mention path variables such as `${userHome}`, so use full paths.

## 3. Check that Antigravity connected

Click **Settings** at the bottom left, open **Customizations**, and look under **Installed MCP Servers**. `agentlatch` is listed and enabled, with the test server's 4 tools. If it's missing, click the refresh button there, or restart Antigravity.

## 4. Test

Watch the trace in any terminal:

```powershell
Get-Content $HOME\agentlatch-trace.jsonl -Wait -Tail 20
```

In Antigravity's agent chat, ask for each tool. MCP tools run in **Ask** mode by default, so approve each call:

| Prompt | Trace shows |
|---|---|
| Use the agentlatch get_weather tool for London | `"server": "gemini-weather"`, a `request` with `argument_names: ["city"]`, and a `response` with the weather text |
| Use the agentlatch leaky_lookup tool for user alice | An excerpt containing `token=[REDACTED]`. Gemini itself sees the fake token, because the proxy only monitors |
| Use the agentlatch broken_tool tool with reason test | A response with `"is_error": true`, or an `error` stage |
| Use the agentlatch echo_injection tool for Paris | The injected instruction in the excerpt. Gemini should not act on it |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `agentlatch` isn't listed | Check the file is at `~/.gemini/config/mcp_config.json` (inside `config`), then refresh or restart Antigravity |
| The server shows an error | A path in the config is usually wrong. Check each file exists, and run the same command in a terminal to see the error |
| Gemini answers without calling the tool | Name the server and tool in the prompt, as in the table above |
| Free-plan requests run out | Antigravity's free plan has weekly limits. Wait for the reset or use a paid plan |

## Wrap your own server

Put the proxy in front of any server in `mcp_config.json`: the command becomes `agent-latch-runtime.exe`, the server's own command and arguments move after `--` in `args`, and any `env` block stays as it was. See [Connect an app](../runtime.md#connect-an-app). Connect only servers you trust.

To turn AgentLatch off without deleting it, use its toggle under **Installed MCP Servers**.
