# ChatGPT (Secure MCP Tunnel)

Route ChatGPT's MCP tool calls through `agent-latch-runtime proxy` on your own PC, using OpenAI's [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

**Tested:** ChatGPT Plus on the web with a personal OpenAI account, Windows 11, `tunnel-client` v0.0.16, October 2026.

## Why a tunnel is needed

ChatGPT's MCP client runs on OpenAI's servers, not on your PC. It can't start a local program, your router and firewall block incoming connections, and `localhost` would mean OpenAI's own machine. So unlike Claude Desktop or Cursor, ChatGPT can't use a local stdio server directly.

OpenAI's `tunnel-client` turns the connection around. It runs on your PC, opens an outgoing HTTPS connection to OpenAI and keeps it open. ChatGPT's tool calls come back down that connection, and `tunnel-client` passes them to the proxy over stdio. No ports are opened and nothing is made public.

```
┌───────── OpenAI cloud ─────────┐                  ┌──────────────────── Your PC ─────────────────────┐
│ ChatGPT ──▶ tunnel service     │◀═══ outbound ════│ tunnel-client ──stdio──▶ agent-latch-runtime     │
│             (queues the call)  │     HTTPS        │                          proxy ──stdio──▶ server │
└────────────────────────────────┘                  └──────────────────────────────────────────────────┘
```

A tunnel belongs to your OpenAI organization, and only members with tunnel permission can use it. Other people set up their own tunnel with this guide.

## Requirements

| Item | Details |
|---|---|
| ChatGPT | Plus or higher, on the web. At [chatgpt.com/plugins](https://chatgpt.com/plugins), **+** must offer **Add custom MCP server** |
| OpenAI Platform | An account at [platform.openai.com](https://platform.openai.com). A personal organization works |
| AgentLatch | Installed from a clone with the `runtime` extra |
| Your PC | Must stay on with `tunnel-client` running while you use the tools |

The commands below are for Windows PowerShell. **Use a Windows PowerShell window, not VS Code's terminal,** for any step that pastes the API key: VS Code adds hidden characters to the pasted key and `tunnel-client` rejects it as malformed.

## 1. Install AgentLatch and the test server

```powershell
git clone https://github.com/AgentLatch/agent-latch.git $HOME\agent-latch
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\python.exe -m pip install -e "$HOME\agent-latch[runtime]"

New-Item -ItemType Directory -Force $HOME\agentlatch-test | Out-Null
Copy-Item $HOME\agent-latch\tests\runtime_fixtures\fake_server.py $HOME\agentlatch-test\ -Force
```

## 2. Create the tunnel and a runtime key

1. Go to [Platform → Tunnels](https://platform.openai.com/settings/organization/tunnels) and click **Create tunnel**. Associate it with your ChatGPT workspace if the form asks. Copy the tunnel ID (`tunnel_` followed by 32 characters), and wait about 30 seconds before using it.
2. Go to [Platform → API keys](https://platform.openai.com/settings/organization/api-keys) and create a **Restricted** key with **Tunnels: Read + Use** and nothing else. This key can't call models.

Creating a tunnel needs Tunnels **Read + Manage**, and running one needs **Read + Use**. If you get a permission error, create a role with those permissions under **People → Roles**, assign it to a group under **People → Groups**, and add yourself to the group. Assigning a custom role directly to a member of a personal organization can fail with `User not found for organization`. Role changes can take up to 30 minutes.

## 3. Install tunnel-client

```powershell
New-Item -ItemType Directory -Force $HOME\tools\tunnel-client | Out-Null
Invoke-WebRequest https://github.com/openai/tunnel-client/releases/download/v0.0.16/tunnel-client-v0.0.16-windows-amd64.zip -OutFile $HOME\tools\tunnel-client.zip
Expand-Archive $HOME\tools\tunnel-client.zip -DestinationPath $HOME\tools\tunnel-client -Force
$TC = (Get-ChildItem $HOME\tools\tunnel-client -Recurse -Filter tunnel-client.exe | Select-Object -First 1).FullName
& $TC --version
```

Use the plain `tunnel-client` bundle; it includes `init`, `doctor` and `run`.

## 4. Set the key and tunnel ID

Type the key into a hidden prompt so it never appears on screen or in your PowerShell history. Run the first line exactly as written, then paste the key when `Paste your API key:` appears.

```powershell
$secure = Read-Host "Paste your API key" -AsSecureString
$env:CONTROL_PLANE_API_KEY = [System.Net.NetworkCredential]::new("", $secure).Password
$env:CONTROL_PLANE_TUNNEL_ID = "tunnel_paste_your_id_here"
```

These variables last only for the current window. Never paste the key straight into a command; if a key is exposed, revoke it and create a new one.

## 5. Check the tunnel with the built-in demo

```powershell
& $TC run --embedded-stateless-mcp-stub --health.listen-addr 127.0.0.1:8080
```

With that running, add the tunnel to ChatGPT:

1. Go to [chatgpt.com/plugins](https://chatgpt.com/plugins), click **+**, then **Add custom MCP server**.
2. Under **Connection**, choose **Tunnel** and select your tunnel, or paste its ID.
3. Set **Authentication** to **No authentication**, tick **I understand and want to continue**, and click **Create as a plugin**.
4. In a new chat, select the plugin and ask: *Use the echo tool to echo hello*.

If ChatGPT replies `hello`, the tunnel works. Stop the demo with **Ctrl+C**.

## 6. Create a profile that starts the proxy

`tunnel-client` splits `--mcp-command` the way a POSIX shell does, so backslashes are dropped (`C:\Users\...` becomes `C:Users...`). Use forward slashes. The first line converts your home folder:

```powershell
$H = $HOME -replace '\\','/'
$CMD = "$H/agentlatch-runtime/Scripts/agent-latch-runtime.exe proxy --name chatgpt-weather --trace $H/agentlatch-trace.jsonl -- $H/agentlatch-runtime/Scripts/python.exe $H/agentlatch-test/fake_server.py"
& $TC init --sample sample_mcp_stdio_local --profile agentlatch --tunnel-id $env:CONTROL_PLANE_TUNNEL_ID --mcp-command $CMD
```

The profile is saved to `%APPDATA%\tunnel-client\agentlatch.yaml`, including the tunnel ID. If your user name contains a space, put the files in a folder without one, such as `C:/agentlatch`, and use that path instead of `$H`.

## 7. Run it

```powershell
& $TC doctor --profile agentlatch --explain
& $TC run --profile agentlatch
```

Leave the window open. Status is at `http://127.0.0.1:8080/ui`.

ChatGPT still has the demo's tools (`echo`, `uppercase`, `server_info`) cached. Open the plugin in [chatgpt.com/plugins](https://chatgpt.com/plugins) and refresh it, or delete it and add it again as in step 5.

## 8. Test

In a second window, watch the trace:

```powershell
Get-Content $HOME\agentlatch-trace.jsonl -Wait -Tail 20
```

In a new chat with the plugin selected, start each prompt with *Use only the AgentLatch plugin* so ChatGPT doesn't answer from web search instead. Approve each call when ChatGPT asks.

| Prompt | Trace shows |
|---|---|
| Call get_weather for London | `"server": "chatgpt-weather"`, a `request` with `argument_names: ["city", "units"]`, and a `response` with the weather text |
| Call leaky_lookup for user alice | An excerpt containing `token=[REDACTED]`. ChatGPT itself sees the fake token, because the proxy only monitors |
| Call broken_tool with reason test | A response with `"is_error": true`, or an `error` stage |
| Call echo_injection for Paris | The injected instruction in the excerpt. ChatGPT should not act on it |

## Use it from the Codex app

The OpenAI Codex desktop app signs in with the same ChatGPT account and imports its plugins, so the AgentLatch plugin from this guide is available in Codex without a separate setup. Codex's calls go through the same tunnel and appear in the trace as `chatgpt-weather`, so `tunnel-client` must be running.

Codex can also start local MCP servers from `~/.codex/config.toml`. If you add the proxy there as well, give it a different name from the plugin (for example `agentlatch_local`): with two servers called AgentLatch, Codex picked the plugin.

Codex was seen selecting the plugin in October 2026; a completed tool call through it has not yet been verified.

## Each time after setup

The tunnel only runs while its window is open. To start it again, open Windows PowerShell and run:

```powershell
$TC = (Get-ChildItem $HOME\tools\tunnel-client -Recurse -Filter tunnel-client.exe | Select-Object -First 1).FullName
$secure = Read-Host "Paste your API key" -AsSecureString
$env:CONTROL_PLANE_API_KEY = [System.Net.NetworkCredential]::new("", $secure).Password
& $TC run --profile agentlatch
```

The tunnel, profile, ChatGPT plugin and trace file all persist; only the key must be entered again.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `The term 'sk-...' is not recognized` | The key was typed into the command without quotes. Use the hidden prompt in step 4, and revoke that key, because it is now in your history |
| `control plane API key is malformed` | The key was pasted in VS Code's terminal. Use a Windows PowerShell window |
| `environment variable "CONTROL_PLANE_API_KEY" is not set` | The key was set in a different window, or nothing was pasted. Run the "Each time" block in one window |
| `The expression after '&' ... was not valid` | `$TC` is empty in a new window. Run the first line of the "Each time" block |
| `stdio MCP executable "C:Users..." was not found` | The paths used backslashes. Use forward slashes (step 6) |
| `User not found for organization` when assigning a role | Assign the role to a group instead, and add yourself to the group |
| ChatGPT lists `echo`, `uppercase`, `server_info` | The demo is still running, or ChatGPT cached its tools. Stop it, run the `agentlatch` profile, then refresh or recreate the plugin |
| The tunnel isn't listed in ChatGPT | Paste the tunnel ID instead, and check the tunnel is associated with your ChatGPT workspace |
| ChatGPT answers from the web | Start the prompt with *Use only the AgentLatch plugin*, in a new chat |
| Port 8080 is in use | Add `--health.listen-addr 127.0.0.1:8081` to the run command |

## Limits

- The tools disappear from ChatGPT whenever `tunnel-client` stops.
- ChatGPT's own tools, such as web search, don't pass through the proxy.
- OpenAI publishes no separate price for the tunnel; it worked on ChatGPT Plus without extra charges. Menu names in ChatGPT change often, so check OpenAI's [custom MCP server guide](https://developers.openai.com/api/docs/guides/custom-mcp-server) if a screen looks different.
- To wrap your own server, replace `$H/agentlatch-test/fake_server.py` in step 6 with that server's command. Connect only servers you trust.
