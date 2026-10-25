# Connect AgentLatch to GitHub Copilot in VS Code

This guide connects AgentLatch to GitHub Copilot in VS Code on Windows, macOS or Linux. Afterwards, every time Copilot uses a tool, AgentLatch writes a record of it to a log file on your computer, with any secrets hidden. AgentLatch only watches: it never changes or blocks what Copilot does.

It takes about 10 minutes. You don't need to know how to code; you'll copy and paste a few commands.

**Tested:** VS Code 1.142 on Windows 11 with GitHub Copilot Chat in **Agent** mode, October 2026. The macOS and Linux steps use the same settings with those systems' file locations, but haven't been tested end to end yet.

This guide is for Copilot Chat **inside VS Code**. Copilot on github.com runs on GitHub's servers and can't start programs on your computer, so it can't use AgentLatch.

## How it works

Copilot can use extra tools, such as "get the weather" or "look up a customer". The tools come from small programs called **MCP servers**. You tell VS Code which ones to start by listing them in a settings file called `mcp.json`.

AgentLatch sits between VS Code and the tools. VS Code starts AgentLatch, AgentLatch starts the tools, and every request passing through is written to the log:

```
VS Code (Copilot)  ──▶  AgentLatch  ──▶  the tools
                            │
                            ▼
               agentlatch-trace.jsonl  (the log)
```

Everything runs on your own computer. Nothing is sent to AgentLatch, and you don't need an account or an API key.

## Before you start

You need:

- **VS Code** 1.102 or newer, from [code.visualstudio.com](https://code.visualstudio.com). Copilot Chat is built in.
- **GitHub Copilot**: sign in with your GitHub account through the Copilot icon in VS Code's status bar (bottom right). The free plan works.
- **Python 3.11 or newer** and **Git**:

| | Windows | macOS | Linux |
|---|---|---|---|
| **Python 3.11+** | [python.org](https://www.python.org/downloads/). Tick **Add python.exe to PATH** when installing | [python.org](https://www.python.org/downloads/), or `brew install python` | Usually installed. On Ubuntu/Debian, also run `sudo apt install python3-venv` |
| **Git** | [git-scm.com](https://git-scm.com/download/win) | Run `git --version`; if it isn't installed, macOS offers to install it | Usually installed. Otherwise `sudo apt install git` (Ubuntu/Debian) or `sudo dnf install git` (Fedora) |
| **Where to run commands** | **Windows PowerShell**: press the Windows key, type `PowerShell`, open **Windows PowerShell** | **Terminal**: press `Cmd+Space`, type `Terminal` | **Terminal**: usually `Ctrl+Alt+T` |

To check your Python version, run `py --version` on Windows or `python3 --version` on macOS and Linux. It must say 3.11 or higher.

Paste each command block in full and press Enter. Each step below has a **Windows** block and a **macOS and Linux** block: use the one for your computer. On macOS, use `Cmd` wherever this guide says `Ctrl`, except where a macOS shortcut is given.

## Step 1: Install AgentLatch

This downloads AgentLatch and a small **test server** with 4 practice tools, so you can check everything works before connecting your own tools.

**Windows (PowerShell):**

```powershell
git clone https://github.com/AgentLatch/agent-latch.git $HOME\agent-latch
py -3 -m venv $HOME\agentlatch-runtime
& $HOME\agentlatch-runtime\Scripts\python.exe -m pip install -e "$HOME\agent-latch[runtime]"

New-Item -ItemType Directory -Force $HOME\agentlatch-test | Out-Null
Copy-Item $HOME\agent-latch\tests\runtime_fixtures\fake_server.py $HOME\agentlatch-test\ -Force
```

**macOS and Linux (Terminal):**

```bash
git clone https://github.com/AgentLatch/agent-latch.git ~/agent-latch
python3 -m venv ~/agentlatch-runtime
~/agentlatch-runtime/bin/python -m pip install -e "$HOME/agent-latch[runtime]"

mkdir -p ~/agentlatch-test
cp ~/agent-latch/tests/runtime_fixtures/fake_server.py ~/agentlatch-test/
```

This creates three folders in your user folder (`C:\Users\<your name>` on Windows, `/Users/<your name>` on macOS, `/home/<your name>` on Linux):

| Folder | What's in it |
|---|---|
| `agent-latch` | The AgentLatch download |
| `agentlatch-runtime` | AgentLatch, installed and ready to run |
| `agentlatch-test` | The test server |

## Step 2: Add AgentLatch to VS Code

You'll add AgentLatch to VS Code's settings file, `mcp.json`. The settings need the exact location of **4 files** on your computer, which you'll find in 2a and paste in during 2c.

**These settings are personal.** The locations include your user name and wherever you installed step 1, so they're different on every computer. Don't copy someone else's settings without changing them.

### 2a. Find your 4 file locations

**Windows (PowerShell):**

```powershell
$paths = [ordered]@{
  "1. AgentLatch program" = "$HOME\agentlatch-runtime\Scripts\agent-latch-runtime.exe"
  "2. Log file"           = "$HOME\agentlatch-trace.jsonl"
  "3. Python"             = "$HOME\agentlatch-runtime\Scripts\python.exe"
  "4. Test server"        = "$HOME\agentlatch-test\fake_server.py"
}
foreach ($name in $paths.Keys) {
  $status = if (Test-Path $paths[$name]) { "found" } elseif ($name -like "2.*") { "made later" } else { "MISSING" }
  "{0,-22} {1,-11} {2}" -f $name, $status, $paths[$name].Replace('\', '\\')
}
```

**macOS and Linux (Terminal):**

```bash
for item in \
  "1. AgentLatch program|$HOME/agentlatch-runtime/bin/agent-latch-runtime" \
  "2. Log file|$HOME/agentlatch-trace.jsonl" \
  "3. Python|$HOME/agentlatch-runtime/bin/python" \
  "4. Test server|$HOME/agentlatch-test/fake_server.py"; do
  name="${item%%|*}"; path="${item#*|}"
  if [ -e "$path" ]; then status="found"; elif [ "${name%%.*}" = "2" ]; then status="made later"; else status="MISSING"; fi
  printf '%-22s %-11s %s\n' "$name" "$status" "$path"
done
```

It prints your 4 locations, already written the way `mcp.json` needs them. For a user called `sam` it looks like this:

**Windows:**

```
1. AgentLatch program  found       C:\\Users\\sam\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe
2. Log file            made later  C:\\Users\\sam\\agentlatch-trace.jsonl
3. Python              found       C:\\Users\\sam\\agentlatch-runtime\\Scripts\\python.exe
4. Test server         found       C:\\Users\\sam\\agentlatch-test\\fake_server.py
```

**macOS** (on Linux, the locations start with `/home/sam` instead of `/Users/sam`):

```
1. AgentLatch program  found       /Users/sam/agentlatch-runtime/bin/agent-latch-runtime
2. Log file            made later  /Users/sam/agentlatch-trace.jsonl
3. Python              found       /Users/sam/agentlatch-runtime/bin/python
4. Test server         found       /Users/sam/agentlatch-test/fake_server.py
```

- **found**: the file is there. Good.
- **made later**: normal for the log file. AgentLatch creates it the first time Copilot uses a tool.
- **MISSING**: that part of step 1 didn't finish. Run step 1 again before continuing.

Keep this window open. You'll copy from it in 2c.

<details>
<summary>What each file is, and where to find it without the command</summary>

All 4 are in your user folder. To open it:

- **Windows:** press `Windows + R`, type `%USERPROFILE%` and press Enter.
- **macOS:** in Finder, press `Cmd+Shift+H`.
- **Linux:** open the Files app; it starts in your user folder (**Home**).

| # | File | What it is | Where it is in your user folder |
|---|---|---|---|
| 1 | `agent-latch-runtime.exe` (Windows) or `agent-latch-runtime` (macOS, Linux) | AgentLatch itself. VS Code starts this | `agentlatch-runtime` → `Scripts` (Windows) or `bin` (macOS, Linux) |
| 2 | `agentlatch-trace.jsonl` | The log. AgentLatch writes every tool call here | Directly in your user folder (appears after the first tool call) |
| 3 | `python.exe` (Windows) or `python` (macOS, Linux) | The Python that runs the test server | Same folder as file 1 |
| 4 | `fake_server.py` | The test server with 4 practice tools | `agentlatch-test` |

To copy a file's location:

- **Windows:** in File Explorer, hold `Shift`, right-click the file and choose **Copy as path**. When you paste it into `mcp.json`, remove the `"` marks around it and change every `\` to `\\`.
- **macOS:** in Finder, select the file and press `Option+Cmd+C`.
- **Linux:** drag the file into a Terminal window to print its location, then copy it from there.

</details>

### 2b. Create VS Code's settings file

VS Code reads AgentLatch's settings from a file called `mcp.json` inside a `.vscode` folder, in the folder you open in VS Code. The settings then apply to that folder.

1. In VS Code, open the folder you want to use Copilot in: **File → Open Folder**.
2. In the **Explorer** panel on the left, check for a folder called `.vscode`. If there isn't one, click the **New Folder** icon at the top of the panel and name it `.vscode`.
3. Right-click `.vscode`, choose **New File**, and name it `mcp.json`. If it already exists, just open it.

<details>
<summary>Want AgentLatch in every folder instead?</summary>

Open the Command Palette (`Ctrl+Shift+P`, or `Cmd+Shift+P` on macOS), run **MCP: Open User Configuration**, and use that file in step 2c instead. It works the same way.

</details>

If the folder is shared with other people through Git, keep `mcp.json` out of it, because it contains your personal file locations. In PowerShell or Terminal, from that folder, run `git check-ignore .vscode/mcp.json`. If it prints nothing, add the line `.vscode/mcp.json` to the file `.git/info/exclude` in that folder.

### 2c. Paste the settings and fill in your locations

1. **Paste the template below.** What you do depends on what's already in `mcp.json`:
   - **Empty:** paste the whole template.
   - **It already lists other tools:** copy only the `"agentlatch": { ... }` part and paste it inside the existing `"servers"`, with a comma after the tool before it. Don't paste a second `"servers"`, or VS Code can't read the file.

   VS Code uses `"servers"` at the top, where other apps use `"mcpServers"`. Keep it as `"servers"`.

   ```json
   {
     "servers": {
       "agentlatch": {
         "type": "stdio",
         "command": "<1. AgentLatch program>",
         "args": [
           "proxy", "--name", "copilot-weather",
           "--trace", "<2. Log file>",
           "--",
           "<3. Python>",
           "<4. Test server>"
         ]
       }
     }
   }
   ```

2. **Replace each placeholder with the matching line from 2a.** Select the placeholder, including the `<` and `>` but **not** the `"` marks around it, and paste the location over it:

   | Placeholder | Paste the location from line | Where it is in the template |
   |---|---|---|
   | `<1. AgentLatch program>` | `1. AgentLatch program` | After `"command":` |
   | `<2. Log file>` | `2. Log file` | After `"--trace",` |
   | `<3. Python>` | `3. Python` | First line after `"--",` |
   | `<4. Test server>` | `4. Test server` | Last line |

   Copy only the location itself (starting `C:\\` on Windows or `/` on macOS and Linux), not the label or the word **found**. To copy from the window, select the location with your mouse, then press `Ctrl+C` in PowerShell, `Cmd+C` in the macOS Terminal, or `Ctrl+Shift+C` in a Linux Terminal.

3. **Check it.** Each location must be inside `"` marks. For `sam`, the finished settings look like this:

   **Windows** (every `\` written as `\\`):

   ```json
   {
     "servers": {
       "agentlatch": {
         "type": "stdio",
         "command": "C:\\Users\\sam\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe",
         "args": [
           "proxy", "--name", "copilot-weather",
           "--trace", "C:\\Users\\sam\\agentlatch-trace.jsonl",
           "--",
           "C:\\Users\\sam\\agentlatch-runtime\\Scripts\\python.exe",
           "C:\\Users\\sam\\agentlatch-test\\fake_server.py"
         ]
       }
     }
   }
   ```

   **macOS** (on Linux, `/home/sam` instead of `/Users/sam`):

   ```json
   {
     "servers": {
       "agentlatch": {
         "type": "stdio",
         "command": "/Users/sam/agentlatch-runtime/bin/agent-latch-runtime",
         "args": [
           "proxy", "--name", "copilot-weather",
           "--trace", "/Users/sam/agentlatch-trace.jsonl",
           "--",
           "/Users/sam/agentlatch-runtime/bin/python",
           "/Users/sam/agentlatch-test/fake_server.py"
         ]
       }
     }
   }
   ```

   Yours should match, with your own user name instead of `sam`. Write the full location, not shortcuts like `~`.

4. **Save** with `Ctrl+S` (`Cmd+S` on macOS).

### What the settings mean

You only need to fill in the 4 locations, but here's what each part does:

| Part | What it means |
|---|---|
| `"servers"` | VS Code's list of tool servers |
| `"agentlatch"` | The name VS Code shows for this server |
| `"type": "stdio"` | VS Code starts AgentLatch as a program on your computer |
| `"command"` | Where AgentLatch is installed. VS Code runs this when you start the server |
| `"proxy"` | Tells AgentLatch to sit between VS Code and the tools |
| `"--name", "copilot-weather"` | The label on every line AgentLatch writes to the log, so you can tell Copilot's tool calls apart |
| `"--trace", "...agentlatch-trace.jsonl"` | Where the log is saved |
| `"--"` | Everything after this is the tool server AgentLatch should start |
| The last two lines | Start the test server, using the Python installed in step 1 |

<details>
<summary>Optional: let a command write the settings for you</summary>

Instead of steps 2a–2c, you can run one of these **from the folder you open in VS Code**. First move into that folder, for example `cd $HOME\my-project` on Windows or `cd ~/my-project` on macOS and Linux. The command creates `.vscode/mcp.json` there with your 4 locations filled in, keeps any tools already in the file, and saves a backup of your old settings as `mcp.json.bak`. You can run it again safely.

**Windows (PowerShell):**

```powershell
$file = Join-Path (Get-Location) ".vscode\mcp.json"
$runtime = "$HOME\agentlatch-runtime\Scripts"
New-Item -ItemType Directory -Force (Split-Path $file) | Out-Null
$raw = if (Test-Path $file) { Get-Content $file -Raw } else { "" }
if ($raw -and $raw.Trim()) { Copy-Item $file "$file.bak" -Force; $config = $raw | ConvertFrom-Json } else { $config = [pscustomobject]@{} }
if (-not $config.servers) { $config | Add-Member -NotePropertyName servers -NotePropertyValue ([pscustomobject]@{}) -Force }
$config.servers | Add-Member -Force -NotePropertyName agentlatch -NotePropertyValue ([ordered]@{
  type    = "stdio"
  command = "$runtime\agent-latch-runtime.exe"
  args    = @("proxy", "--name", "copilot-weather", "--trace", "$HOME\agentlatch-trace.jsonl", "--",
              "$runtime\python.exe", "$HOME\agentlatch-test\fake_server.py")
})
[IO.File]::WriteAllText($file, ($config | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
Write-Host "Done. Settings saved to $file"
```

**macOS and Linux (Terminal):**

```bash
~/agentlatch-runtime/bin/python - <<'EOF'
import json, pathlib, shutil
home = pathlib.Path.home()
f = pathlib.Path.cwd() / ".vscode" / "mcp.json"
f.parent.mkdir(parents=True, exist_ok=True)
config = {}
if f.exists() and f.read_text().strip():
    shutil.copy(f, f.with_suffix(".json.bak"))
    config = json.loads(f.read_text())
runtime = home / "agentlatch-runtime" / "bin"
config.setdefault("servers", {})["agentlatch"] = {
    "type": "stdio",
    "command": str(runtime / "agent-latch-runtime"),
    "args": ["proxy", "--name", "copilot-weather", "--trace", str(home / "agentlatch-trace.jsonl"), "--",
             str(runtime / "python"), str(home / "agentlatch-test" / "fake_server.py")],
}
f.write_text(json.dumps(config, indent=2) + "\n")
print(f"Done. Settings saved to {f}")
EOF
```

</details>

## Step 3: Start AgentLatch in VS Code

Unlike some apps, VS Code doesn't start a new server by itself. Start it once:

1. Open `.vscode/mcp.json`. Above `"agentlatch"`, click **Start**.
   Or open the Command Palette (`Ctrl+Shift+P`, or `Cmd+Shift+P` on macOS), run **MCP: List Servers**, choose **agentlatch** and then **Start Server**.
2. Look at the line above `"agentlatch"`:
   - **Running** with **4 tools** means it's working.
   - An error means something is wrong. Click **Show Output** to see it, then see [If something goes wrong](#if-something-goes-wrong).

## Step 4: Try it

1. Open the log so you can watch it update:

   **Windows (PowerShell):**

   ```powershell
   Get-Content $HOME\agentlatch-trace.jsonl -Wait -Tail 20
   ```

   **macOS and Linux (Terminal):**

   ```bash
   tail -f -n 20 ~/agentlatch-trace.jsonl
   ```

   If it says the file doesn't exist, that's fine: it's created after the first tool call. Run it again after the next step. To stop watching, press `Ctrl+C`.

2. Open Copilot Chat (`Ctrl+Alt+I` on Windows and Linux, `Ctrl+Cmd+I` on macOS). At the bottom of the chat, set the mode to **Agent**. Click the tools icon next to it and check **agentlatch** is ticked.
3. Type the prompts below one at a time. When Copilot asks permission to use a tool, click **Allow**.

| Type this in Copilot Chat | What you should see in the log |
|---|---|
| Use the agentlatch get_weather tool for London | New lines containing `copilot-weather`. The tool call was recorded |
| Use the agentlatch leaky_lookup tool for user alice | `token=[REDACTED]`. Copilot shows a fake secret key, but the log hides it |
| Use the agentlatch broken_tool tool with reason test | `"is_error": true`. Failed tool calls are recorded too |
| Use the agentlatch echo_injection tool for Paris | A hidden instruction in the tool's reply. Copilot should ignore it |

Saying "the agentlatch … tool" makes sure Copilot uses AgentLatch rather than, say, searching the web. VS Code checks the list of tools again after every call, so the log has an extra `tools/list` line after each one. That's normal.

## Connect your own tools

The test server is just for practice. To watch your real tools, change the `agentlatch` entry in `mcp.json`:

- Keep `"command"` and the first part of `"args"` as they are, up to and including `"--"`.
- After `"--"`, put the command that starts your tool server, in place of the test server's two lines.
- Change `copilot-weather` to a name you'll recognise in the log.

For more detail, see [Connect an app](../runtime.md#connect-an-app). Only connect tool servers you trust.

## Turn it off or remove it

- **Pause it:** open `.vscode/mcp.json` and click **Stop** above `"agentlatch"`, or untick **agentlatch** under the tools icon in Copilot Chat.
- **Remove it:** delete the `"agentlatch": { ... }` part from `mcp.json`, or delete the file if AgentLatch is the only thing in it.
- **Go back to your old settings**, from the folder you opened in VS Code:
  - Windows: `Copy-Item .vscode\mcp.json.bak .vscode\mcp.json -Force`
  - macOS and Linux: `cp .vscode/mcp.json.bak .vscode/mcp.json`

## If something goes wrong

| What you see | What to do |
|---|---|
| Chat says you need to upgrade for Agent mode | You may be using Copilot on github.com. Open Copilot Chat inside VS Code instead (`Ctrl+Alt+I`, or `Ctrl+Cmd+I` on macOS). If VS Code shows it too, check you're signed in, choose a model without a premium label, and check your monthly usage in the Copilot menu in the status bar |
| **agentlatch** isn't under the tools icon | The server isn't started. Start it as in step 3 |
| The server won't start | Click **Show Output**. A file location is usually wrong: run step 2a again and check each location matches its line exactly, and that no `<...>` placeholder is left. On Windows, check every `\` is written `\\` |
| VS Code shows red underlines in `mcp.json` | A comma, bracket or `"` mark is wrong, or there are two `"servers"`. Compare your file with the example in step 2c |
| The tools are missing in another folder | `.vscode/mcp.json` only applies to the folder it's in. Use the user configuration (see 2b) instead |
| `git`, `py`, `python3` "is not recognized" or "command not found" | Git or Python isn't installed, or (on Windows) wasn't added to PATH. Install it as shown in [Before you start](#before-you-start), then open a new window |
| Linux: `ensurepip is not available` during step 1 | Run `sudo apt install python3-venv`, delete the `agentlatch-runtime` folder, and run step 1 again |
| macOS: `python3 --version` shows lower than 3.11 | Install a newer Python from [python.org](https://www.python.org/downloads/) or with `brew install python`, then open a new Terminal |
| Your user name contains a space | VS Code may not cope with it. Move the folders to one without spaces, such as `C:\agentlatch` or `/opt/agentlatch`, and use those locations instead |
