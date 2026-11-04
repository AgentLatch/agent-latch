# Connect AgentLatch to Claude Desktop

This guide connects AgentLatch to the Claude Desktop app on Windows or macOS. Afterwards, every time Claude uses a tool, AgentLatch writes a record of it to a log file on your computer, with any secrets hidden. AgentLatch only watches: it never changes or blocks what Claude does.

It takes about 10 minutes. You don't need to know how to code; you'll copy and paste a few commands.

**Tested:** Claude Desktop on Windows 11 (Microsoft Store install), October 2026. The macOS steps use the same settings with macOS file locations, but haven't been tested end to end yet. Claude Desktop is offered for Windows and macOS, so there are no Linux steps.

This guide is for the Claude Desktop app. Claude in a web browser (claude.ai) can't start programs on your computer, and Claude Code uses a different settings file (see [Connect an app](../runtime.md#connect-an-app)).

## How it works

Claude can use extra tools, such as "get the weather" or "look up a customer". The tools come from small programs called **MCP servers**. You tell Claude Desktop which ones to start by listing them in a settings file called `claude_desktop_config.json`.

AgentLatch sits between Claude and the tools. Claude Desktop starts AgentLatch, AgentLatch starts the tools, and every request passing through is written to the log:

```
Claude Desktop  ──▶  AgentLatch  ──▶  the tools
                         │
                         ▼
            agentlatch-trace.jsonl  (the log)
```

Everything runs on your own computer. Nothing is sent to AgentLatch, and you don't need an account or an API key.

## Before you start

You need **Claude Desktop** from [claude.ai/download](https://claude.ai/download), signed in, plus **Python 3.11 or newer** and **Git**:

| | Windows | macOS |
|---|---|---|
| **Python 3.11+** | [python.org](https://www.python.org/downloads/). Tick **Add python.exe to PATH** when installing | [python.org](https://www.python.org/downloads/), or `brew install python` |
| **Git** | [git-scm.com](https://git-scm.com/download/win) | Run `git --version`; if it isn't installed, macOS offers to install it |
| **Where to run commands** | **Windows PowerShell**: press the Windows key, type `PowerShell`, open **Windows PowerShell** | **Terminal**: press `Cmd+Space`, type `Terminal` |

To check your Python version, run `py --version` on Windows or `python3 --version` on macOS. It must say 3.11 or higher.

Paste each command block in full and press Enter. Each step below has a **Windows** block and a **macOS** block: use the one for your computer. On macOS, use `Cmd` wherever this guide says `Ctrl`.

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

**macOS (Terminal):**

```bash
git clone https://github.com/AgentLatch/agent-latch.git ~/agent-latch
python3 -m venv ~/agentlatch-runtime
~/agentlatch-runtime/bin/python -m pip install -e "$HOME/agent-latch[runtime]"

mkdir -p ~/agentlatch-test
cp ~/agent-latch/tests/runtime_fixtures/fake_server.py ~/agentlatch-test/
```

This creates three folders in your user folder (`C:\Users\<your name>` on Windows, `/Users/<your name>` on macOS):

| Folder | What's in it |
|---|---|
| `agent-latch` | The AgentLatch download |
| `agentlatch-runtime` | AgentLatch, installed and ready to run |
| `agentlatch-test` | The test server |

## Step 2: Quit Claude Desktop completely

Claude only reads its settings when it starts, and if it's running it can save over your changes. Closing the window isn't enough:

- **Windows:** closing the window leaves Claude running in the system tray (bottom right, by the clock). Right-click the Claude icon there and choose **Quit**.
- **macOS:** with Claude open, press `Cmd+Q`, or choose **Claude → Quit Claude** in the menu bar.

To check it has stopped, run this. **No output** means Claude is closed:

**Windows (PowerShell):**

```powershell
Get-Process Claude -ErrorAction SilentlyContinue | Where-Object { $_.Path -match 'WindowsApps\\Claude_|AnthropicClaude' }
```

If anything is listed, add `| Stop-Process -Force` to the end of the command and run it again.

**macOS (Terminal):**

```bash
pgrep -l Claude
```

If anything is listed, run `pkill Claude`.

## Step 3: Add AgentLatch to Claude Desktop

You'll add AgentLatch to Claude's settings file, `claude_desktop_config.json`. The settings need the exact location of **4 files** on your computer, which you'll find in 3a and paste in during 3c.

**These settings are personal.** The locations include your user name and wherever you installed step 1, so they're different on every computer. Don't copy someone else's settings without changing them.

### 3a. Find your 4 file locations

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

**macOS (Terminal):**

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

It prints your 4 locations, already written the way the settings file needs them. For a user called `sam` it looks like this:

**Windows:**

```
1. AgentLatch program  found       C:\\Users\\sam\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe
2. Log file            made later  C:\\Users\\sam\\agentlatch-trace.jsonl
3. Python              found       C:\\Users\\sam\\agentlatch-runtime\\Scripts\\python.exe
4. Test server         found       C:\\Users\\sam\\agentlatch-test\\fake_server.py
```

**macOS:**

```
1. AgentLatch program  found       /Users/sam/agentlatch-runtime/bin/agent-latch-runtime
2. Log file            made later  /Users/sam/agentlatch-trace.jsonl
3. Python              found       /Users/sam/agentlatch-runtime/bin/python
4. Test server         found       /Users/sam/agentlatch-test/fake_server.py
```

- **found**: the file is there. Good.
- **made later**: normal for the log file. AgentLatch creates it the first time Claude uses a tool.
- **MISSING**: that part of step 1 didn't finish. Run step 1 again before continuing.

Keep this window open. You'll copy from it in 3c.

<details>
<summary>What each file is, and where to find it without the command</summary>

All 4 are in your user folder. To open it:

- **Windows:** press `Windows + R`, type `%USERPROFILE%` and press Enter.
- **macOS:** in Finder, press `Cmd+Shift+H`.

| # | File | What it is | Where it is in your user folder |
|---|---|---|---|
| 1 | `agent-latch-runtime.exe` (Windows) or `agent-latch-runtime` (macOS) | AgentLatch itself. Claude starts this | `agentlatch-runtime` → `Scripts` (Windows) or `bin` (macOS) |
| 2 | `agentlatch-trace.jsonl` | The log. AgentLatch writes every tool call here | Directly in your user folder (appears after the first tool call) |
| 3 | `python.exe` (Windows) or `python` (macOS) | The Python that runs the test server | Same folder as file 1 |
| 4 | `fake_server.py` | The test server with 4 practice tools | `agentlatch-test` |

To copy a file's location:

- **Windows:** in File Explorer, hold `Shift`, right-click the file and choose **Copy as path**. When you paste it into the settings, remove the `"` marks around it and change every `\` to `\\`.
- **macOS:** in Finder, select the file and press `Option+Cmd+C`.

</details>

### 3b. Open Claude's settings file

The easiest way is from Claude itself. Open Claude Desktop just for this, then:

1. Open **Settings** (on Windows, the menu ☰ at the top left → **File → Settings**; on macOS, **Claude → Settings** in the menu bar) → **Developer** → **Edit Config**. This opens the folder containing `claude_desktop_config.json`.
2. Open the file in a text editor: right-click it and choose **Open with → Notepad** on Windows, or **Open With → TextEdit** on macOS.
3. **Quit Claude again** as in step 2, leaving the file open in the editor.

The file is stored here, if you'd rather open it directly:

| Install | Settings file |
|---|---|
| Windows, Microsoft Store | `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| Windows, installer from claude.ai | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |

On macOS, if TextEdit changes `"` into curly quotes as you type, turn it off in **Edit → Substitutions → Smart Quotes**. The file needs straight `"` marks.

### 3c. Paste the settings and fill in your locations

1. **Paste the template below.** What you do depends on what's already in the file:
   - **Empty, or only `{}`:** delete everything and paste the whole template.
   - **It already has other settings but no `"mcpServers"`:** paste `"mcpServers": { ... }` from the template just after the first `{`, followed by a comma.
   - **It already has `"mcpServers"`:** copy only the `"agentlatch": { ... }` part and paste it inside the existing `"mcpServers"`, with a comma after the tool before it. Don't paste a second `"mcpServers"`, or Claude can't read the file.

   ```json
   {
     "mcpServers": {
       "agentlatch": {
         "command": "<1. AgentLatch program>",
         "args": [
           "proxy", "--name", "claude-weather",
           "--trace", "<2. Log file>",
           "--",
           "<3. Python>",
           "<4. Test server>"
         ]
       }
     }
   }
   ```

2. **Replace each placeholder with the matching line from 3a.** Select the placeholder, including the `<` and `>` but **not** the `"` marks around it, and paste the location over it:

   | Placeholder | Paste the location from line | Where it is in the template |
   |---|---|---|
   | `<1. AgentLatch program>` | `1. AgentLatch program` | After `"command":` |
   | `<2. Log file>` | `2. Log file` | After `"--trace",` |
   | `<3. Python>` | `3. Python` | First line after `"--",` |
   | `<4. Test server>` | `4. Test server` | Last line |

   Copy only the location itself (starting `C:\\` on Windows or `/` on macOS), not the label or the word **found**. To copy from the window, select the location with your mouse and press `Ctrl+C` in PowerShell, or `Cmd+C` in Terminal.

3. **Check it.** Each location must be inside `"` marks. For `sam`, the finished settings look like this:

   **Windows** (every `\` written as `\\`):

   ```json
   {
     "mcpServers": {
       "agentlatch": {
         "command": "C:\\Users\\sam\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe",
         "args": [
           "proxy", "--name", "claude-weather",
           "--trace", "C:\\Users\\sam\\agentlatch-trace.jsonl",
           "--",
           "C:\\Users\\sam\\agentlatch-runtime\\Scripts\\python.exe",
           "C:\\Users\\sam\\agentlatch-test\\fake_server.py"
         ]
       }
     }
   }
   ```

   **macOS:**

   ```json
   {
     "mcpServers": {
       "agentlatch": {
         "command": "/Users/sam/agentlatch-runtime/bin/agent-latch-runtime",
         "args": [
           "proxy", "--name", "claude-weather",
           "--trace", "/Users/sam/agentlatch-trace.jsonl",
           "--",
           "/Users/sam/agentlatch-runtime/bin/python",
           "/Users/sam/agentlatch-test/fake_server.py"
         ]
       }
     }
   }
   ```

   Yours should match, with your own user name instead of `sam`. Write the full location: shortcuts like `~` don't work here.

4. **Save** with `Ctrl+S` (`Cmd+S` on macOS) and close the editor.

### What the settings mean

You only need to fill in the 4 locations, but here's what each part does:

| Part | What it means |
|---|---|
| `"agentlatch"` | The name Claude shows in **Settings → Developer** |
| `"command"` | Where AgentLatch is installed. Claude runs this when it opens |
| `"proxy"` | Tells AgentLatch to sit between Claude and the tools |
| `"--name", "claude-weather"` | The label on every line AgentLatch writes to the log, so you can tell Claude's tool calls apart |
| `"--trace", "...agentlatch-trace.jsonl"` | Where the log is saved |
| `"--"` | Everything after this is the tool server AgentLatch should start |
| The last two lines | Start the test server, using the Python installed in step 1 |

<details>
<summary>Optional: let a command write the settings for you</summary>

Instead of steps 3a–3c, you can paste one of these while Claude is quit. It finds the settings file, fills in your 4 locations, keeps your other settings, and saves a backup of your old settings as `claude_desktop_config.json.bak`. You can run it again safely.

**Windows (PowerShell):**

```powershell
$store = Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory -Filter "Claude_*" -ErrorAction SilentlyContinue | Select-Object -First 1
$file = if ($store) { "$($store.FullName)\LocalCache\Roaming\Claude\claude_desktop_config.json" } else { "$env:APPDATA\Claude\claude_desktop_config.json" }
$runtime = "$HOME\agentlatch-runtime\Scripts"
New-Item -ItemType Directory -Force (Split-Path $file) | Out-Null
$raw = if (Test-Path $file) { Get-Content $file -Raw } else { "" }
if ($raw -and $raw.Trim()) { Copy-Item $file "$file.bak" -Force; $config = $raw | ConvertFrom-Json } else { $config = [pscustomobject]@{} }
if (-not $config.mcpServers) { $config | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([pscustomobject]@{}) -Force }
$config.mcpServers | Add-Member -Force -NotePropertyName agentlatch -NotePropertyValue ([ordered]@{
  command = "$runtime\agent-latch-runtime.exe"
  args    = @("proxy", "--name", "claude-weather", "--trace", "$HOME\agentlatch-trace.jsonl", "--",
              "$runtime\python.exe", "$HOME\agentlatch-test\fake_server.py")
})
[IO.File]::WriteAllText($file, ($config | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
Write-Host "Done. Settings saved to $file"
```

**macOS (Terminal):**

```bash
~/agentlatch-runtime/bin/python - <<'EOF'
import json, pathlib, shutil
home = pathlib.Path.home()
f = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
f.parent.mkdir(parents=True, exist_ok=True)
config = {}
if f.exists() and f.read_text().strip():
    shutil.copy(f, f.with_suffix(".json.bak"))
    config = json.loads(f.read_text())
runtime = home / "agentlatch-runtime" / "bin"
config.setdefault("mcpServers", {})["agentlatch"] = {
    "command": str(runtime / "agent-latch-runtime"),
    "args": ["proxy", "--name", "claude-weather", "--trace", str(home / "agentlatch-trace.jsonl"), "--",
             str(runtime / "python"), str(home / "agentlatch-test" / "fake_server.py")],
}
f.write_text(json.dumps(config, indent=2) + "\n")
print(f"Done. Settings saved to {f}")
EOF
```

</details>

## Step 4: Check that Claude connected

1. Open Claude Desktop.
2. Open **Settings** → **Developer**.
3. Look at **agentlatch**:
   - **running** means it's working.
   - **failed**, or no servers listed, means something is wrong. See [If something goes wrong](#if-something-goes-wrong).

## Step 5: Try it

1. Open the log so you can watch it update:

   **Windows (PowerShell):**

   ```powershell
   Get-Content $HOME\agentlatch-trace.jsonl -Wait -Tail 20
   ```

   **macOS (Terminal):**

   ```bash
   tail -f -n 20 ~/agentlatch-trace.jsonl
   ```

   If it says the file doesn't exist, that's fine: it's created after the first tool call. Run it again after the next step. To stop watching, press `Ctrl+C`.

2. In Claude, start a new chat and type the prompts below one at a time. When Claude asks permission to use a tool, click **Allow**.

| Type this in Claude | What you should see in the log |
|---|---|
| Use the agentlatch get_weather tool for London | New lines containing `claude-weather`. The tool call was recorded |
| Use the agentlatch leaky_lookup tool for user alice | `token=[REDACTED]`. Claude shows a fake secret key, but the log hides it |
| Use the agentlatch broken_tool tool with reason test | `"is_error": true`. Failed tool calls are recorded too |
| Use the agentlatch echo_injection tool for Paris | A hidden instruction in the tool's reply. Claude should ignore it |

Saying "the agentlatch … tool" makes sure Claude uses AgentLatch rather than, say, searching the web.

## Connect your own tools

The test server is just for practice. To watch your real tools, change the `agentlatch` entry in the settings file (with Claude quit):

- Keep `"command"` and the first part of `"args"` as they are, up to and including `"--"`.
- After `"--"`, put the command that starts your tool server, in place of the test server's two lines.
- Change `claude-weather` to a name you'll recognise in the log.

For more detail, see [Connect an app](../runtime.md#connect-an-app). Only connect tool servers you trust.

## Turn it off or remove it

- **Remove it:** quit Claude (step 2), delete the `"agentlatch": { ... }` part from the settings file, and open Claude again.
- **Go back to your old settings:** quit Claude, put back the backup made by the optional command, then open Claude:
  - Windows: in the settings folder, delete `claude_desktop_config.json` and rename `claude_desktop_config.json.bak` to `claude_desktop_config.json`
  - macOS: `cp ~/Library/Application\ Support/Claude/claude_desktop_config.json.bak ~/Library/Application\ Support/Claude/claude_desktop_config.json`

## If something goes wrong

| What you see | What to do |
|---|---|
| **Settings → Developer** shows no servers | Claude didn't restart, so it hasn't read the settings. Quit it fully (step 2) and open it again |
| Your changes have disappeared from the file | Claude was running and saved over them. Quit it fully, then add the settings again |
| **agentlatch** shows as **failed** | A file location is usually wrong. Run step 3a again and check each location matches its line exactly, and that no `<...>` placeholder is left. On Windows, check every `\` is written `\\` |
| Claude won't start after your change | A comma, bracket or `"` mark is wrong, or there are two `"mcpServers"`. Compare your file with the example in step 3c, or put back the `.bak` backup |
| `git`, `py`, `python3` "is not recognized" or "command not found" | Git or Python isn't installed, or (on Windows) wasn't added to PATH. Install it as shown in [Before you start](#before-you-start), then open a new window |
| macOS: `python3 --version` shows lower than 3.11 | Install a newer Python from [python.org](https://www.python.org/downloads/) or with `brew install python`, then open a new Terminal |
| Your user name contains a space | Claude may not cope with it. Move the folders to one without spaces, such as `C:\agentlatch` or `/opt/agentlatch`, and use those locations instead |
| The tools are missing in Claude Code | Claude Code uses a different settings file. See [Connect an app](../runtime.md#connect-an-app) |

To see the full error, open the log Claude keeps for AgentLatch, `mcp-server-agentlatch.log`. On Windows it's in the `logs` folder next to the settings file; on macOS it's in `~/Library/Logs/Claude/`.
