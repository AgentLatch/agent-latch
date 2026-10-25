# Connect AgentLatch to Cursor

This guide connects AgentLatch to the Cursor app on Windows, macOS or Linux. Afterwards, every time Cursor's AI uses a tool, AgentLatch writes a record of it to a log file on your computer, with any secrets hidden. AgentLatch only watches: it never changes or blocks what Cursor does.

It takes about 10 minutes. You don't need to know how to code; you'll copy and paste a few commands.

**Tested:** Cursor on Windows 11, October 2026. The macOS and Linux steps use the same settings with those systems' file locations, but haven't been tested end to end yet.

## How it works

Cursor can use extra tools, such as "get the weather" or "look up a customer". The tools come from small programs called **MCP servers**. You tell Cursor which ones to start by listing them in a settings file called `mcp.json`.

AgentLatch sits between Cursor and the tools. Cursor starts AgentLatch, AgentLatch starts the tools, and every request passing through is written to the log:

```
Cursor  ──▶  AgentLatch  ──▶  the tools
                 │
                 ▼
    agentlatch-trace.jsonl  (the log)
```

Everything runs on your own computer. Nothing is sent to AgentLatch, and you don't need an account or an API key.

## Before you start

You need **Cursor** from [cursor.com](https://cursor.com), plus **Python 3.11 or newer** and **Git**:

| | Windows | macOS | Linux |
|---|---|---|---|
| **Python 3.11+** | [python.org](https://www.python.org/downloads/). Tick **Add python.exe to PATH** when installing | [python.org](https://www.python.org/downloads/), or `brew install python` | Usually installed. On Ubuntu/Debian, also run `sudo apt install python3-venv` |
| **Git** | [git-scm.com](https://git-scm.com/download/win) | Run `git --version`; if it isn't installed, macOS offers to install it | Usually installed. Otherwise `sudo apt install git` (Ubuntu/Debian) or `sudo dnf install git` (Fedora) |
| **Where to run commands** | **Windows PowerShell**: press the Windows key, type `PowerShell`, open **Windows PowerShell** | **Terminal**: press `Cmd+Space`, type `Terminal` | **Terminal**: usually `Ctrl+Alt+T` |

To check your Python version, run `py --version` on Windows or `python3 --version` on macOS and Linux. It must say 3.11 or higher.

Paste each command block in full and press Enter. Each step below has a **Windows** block and a **macOS and Linux** block: use the one for your computer. On macOS, use `Cmd` wherever this guide says `Ctrl`.

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

## Step 2: Add AgentLatch to Cursor

You'll add AgentLatch to Cursor's settings file, `mcp.json`. The settings need the exact location of **4 files** on your computer, which you'll find in 2a and paste in during 2c.

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
- **made later**: normal for the log file. AgentLatch creates it the first time Cursor uses a tool.
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
| 1 | `agent-latch-runtime.exe` (Windows) or `agent-latch-runtime` (macOS, Linux) | AgentLatch itself. Cursor starts this | `agentlatch-runtime` → `Scripts` (Windows) or `bin` (macOS, Linux) |
| 2 | `agentlatch-trace.jsonl` | The log. AgentLatch writes every tool call here | Directly in your user folder (appears after the first tool call) |
| 3 | `python.exe` (Windows) or `python` (macOS, Linux) | The Python that runs the test server | Same folder as file 1 |
| 4 | `fake_server.py` | The test server with 4 practice tools | `agentlatch-test` |

To copy a file's location:

- **Windows:** in File Explorer, hold `Shift`, right-click the file and choose **Copy as path**. When you paste it into `mcp.json`, remove the `"` marks around it and change every `\` to `\\`.
- **macOS:** in Finder, select the file and press `Option+Cmd+C`.
- **Linux:** drag the file into a Terminal window to print its location, then copy it from there.

</details>

### 2b. Open Cursor's settings file

In Cursor, open **Cursor Settings** (`Ctrl+Shift+J`, or `Cmd+Shift+J` on macOS) → **Tools & MCP** → **Add Custom MCP** (sometimes called **New MCP Server**). Cursor opens a file called `mcp.json`.

It's stored in your user folder at `.cursor/mcp.json` on every system, so you can also open it from there.

### 2c. Paste the settings and fill in your locations

1. **Paste the template below.** What you do depends on what's already in `mcp.json`:
   - **Empty, or only `{ "mcpServers": {} }`:** delete everything and paste the whole template.
   - **It already lists other tools:** copy only the `"agentlatch": { ... }` part and paste it inside the existing `"mcpServers"`, with a comma after the tool before it. Don't paste a second `"mcpServers"`, or Cursor can't read the file.

   ```json
   {
     "mcpServers": {
       "agentlatch": {
         "type": "stdio",
         "command": "<1. AgentLatch program>",
         "args": [
           "proxy", "--name", "cursor-weather",
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
     "mcpServers": {
       "agentlatch": {
         "type": "stdio",
         "command": "C:\\Users\\sam\\agentlatch-runtime\\Scripts\\agent-latch-runtime.exe",
         "args": [
           "proxy", "--name", "cursor-weather",
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
     "mcpServers": {
       "agentlatch": {
         "type": "stdio",
         "command": "/Users/sam/agentlatch-runtime/bin/agent-latch-runtime",
         "args": [
           "proxy", "--name", "cursor-weather",
           "--trace", "/Users/sam/agentlatch-trace.jsonl",
           "--",
           "/Users/sam/agentlatch-runtime/bin/python",
           "/Users/sam/agentlatch-test/fake_server.py"
         ]
       }
     }
   }
   ```

   Yours should match, with your own user name instead of `sam`. Write the full location: shortcuts like `${userHome}` or `~` didn't work in our Windows test, and full locations work everywhere.

4. **Save** with `Ctrl+S` (`Cmd+S` on macOS).

### What the settings mean

You only need to fill in the 4 locations, but here's what each part does:

| Part | What it means |
|---|---|
| `"agentlatch"` | The name Cursor shows in **Tools & MCP** |
| `"type": "stdio"` | Cursor starts AgentLatch as a program on your computer |
| `"command"` | Where AgentLatch is installed. Cursor runs this when it opens |
| `"proxy"` | Tells AgentLatch to sit between Cursor and the tools |
| `"--name", "cursor-weather"` | The label on every line AgentLatch writes to the log, so you can tell Cursor's tool calls apart |
| `"--trace", "...agentlatch-trace.jsonl"` | Where the log is saved |
| `"--"` | Everything after this is the tool server AgentLatch should start |
| The last two lines | Start the test server, using the Python installed in step 1 |

<details>
<summary>Optional: let a command write the settings for you</summary>

Instead of steps 2a–2c, you can paste one of these. It fills in your 4 locations, keeps any tools already in the file, and saves a backup of your old settings as `mcp.json.bak`. You can run it again safely.

**Windows (PowerShell):**

```powershell
$file = "$HOME\.cursor\mcp.json"
$runtime = "$HOME\agentlatch-runtime\Scripts"
New-Item -ItemType Directory -Force "$HOME\.cursor" | Out-Null
$raw = if (Test-Path $file) { Get-Content $file -Raw } else { "" }
if ($raw -and $raw.Trim()) { Copy-Item $file "$file.bak" -Force; $config = $raw | ConvertFrom-Json } else { $config = [pscustomobject]@{} }
if (-not $config.mcpServers) { $config | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([pscustomobject]@{}) -Force }
$config.mcpServers | Add-Member -Force -NotePropertyName agentlatch -NotePropertyValue ([ordered]@{
  type    = "stdio"
  command = "$runtime\agent-latch-runtime.exe"
  args    = @("proxy", "--name", "cursor-weather", "--trace", "$HOME\agentlatch-trace.jsonl", "--",
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
f = home / ".cursor" / "mcp.json"
f.parent.mkdir(exist_ok=True)
config = {}
if f.exists() and f.read_text().strip():
    shutil.copy(f, f.with_suffix(".json.bak"))
    config = json.loads(f.read_text())
runtime = home / "agentlatch-runtime" / "bin"
config.setdefault("mcpServers", {})["agentlatch"] = {
    "type": "stdio",
    "command": str(runtime / "agent-latch-runtime"),
    "args": ["proxy", "--name", "cursor-weather", "--trace", str(home / "agentlatch-trace.jsonl"), "--",
             str(runtime / "python"), str(home / "agentlatch-test" / "fake_server.py")],
}
f.write_text(json.dumps(config, indent=2) + "\n")
print(f"Done. Settings saved to {f}")
EOF
```

</details>

## Step 3: Check that Cursor connected

1. Open Cursor. If it was already open, reload it: press `Ctrl+Shift+P` (`Cmd+Shift+P` on macOS), type **Reload Window** and press Enter.
2. Open **Cursor Settings** → **Tools & MCP**.
3. Look at **agentlatch**:
   - A **green dot** and **4 tools** means it's working.
   - A **red dot** means something is wrong. See [If something goes wrong](#if-something-goes-wrong).

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

2. In Cursor, open the chat (`Ctrl+L`, or `Cmd+L` on macOS), make sure it's set to **Agent**, and type the prompts below one at a time. When Cursor asks permission to use a tool, click **Run**.

| Type this in Cursor | What you should see in the log |
|---|---|
| Use the agentlatch get_weather tool for London | New lines containing `cursor-weather`. The tool call was recorded |
| Use the agentlatch leaky_lookup tool for user alice | `token=[REDACTED]`. Cursor shows a fake secret key, but the log hides it |
| Use the agentlatch broken_tool tool with reason test | `"is_error": true`. Failed tool calls are recorded too |
| Use the agentlatch echo_injection tool for Paris | A hidden instruction in the tool's reply. Cursor should ignore it |

Saying "the agentlatch … tool" makes sure Cursor uses AgentLatch rather than, say, searching the web.

## Connect your own tools

The test server is just for practice. To watch your real tools, change the `agentlatch` entry in `mcp.json`:

- Keep `"command"` and the first part of `"args"` as they are, up to and including `"--"`.
- After `"--"`, put the command that starts your tool server, in place of the test server's two lines.
- Change `cursor-weather` to a name you'll recognise in the log.

For more detail, see [Connect an app](../runtime.md#connect-an-app). Only connect tool servers you trust.

## Turn it off or remove it

- **Pause it:** in **Cursor Settings → Tools & MCP**, switch off the toggle next to **agentlatch**.
- **Remove it:** in the same place, hover over **agentlatch** and click the delete icon. Then reload Cursor (**Reload Window**).
- **Go back to your old settings**, then reload Cursor:
  - Windows: `Copy-Item "$HOME\.cursor\mcp.json.bak" "$HOME\.cursor\mcp.json" -Force`
  - macOS and Linux: `cp ~/.cursor/mcp.json.bak ~/.cursor/mcp.json`

## If something goes wrong

| What you see | What to do |
|---|---|
| Red dot, and the error mentions **filename, directory name, or volume label syntax** (Windows) or **No such file or directory** / **ENOENT** (macOS, Linux) | A file location in the settings is wrong. Run step 2a again and check each location in `mcp.json` matches its line exactly, and that no `<...>` placeholder is left. On Windows, check every `\` is written `\\` |
| Cursor says it can't read `mcp.json` | A comma or bracket is missing, or there are two `"mcpServers"`. Compare your file with the example in step 2c |
| Red dot, and the error mentions **Connection closed** | Step 1 didn't finish. Run step 1 again and look for error text |
| `git`, `py`, `python3` "is not recognized" or "command not found" | Git or Python isn't installed, or (on Windows) wasn't added to PATH. Install it as shown in [Before you start](#before-you-start), then open a new window |
| Linux: `ensurepip is not available` during step 1 | Run `sudo apt install python3-venv`, delete the `agentlatch-runtime` folder, and run step 1 again |
| macOS: `python3 --version` shows lower than 3.11 | Install a newer Python from [python.org](https://www.python.org/downloads/) or with `brew install python`, then open a new Terminal |
| Your user name contains a space | Cursor may not cope with it. Move the folders to one without spaces, such as `C:\agentlatch` or `/opt/agentlatch`, and use those locations instead |
| AgentLatch doesn't appear in chat | Set the chat to **Agent**, and check **agentlatch** is switched on in Tools & MCP |
| The log shows lines marked `[error]` such as `tools/list -> 4 tool(s)` | Nothing is wrong. Cursor labels everything AgentLatch prints as `[error]` |

To see the full error, click **Error - Show Output** next to the red dot in Tools & MCP.
