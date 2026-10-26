<#
.SYNOPSIS
agentlatch-chatgpt: connect ChatGPT to AgentLatch through OpenAI's Secure MCP Tunnel, in one command.

.DESCRIPTION
The first run sets everything up: it installs AgentLatch and the test server if they're missing,
downloads and checks tunnel-client, asks for your tunnel ID, creates the "agentlatch" profile and
starts the tunnel. Later runs skip the steps that are already done, ask for your API key and start
the tunnel. The key is typed into a hidden prompt and is never saved.

Creating the tunnel and the API key on platform.openai.com, and adding the plugin in ChatGPT, are
still done by hand: see docs/clients/chatgpt.md. This script writes a trace only. It does not
pass --payloads and it does not run import-logs, so it does not produce a finding.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\agentlatch-chatgpt.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\agentlatch-chatgpt.ps1 -Reset -TunnelId tunnel_...
#>
param(
    # Tunnel ID from Platform -> Tunnels. Asked for when the profile is first created.
    [string]$TunnelId,
    # Label for this app's lines in the trace.
    [string]$Name = "chatgpt-weather",
    # Recreate the profile (for example after changing -Name or the tunnel ID).
    [switch]$Reset,
    # Install and create the profile, but don't start the tunnel.
    [switch]$SetupOnly
)

$ErrorActionPreference = "Stop"
$Version = "v0.0.16"
$ProfileName = "agentlatch"
$Repo = Split-Path -Parent $PSScriptRoot
$Runtime = "$HOME\agentlatch-runtime"
$TestDir = "$HOME\agentlatch-test"
$Trace = "$HOME\agentlatch-trace.jsonl"
$ToolsDir = "$HOME\tools\tunnel-client"

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Fail([string]$Message) { Write-Host "`nError: $Message" -ForegroundColor Red; exit 1 }
function Check([string]$What) { if ($LASTEXITCODE -ne 0) { Fail "$What failed (exit code $LASTEXITCODE)." } }

# 1. AgentLatch
if (Test-Path "$Runtime\Scripts\agent-latch-runtime.exe") {
    Step "AgentLatch is already installed in $Runtime"
} else {
    Step "Installing AgentLatch into $Runtime"
    if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 -m venv $Runtime } else { & python -m venv $Runtime }
    Check "Creating the Python environment"
    & "$Runtime\Scripts\python.exe" -m pip install -e "$Repo[runtime]"
    Check "Installing AgentLatch"
}

# 2. Test server
Step "Copying the test server to $TestDir"
New-Item -ItemType Directory -Force $TestDir | Out-Null
Copy-Item "$Repo\tests\runtime_fixtures\fake_server.py" $TestDir -Force

# 3. tunnel-client
$TC = Get-ChildItem $ToolsDir -Recurse -Filter tunnel-client.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if ($TC) {
    Step "tunnel-client is already installed"
} else {
    $Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    $Zip = "tunnel-client-$Version-windows-$Arch.zip"
    $Base = "https://github.com/openai/tunnel-client/releases/download/$Version"
    Step "Downloading $Zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    New-Item -ItemType Directory -Force $ToolsDir | Out-Null
    $ZipPath = "$ToolsDir\$Zip"
    Invoke-WebRequest "$Base/$Zip" -OutFile $ZipPath -UseBasicParsing
    $SumsPath = "$ToolsDir\SHA256SUMS.txt"
    Invoke-WebRequest "$Base/SHA256SUMS.txt" -OutFile $SumsPath -UseBasicParsing
    $Expected = Get-Content $SumsPath | ForEach-Object { $f = -split $_; if ($f.Count -ge 2 -and $f[1].TrimStart('*') -eq $Zip) { $f[0] } } | Select-Object -First 1
    Remove-Item $SumsPath -Force
    $Actual = (Get-FileHash $ZipPath -Algorithm SHA256).Hash
    if (-not $Expected -or $Expected -ne $Actual.ToLower()) { Remove-Item $ZipPath -Force; Fail "The download's checksum doesn't match the published one, so it wasn't used." }
    Expand-Archive $ZipPath -DestinationPath $ToolsDir -Force
    Remove-Item $ZipPath -Force
    $TC = Get-ChildItem $ToolsDir -Recurse -Filter tunnel-client.exe | Select-Object -First 1 -ExpandProperty FullName
}
& $TC --version

# 4. API key: hidden prompt, kept only in this window's memory
if (-not $SetupOnly) {
    Step "API key"
    Write-Host "Paste your restricted key (Tunnels: Read + Use). Nothing shows as you paste; press Enter."
    $Secure = Read-Host "API key" -AsSecureString
    $Key = [System.Net.NetworkCredential]::new("", $Secure).Password
    # Drop hidden characters that some terminals add to pasted text.
    $Key = ($Key -replace "\x1b\[20[01]~", "" -replace "[\x00-\x1F\x7F]", "").Trim()
    if (-not $Key) { Fail "No key was entered." }
    if (-not $Key.StartsWith("sk-")) { Write-Warning "That doesn't look like an OpenAI key (they start with sk-). Trying anyway." }
    $env:CONTROL_PLANE_API_KEY = $Key
    Remove-Variable Key, Secure
}

try {
    # 5. Profile
    $HasProfile = [bool](& $TC profiles list | Where-Object { ($_ -split "`t")[0] -eq $ProfileName })
    if ($HasProfile -and -not $Reset) {
        Step "Using the existing '$ProfileName' profile (run with -Reset to recreate it)"
    } else {
        if (-not $TunnelId) { $TunnelId = (Read-Host "Paste your tunnel ID (tunnel_...)").Trim() }
        if ($TunnelId -notmatch '^tunnel_[A-Za-z0-9]+$') { Fail "'$TunnelId' isn't a tunnel ID. Copy it from Platform -> Tunnels; it starts with tunnel_." }
        # tunnel-client drops backslashes from --mcp-command, so the paths use forward slashes.
        $H = $HOME -replace '\\', '/'
        $Command = "$H/agentlatch-runtime/Scripts/agent-latch-runtime.exe proxy --name $Name --trace $H/agentlatch-trace.jsonl -- $H/agentlatch-runtime/Scripts/python.exe $H/agentlatch-test/fake_server.py"
        Step "Creating the '$ProfileName' profile"
        $InitArgs = @("init", "--sample", "sample_mcp_stdio_local", "--profile", $ProfileName, "--tunnel-id", $TunnelId, "--mcp-command", $Command)
        if ($HasProfile) { $InitArgs += "--force" }
        & $TC @InitArgs
        Check "Creating the profile"
    }

    if ($SetupOnly) {
        Step "Setup finished. Run this command again without -SetupOnly to start the tunnel."
        exit 0
    }

    # 6. Check, then run
    Step "Checking the profile"
    & $TC doctor --profile $ProfileName --explain
    if ($LASTEXITCODE -ne 0) { Write-Warning "doctor reported a problem (see above). Starting anyway." }

    Step "Starting the tunnel. Leave this window open; press Ctrl+C to stop."
    Write-Host "Status page: http://127.0.0.1:8080/ui"
    Write-Host "Trace file:  $Trace"
    & $TC run --profile $ProfileName
} finally {
    Remove-Item Env:CONTROL_PLANE_API_KEY -ErrorAction SilentlyContinue
}
