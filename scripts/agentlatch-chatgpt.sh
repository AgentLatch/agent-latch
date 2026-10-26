#!/usr/bin/env bash
# agentlatch-chatgpt: connect ChatGPT to AgentLatch through OpenAI's Secure MCP Tunnel, in one command.
#
# The first run sets everything up: it installs AgentLatch and the test server if they're missing,
# downloads and checks tunnel-client, asks for your tunnel ID, creates the "agentlatch" profile and
# starts the tunnel. Later runs skip the steps that are already done, ask for your API key and start
# the tunnel. The key is typed into a hidden prompt and is never saved.
#
# Usage: scripts/agentlatch-chatgpt.sh [--tunnel-id tunnel_...] [--name LABEL] [--reset] [--setup-only]
#   --tunnel-id   Tunnel ID from Platform -> Tunnels (asked for when the profile is first created)
#   --name        Label for this app's lines in the trace (default chatgpt-weather)
#   --reset       Recreate the profile, for example after changing --name or the tunnel ID
#   --setup-only  Install and create the profile, but don't start the tunnel
#
# Creating the tunnel and the API key, and adding the plugin in ChatGPT, are still done by hand:
# see docs/clients/chatgpt.md. This script writes a trace only. It does not pass --payloads and
# it does not run import-logs, so it does not produce a finding.
set -euo pipefail

VERSION="v0.0.16"
PROFILE_NAME="agentlatch"
NAME="chatgpt-weather"
TUNNEL_ID=""
RESET=0
SETUP_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --tunnel-id) TUNNEL_ID="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --reset) RESET=1; shift ;;
    --setup-only) SETUP_ONLY=1; shift ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="$HOME/agentlatch-runtime"
TEST_DIR="$HOME/agentlatch-test"
TRACE="$HOME/agentlatch-trace.jsonl"
TOOLS_DIR="$HOME/tools/tunnel-client"

step() { printf '\n==> %s\n' "$1"; }
fail() { printf '\nError: %s\n' "$1" >&2; exit 1; }

# 1. AgentLatch
if [ -x "$RUNTIME/bin/agent-latch-runtime" ]; then
  step "AgentLatch is already installed in $RUNTIME"
else
  step "Installing AgentLatch into $RUNTIME"
  python3 -m venv "$RUNTIME" || fail "Creating the Python environment failed. On Ubuntu/Debian, run: sudo apt install python3-venv"
  "$RUNTIME/bin/python" -m pip install -e "$REPO[runtime]" || fail "Installing AgentLatch failed."
fi

# 2. Test server
step "Copying the test server to $TEST_DIR"
mkdir -p "$TEST_DIR"
cp "$REPO/tests/runtime_fixtures/fake_server.py" "$TEST_DIR/"

# 3. tunnel-client
TC="$(find "$TOOLS_DIR" -type f -name tunnel-client 2>/dev/null | head -n 1 || true)"
if [ -n "$TC" ]; then
  step "tunnel-client is already installed"
else
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) PLATFORM=darwin-arm64 ;;
    Darwin-x86_64) PLATFORM=darwin-amd64 ;;
    Linux-x86_64) PLATFORM=linux-amd64 ;;
    Linux-aarch64|Linux-arm64) PLATFORM=linux-arm64 ;;
    *) fail "tunnel-client has no download for $(uname -s) $(uname -m)." ;;
  esac
  command -v unzip >/dev/null || fail "unzip isn't installed. Install it (for example: sudo apt install unzip) and run this again."
  ZIP="tunnel-client-$VERSION-$PLATFORM.zip"
  BASE="https://github.com/openai/tunnel-client/releases/download/$VERSION"
  step "Downloading $ZIP"
  mkdir -p "$TOOLS_DIR"
  curl -fsSL -o "$TOOLS_DIR/$ZIP" "$BASE/$ZIP"
  EXPECTED="$(curl -fsSL "$BASE/SHA256SUMS.txt" | awk -v f="$ZIP" '$2 == f || $2 == "*" f { print $1; exit }')"
  if command -v sha256sum >/dev/null; then
    ACTUAL="$(sha256sum "$TOOLS_DIR/$ZIP" | awk '{ print $1 }')"
  else
    ACTUAL="$(shasum -a 256 "$TOOLS_DIR/$ZIP" | awk '{ print $1 }')"
  fi
  if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    rm -f "$TOOLS_DIR/$ZIP"
    fail "The download's checksum doesn't match the published one, so it wasn't used."
  fi
  unzip -oq "$TOOLS_DIR/$ZIP" -d "$TOOLS_DIR"
  rm -f "$TOOLS_DIR/$ZIP"
  TC="$(find "$TOOLS_DIR" -type f -name tunnel-client | head -n 1)"
  chmod +x "$TC"
fi
"$TC" --version

# 4. API key: hidden prompt, kept only in this process's memory
if [ "$SETUP_ONLY" -eq 0 ]; then
  step "API key"
  echo "Paste your restricted key (Tunnels: Read + Use). Nothing shows as you paste; press Enter."
  printf 'API key: '
  IFS= read -rs KEY
  echo
  # Drop hidden characters that some terminals add to pasted text.
  KEY="$(printf '%s' "$KEY" | sed $'s/\x1b\\[20[01]~//g' | tr -d '[:cntrl:][:space:]')"
  [ -n "$KEY" ] || fail "No key was entered."
  case "$KEY" in sk-*) ;; *) echo "Warning: that doesn't look like an OpenAI key (they start with sk-). Trying anyway." >&2 ;; esac
  export CONTROL_PLANE_API_KEY="$KEY"
  unset KEY
fi

# 5. Profile
HAS_PROFILE=0
if "$TC" profiles list 2>/dev/null | awk -F'\t' -v p="$PROFILE_NAME" '$1 == p { found = 1 } END { exit !found }'; then
  HAS_PROFILE=1
fi
if [ "$HAS_PROFILE" -eq 1 ] && [ "$RESET" -eq 0 ]; then
  step "Using the existing '$PROFILE_NAME' profile (run with --reset to recreate it)"
else
  if [ -z "$TUNNEL_ID" ]; then
    printf 'Paste your tunnel ID (tunnel_...): '
    read -r TUNNEL_ID
  fi
  TUNNEL_ID="$(printf '%s' "$TUNNEL_ID" | tr -d '[:space:]')"
  [[ "$TUNNEL_ID" =~ ^tunnel_[A-Za-z0-9]+$ ]] || fail "'$TUNNEL_ID' isn't a tunnel ID. Copy it from Platform -> Tunnels; it starts with tunnel_."
  COMMAND="$RUNTIME/bin/agent-latch-runtime proxy --name $NAME --trace $TRACE -- $RUNTIME/bin/python $TEST_DIR/fake_server.py"
  step "Creating the '$PROFILE_NAME' profile"
  INIT_ARGS=(init --sample sample_mcp_stdio_local --profile "$PROFILE_NAME" --tunnel-id "$TUNNEL_ID" --mcp-command "$COMMAND")
  [ "$HAS_PROFILE" -eq 1 ] && INIT_ARGS+=(--force)
  "$TC" "${INIT_ARGS[@]}" || fail "Creating the profile failed."
fi

if [ "$SETUP_ONLY" -eq 1 ]; then
  step "Setup finished. Run this command again without --setup-only to start the tunnel."
  exit 0
fi

# 6. Check, then run
step "Checking the profile"
"$TC" doctor --profile "$PROFILE_NAME" --explain || echo "Warning: doctor reported a problem (see above). Starting anyway." >&2

step "Starting the tunnel. Leave this window open; press Ctrl+C to stop."
echo "Status page: http://127.0.0.1:8080/ui"
echo "Trace file:  $TRACE"
exec "$TC" run --profile "$PROFILE_NAME"
