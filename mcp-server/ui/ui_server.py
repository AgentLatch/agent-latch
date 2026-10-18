"""Local dashboard for the MCP gateway and the AgentLatch scanner.

    python ui/ui_server.py        # then open http://127.0.0.1:8766

Three things, all driven by real commands, nothing faked:
  - Run a static AgentLatch scan on a path and show the vulnerabilities found.
  - Check whether the gateway is connected, and list its tools.
  - Run selected tools through the gateway, streaming each step so the page can
    animate the agent -> gateway -> tool path.

Stdlib only. It talks to the running HTTP gateway, so start that first:
    python server.py --http
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
MCP_DIR = HERE.parent
REPO_ROOT = MCP_DIR.parent
sys.path.insert(0, str(MCP_DIR))

UI_HOST = os.environ.get("MCP_UI_HOST", "127.0.0.1")
UI_PORT = int(os.environ.get("MCP_UI_PORT", "8766"))
GATEWAY_PORT = int(os.environ.get("MCP_GATEWAY_PORT", "8765"))
GATEWAY_HOST = os.environ.get("MCP_GATEWAY_HOST", "127.0.0.1")
GATEWAY_URL = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/mcp"
GATEWAY_TOKEN = os.environ.get("MCP_GATEWAY_TOKEN") or None

# Safe default arguments for the tools that ship enabled, so "Run" works with no typing.
DEFAULT_ARGS: dict[str, dict[str, object]] = {
    "echo": {"text": "hello from the dashboard"},
    "utc_now": {},
    "time_get_current_time": {"timezone": "UTC"},
    "fetch_fetch": {"url": "https://example.com", "max_length": 400},
    "slack_send_message": {"text": "Hi! This message is from an AI agent, sent through the MCP gateway. \U0001f44b"},
    "slack_whoami": {},
}


def find_agent_latch() -> list[str] | None:
    """Locate the agent-latch CLI, or return None if it is not installed."""
    override = os.environ.get("AGENT_LATCH_CMD")
    if override:
        return override.split()
    found = shutil.which("agent-latch")
    return [found] if found else None


def run_scan(target: str) -> dict:
    """Run a static AgentLatch scan and return its JSON report (or an error dict)."""
    cmd = find_agent_latch()
    if cmd is None:
        return {
            "error": "agent-latch is not installed. From the repo root run: "
            "pip install -e \".[dev]\"  (or set AGENT_LATCH_CMD).",
        }
    path = (REPO_ROOT / target).resolve() if not os.path.isabs(target) else Path(target)
    if not str(path).startswith(str(REPO_ROOT)):
        return {"error": "Scan path must be inside the repository."}
    if not path.exists():
        return {"error": f"Path not found: {target}"}
    try:
        proc = subprocess.run(
            [*cmd, "scan", str(path), "--format", "json", "--fail-on", "none"],
            check=False, capture_output=True, text=True, timeout=300, cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 5 minutes."}
    if not proc.stdout.strip():
        return {"error": f"Scan produced no output. {proc.stderr.strip()[:300]}"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": f"Could not read scan output. {proc.stderr.strip()[:300]}"}


def gateway_status() -> dict:
    """Return whether the gateway is reachable and, if so, its tools."""
    try:
        from bridge import GatewayTools
    except Exception as exc:  # noqa: BLE001
        return {"connected": False, "reason": f"bridge import failed: {exc}"}
    try:
        gw = GatewayTools(url=GATEWAY_URL, token=GATEWAY_TOKEN)
    except Exception as exc:  # noqa: BLE001
        detail = str(exc).splitlines()[0][:160] if str(exc) else exc.__class__.__name__
        return {
            "connected": False,
            "url": GATEWAY_URL,
            "reason": (
                "Not connected. Start the gateway first: open a terminal in mcp-server "
                "and run `python server.py --http`. See SETUP.md."
            ),
            "detail": detail,
        }
    try:
        tools = [{"name": n, "description": gw.describe(n)} for n in gw.names()]
    finally:
        gw.close()
    return {"connected": True, "url": GATEWAY_URL, "tools": tools}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # quieter console
        return

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, name: str, content_type: str) -> None:
        path = HERE / name
        if not path.exists():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, event: dict) -> None:
        self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
        self.wfile.flush()

    def do_GET(self) -> None:
        route = urlparse(self.path)
        if route.path in ("/", "/index.html"):
            self._send_file("index.html", "text/html; charset=utf-8")
        elif route.path == "/api/gateway/status":
            self._send_json(gateway_status())
        elif route.path == "/api/gateway/run":
            self._run_tools(parse_qs(route.query))
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/scan":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or "{}")
        except json.JSONDecodeError:
            body = {}
        target = body.get("path") or "examples/vulnerable-agent"
        self._send_json(run_scan(target))

    def _run_tools(self, query: dict[str, list[str]]) -> None:
        """Stream the agent -> gateway -> tool run as Server-Sent Events."""
        requested = [t for t in (query.get("tools", [""])[0] or "").split(",") if t]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        try:
            from bridge import GatewayTools
        except Exception as exc:  # noqa: BLE001
            self._sse({"step": "error", "message": f"bridge import failed: {exc}"})
            return

        self._sse({"step": "connecting", "target": GATEWAY_URL})
        time.sleep(0.4)
        try:
            gw = GatewayTools(url=GATEWAY_URL, token=GATEWAY_TOKEN)
        except Exception:  # noqa: BLE001
            self._sse({"step": "not_connected", "message": (
                "The gateway is not connected. You still need to start it: "
                "run `python server.py --http` in mcp-server. See SETUP.md."
            )})
            return
        try:
            available = gw.names()
            self._sse({"step": "connected", "tools": available})
            time.sleep(0.4)
            for name in requested:
                if name not in available:
                    self._sse({"step": "tool_skipped", "tool": name, "reason": "not available"})
                    continue
                args = DEFAULT_ARGS.get(name, {})
                self._sse({"step": "tool_call", "tool": name, "args": args})
                time.sleep(0.5)
                try:
                    result = gw.call(name, **args)
                    text = result if isinstance(result, str) else json.dumps(result, default=str)
                    self._sse({"step": "tool_result", "tool": name, "result": str(text)[:600]})
                except Exception as exc:  # noqa: BLE001
                    self._sse({"step": "tool_error", "tool": name, "error": str(exc)[:300]})
                time.sleep(0.3)
            self._sse({"step": "done"})
        finally:
            gw.close()


def main() -> None:
    server = ThreadingHTTPServer((UI_HOST, UI_PORT), Handler)
    url = f"http://{UI_HOST}:{UI_PORT}"
    print(f"Dashboard: {url}")
    print(f"Gateway expected at: {GATEWAY_URL} (start it with: python server.py --http)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
