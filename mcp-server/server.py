"""Local MCP gateway: one MCP server that gives any agent your local tools plus every
MCP server listed in servers.json, with secrets kept in .env.

    python server.py --check   # list the tools that load, then exit
    python server.py           # stdio, for agents that launch the server themselves
    python server.py --http    # serve http://127.0.0.1:8765/mcp for any agent
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import logging
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "servers.json"
TOOLS_DIR = HERE / "tools"
LOG_DIR = HERE / "logs"
ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Keys this gateway understands in servers.json; everything else is passed to FastMCP.
GATEWAY_KEYS = {"enabled", "description"}

log = logging.getLogger("mcp-gateway")


def fill_env(value: Any, missing: set[str]) -> Any:
    """Replace ${NAME} with its environment value, recording names that are unset or empty."""
    if isinstance(value, str):

        def lookup(match: re.Match[str]) -> str:
            resolved = os.environ.get(match.group(1), "")
            if not resolved:
                missing.add(match.group(1))
            return resolved

        return ENV_REF.sub(lookup, value)
    if isinstance(value, list):
        return [fill_env(item, missing) for item in value]
    if isinstance(value, dict):
        return {key: fill_env(item, missing) for key, item in value.items()}
    return value


def load_servers(config_path: Path) -> dict[str, dict[str, Any]]:
    """Return the servers in servers.json that are enabled and have what they need to start."""
    servers = json.loads(config_path.read_text(encoding="utf-8")).get("mcpServers", {})
    ready: dict[str, dict[str, Any]] = {}
    for name, spec in servers.items():
        if not spec.get("enabled", True):
            log.info("skip %s: disabled in %s", name, config_path.name)
            continue
        missing: set[str] = set()
        spec = fill_env({k: v for k, v in spec.items() if k not in GATEWAY_KEYS}, missing)
        if missing:
            log.warning("skip %s: set %s in .env", name, ", ".join(sorted(missing)))
            continue
        command = spec.get("command")
        if command and shutil.which(command) is None:
            log.warning("skip %s: '%s' is not installed", name, command)
            continue
        if command:
            # Relative paths in servers.json (for example ./workspace) are relative to this folder.
            spec.setdefault("cwd", str(HERE))
        ready[name] = spec
    return ready


def load_local_tools(gateway: FastMCP) -> None:
    """Import every tools/*.py file and let its register(mcp) function add tools."""
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"gateway_tools.{path.stem}", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        register = getattr(module, "register", None)
        if callable(register):
            register(gateway)
            log.info("loaded tools/%s", path.name)
        else:
            log.warning("skip tools/%s: it has no register(mcp) function", path.name)


def build_gateway(config_path: Path, auth: StaticTokenVerifier | None = None) -> FastMCP:
    """Create the gateway with local tools and one mounted proxy per ready server."""
    gateway = FastMCP(
        "agentlatch-gateway",
        instructions=(
            "Local gateway for live agent runs. Tools from servers.json are prefixed with "
            "their server name, for example time_get_current_time."
        ),
        auth=auth,
    )
    load_local_tools(gateway)
    for name, spec in load_servers(config_path).items():
        target: Any = {"mcpServers": {name: spec}}
        if "command" in spec:
            # A local server's own output goes to logs/<name>.log instead of the terminal.
            LOG_DIR.mkdir(exist_ok=True)
            target = StdioTransport(
                command=spec["command"],
                args=spec.get("args", []),
                env=spec.get("env") or None,
                cwd=spec.get("cwd"),
                log_file=LOG_DIR / f"{name}.log",
            )
        # mode="auto" lets each server negotiate its own protocol version, so older
        # servers that need the initialize handshake still work behind a newer client.
        gateway.mount(create_proxy(target, name=name, mode="auto"), namespace=name)
        log.info("mounted %s", name)
    return gateway


async def show_tools(gateway: FastMCP) -> None:
    """Print every tool an agent would see."""
    async with Client(gateway) as client:
        tools = await client.list_tools()
    print(f"{len(tools)} tool(s) available:")
    for tool in tools:
        summary = (tool.description or "").strip().splitlines()
        print(f"  {tool.name:<36} {summary[0][:80] if summary else ''}")


def main(argv: list[str] | None = None) -> None:
    load_dotenv(HERE / ".env")
    parser = argparse.ArgumentParser(description="Local MCP gateway for live agent runs.")
    parser.add_argument("--check", action="store_true", help="list the tools that load, then exit")
    parser.add_argument("--http", action="store_true", help="serve over HTTP instead of stdio")
    parser.add_argument("--host", default=os.environ.get("MCP_GATEWAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_GATEWAY_PORT", "8765")))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="servers file")
    args = parser.parse_args(argv)

    # stdout carries the MCP protocol in stdio mode, so all logging goes to stderr.
    logging.basicConfig(level=logging.INFO, format="[gateway] %(message)s", stream=sys.stderr)

    token = os.environ.get("MCP_GATEWAY_TOKEN", "")
    auth = None
    if args.http and token:
        auth = StaticTokenVerifier(tokens={token: {"client_id": "local-agent", "scopes": []}})
    gateway = build_gateway(args.config, auth)

    if args.check:
        asyncio.run(show_tools(gateway))
    elif args.http:
        if not token:
            log.warning("no MCP_GATEWAY_TOKEN set: any program on this machine can connect")
        log.info("serving http://%s:%d/mcp", args.host, args.port)
        gateway.run(transport="http", host=args.host, port=args.port, show_banner=False)
    else:
        gateway.run(show_banner=False)


if __name__ == "__main__":
    main()
