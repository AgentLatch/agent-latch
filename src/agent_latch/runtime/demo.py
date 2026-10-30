"""``agent-latch-runtime demo``: record and import a short synthetic MCP session [needs fastmcp].

It starts the bundled demo server (``demo_server``) behind the real proxy with ``--trace`` and
``--payloads``, makes a few calls through it as an MCP client would, then imports the logs once.
Nothing leaves the machine: the server is local and synthetic, and its fake credential is masked.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import TextIO

from agent_latch.runtime.importer import RuntimeLogImporter, discover_gates

DEMO_SERVER = "demo-server"
ROGUE_SERVER = "rogue-server"
# The only files the demo writes; a rerun removes just these, so the demo starts clean.
DEMO_FILES = (
    "trace.jsonl", "payloads.jsonl", "events.csv", "gate-results.csv", "normalized.jsonl",
    "proxy.log",
)


async def _drive(directory: Path, log_file: TextIO, *, server_module: str, server_name: str) -> None:
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    transport = StdioTransport(
        command=sys.executable,
        args=[
            "-m", "agent_latch.runtime.cli", "proxy", "--quiet", "--name", server_name,
            "--trace", str(directory / "trace.jsonl"),
            "--payloads", str(directory / "payloads.jsonl"),
            "--", sys.executable, "-m", server_module,
        ],
        env=dict(os.environ),
        keep_alive=False,
        log_file=log_file,
    )
    async with Client(transport) as client:
        await client.list_tools()
        await client.call_tool("get_weather", {"city": "London"})
        await client.call_tool("leaky_lookup", {"user": "alice"})
        await client.call_tool("broken_tool", {"reason": "demo"}, raise_on_error=False)
        await client.list_prompts()
        await client.get_prompt("summarize", {"topic": "Mars"})


async def _drive_rogue(directory: Path, log_file: TextIO) -> None:
    """Drive the rogue server: it has only ``ping``, so the calls differ from the normal demo."""
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    transport = StdioTransport(
        command=sys.executable,
        args=[
            "-m", "agent_latch.runtime.cli", "proxy", "--quiet", "--name", ROGUE_SERVER,
            "--trace", str(directory / "trace.jsonl"),
            "--payloads", str(directory / "payloads.jsonl"),
            "--", sys.executable, "-m", "agent_latch.runtime.rogue_server",
        ],
        env=dict(os.environ),
        keep_alive=False,
        log_file=log_file,
    )
    async with Client(transport) as client:
        await client.list_tools()
        await client.call_tool("ping", {})


def run_demo(directory: Path, *, out: TextIO | None = None, rogue: bool = False) -> None:
    """Record a demo session into ``directory`` and import it; raises on failure.

    With ``rogue``, the demo server hides its identity so ALR03 reports a finding.
    """
    out = out if out is not None else sys.stderr
    directory.mkdir(parents=True, exist_ok=True)
    for name in DEMO_FILES:
        (directory / name).unlink(missing_ok=True)
    server_name = ROGUE_SERVER if rogue else DEMO_SERVER
    out.write(
        f"agent-latch-runtime: demo: calling the synthetic {server_name} through the proxy\n"
    )
    out.flush()
    # The proxy's own stderr (startup message, warnings) goes to proxy.log in the demo folder.
    with (directory / "proxy.log").open("w", encoding="utf-8") as log_file:
        if rogue:
            asyncio.run(_drive_rogue(directory, log_file))
        else:
            asyncio.run(_drive(directory, log_file,
                               server_module="agent_latch.runtime.demo_server",
                               server_name=DEMO_SERVER))
    gates = discover_gates()
    out.write(f"agent-latch-runtime: demo: importing the logs ({len(gates)} gate(s))\n")
    out.flush()
    RuntimeLogImporter(
        directory / "trace.jsonl",
        directory / "gate-results.csv",
        gates,
        payloads_path=directory / "payloads.jsonl",
        events_csv=directory / "events.csv",
        normalized_path=directory / "normalized.jsonl",
        summary=out,
        follow=False,
    ).run()
    written = [name for name in DEMO_FILES if (directory / name).exists()]
    out.write(f"agent-latch-runtime: demo: files in {directory}: {', '.join(written)}\n")
    out.flush()
