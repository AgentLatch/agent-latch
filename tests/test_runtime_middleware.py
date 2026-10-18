"""End-to-end runtime proxy tests through real MCP clients. Skipped without the [runtime] extra."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from io import StringIO
from pathlib import Path

import pytest

pytest.importorskip("fastmcp")

from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy

from agent_latch.runtime.middleware import AgentLatchMiddleware
from agent_latch.runtime.redact import MASK
from agent_latch.runtime.trace import TraceLog

FIXTURES = Path(__file__).resolve().parent / "runtime_fixtures"
SRC = Path(__file__).resolve().parents[1] / "src"
FAKE_TOKEN = "sk-" + "FAKE0123456789abcdefFAKE"


async def _exercise(client: Client) -> dict[str, object]:
    async with client:
        tools = await client.list_tools()
        weather = await client.call_tool("get_weather", {"city": "London"})
        leaky = await client.call_tool("leaky_lookup", {"user": "alice"})
        broken = await client.call_tool("broken_tool", {"reason": "x"}, raise_on_error=False)
        prompts = await client.list_prompts()
        prompt = await client.get_prompt("summarize", {"topic": "Mars"})
    return {
        "tools": sorted(tool.name for tool in tools),
        "weather": weather.content[0].text,
        "leaky": leaky.content[0].text,
        "broken_is_error": broken.is_error,
        "prompts": [p.name for p in prompts],
        "prompt": prompt.messages[0].content.text,
    }


def _records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _check_trace(records: list[dict[str, object]], server: str) -> None:
    by_key = {(r["method"], r["stage"], r.get("tool") or r.get("prompt")): r for r in records}
    assert all(r["server"] == server for r in records)

    listed = next(r for r in records if r["method"] == "tools/list")
    assert {t["name"] for t in listed["tools"]} >= {"get_weather", "leaky_lookup", "broken_tool"}

    request = by_key[("tools/call", "request", "get_weather")]
    assert request["argument_names"] == ["city"]
    response = by_key[("tools/call", "response", "get_weather")]
    assert response["is_error"] is False and "Weather in London" in response["excerpt"]

    leaky = by_key[("tools/call", "response", "leaky_lookup")]
    assert MASK in leaky["excerpt"]

    broken = by_key.get(("tools/call", "error", "broken_tool")) or by_key.get(
        ("tools/call", "response", "broken_tool")
    )
    assert broken is not None
    assert broken["stage"] == "error" or broken["is_error"] is True

    assert by_key[("prompts/get", "request", "summarize")]["argument_names"] == ["topic"]
    assert by_key[("prompts/get", "response", "summarize")]["roles"] == ["user"]
    assert any(r["method"] == "prompts/list" for r in records)


def test_middleware_passes_traffic_through_unchanged(tmp_path: Path) -> None:
    sys.path.insert(0, str(FIXTURES))
    try:
        from fake_server import server as backend
    finally:
        sys.path.remove(str(FIXTURES))

    direct = asyncio.run(_exercise(Client(backend)))

    trace_path = tmp_path / "trace.jsonl"
    trace = TraceLog(trace_path, summary=StringIO())
    proxy = create_proxy(backend, name="weather")
    proxy.add_middleware(AgentLatchMiddleware(trace, server="weather"))
    proxied = asyncio.run(_exercise(Client(proxy)))
    trace.close()

    assert proxied == direct
    raw = trace_path.read_text(encoding="utf-8")
    assert FAKE_TOKEN not in raw and "London" not in raw.split('"excerpt"')[0]
    _check_trace(_records(trace_path), "weather")


def test_middleware_survives_trace_failures() -> None:
    class BrokenTrace(TraceLog):
        def write(self, record):  # type: ignore[override]
            raise OSError("disk full")

    sys.path.insert(0, str(FIXTURES))
    try:
        from fake_server import server as backend
    finally:
        sys.path.remove(str(FIXTURES))

    proxy = create_proxy(backend, name="weather")
    proxy.add_middleware(AgentLatchMiddleware(BrokenTrace(None, summary=None), server="weather"))
    result = asyncio.run(_exercise(Client(proxy)))
    assert result["weather"].startswith("Weather in London")


def test_proxy_command_over_stdio(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.jsonl"
    stderr_path = tmp_path / "stderr.log"
    transport = StdioTransport(
        command=sys.executable,
        args=[
            "-m", "agent_latch.runtime.cli", "proxy",
            "--trace", str(trace_path),
            "--",
            sys.executable, str(FIXTURES / "fake_server.py"),
        ],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        log_file=stderr_path,
        keep_alive=False,
    )
    result = asyncio.run(_exercise(Client(transport)))

    assert result["weather"] == "Weather in London: 18 degrees (metric), light rain."
    assert FAKE_TOKEN in result["leaky"]  # the agent still gets the real output
    assert result["prompts"] == ["summarize"]
    _check_trace(_records(trace_path), "fake_server")
    stderr = stderr_path.read_text(encoding="utf-8")
    assert "monitoring 'fake_server'" in stderr
    assert "tools/call get_weather (city)" in stderr
    assert FAKE_TOKEN not in trace_path.read_text(encoding="utf-8") + stderr
