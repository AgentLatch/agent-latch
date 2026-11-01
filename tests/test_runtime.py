"""Runtime tests that need no FastMCP: package import, redaction, trace log, CLI parsing."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

from agent_latch.runtime import (
    PAYLOAD_SCHEMA,
    TRACE_SCHEMA,
    PayloadEvent,
    PayloadFile,
    PayloadTap,
    ToolCall,
    ToolInfo,
    ToolOutput,
    TraceLog,
)
from agent_latch.runtime.cli import _default_name, _parse_http, main
from agent_latch.runtime.redact import MASK, excerpt, mask_secrets, mask_value, payload_sha256

SRC = Path(__file__).resolve().parents[1] / "src"
FAKE_TOKEN = "sk-" + "FAKE0123456789abcdefFAKE"


def _call(**arguments: object) -> ToolCall:
    return ToolCall(
        session_id="s1",
        request_id="7",
        client_id=None,
        tool="get_weather",
        server="weather",
        arguments=arguments,
        timestamp="2026-10-17T00:00:00.000Z",
    )


def _call_tool(tool: str) -> ToolCall:
    return ToolCall(
        session_id="s1",
        request_id="8",
        client_id=None,
        tool=tool,
        server="weather",
        arguments={},
        timestamp="2026-10-17T00:00:00.000Z",
    )


def test_import_does_not_load_fastmcp() -> None:
    code = "import sys, agent_latch.runtime; print('fastmcp' in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
        check=True,
    )
    assert result.stdout.strip() == "False"


@pytest.mark.parametrize(
    "text",
    [
        f"token is {FAKE_TOKEN}",
        "password=" + "hunter2hunter2",
        '{"api_key": "' + "abcd1234efgh5678" + '"}',
        "Authorization: Bearer " + "abcdefghijklmnop",
        "ghp_" + "A" * 36,
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_mask_secrets_hides_credential_values(text: str) -> None:
    masked = mask_secrets(text)
    assert MASK in masked
    for secret in (FAKE_TOKEN, "hunter2hunter2", "abcd1234efgh5678", "abcdefghijklmnop", "A" * 36,
                   "MIIEow"):
        assert secret not in masked


def test_excerpt_is_short_single_line_and_optional() -> None:
    text = "line one\nline two " + "x" * 500
    short = excerpt(text, 40)
    assert len(short) == 40 and "\n" not in short and short.endswith("…")
    assert excerpt(text, 0) == ""
    # A secret straddling the cut is masked before truncation.
    assert "FAKE0123" not in excerpt("a" * 30 + " " + FAKE_TOKEN, 40)


def test_payload_hash_is_order_independent() -> None:
    assert payload_sha256({"a": 1, "b": 2}) == payload_sha256({"b": 2, "a": 1})


def test_trace_log_keeps_names_and_hashes_not_values(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "trace.jsonl"
    summary = StringIO()
    trace = TraceLog(path, summary=summary, excerpt_chars=200)
    call = _call(city="London", api_key=FAKE_TOKEN)
    trace.call_request(call)
    trace.call_response(call, ToolOutput((f"ok {FAKE_TOKEN}",), None, False), 3.21)
    trace.tools_listed(
        session_id="s1",
        request_id="1",
        server="weather",
        tools=[ToolInfo("get_weather", "weather", "Get weather.", {"type": "object"})],
    )
    trace.close()

    raw = path.read_text(encoding="utf-8")
    assert FAKE_TOKEN not in raw and "London" not in raw
    request, response, listed = (json.loads(line) for line in raw.splitlines())
    assert request["schema"] == TRACE_SCHEMA
    assert request["method"] == "tools/call" and request["stage"] == "request"
    assert request["argument_names"] == ["api_key", "city"]
    assert len(request["arguments_sha256"]) == 64
    assert response["excerpt"] == f"ok {MASK}" and response["duration_ms"] == 3.2
    assert listed["tools"][0]["name"] == "get_weather"
    assert "tools/call get_weather (api_key, city)" in summary.getvalue()
    assert FAKE_TOKEN not in summary.getvalue()
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_trace_error_records_type_only(tmp_path: Path) -> None:
    trace = TraceLog(tmp_path / "t.jsonl", summary=None)
    record = trace.call_error(_call(city="London"), ValueError("bad city London"), 1.0)
    trace.close()
    assert record["error_type"] == "ValueError"
    assert "London" not in (tmp_path / "t.jsonl").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("command", "url", "expected"),
    [
        (["npx", "-y", "@modelcontextprotocol/server-github"], None, "server-github"),
        (["python", "tools/server.py"], None, "server"),
        (["uvx", "mcp-server-time"], None, "mcp-server-time"),
        ([], "https://tools.example.com/mcp", "tools.example.com"),
    ],
)
def test_default_server_name(command: list[str], url: str | None, expected: str) -> None:
    assert _default_name(command, url) == expected


def test_http_listener_must_be_loopback() -> None:
    assert _parse_http("127.0.0.1:8770") == ("127.0.0.1", 8770)
    assert _parse_http("[::1]:8770") == ("::1", 8770)
    for bad in ("0.0.0.0:8770", "192.168.1.5:8770", "127.0.0.1"):
        with pytest.raises(ValueError):
            _parse_http(bad)


def test_proxy_needs_exactly_one_upstream(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["proxy"]) == 2
    assert main(["proxy", "--upstream-url", "http://127.0.0.1:1/mcp", "--", "python", "x.py"]) == 2
    assert "--upstream-url" in capsys.readouterr().err


def test_mask_value_masks_secret_keys_and_cuts_long_strings() -> None:
    value = {
        "api_key": "plainvalue",
        "query": f"use {FAKE_TOKEN}",
        "nested": [{"password": "x" * 8}, 3, None, True],
        "long": "a" * 50,
    }
    masked = mask_value(value, 20)
    assert masked["api_key"] == MASK
    assert masked["query"] == f"use {MASK}"
    assert masked["nested"] == [{"password": MASK}, 3, None, True]
    assert masked["long"] == "a" * 20 + "…[30 more chars]"


def test_payload_tap_attaches_tool_definition_and_isolates_sinks() -> None:
    seen: list[PayloadEvent] = []

    def broken(event: PayloadEvent) -> None:
        raise RuntimeError("sink down")

    tap = PayloadTap([broken, seen.append])
    weather = ToolInfo(
        "get_weather", "weather", "Weather for a city.", {"type": "object"}, {"readOnlyHint": True}
    )
    tap.tools_listed(
        session_id="s1", request_id="1", client_id=None, server="weather", tools=[weather]
    )
    call = _call(city="London")
    tap.call_request(call)
    tap.call_response(call, ToolOutput(("rainy",), {"temp": 18}, False), 4.25)
    tap.call_request(_call_tool("unlisted_tool"))
    tap.prompt_response(
        session_id="s1", request_id="9", client_id="c1", server="weather", prompt="summarize",
        roles=["user"], texts=["Summarize Mars"],
    )

    listed, request, response, unlisted, prompt = (event.to_dict() for event in seen)
    assert [e["seq"] for e in (listed, request, response, unlisted, prompt)] == [1, 2, 3, 4, 5]
    assert all(e["schema"] == PAYLOAD_SCHEMA for e in (listed, request, prompt))
    assert listed["payload"]["tools"][0]["annotations"] == {"readOnlyHint": True}
    assert request["payload"]["arguments"] == {"city": "London"}
    assert request["payload"]["tool_definition"]["description"] == "Weather for a city."
    assert response["payload"] == {
        "tool": "get_weather", "is_error": False, "content": ["rainy"],
        "structured": {"temp": 18}, "duration_ms": 4.2,
    }
    assert unlisted["payload"]["tool_definition"] is None
    assert prompt["payload"]["messages"] == [{"role": "user", "text": "Summarize Mars"}]


def test_payload_file_masks_values(tmp_path: Path) -> None:
    path = tmp_path / "payloads.jsonl"
    sink = PayloadFile(path)
    tap = PayloadTap([sink])
    call = _call(api_key="plainvalue", city="London")
    tap.call_request(call)
    tap.call_response(call, ToolOutput((f"token={FAKE_TOKEN}",), None, False), 1.0)
    sink.close()

    request, response = (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())
    assert request["payload"]["arguments"] == {"api_key": MASK, "city": "London"}
    assert FAKE_TOKEN not in json.dumps(response)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
