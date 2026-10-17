"""Runtime tests that need no FastMCP: package import, redaction, trace log, CLI parsing."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

from agent_latch.runtime import TRACE_SCHEMA, ToolCall, ToolInfo, ToolOutput, TraceLog
from agent_latch.runtime.cli import _default_name, _parse_http, main
from agent_latch.runtime.redact import MASK, excerpt, mask_secrets, payload_sha256

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
