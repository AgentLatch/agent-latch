"""Runtime tests that need no FastMCP: package import, redaction, trace log, CLI parsing."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import UTC
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


def test_proxy_ledger_flag_seals_trace_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    from types import SimpleNamespace

    def build_proxy(*, trace, **_kwargs):
        trace.tools_listed(session_id="s", request_id="1", server="x", tools=[])
        return SimpleNamespace(run=lambda **_run_kwargs: None)

    # A stand-in for the FastMCP-backed module, so this runs without the [runtime] extra.
    monkeypatch.setitem(
        sys.modules, "agent_latch.runtime.proxy", SimpleNamespace(build_proxy=build_proxy)
    )
    trace, ledger = tmp_path / "t.jsonl", tmp_path / "t.ledger.jsonl"
    arguments = ["proxy", "--quiet", "--trace", str(trace), "--ledger", str(ledger)]
    assert main([*arguments, "--", "python", "server.py"]) == 0
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 1
    assert main(["verify", str(ledger)]) == 0


def _stub_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    from types import SimpleNamespace

    def build_proxy(*, trace, **_kwargs):
        trace.tools_listed(session_id="s", request_id="1", server="x", tools=[])
        return SimpleNamespace(run=lambda **_run_kwargs: None)

    monkeypatch.setitem(
        sys.modules, "agent_latch.runtime.proxy", SimpleNamespace(build_proxy=build_proxy)
    )


_RUN_STAMP = re.compile(r"\d{8}-\d{6}(-\d+)?")


def _only_run(root: Path, name: str) -> Path:
    runs = [path for path in (root / name).iterdir() if path.is_dir()]
    assert len(runs) == 1
    assert _RUN_STAMP.fullmatch(runs[0].name)
    return runs[0]


def _set_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def test_proxy_records_trace_and_ledger_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_proxy(monkeypatch)
    arguments = ["proxy", "--quiet", "--log-dir", str(tmp_path), "--name", "My Server"]
    assert main([*arguments, "--", "python", "server.py"]) == 0
    folder = _only_run(tmp_path, "my-server")
    assert len((folder / "trace.jsonl").read_text(encoding="utf-8").splitlines()) == 1
    assert len((folder / "trace.ledger.jsonl").read_text(encoding="utf-8").splitlines()) == 1
    assert main(["verify", str(folder / "trace.ledger.jsonl")]) == 0
    assert not (folder / "payloads.jsonl").exists()  # payloads stay opt-in


def test_proxy_writes_under_the_home_folder_without_a_log_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    home, elsewhere = tmp_path / "home", tmp_path / "elsewhere"
    elsewhere.mkdir()
    _set_home(monkeypatch, home)
    monkeypatch.chdir(elsewhere)  # where an MCP client happens to start the proxy
    assert main(["proxy", "--name", "github", "--", "python", "server.py"]) == 0
    folder = _only_run(home / "agent-latch" / "runtime-logs", "github")
    assert (folder / "trace.jsonl").is_file()
    assert (folder / "trace.ledger.jsonl").is_file()
    assert list(elsewhere.iterdir()) == []
    err = capsys.readouterr().err
    assert f"import-logs --dir {folder.resolve()}" in err  # startup hint
    assert f"run folder: {folder.resolve()}" in err  # and again on exit


def test_every_run_gets_its_own_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import datetime

    from agent_latch.runtime.cli import run_folder

    moment = datetime(2026, 11, 22, 7, 45, 0, tzinfo=UTC)
    first = run_folder(tmp_path, "My Server", moment)
    assert first == tmp_path / "my-server" / "20261122-074500"
    first.mkdir(parents=True)
    assert run_folder(tmp_path, "My Server", moment) == tmp_path / "my-server" / "20261122-074500-2"

    _stub_proxy(monkeypatch)
    command = ["proxy", "--quiet", "--log-dir", str(tmp_path / "logs"), "--name", "s", "--",
               "python", "s.py"]
    assert main(command) == 0
    assert main(command) == 0
    runs = [path for path in (tmp_path / "logs" / "s").iterdir()]
    assert len(runs) == 2  # a second run never appends to the first run's ledger


def test_proxy_ledger_follows_an_explicit_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_proxy(monkeypatch)
    trace = tmp_path / "t.jsonl"
    assert main(["proxy", "--quiet", "--trace", str(trace), "--", "python", "server.py"]) == 0
    assert (tmp_path / "t.ledger.jsonl").is_file()


def test_proxy_opt_outs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_proxy(monkeypatch)
    base = ["proxy", "--quiet", "--log-dir", str(tmp_path)]
    assert main([*base, "--no-ledger", "--", "python", "a.py"]) == 0
    run = _only_run(tmp_path, "a")
    assert (run / "trace.jsonl").is_file()
    assert not (run / "trace.ledger.jsonl").exists()
    assert main([*base, "--no-trace", "--", "python", "b.py"]) == 0
    assert not (tmp_path / "b").exists()


def test_record_payloads_writes_beside_the_trace_and_import_finds_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    base = ["proxy", "--log-dir", str(tmp_path), "--name", "s"]
    assert main([*base, "--record-payloads", "--", "python", "s.py"]) == 0
    run = _only_run(tmp_path, "s")
    assert (run / "payloads.jsonl").is_file()
    assert f"payloads to {(run / 'payloads.jsonl').resolve()}" in capsys.readouterr().err
    # import-logs --dir reads payloads.jsonl from the same run folder with no extra flag.
    assert main(["import-logs", "--dir", str(run), "--once", "--quiet"]) == 0

    # Without the flag no payloads file is written.
    assert main([*base, "--", "python", "s.py"]) == 0
    other = next(path for path in (tmp_path / "s").iterdir() if path != run)
    assert not (other / "payloads.jsonl").exists()


def test_record_payloads_contradictions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    command = ["--", "python", "s.py"]
    for flags in (
        ["--record-payloads", "--payloads", str(tmp_path / "p.jsonl")],
        ["--record-payloads", "--no-trace"],
    ):
        assert main(["proxy", "--quiet", "--log-dir", str(tmp_path), *flags, *command]) == 2
        assert "--record-payloads" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_import_logs_needs_a_named_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    root = tmp_path / "logs"
    assert main(["proxy", "--quiet", "--no-import", "--log-dir", str(root), "--name", "s", "--", "python", "s.py"]) == 0
    run = _only_run(root, "s")

    # Pointing at the server's folder or the root lists the runs and imports nothing.
    for parent in (root, root / "s"):
        assert main(["import-logs", "--dir", str(parent), "--once", "--quiet"]) == 2
        err = capsys.readouterr().err
        assert "1 run folder(s)" in err and str(run) in err
    assert not (run / "events.csv").exists()

    assert main(["import-logs", "--dir", str(run), "--once", "--quiet"]) == 0
    assert (run / "events.csv").is_file()


def test_proxy_imports_its_run_when_it_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    command = ["proxy", "--log-dir", str(tmp_path), "--name", "s", "--record-payloads", "--",
               "python", "s.py"]
    assert main(command) == 0
    run = _only_run(tmp_path, "s")
    for name in ("events.csv", "gate-results.csv", "gate-results.sarif", "normalized.jsonl"):
        assert (run / name).is_file(), name
    err = capsys.readouterr().err
    assert f"run folder: {run.resolve()}" in err
    assert "1 event(s)" in err and "ledger unanchored" in err
    # A block the user can paste as is: RUN=... then the report and the events table.
    assert f"\nRUN={run.resolve()}\n" in err
    assert '--runtime-result "$RUN/gate-results.csv" --ledger "$RUN/trace.ledger.jsonl"' in err
    assert 'column -s, -t < "$RUN/events.csv" | less -S' in err
    assert "agent-latch-runtime anchor --ledger" in err


def test_proxy_import_can_be_turned_off_and_is_quiet_with_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    base = ["proxy", "--log-dir", str(tmp_path)]
    assert main([*base, "--name", "off", "--no-import", "--", "python", "s.py"]) == 0
    off = _only_run(tmp_path, "off")
    assert not (off / "events.csv").exists()
    assert f"run folder: {off.resolve()}" in capsys.readouterr().err

    assert main([*base, "--name", "q", "--quiet", "--", "python", "s.py"]) == 0
    assert (_only_run(tmp_path, "q") / "events.csv").is_file()  # still imported
    err = capsys.readouterr().err
    assert "run folder" not in err and "event(s)" not in err  # but no summary printed


def test_proxy_with_no_traffic_says_so_and_does_not_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sys
    from types import SimpleNamespace

    monkeypatch.setitem(
        sys.modules,
        "agent_latch.runtime.proxy",
        SimpleNamespace(build_proxy=lambda **_k: SimpleNamespace(run=lambda **_r: None)),
    )
    assert main(["proxy", "--log-dir", str(tmp_path), "--name", "idle", "--", "python", "s.py"]) == 0
    assert "no traffic was recorded" in capsys.readouterr().err


def test_ctrl_c_stops_cleanly_and_the_summary_is_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sys
    from types import SimpleNamespace

    def build_proxy(*, trace, **_kwargs):
        trace.tools_listed(session_id="s", request_id="1", server="x", tools=[])

        def run(**_run_kwargs):
            raise KeyboardInterrupt

        return SimpleNamespace(run=run)

    monkeypatch.setitem(
        sys.modules, "agent_latch.runtime.proxy", SimpleNamespace(build_proxy=build_proxy)
    )
    assert main(["proxy", "--log-dir", str(tmp_path), "--name", "s", "--", "python", "s.py"]) == 0
    lines = capsys.readouterr().err.splitlines()
    assert "Traceback" not in "\n".join(lines)
    assert "agent-latch --runtime-result" in lines[-2] or "anchor --ledger" in lines[-1]
    assert lines[-1].startswith("agent-latch-runtime: anchor it")


def test_a_failing_import_is_a_warning_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agent_latch.runtime import autoimport

    _stub_proxy(monkeypatch)

    def broken(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(autoimport, "discover_gates", broken)
    assert main(["proxy", "--log-dir", str(tmp_path), "--name", "s", "--", "python", "s.py"]) == 0
    err = capsys.readouterr().err
    assert "could not import this run automatically (RuntimeError: boom)" in err
    assert "import-logs --dir" in err


def test_import_logs_once_refuses_a_folder_with_no_trace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "20261122-074500"
    assert main(["import-logs", "--dir", str(missing), "--once", "--quiet"]) == 2
    assert f"no trace at {missing / 'trace.jsonl'}" in capsys.readouterr().err
    assert not missing.exists()


def test_import_logs_without_dir_lists_runs_in_the_home_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    _set_home(monkeypatch, tmp_path / "home")
    monkeypatch.chdir(tmp_path)
    assert main(["proxy", "--quiet", "--name", "s", "--", "python", "s.py"]) == 0
    assert main(["import-logs", "--once", "--quiet"]) == 2
    assert str(tmp_path / "home" / "agent-latch" / "runtime-logs") in capsys.readouterr().err


def test_proxy_rejects_contradictory_recording_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    command = ["--", "python", "server.py"]
    for flags in (
        ["--no-trace", "--trace", str(tmp_path / "t.jsonl")],
        ["--no-ledger", "--ledger", str(tmp_path / "l.jsonl")],
        ["--no-trace", "--ledger", str(tmp_path / "l.jsonl")],
    ):
        assert main(["proxy", "--quiet", *flags, *command]) == 2
        assert "--no-" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def test_proxy_keeps_running_when_the_default_folder_is_unwritable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_proxy(monkeypatch)
    blocker = tmp_path / "file"
    blocker.write_text("not a folder", encoding="utf-8")
    assert main(["proxy", "--log-dir", str(blocker), "--", "python", "server.py"]) == 0
    assert "cannot open the default" in capsys.readouterr().err
    # The same location given explicitly is a configuration error.
    explicit = ["proxy", "--trace", str(blocker / "t.jsonl"), "--", "python", "server.py"]
    assert main(explicit) == 2


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


def test_safe_text_caps_length_and_escapes_control_characters() -> None:
    from agent_latch.runtime.redact import MAX_IDENTITY_CHARS, safe_text

    hostile = "evil\x1b[2J\x1b[31m" + "A" * 5000
    out = safe_text(hostile)
    assert len(out) <= MAX_IDENTITY_CHARS * 4  # at most 4 chars per escaped character
    assert "\x1b" not in out and "\\x1b" in out
    assert safe_text("1.0\x1b]0;pwned\x07") == "1.0\\x1b]0;pwned\\x07"
    assert safe_text("a\u200bb") == "a\\u200bb"  # invisible characters stay visible as evidence
    assert safe_text("fake-weather") == "fake-weather"


def test_unescape_text_restores_escapes_and_leaves_the_rest() -> None:
    from agent_latch.runtime.redact import safe_text, unescape_text

    assert unescape_text(safe_text("githu\u200bb")) == "githu\u200bb"
    assert unescape_text(safe_text("a\x1b[0m")) == "a\x1b[0m"
    assert unescape_text("plain") == "plain"
    assert unescape_text("bad \\u12 and \\xZZ") == "bad \\u12 and \\xZZ"
