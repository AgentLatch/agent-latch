"""Tests for the MCP event normalizer and the runtime log importer (no FastMCP needed)."""

from __future__ import annotations

import csv
import io
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from agent_latch.runtime import (
    PayloadFile,
    PayloadTap,
    ToolCall,
    ToolInfo,
    ToolOutput,
    TraceLog,
    cli,
)
from agent_latch.runtime.importer import GatePlugin, RuntimeLogImporter, discover_gates
from agent_latch.runtime.normalizer import MCPEventNormalizer, run_id_for


def _record_run(tmp_path: Path, *, payloads: bool = True) -> tuple[Path, Path]:
    """Write a small run with the real trace and payload writers."""
    trace_path, payloads_path = tmp_path / "trace.jsonl", tmp_path / "payloads.jsonl"
    trace = TraceLog(trace_path, summary=None)
    file = PayloadFile(payloads_path)
    tap = PayloadTap([file])
    tools = [ToolInfo("run_command", "demo", "Run a shell command.", {"type": "object"},
                      {"destructiveHint": True})]
    trace.tools_listed(session_id="s", request_id="1", server="demo", tools=tools)
    tap.tools_listed(session_id="s", request_id="1", client_id="claude", server="demo", tools=tools)
    trace.prompts_listed(session_id="s", request_id="2", server="demo", names=["triage"])
    call = ToolCall("s", "3", "claude", "run_command", "demo", {"command": "rm -rf /"}, "t")
    trace.call_request(call)
    tap.call_request(call)
    output = ToolOutput(("done",), None, False)
    trace.call_response(call, output, 1.5)
    tap.call_response(call, output, 1.5)
    trace.close()
    file.close()
    if not payloads:
        payloads_path.unlink()
    return trace_path, payloads_path


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _gate(gate_id: str, seen: list[dict[str, Any]] | None = None) -> GatePlugin:
    def evaluate(event: dict[str, Any]) -> dict[str, Any]:
        if seen is not None:
            seen.append(event)
        payload = event["payload"] or {}
        if "rm -rf" in json.dumps(payload.get("arguments", {})):
            return {"findings": [{"rule": "DEMO", "owasp": ["ASI05"]}]}
        return {"findings": []}

    return GatePlugin(gate_id, evaluate)


def test_normalizer_joins_trace_and_payload() -> None:
    trace = {
        "schema": "agentlatch.runtime.trace/1", "timestamp": "t", "session_id": "s",
        "request_id": "3", "server": "demo", "method": "tools/call", "tool": "run_command",
        "stage": "request", "argument_names": ["command"], "arguments_sha256": "ab",
    }
    payload = {"client_id": "claude", "payload": {"tool": "run_command", "arguments": {}}}
    normalizer = MCPEventNormalizer("run1", trace_name="trace.jsonl", payloads_name="p.jsonl")
    event = normalizer.normalize(trace_line=5, trace=trace, payload_line=4, payload=payload)

    assert list(event) == [
        "run_id", "order", "timestamp", "session_id", "request_id", "client_id", "server",
        "method", "stage", "name", "trace", "payloads", "metadata", "payload",
    ]
    assert event["name"] == "run_command" and event["client_id"] == "claude"
    assert event["trace"] == {"path": "trace.jsonl", "line": 5}
    assert event["payloads"] == {"path": "p.jsonl", "line": 4}
    assert event["metadata"] == {"argument_names": ["command"], "arguments_sha256": "ab"}
    bare = normalizer.normalize(trace_line=6, trace=trace)
    assert bare["payload"] is None and bare["payloads"] is None and bare["client_id"] is None


def test_importer_runs_every_gate_in_turn_and_writes_a_row_per_gate(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    seen: list[dict[str, Any]] = []
    out = tmp_path / "out" / "results.csv"
    normalized = tmp_path / "normalized.jsonl"

    RuntimeLogImporter(
        trace_path, out, [_gate("one", seen), _gate("two", seen)],
        payloads_path=payloads_path, normalized_path=normalized, follow=False,
    ).run()

    rows = _rows(out)
    assert [(r["order"], r["gate_id"]) for r in rows] == [
        (str(order), gate) for order in (1, 2, 3, 4) for gate in ("one", "two")
    ]
    assert len({r["run_id"] for r in rows}) == 1
    flagged = [r for r in rows if json.loads(r["result_json"])["findings"]]
    assert [(r["order"], r["gate_id"]) for r in flagged] == [("3", "one"), ("3", "two")]
    # Every gate got the same event, joined with its payload; the prompts/list has none.
    assert seen[4]["payload"]["arguments"] == {"command": "rm -rf /"}
    assert seen[4] == seen[5] and seen[4] is not seen[5]
    assert [e["payloads"] for e in seen[2:4]] == [None, None]
    events = [json.loads(line) for line in normalized.read_text(encoding="utf-8").splitlines()]
    assert [e["order"] for e in events] == [1, 2, 3, 4]
    assert events[3]["payload"]["content"] == ["done"] and events[3]["client_id"] == "claude"


def test_importer_works_from_the_trace_alone(tmp_path: Path) -> None:
    trace_path, _ = _record_run(tmp_path, payloads=False)
    out = tmp_path / "results.csv"
    seen: list[dict[str, Any]] = []
    RuntimeLogImporter(trace_path, out, [_gate("one", seen)], follow=False).run()
    assert len(_rows(out)) == 4
    assert all(event["payload"] is None for event in seen)
    assert seen[2]["metadata"]["argument_names"] == ["command"]


def test_gate_failure_is_recorded_and_later_gates_still_run(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    out = tmp_path / "results.csv"

    def failing(_event: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("secret detail")

    RuntimeLogImporter(
        trace_path, out, [GatePlugin("bad", failing), _gate("good")],
        payloads_path=payloads_path, follow=False,
    ).run()

    rows = _rows(out)
    bad = json.loads(rows[0]["result_json"])
    assert bad["status"] == "error" and bad["error"] == {"type": "RuntimeError"}
    assert "secret detail" not in rows[0]["result_json"]
    assert rows[1]["gate_id"] == "good" and len(rows) == 8


def test_rerun_does_not_repeat_results_and_picks_up_new_lines(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    out, normalized = tmp_path / "results.csv", tmp_path / "normalized.jsonl"

    def run() -> None:
        RuntimeLogImporter(
            trace_path, out, [_gate("one")], payloads_path=payloads_path,
            normalized_path=normalized, follow=False,
        ).run()

    run()
    run()
    assert len(_rows(out)) == 4
    assert len(normalized.read_text(encoding="utf-8").splitlines()) == 4

    trace = TraceLog(trace_path, summary=None)
    trace.prompts_listed(session_id="s", request_id="9", server="demo", names=["x"])
    trace.close()
    run()
    assert [r["order"] for r in _rows(out)] == ["1", "2", "3", "4", "5"]


def test_unmatched_trace_record_still_reaches_gates_when_input_ends(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    lines = payloads_path.read_text(encoding="utf-8").splitlines()
    payloads_path.write_text("\n".join(lines[:1]) + "\n", encoding="utf-8")  # drop the call
    seen: list[dict[str, Any]] = []
    RuntimeLogImporter(
        trace_path, tmp_path / "r.csv", [_gate("one", seen)], payloads_path=payloads_path,
        follow=False,
    ).run()
    assert [e["payload"] is not None for e in seen] == [True, False, False, False]


def test_bad_lines_are_skipped_and_partial_last_line_waits(tmp_path: Path) -> None:
    trace_path, _ = _record_run(tmp_path, payloads=False)
    text = trace_path.read_text(encoding="utf-8")
    trace_path.write_text("not json\n" + text + '{"schema": "agentlatch.runtime.trace/1"',
                          encoding="utf-8")
    out = tmp_path / "r.csv"
    RuntimeLogImporter(trace_path, out, [_gate("one")], follow=False).run()
    assert [r["order"] for r in _rows(out)] == ["2", "3", "4", "5"]


def test_follow_mode_processes_lines_appended_while_running(tmp_path: Path) -> None:
    trace_path, payloads_path = tmp_path / "trace.jsonl", tmp_path / "payloads.jsonl"
    out = tmp_path / "r.csv"
    importer = RuntimeLogImporter(
        trace_path, out, [_gate("one")], payloads_path=payloads_path, poll_interval=0.01,
    )
    thread = threading.Thread(target=importer.run)
    thread.start()
    try:
        time.sleep(0.05)  # the files do not exist yet
        trace = TraceLog(trace_path, summary=None)
        file = PayloadFile(payloads_path)
        tap = PayloadTap([file])
        call = ToolCall("s", "3", None, "run_command", "demo", {"command": "rm -rf /"}, "t")
        trace.call_request(call)
        time.sleep(0.05)  # the trace record waits for its payload record
        assert not out.exists() or len(_rows(out)) == 0
        tap.call_request(call)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not (out.exists() and _rows(out)):
            time.sleep(0.02)
        trace.close()
        file.close()
        assert json.loads(_rows(out)[0]["result_json"])["findings"]
    finally:
        importer.stop()
        thread.join(5)
    assert not thread.is_alive()


def test_importer_rejects_bad_setup(tmp_path: Path) -> None:
    trace_path, _ = _record_run(tmp_path, payloads=False)
    with pytest.raises(ValueError, match="different files"):
        RuntimeLogImporter(trace_path, trace_path, [], follow=False)
    out = tmp_path / "r.csv"
    out.write_text("wrong,header\n", encoding="utf-8")
    with pytest.raises(ValueError, match="CSV header"):
        RuntimeLogImporter(trace_path, out, [_gate("one")], follow=False).run()
    with pytest.raises(ValueError, match="CSV header"):
        RuntimeLogImporter(trace_path, None, [], events_csv=out, follow=False).run()


def test_run_id_is_stable_and_gate_discovery_finds_no_gates_yet() -> None:
    assert run_id_for("abc\n") == run_id_for("abc") and len(run_id_for("abc")) == 16
    assert discover_gates() == []


def test_events_are_visible_without_any_gate(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    events_csv, gate_csv = tmp_path / "events.csv", tmp_path / "gate-results.csv"
    summary = io.StringIO()

    def run() -> None:
        RuntimeLogImporter(
            trace_path, gate_csv, [], payloads_path=payloads_path, events_csv=events_csv,
            summary=summary, follow=False,
        ).run()

    run()
    rows = _rows(events_csv)
    assert [(r["order"], r["method"], r["stage"]) for r in rows] == [
        ("1", "tools/list", "response"), ("2", "prompts/list", "response"),
        ("3", "tools/call", "request"), ("4", "tools/call", "response"),
    ]
    assert [r["has_payload"] for r in rows] == ["yes", "no", "yes", "yes"]
    assert rows[3]["outcome"] == "ok" and rows[3]["excerpt"] == "done"
    assert not gate_csv.exists()  # no gates installed, so no empty gate CSV
    lines = summary.getvalue().splitlines()
    assert len(lines) == 4
    assert lines[2] == "agent-latch-runtime: #3 demo: tools/call run_command (command) [payload]"
    assert "rm -rf" not in summary.getvalue()  # argument values are never printed

    run()  # a rerun adds no rows and prints nothing new
    assert len(_rows(events_csv)) == 4 and len(summary.getvalue().splitlines()) == 4


def test_events_csv_cells_cannot_run_as_formulas(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.jsonl"
    trace = TraceLog(trace_path, summary=None)
    call = ToolCall("s", "1", None, "=cmd", "demo", {}, "t")
    trace.call_response(call, ToolOutput(("=HYPERLINK(\"x\")",), None, True), 1.0)
    trace.close()
    events_csv = tmp_path / "events.csv"
    RuntimeLogImporter(trace_path, None, [], events_csv=events_csv, follow=False).run()
    row = _rows(events_csv)[0]
    assert row["name"] == "'=cmd" and row["excerpt"].startswith("'=")
    assert row["outcome"] == "error result"


def test_import_logs_cli_uses_the_log_folder_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _record_run(tmp_path)
    assert cli.main(["import-logs", "--dir", str(tmp_path), "--once"]) == 0
    assert len(_rows(tmp_path / "events.csv")) == 4
    events = (tmp_path / "normalized.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(events[2])["payload"]["arguments"] == {"command": "rm -rf /"}
    assert not (tmp_path / "gate-results.csv").exists()
    err = capsys.readouterr().err
    assert "with 0 gate(s)" in err and "#4 demo: tools/call run_command -> ok" in err

    (tmp_path / "events.csv").write_text("wrong,header\n", encoding="utf-8")
    assert cli.main(["import-logs", "--dir", str(tmp_path), "--once"]) == 2
    assert "CSV header must be" in capsys.readouterr().err
