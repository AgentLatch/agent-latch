"""Tests for the MCP event normalizer and the runtime log importer (no FastMCP needed)."""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from agent_latch.gates.alr04 import reset_state
from agent_latch.runtime import (
    PayloadFile,
    PayloadTap,
    ToolCall,
    ToolInfo,
    ToolOutput,
    TraceLog,
    cli,
    sqlite_store,
)
from agent_latch.runtime.importer import GatePlugin, RuntimeLogImporter, discover_gates
from agent_latch.runtime.normalizer import MCPEventNormalizer, run_id_for
from agent_latch.runtime.sqlite_store import SQLiteEventStore

FIXTURE = Path(__file__).parent / "runtime_fixtures" / "normalized-sample.json"


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


def test_run_id_is_stable_and_gate_discovery_finds_alr04() -> None:
    assert run_id_for("abc\n") == run_id_for("abc") and len(run_id_for("abc")) == 16
    assert [plugin.gate_id for plugin in discover_gates()] == ["ALR04"]


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
    reset_state()
    _record_run(tmp_path)
    assert cli.main(["import-logs", "--dir", str(tmp_path), "--once"]) == 0
    assert len(_rows(tmp_path / "events.csv")) == 4
    events = (tmp_path / "normalized.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(events[2])["payload"]["arguments"] == {"command": "rm -rf /"}
    gate_rows = _rows(tmp_path / "gate-results.csv")
    assert len(gate_rows) == 4 and {row["gate_id"] for row in gate_rows} == {"ALR04"}
    findings = [
        finding
        for row in gate_rows
        for finding in json.loads(row["result_json"])["findings"]
    ]
    assert findings and not any(finding.get("outcome") == "FAIL" for finding in findings)
    err = capsys.readouterr().err
    assert "with 1 gate(s)" in err and "#4 demo: tools/call run_command -> ok" in err

    (tmp_path / "events.csv").write_text("wrong,header\n", encoding="utf-8")
    assert cli.main(["import-logs", "--dir", str(tmp_path), "--once"]) == 2
    assert "CSV header must be" in capsys.readouterr().err


# --- SQLite event storage --------------------------------------------------------------------


def _stored(path: Path) -> list[dict[str, Any]]:
    store = SQLiteEventStore(path)
    store.open()
    try:
        return list(store.events())
    finally:
        store.close()


def _import(tmp_path: Path, trace_path: Path, payloads_path: Path | None, **kwargs: Any) -> Path:
    database = tmp_path / "runtime.db"
    RuntimeLogImporter(
        trace_path, tmp_path / "results.csv", [], payloads_path=payloads_path,
        store=SQLiteEventStore(database), follow=False, **kwargs,
    ).run()
    return database


def test_sqlite_store_keeps_the_sample_events_unchanged(tmp_path: Path) -> None:
    sample = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert sample, "the fixture must hold at least one event"
    store = SQLiteEventStore(tmp_path / "runtime.db")
    store.open()
    try:
        assert store.save(sample) == len(sample)
        stored = list(store.events())
    finally:
        store.close()

    expected = sorted(sample, key=lambda event: (event["run_id"], event["order"]))
    assert stored == expected
    # Same keys, in the normalizer's order, for every event.
    assert all(list(got) == list(want) for got, want in zip(stored, expected, strict=True))
    assert any(event["payload"] is None and event["payloads"] is None for event in stored)


def test_importer_stores_every_normalized_event(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    normalized = tmp_path / "normalized.jsonl"
    database = _import(tmp_path, trace_path, payloads_path, normalized_path=normalized)

    written = [json.loads(line) for line in normalized.read_text(encoding="utf-8").splitlines()]
    assert _stored(database) == written
    assert [event["order"] for event in written] == [1, 2, 3, 4]


def test_reimport_and_restart_do_not_duplicate_events(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    database = _import(tmp_path, trace_path, payloads_path)
    _import(tmp_path, trace_path, payloads_path)
    assert len(_stored(database)) == 4

    trace = TraceLog(trace_path, summary=None)
    trace.prompts_listed(session_id="s", request_id="9", server="demo", names=["x"])
    trace.close()
    _import(tmp_path, trace_path, payloads_path)
    assert [event["order"] for event in _stored(database)] == [1, 2, 3, 4, 5]


def test_trace_only_import_stores_null_payloads(tmp_path: Path) -> None:
    trace_path, _ = _record_run(tmp_path, payloads=False)
    database = _import(tmp_path, trace_path, None)
    stored = _stored(database)
    assert len(stored) == 4
    assert all(event["payload"] is None and event["payloads"] is None for event in stored)
    assert stored[2]["metadata"]["argument_names"] == ["command"]


def test_existing_outputs_are_unchanged_by_the_database(tmp_path: Path) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    plain, with_db = tmp_path / "plain", tmp_path / "with_db"
    for folder in (plain, with_db):
        folder.mkdir()
        RuntimeLogImporter(
            trace_path, folder / "results.csv", [_gate("one")], payloads_path=payloads_path,
            normalized_path=folder / "normalized.jsonl", follow=False,
            store=SQLiteEventStore(folder / "runtime.db") if folder is with_db else None,
        ).run()
    for name in ("results.csv", "normalized.jsonl"):
        assert (plain / name).read_bytes() == (with_db / name).read_bytes()
    assert sorted(p.name for p in plain.iterdir()) == ["normalized.jsonl", "results.csv"]


def test_follow_mode_keeps_the_database_in_sync(tmp_path: Path) -> None:
    trace_path, payloads_path = tmp_path / "trace.jsonl", tmp_path / "payloads.jsonl"
    database = tmp_path / "runtime.db"
    importer = RuntimeLogImporter(
        trace_path, tmp_path / "r.csv", [], payloads_path=payloads_path,
        store=SQLiteEventStore(database), poll_interval=0.01, payload_grace=0.05,
    )
    thread = threading.Thread(target=importer.run)
    thread.start()
    try:
        trace = TraceLog(trace_path, summary=None)
        for number in range(1, 4):  # lines arrive one by one while the importer runs
            trace.prompts_listed(session_id="s", request_id=str(number), server="demo", names=[])
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and len(_stored(database)) < number:
                time.sleep(0.02)
            assert len(_stored(database)) == number
        trace.close()
    finally:
        importer.stop()
        thread.join(5)
    assert not thread.is_alive()


class _FlakyStore:
    """An in-memory store whose first save fails: proves any store works and nothing is lost."""

    path = None

    def __init__(self) -> None:
        self.events: dict[tuple[str, int], dict[str, Any]] = {}
        self.calls = 0

    def open(self) -> None:
        pass

    def save(self, events: list[dict[str, Any]]) -> int:
        self.calls += 1
        if self.calls == 1:
            raise OSError("database is locked")
        new = [event for event in events if (event["run_id"], event["order"]) not in self.events]
        self.events.update({(event["run_id"], event["order"]): event for event in new})
        return len(new)

    def close(self) -> None:
        pass


def test_failed_save_is_retried_and_no_event_is_lost(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    store = _FlakyStore()
    importer = RuntimeLogImporter(
        trace_path, tmp_path / "r.csv", [], payloads_path=payloads_path, store=store,
        poll_interval=0.01,
    )
    thread = threading.Thread(target=importer.run)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(store.events) < 4:
            time.sleep(0.02)
    finally:
        importer.stop()
        thread.join(5)
    assert sorted(order for _, order in store.events) == [1, 2, 3, 4]
    assert store.calls >= 2
    assert "retrying" in caplog.text and "reachable again" in caplog.text


def test_failed_save_in_one_shot_mode_is_an_error(tmp_path: Path) -> None:
    trace_path, _ = _record_run(tmp_path, payloads=False)

    class _Broken(_FlakyStore):
        def save(self, events: list[dict[str, Any]]) -> int:
            raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        RuntimeLogImporter(trace_path, tmp_path / "r.csv", [], store=_Broken(), follow=False).run()


def test_migrations_create_and_keep_the_schema(tmp_path: Path) -> None:
    database = tmp_path / "runtime.db"
    _stored(database)
    _stored(database)  # opening again is safe
    conn = sqlite3.connect(database)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == len(sqlite_store.MIGRATIONS)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(events)")]
        assert columns == list(sqlite_store.COLUMNS)
    finally:
        conn.close()


def test_a_new_migration_upgrades_an_existing_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    database = _import(tmp_path, trace_path, payloads_path)

    def add_note(conn: sqlite3.Connection) -> None:
        conn.execute("ALTER TABLE events ADD COLUMN note TEXT")

    monkeypatch.setattr(sqlite_store, "MIGRATIONS", (*sqlite_store.MIGRATIONS, add_note))
    assert len(_stored(database)) == 4  # opening runs the new migration and keeps every event
    conn = sqlite3.connect(database)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == len(sqlite_store.MIGRATIONS)
        assert "note" in [row[1] for row in conn.execute("PRAGMA table_info(events)")]
    finally:
        conn.close()


def test_a_failed_migration_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "runtime.db"

    def broken(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE half_done (x INTEGER)")
        raise RuntimeError("migration bug")

    monkeypatch.setattr(sqlite_store, "MIGRATIONS", (*sqlite_store.MIGRATIONS, broken))
    with pytest.raises(RuntimeError, match="migration bug"):
        SQLiteEventStore(database).open()
    conn = sqlite3.connect(database)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master")]
        assert tables == []  # migration 1 was rolled back too: all or nothing
    finally:
        conn.close()


def test_newer_or_foreign_databases_are_refused(tmp_path: Path) -> None:
    newer = tmp_path / "newer.db"
    conn = sqlite3.connect(newer)
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(ValueError, match="newer than this AgentLatch"):
        SQLiteEventStore(newer).open()

    not_a_database = tmp_path / "notes.db"
    not_a_database.write_text("hello, this is not SQLite\n" * 100, encoding="utf-8")
    with pytest.raises(ValueError, match="not a usable AgentLatch database"):
        SQLiteEventStore(not_a_database).open()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes; Windows uses folder permissions")
def test_new_database_file_is_private(tmp_path: Path) -> None:
    database = tmp_path / "runtime.db"
    _stored(database)
    assert database.stat().st_mode & 0o777 == 0o600


def test_cli_database_option(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    trace_path, payloads_path = _record_run(tmp_path)
    database = tmp_path / "runtime.db"
    argv = [
        "import-logs", "--dir", str(tmp_path), "--trace", str(trace_path),
        "--payloads", str(payloads_path), "--database", str(database), "--once",
    ]
    assert cli.main(argv) == 0
    assert cli.main(argv) == 0  # a second run adds nothing
    assert len(_stored(database)) == 4
    assert str(database) in capsys.readouterr().err

    bad = [
        "import-logs", "--dir", str(tmp_path), "--trace", str(trace_path),
        "--database", str(trace_path), "--once",
    ]
    assert cli.main(bad) == 2  # same file as --trace
