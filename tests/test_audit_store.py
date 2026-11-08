"""Integration tests for the sealed, append-only event store (the immutable audit trail ticket).

Each test works on a store written by the real pipeline (``import-logs --database --anchor``) and
then attacks it the way a careless or hostile agent could. The numbers match the plan's test list.
No test uses the network; synthetic fixtures only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from store_contract import assert_store_is_append_only, sample_events

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
from agent_latch.runtime import importer as importer_module
from agent_latch.runtime.importer import RuntimeLogImporter
from agent_latch.runtime.ledger.anchor import AnchorError, AnchorPoint, FileAnchor
from agent_latch.runtime.ledger.chain import GENESIS, Ledger
from agent_latch.runtime.ledger.event_seal import (
    SOURCE,
    Seal,
    StoredRow,
    StoreRefused,
    StoreTampered,
    event_sha256,
    next_seal,
    seal_digest,
    verify_store,
    walk_chain,
)
from agent_latch.runtime.ledger.verify import (
    STATUS_UNANCHORED,
    status_for,
    verify_ledger,
)
from agent_latch.runtime.sqlite_store import (
    COLUMNS,
    SQLiteEventReader,
    SQLiteEventStore,
    event_to_row,
    row_to_event,
)

FIXTURES = Path(__file__).resolve().parent / "runtime_fixtures"


# --- helpers ------------------------------------------------------------------------------------


def _record_run(directory: Path, *, payloads: bool = True) -> tuple[Path, Path | None]:
    """Write a small run (four events) with the real trace and payload writers."""
    directory.mkdir(parents=True, exist_ok=True)
    trace_path, payloads_path = directory / "trace.jsonl", directory / "payloads.jsonl"
    trace = TraceLog(trace_path, summary=None)
    file = PayloadFile(payloads_path)
    tap = PayloadTap([file])
    tools = [ToolInfo("run_command", "demo", "Run a shell command.", {"type": "object"},
                      {"destructiveHint": True})]
    trace.tools_listed(session_id="s", request_id="1", server="demo", tools=tools)
    tap.tools_listed(session_id="s", request_id="1", client_id="claude", server="demo", tools=tools)
    trace.prompts_listed(session_id="s", request_id="2", server="demo", names=["triage"])
    call = ToolCall("s", "3", "claude", "run_command", "demo", {"command": "ls"}, "t")
    trace.call_request(call)
    tap.call_request(call)
    output = ToolOutput(("done",), None, False)
    trace.call_response(call, output, 1.5)
    tap.call_response(call, output, 1.5)
    trace.close()
    file.close()
    if not payloads:
        payloads_path.unlink()
        return trace_path, None
    return trace_path, payloads_path


def _import(
    directory: Path,
    trace: Path,
    database: Path,
    *,
    payloads: Path | None = None,
    anchor: Path | None = None,
) -> int:
    """Run ``import-logs`` through the CLI for one trace; returns its exit code."""
    argv = ["import-logs", "--dir", str(directory), "--trace", str(trace),
            "--database", str(database), "--once", "--quiet"]
    if payloads is not None:
        argv += ["--payloads", str(payloads)]
    if anchor is not None:
        argv += ["--anchor", str(anchor)]
    return cli.main(argv)


def _verify(database: Path, anchor: Path | None = None) -> int:
    """Run ``verify --database`` through the CLI; returns its exit code."""
    argv = ["verify", "--database", str(database)]
    if anchor is not None:
        argv += ["--anchor", str(anchor)]
    return cli.main(argv)


class Sealed:
    """A store written by the real pipeline, with its logs and anchor."""

    def __init__(self, root: Path) -> None:
        """Record a run and import it with an anchor, the way the real pipeline does."""
        self.root = root
        self.logs = root / "logs"
        self.trace, self.payloads = _record_run(self.logs)
        self.database = root / "events.db"
        self.anchor = root / "anchors.jsonl"
        assert _import(self.logs, self.trace, self.database, payloads=self.payloads,
                       anchor=self.anchor) == 0

    def import_again(self, *, anchor: bool = True) -> int:
        """Import the same logs again, with or without the anchor."""
        return _import(self.logs, self.trace, self.database, payloads=self.payloads,
                       anchor=self.anchor if anchor else None)

    def verify(self, *, anchor: bool = True) -> int:
        """Verify the store, with or without its anchor; returns the exit code."""
        return _verify(self.database, self.anchor if anchor else None)

    def rows(self) -> int:
        conn = sqlite3.connect(self.database)
        try:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            conn.close()


@pytest.fixture
def sealed(tmp_path: Path) -> Sealed:
    return Sealed(tmp_path)


def _connect_as_attacker(database: Path) -> sqlite3.Connection:
    """Full access to the file, as an agent on the same OS user has. Drops the guards first."""
    conn = sqlite3.connect(database, isolation_level=None)
    for trigger in ("events_no_update", "events_no_delete"):
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    return conn


def _cover_tracks(conn: sqlite3.Connection) -> None:
    """What a careful attacker does last: put the triggers back, so the table layout looks normal."""
    sqlite_store._add_append_only_triggers(conn)


def _reseal_all(conn: sqlite3.Connection) -> None:
    """What a careful attacker does after changing rows: recompute every seal."""
    head: Seal | None = None
    rows = conn.execute(f"SELECT {', '.join(COLUMNS)} FROM events ORDER BY seal_seq").fetchall()
    for row in rows:
        head = next_seal(head, row_to_event(row), row[-1])
        conn.execute(
            "UPDATE events SET seal_seq=?, seal_prev=?, seal_digest=? WHERE run_id=? AND event_order=?",
            (head.seq, head.prev, head.digest, row[0], row[1]),
        )


def _out(capsys: pytest.CaptureFixture[str]) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


# --- 1. a real, sealed store from the real pipeline ---------------------------------------------


def test_1_sealed_import_verifies_intact(sealed: Sealed, capsys: pytest.CaptureFixture[str]) -> None:
    """A store written by the real pipeline verifies intact, and importing again adds nothing."""
    capsys.readouterr()
    assert sealed.verify() == 0
    out = _out(capsys)
    assert "AUDIT TRAIL INTACT" in out and "4 record(s)" in out
    head = FileAnchor(sealed.anchor).latest()
    assert head is not None and head.seq == 4 and head.source == SOURCE
    assert head.schema_sha256 and head.schema_version == len(sqlite_store.MIGRATIONS)
    assert sealed.rows() == 4

    # No anchor given: the file verifies locally, and says nothing outside proves it.
    assert sealed.verify(anchor=False) == 0
    assert "UNANCHORED" in _out(capsys)

    # Importing the same logs again adds nothing and keeps it intact.
    assert sealed.import_again() == 0 and sealed.rows() == 4 and sealed.verify() == 0


# --- 2. the first write stays; SQL cannot change a row -------------------------------------------


def test_2_writer_keeps_the_first_write_and_triggers_stop_sql(tmp_path: Path) -> None:
    """The first write stays, and the triggers abort plain UPDATE and DELETE."""
    def make_store() -> SQLiteEventStore:
        return SQLiteEventStore(Path(tempfile.mkdtemp(dir=tmp_path)) / "events.db")

    def tamper(store: SQLiteEventStore, how: str) -> None:
        """Change the rows behind the store's back, as an agent with the file could."""
        conn = _connect_as_attacker(store.path)
        try:
            if how == "edit":
                conn.execute("UPDATE events SET name = 'evil' WHERE event_order = 2")
            elif how == "delete":
                conn.execute("DELETE FROM events WHERE event_order = 2")
            else:
                first, second = (
                    conn.execute("SELECT name FROM events WHERE event_order = ?", (n,)).fetchone()[0]
                    for n in (1, 2)
                )
                conn.execute("UPDATE events SET name = ? WHERE event_order = 1", (second,))
                conn.execute("UPDATE events SET name = ? WHERE event_order = 2", (first,))
        finally:
            conn.close()

    assert_store_is_append_only(make_store, tamper)

    # The triggers (migration 4) abort plain UPDATE and DELETE, and leave the rows as they were.
    store = SQLiteEventStore(tmp_path / "guarded.db")
    store.open()
    store.save(sample_events())
    store.close()
    conn = sqlite3.connect(store.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE events SET name = 'x'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM events")
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 5
    finally:
        conn.close()


# --- 3. the reader has no way to write -----------------------------------------------------------


WRITE_ATTEMPTS = [
    "DELETE FROM events",
    "UPDATE events SET name = 'x'",
    "INSERT INTO events (run_id) VALUES ('x')",
    "DROP TABLE events",
    "DROP TRIGGER events_no_update",
    "ALTER TABLE events ADD COLUMN x TEXT",
    "CREATE TABLE evil (x)",
    "ATTACH DATABASE ':memory:' AS other",
    "PRAGMA query_only = OFF",
    "PRAGMA writable_schema = 1",
    "WITH x AS (SELECT 1) DELETE FROM events",
    "SELECT 1; DELETE FROM events",
]


def test_3_reader_has_no_way_to_write(sealed: Sealed) -> None:
    """Every write statement is refused by the reader, and the store still verifies."""
    reader = SQLiteEventReader(sealed.database)
    reader.open()
    try:
        assert not any(hasattr(reader, name) for name in ("save", "delete", "update", "execute"))
        before = list(reader.events())
        assert len(before) == 4 and reader.head() is not None
        assert reader.query("SELECT COUNT(*) AS n FROM events") == [{"n": 4}]
        for sql in WRITE_ATTEMPTS:
            with pytest.raises(sqlite3.Error):
                reader.query(sql)
        assert list(reader.events()) == before
    finally:
        reader.close()
    assert sealed.rows() == 4 and sealed.verify() == 0

    # A reader never opens a database that does not exist, and never creates one.
    with pytest.raises(ValueError, match="no event store"):
        SQLiteEventReader(sealed.root / "nothing.db").open()
    assert not (sealed.root / "nothing.db").exists()


# --- 4. full file access: edit, delete, swap ----------------------------------------------------


@pytest.mark.parametrize("how", ["edit", "delete", "swap"])
def test_4_direct_tampering_is_named_and_import_refuses(
    sealed: Sealed, how: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Edits, deletions and swaps are named by verify, and import-logs refuses the store."""
    conn = _connect_as_attacker(sealed.database)
    if how == "edit":
        conn.execute("UPDATE events SET name = 'evil' WHERE event_order = 2")
    elif how == "delete":
        conn.execute("DELETE FROM events WHERE event_order = 2")
    else:
        conn.execute("UPDATE events SET timestamp = 'x' WHERE event_order = 1")
        conn.execute("UPDATE events SET seal_seq = 0 WHERE event_order = 3")
        conn.execute("UPDATE events SET seal_seq = 3, seal_prev = NULL WHERE event_order = 4")
        conn.execute("UPDATE events SET seal_seq = 4 WHERE event_order = 3")
    conn.close()
    rows_before = sealed.rows()
    capsys.readouterr()

    assert sealed.verify() == 1
    out = _out(capsys)
    assert ("TAMPERED" in out) or ("DELETED" in out)
    assert "#2" in out or how == "swap"

    # import-logs refuses the store (exit 1) and adds nothing; it never repairs or re-seals.
    assert sealed.import_again() == 1
    assert "keep this file as evidence" in _out(capsys)
    assert sealed.rows() == rows_before
    assert FileAnchor(sealed.anchor).latest().seq == 4  # type: ignore[union-attr]


# --- 5. the careful attacks, against the anchor -------------------------------------------------


def test_5_drop_table_and_cut_rows_are_deleted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A dropped table and cut rows are reported deleted against the anchor."""
    dropped = Sealed(tmp_path / "dropped")
    conn = _connect_as_attacker(dropped.database)
    conn.execute("DROP TABLE events")
    conn.close()
    assert dropped.verify() == 1
    assert "DELETED" in _out(capsys)
    assert dropped.import_again() == 1

    cut = Sealed(tmp_path / "cut")
    conn = _connect_as_attacker(cut.database)
    conn.execute("DELETE FROM events WHERE seal_seq > 2")
    conn.close()
    assert cut.verify() == 1
    out = _out(capsys)
    assert "DELETED" in out and "#4 was anchored" in out
    assert cut.import_again() == 1
    # anchor --database on a store shorter than its anchor is an integrity failure (1), not a
    # configuration error (2), and publishes nothing.
    before = cut.anchor.read_text(encoding="utf-8")
    argv = ["anchor", "--database", str(cut.database), "--to", str(cut.anchor), "--quiet"]
    assert cli.main(argv) == 1
    assert cut.anchor.read_text(encoding="utf-8") == before


def test_5_forged_row_after_the_anchor_is_caught_by_import(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """A validly sealed forged row past the anchor is refused by import-logs."""
    forged = sample_events(1, run_id="forged")[0]
    forged["order"] = 99
    writer = SQLiteEventStore(sealed.database)
    writer.open()
    writer.save([forged])  # a valid seal: whoever has the code can compute it
    writer.close()
    assert sealed.rows() == 5
    capsys.readouterr()

    # verify can only say the new row is not covered by the anchor yet.
    assert sealed.verify() == 0
    assert "UNANCHORED" in _out(capsys)
    # import-logs holds the store to the anchor: the row has no matching trace record.
    assert sealed.import_again() == 1
    assert "no matching trace record" in _out(capsys)
    assert FileAnchor(sealed.anchor).latest().seq == 4  # type: ignore[union-attr]


def test_5_rewriting_every_seal_is_rewritten(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """A full reseal looks fine alone but is reported rewritten against the anchor."""
    conn = _connect_as_attacker(sealed.database)
    conn.execute("UPDATE events SET name = 'cover-up' WHERE event_order = 2")
    _reseal_all(conn)  # the chain is now perfectly consistent
    _cover_tracks(conn)  # and the layout is back to normal
    conn.close()
    capsys.readouterr()
    assert sealed.verify(anchor=False) == 0  # alone, the file cannot tell
    assert "UNANCHORED" in _out(capsys)
    assert sealed.verify() == 1
    assert "REWRITTEN" in _out(capsys)
    assert sealed.import_again() == 1


def test_5_deleting_the_file(sealed: Sealed, capsys: pytest.CaptureFixture[str]) -> None:
    """A deleted store is deleted with an anchor, and merely missing without one."""
    sealed.database.unlink()
    assert sealed.verify() == 1  # the anchor proves rows existed
    assert "DELETED" in _out(capsys)
    # Without an anchor nothing proves it ever existed: a wrong path, not a verdict.
    assert sealed.verify(anchor=False) == 2
    assert "no event store" in _out(capsys)
    # Importing into a new file with the old anchor is refused: it would hide the deletion.
    assert sealed.import_again() == 1


# --- 6. a version 2 database is upgraded and sealed ----------------------------------------------


def test_6_version_2_database_is_upgraded_and_sealed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An older database is upgraded and sealed with its rows unchanged, and later edits are
    caught.
    """
    database = tmp_path / "v2.db"
    conn = sqlite3.connect(database, isolation_level=None)
    for step in sqlite_store.MIGRATIONS[:2]:  # today's released schema
        step(conn)
    conn.execute("PRAGMA user_version = 2")
    events = [*sample_events(3, run_id="b"), *sample_events(2, run_id="a")]
    for event in events:
        conn.execute(
            f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({', '.join('?' for _ in COLUMNS)})",
            event_to_row(event, "2026-01-01T00:00:00.000Z"),
        )
    conn.close()

    # A reader never migrates: it says the file is not sealed yet.
    with pytest.raises(ValueError, match="not sealed yet"):
        SQLiteEventReader(database).open()
    assert _verify(database) == 2

    store = SQLiteEventStore(database)
    store.open()
    try:
        assert len(list(store.events())) == 5
        assert store.head() is not None and store.head().seq == 5
        # Sealed in (run_id, order) order, so the first seal belongs to run "a".
        first = next(iter(store.sealed_rows()))
        assert first.event["run_id"] == "a" and first.event["order"] == 1
        assert verify_store(store, name="v2.db").status == STATUS_UNANCHORED
    finally:
        store.close()
    # The upgrade changed no row: every event reads back exactly as it was stored.
    keep = SQLiteEventStore(database).as_stored
    assert list(_read_events(database)) == sorted(
        (keep(event) for event in events), key=lambda e: (e["run_id"], e["order"])
    )
    conn = sqlite3.connect(database)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == len(sqlite_store.MIGRATIONS)
    conn.close()
    capsys.readouterr()
    assert _verify(database) == 0

    # After the upgrade a later change is caught.
    conn = _connect_as_attacker(database)
    conn.execute("UPDATE events SET name = 'evil' WHERE run_id = 'a' AND event_order = 1")
    conn.close()
    assert _verify(database) == 1
    assert "TAMPERED" in _out(capsys)


def _read_events(database: Path) -> Iterator[dict[str, Any]]:
    store = SQLiteEventStore(database)
    store.open()
    try:
        yield from list(store.events())
    finally:
        store.close()


# --- 7. an agent path through the AgentLatch proxy ----------------------------------------------


def test_7_agent_tool_through_the_proxy_cannot_change_the_store(
    sealed: Sealed, tmp_path: Path
) -> None:
    """An MCP client sends raw write SQL through the proxy and every attempt is refused."""
    pytest.importorskip("fastmcp")
    from fastmcp import Client
    from fastmcp.server import create_proxy

    from agent_latch.runtime.middleware import AgentLatchMiddleware

    sys.path.insert(0, str(FIXTURES))
    try:
        from audit_reader_server import build_server
    finally:
        sys.path.remove(str(FIXTURES))

    trace_path = tmp_path / "agent-trace.jsonl"
    trace = TraceLog(trace_path, summary=None)
    proxy = create_proxy(build_server(sealed.database), name="audit")
    proxy.add_middleware(AgentLatchMiddleware(trace, server="audit"))
    attacks = [*WRITE_ATTEMPTS, f"ATTACH DATABASE '{tmp_path / 'x.db'}' AS other"]

    async def drive() -> tuple[Any, list[bool]]:
        """Make the reads, then every write attempt, through the proxied MCP session."""
        async with Client(proxy) as client:
            reading = await client.call_tool("query_audit_log", {"sql": "SELECT COUNT(*) AS n FROM events"})
            recent = await client.call_tool("recent_events", {"limit": 2})
            failed = [
                (await client.call_tool("query_audit_log", {"sql": sql}, raise_on_error=False)).is_error
                for sql in attacks
            ]
            return (reading, recent), failed

    (reading, recent), failed = asyncio.run(drive())
    trace.close()

    assert "4" in reading.content[0].text and "seal_seq" in recent.content[0].text
    assert all(failed) and len(failed) == len(attacks)  # every attempt was refused
    assert sealed.rows() == 4 and sealed.verify() == 0  # the store is untouched and intact
    requests = [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
        if '"tools/call"' in line and '"request"' in line
    ]
    assert len(requests) == 2 + len(attacks)  # the attempts are in the trace


# --- 8. a second OS user ------------------------------------------------------------------------

_CHILD = """
import json, os, sqlite3, sys
database, anchor, control, folder = sys.argv[1:5]
out = {}
def attempt(name, action):
    try:
        action()
        out[name] = "allowed"
    except PermissionError:
        out[name] = "denied"
    except Exception as error:
        out[name] = type(error).__name__
attempt("read_store", lambda: open(database, "rb").close())
attempt("write_store", lambda: open(database, "r+b").close())
attempt("append_anchor", lambda: open(anchor, "a").close())
attempt("chmod_store", lambda: os.chmod(database, 0o666))
attempt("chmod_anchor", lambda: os.chmod(anchor, 0o666))
attempt("delete_store", lambda: os.unlink(database))
attempt("delete_anchor", lambda: os.unlink(anchor))
attempt("sql_delete", lambda: sqlite3.connect(database).execute("DELETE FROM events"))
attempt("control_write", lambda: open(control, "r+b").close())
attempt("list_folder", lambda: os.listdir(folder))
print(json.dumps(out))
"""


def _second_user_command(python: str) -> list[str]:
    """Run a command as a user other than the store's owner, or skip the test."""
    if os.name != "posix":
        pytest.skip("needs POSIX file permissions")
    if os.geteuid() == 0:
        return []  # root drops to `nobody` itself, below
    name = os.environ.get("AGENTLATCH_SECOND_USER")
    if not name:
        message = "set AGENTLATCH_SECOND_USER to a second OS user to run this test (see CI)"
        if os.environ.get("AGENTLATCH_REQUIRE_SECOND_USER"):
            pytest.fail(message)  # CI must run this test, not skip it
        pytest.skip(message)
    return ["sudo", "-n", "-u", name, python]


def test_8_second_os_user_is_denied() -> None:
    """A second OS user is denied read, write, chmod, delete and anchor access by the operating
    system.
    """
    python = os.path.realpath(sys.executable)
    prefix = _second_user_command(python)
    folder = Path(tempfile.mkdtemp(prefix="agentlatch-os-"))
    try:
        folder.chmod(0o755)  # the other user can walk in and list, but not change anything
        database, anchor, control = folder / "events.db", folder / "anchors.jsonl", folder / "ctl"
        logs = folder / "logs"
        trace, payloads = _record_run(logs)
        assert _import(logs, trace, database, payloads=payloads, anchor=anchor) == 0
        control.write_bytes(b"x")
        control.chmod(0o666)  # proves the child can act when it is allowed to
        for path in (database, anchor):
            assert (path.stat().st_mode & 0o777) == 0o600
        shutil.rmtree(logs)  # the logs are not what this test is about
        logs.mkdir()
        logs.chmod(0o700)

        command = [*(prefix or [python]), "-I", "-c", _CHILD,
                   str(database), str(anchor), str(control), str(folder)]
        kwargs: dict[str, Any] = {"capture_output": True, "text": True, "cwd": "/",
                                  "env": {"PATH": "/usr/bin:/bin"}, "timeout": 60}
        if not prefix:  # running as root: drop to `nobody`, no sudo needed
            try:
                nobody = pwd.getpwnam("nobody")
            except KeyError:
                pytest.skip("no `nobody` user to drop to")
            kwargs.update(user=nobody.pw_uid, group=nobody.pw_gid, extra_groups=[])
        done = subprocess.run(command, check=False, **kwargs)
        assert done.returncode == 0, done.stderr
        result = json.loads(done.stdout)

        assert result["control_write"] == "allowed" and result["list_folder"] == "allowed"
        for attempt in ("read_store", "write_store", "append_anchor", "chmod_store",
                        "chmod_anchor", "delete_store", "delete_anchor"):
            assert result[attempt] == "denied", (attempt, result)
        assert result["sql_delete"] != "allowed"

        # Nothing changed, and the store still verifies against its anchor.
        assert _verify(database, anchor) == 0
        assert database.exists() and anchor.exists()
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# --- 9. a crash between saving and publishing ----------------------------------------------------


def _crashed_store(tmp_path: Path, *, saved: int = 4) -> tuple[Sealed, Path, Path]:
    """Stage 1: anchor 2 events. Stage 2: the process dies after saving more, before publishing.

    ``saved`` is how many of the 4 events the dying process had saved. Returns the store
    (anchored at 2, holding ``saved`` rows) and the full logs it must be rebuilt from.
    """
    full_trace, _ = _record_run(tmp_path / "full", payloads=False)
    partial = tmp_path / "partial"
    partial.mkdir()
    lines = full_trace.read_text(encoding="utf-8").splitlines(keepends=True)
    (partial / "trace.jsonl").write_text("".join(lines[:2]), encoding="utf-8")
    database, anchor = tmp_path / "events.db", tmp_path / "anchors.jsonl"
    assert _import(partial, partial / "trace.jsonl", database, anchor=anchor) == 0
    assert FileAnchor(anchor).latest().seq == 2  # type: ignore[union-attr]
    # Saved but not published: the same import without --anchor.
    if saved == 4:
        assert _import(tmp_path / "full", full_trace, database) == 0
    else:
        (partial / "trace.jsonl").write_text("".join(lines[:saved]), encoding="utf-8")
        assert _import(partial, partial / "trace.jsonl", database) == 0
    store = Sealed.__new__(Sealed)
    store.root, store.logs, store.trace, store.payloads = tmp_path, tmp_path / "full", full_trace, None
    store.database, store.anchor = database, anchor
    return store, full_trace, anchor


def test_9_store_ahead_of_its_anchor_is_rebuilt_from_the_logs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A store left ahead of its anchor by a crash is rebuilt from the logs and re-anchored."""
    store, _, anchor = _crashed_store(tmp_path)
    assert store.rows() == 4
    assert _verify(store.database, anchor) == 0
    assert "UNANCHORED" in _out(capsys)  # the two extra rows are not covered yet

    # The logs rebuild exactly those rows, so the importer accepts them and anchors them.
    assert store.import_again() == 0
    assert FileAnchor(anchor).latest().seq == 4  # type: ignore[union-attr]
    assert store.rows() == 4 and store.verify() == 0
    assert "INTACT" in _out(capsys)


def test_9_a_changed_row_past_the_anchor_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A resealed row past the anchor that differs from the logs is refused."""
    store, _, anchor = _crashed_store(tmp_path)
    conn = _connect_as_attacker(store.database)
    conn.execute("UPDATE events SET name = 'rewritten' WHERE event_order = 4")
    _reseal_all(conn)  # a consistent chain: only the trace can show the row is wrong
    _cover_tracks(conn)
    conn.close()
    capsys.readouterr()
    assert store.import_again() == 1
    assert "differs from what the trace" in _out(capsys)
    assert FileAnchor(anchor).latest().seq == 2  # type: ignore[union-attr]


def test_9_an_extra_row_past_the_anchor_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A row past the anchor with no matching trace record is refused."""
    store, _, anchor = _crashed_store(tmp_path)
    forged = sample_events(1, run_id="forged")[0]
    writer = SQLiteEventStore(store.database)
    writer.open()
    writer.save([forged])
    writer.close()
    capsys.readouterr()
    assert store.import_again() == 1
    assert "no matching trace record" in _out(capsys)
    assert FileAnchor(anchor).latest().seq == 2  # type: ignore[union-attr]


def test_9_a_forged_row_is_never_anchored_even_when_new_events_arrive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The dying process saved 3 of 4 events. Someone then forged a row after the anchor, and the
    # restarted importer finds a genuinely new event (the fourth) to save in the same run.
    """A forged row is never anchored, even when a genuine new event is saved in the same run."""
    store, _, anchor = _crashed_store(tmp_path, saved=3)
    forged = sample_events(1, run_id="forged")[0]
    writer = SQLiteEventStore(store.database)
    writer.open()
    writer.save([forged])
    writer.close()
    capsys.readouterr()
    assert store.import_again() == 1
    assert "no matching trace record" in _out(capsys)
    # The new event was saved, but the anchor must not have moved over the forged row.
    assert FileAnchor(anchor).latest().seq == 2  # type: ignore[union-attr]


# --- 10. the first anchor ------------------------------------------------------------------------


def test_10_first_anchor_is_made_for_a_new_store_only(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only a new store creates its first anchor; a sealed store without one is refused."""
    assert FileAnchor(sealed.anchor).latest() is not None  # a new store made its first point

    sealed.anchor.unlink()  # the same as someone deleting the anchor
    capsys.readouterr()
    assert sealed.import_again() == 1
    out = _out(capsys)
    assert "missing or empty" in out and "anchor --database" in out
    assert sealed.rows() == 4 and not sealed.anchor.exists()

    # On purpose, once: `anchor --database` writes the first point of an existing store.
    assert cli.main(["anchor", "--database", str(sealed.database), "--to", str(sealed.anchor),
                     "--quiet"]) == 0
    assert FileAnchor(sealed.anchor).latest().seq == 4  # type: ignore[union-attr]
    assert sealed.import_again() == 0 and sealed.verify() == 0


def test_10_anchor_command_refuses_a_store_that_fails_its_check(
    sealed: Sealed, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor command never blesses a store that fails its check."""
    conn = _connect_as_attacker(sealed.database)
    conn.execute("UPDATE events SET name = 'evil' WHERE event_order = 3")
    conn.close()
    other = tmp_path / "other-anchor.jsonl"
    assert cli.main(["anchor", "--database", str(sealed.database), "--to", str(other)]) == 1
    assert "not anchored" in _out(capsys) and not other.exists()  # never bless a changed store


# --- 11. the table layout ----------------------------------------------------------------------


@pytest.mark.parametrize("change", ["add_column", "edit_view", "drop_trigger"])
def test_11_schema_changes_are_caught(
    sealed: Sealed, change: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """An added column, an edited view or a dropped trigger is reported as tampering."""
    conn = sqlite3.connect(sealed.database, isolation_level=None)
    if change == "add_column":
        conn.execute("ALTER TABLE events ADD COLUMN hidden TEXT")
    elif change == "edit_view":
        conn.execute("DROP VIEW event_log")
        conn.execute("CREATE VIEW event_log AS SELECT 'nothing to see' AS time")
    else:
        conn.execute("DROP TRIGGER events_no_delete")
    conn.close()
    capsys.readouterr()
    assert sealed.verify() == 1  # no row changed, yet the layout no longer matches
    assert "TAMPERED" in _out(capsys)
    assert sealed.import_again() == 1
    assert sealed.rows() == 4


# --- 12. the guards between ledgers and stores ---------------------------------------------------


def test_12_a_database_is_never_read_as_a_ledger(
    sealed: Sealed, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A SQLite file given to verify as a ledger is refused with a pointer to --database."""
    assert cli.main(["verify", str(sealed.database)]) == 2
    assert "SQLite database, not a ledger" in _out(capsys)
    assert cli.main(["verify", "--ledger", str(sealed.database)]) == 2
    # --database checks one store; it is not combined with ledger options.
    assert cli.main(["verify", "--database", str(sealed.database), "--trace", "x"]) == 2


def test_12_one_anchor_file_per_chain(sealed: Sealed, tmp_path: Path) -> None:
    """A ledger and an event store cannot share one anchor file."""
    ledger_path = tmp_path / "trace.ledger.jsonl"
    with Ledger(ledger_path) as ledger:
        ledger.append('{"a":1}', method="tools/call", stage="request")
        head = ledger.head
    # A trace-ledger point cannot join a file that holds an event store's points ...
    point = AnchorPoint(seq=head[0], digest=head[1], records=1, timestamp="t", ledger="l")
    with pytest.raises(AnchorError, match="another source"):
        FileAnchor(sealed.anchor).publish(point)
    assert cli.main(["anchor", "--ledger", str(ledger_path), "--to", str(sealed.anchor)]) == 2
    # ... and a ledger checked against a store's anchor is flagged, not trusted.
    result = verify_ledger(ledger_path, anchor_path=sealed.anchor)
    assert result.failed and any(issue.kind == "malformed" for issue in result.issues)
    # The reverse: the store's own point cannot be put in a ledger's anchor file.
    ledger_anchor = tmp_path / "ledger-anchors.jsonl"
    assert cli.main(["anchor", "--ledger", str(ledger_path), "--to", str(ledger_anchor),
                     "--quiet"]) == 0
    assert cli.main(["anchor", "--database", str(sealed.database), "--to", str(ledger_anchor)]) == 2
    # The importer refuses an anchor file that belongs to a ledger.
    assert _import(sealed.logs, sealed.trace, tmp_path / "other.db", payloads=sealed.payloads,
                   anchor=ledger_anchor) == 1


# --- the seal itself -------------------------------------------------------------------------


def test_seal_is_deterministic_and_covers_every_field() -> None:
    """The same event seals the same way, and every field and the import time change the digest."""
    event = sample_events(1)[0]
    first = next_seal(None, event, "2026-01-01T00:00:00Z")
    assert first == next_seal(None, event, "2026-01-01T00:00:00Z")
    assert first.seq == 1 and first.prev == GENESIS

    changed_event = {**event, "name": "other"}
    assert next_seal(None, changed_event, "2026-01-01T00:00:00Z").digest != first.digest
    assert next_seal(None, event, "2026-01-01T00:00:01Z").digest != first.digest  # imported_at
    second = next_seal(first, event, "2026-01-01T00:00:00Z")
    assert second.seq == 2 and second.prev == first.digest and second.digest != first.digest
    # Key order in the event does not matter; values do.
    assert event_sha256(dict(reversed(list(event.items()))), "t") == event_sha256(event, "t")


def test_store_seals_use_their_own_domain_not_the_ledgers() -> None:
    """A store seal uses its own domain tag, so it can never pass as a trace-ledger block."""
    from agent_latch.runtime.ledger.chain import DOMAIN as LEDGER_DOMAIN
    from agent_latch.runtime.ledger.event_seal import DOMAIN as STORE_DOMAIN

    assert STORE_DOMAIN != LEDGER_DOMAIN and STORE_DOMAIN.startswith(b"agentlatch.runtime.store-seal")
    body = {"prev": GENESIS, "seq": 1, "event_sha256": "0" * 64}
    import hashlib

    from agent_latch.runtime.ledger.canonical import dumps
    assert seal_digest(prev=GENESIS, seq=1, event_sha256="0" * 64) != hashlib.sha256(
        LEDGER_DOMAIN + dumps(body)
    ).hexdigest()


def test_walk_chain_names_each_kind_of_problem() -> None:
    """The chain walk names a gap, an edit and an unsealed row, and gives a clean chain no
    issues.
    """
    events = sample_events(4)
    rows: list[StoredRow] = []
    head = None
    for event in events:
        head = next_seal(head, event, "t")
        rows.append(StoredRow(head, event, "t"))
    assert not walk_chain(rows).issues
    assert walk_chain(rows).head == head

    assert {i.kind for i in walk_chain([rows[0], rows[2], rows[3]]).issues} >= {"deleted"}
    edited = [rows[0], StoredRow(rows[1].seal, {**events[1], "name": "x"}, "t"), *rows[2:]]
    assert [i.kind for i in walk_chain(edited).issues] == ["edited"]
    unsealed = [rows[0], StoredRow(None, events[1], "t")]
    assert [i.kind for i in walk_chain(unsealed).issues] == ["added"]
    assert status_for({"added"}, anchored=True) == "tampered"
    assert status_for({"unanchored"}, anchored=True) == STATUS_UNANCHORED


def test_anchor_points_without_the_new_fields_are_unchanged(tmp_path: Path) -> None:
    """A trace-ledger point is byte-identical to before, and old readers still read new points."""
    old = AnchorPoint(seq=1, digest="d", records=1, timestamp="t", ledger="l")
    assert set(old.to_dict()) == {"schema", "seq", "digest", "records", "timestamp", "ledger"}
    assert AnchorPoint.from_dict(old.to_dict()) == old
    new = AnchorPoint(seq=1, digest="d", records=1, timestamp="t", ledger="l", source=SOURCE,
                      schema_sha256="abc", schema_version=4)
    assert AnchorPoint.from_dict(new.to_dict()) == new
    # An older reader that only knows the original keys still understands a new point.
    legacy = {key: new.to_dict()[key] for key in old.to_dict()}
    assert AnchorPoint.from_dict(legacy) == old
    assert AnchorPoint.from_dict({**new.to_dict(), "schema_version": True}) is None
    assert AnchorPoint.from_dict({**new.to_dict(), "source": 7}) is None


def test_audit_tool_command_serves_only_a_sealed_store(
    sealed: Sealed, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """audit-tool refuses a missing or unsealed store and offers exactly two tools."""
    pytest.importorskip("fastmcp")
    from agent_latch.runtime.audit_tool import build_audit_tool

    # A missing store, and an older (unsealed) one, are configuration errors: exit 2, no server.
    assert cli.main(["audit-tool", "--database", str(tmp_path / "nothing.db")]) == 2
    assert "no event store" in _out(capsys)
    older = tmp_path / "v1.db"
    conn = sqlite3.connect(older, isolation_level=None)
    sqlite_store.MIGRATIONS[0](conn)
    conn.execute("PRAGMA user_version = 1")
    conn.close()
    assert cli.main(["audit-tool", "--database", str(older)]) == 2
    assert "not sealed yet" in _out(capsys)

    # A sealed store gets exactly two tools, and building the tool leaves the store untouched.
    server = build_audit_tool(sealed.database)
    tools = asyncio.run(server.list_tools())
    assert sorted(tool.name for tool in tools) == ["query_audit_log", "recent_events"]
    assert sealed.rows() == 4 and sealed.verify() == 0


# --- findings from the PR review, each pinned by a test --------------------------------------


def test_file_prefixed_anchor_specs_name_the_file_the_commands_write(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file:/path anchor spec is read from the same file the commands write, so a rewrite is
    caught.
    """
    spec = f"file:{sealed.anchor}"
    capsys.readouterr()
    assert cli.main(["verify", "--database", str(sealed.database), "--anchor", spec]) == 0
    assert "INTACT" in _out(capsys)

    conn = _connect_as_attacker(sealed.database)
    conn.execute("UPDATE events SET name = 'cover-up' WHERE event_order = 2")
    _reseal_all(conn)
    _cover_tracks(conn)
    conn.close()
    # Read as a bare path, the spec would name a file that does not exist and the rewrite would pass.
    assert cli.main(["verify", "--database", str(sealed.database), "--anchor", spec]) == 1
    assert "REWRITTEN" in _out(capsys)
    before = sealed.anchor.read_text(encoding="utf-8")
    assert cli.main(["anchor", "--database", str(sealed.database), "--to", spec, "--quiet"]) == 1
    assert sealed.anchor.read_text(encoding="utf-8") == before  # a rewritten store is not blessed


def test_a_store_with_no_rows_has_nothing_to_verify_or_anchor(tmp_path: Path) -> None:
    """A store with no rows exits 2 from verify and anchor, not 0 or 1."""
    empty = tmp_path / "empty.db"
    store = SQLiteEventStore(empty)
    store.open()
    store.close()
    target = tmp_path / "anchors.jsonl"
    assert cli.main(["verify", "--database", str(empty)]) == 2  # not "verified": nothing to check
    assert cli.main(["anchor", "--database", str(empty), "--to", str(target)]) == 2  # not "altered"
    assert not target.exists()


def test_a_lowered_schema_version_is_tampering_and_is_never_migrated(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """A version lowered below the anchor's is tampering, and the importer refuses it before
    migrating.
    """
    conn = sqlite3.connect(sealed.database)
    conn.execute("PRAGMA user_version = 2")  # makes a sealed store look like an old one
    conn.close()
    before = hashlib.sha256(sealed.database.read_bytes()).hexdigest()
    capsys.readouterr()

    assert sealed.verify() == 1
    out = _out(capsys)
    assert "TAMPERED" in out and "lowered" in out
    # The importer refuses before opening: opening an old file would seal whatever rows it holds.
    assert sealed.import_again() == 1
    assert "lowered" in _out(capsys)
    assert hashlib.sha256(sealed.database.read_bytes()).hexdigest() == before
    # With no anchor there is nothing to say the version was lowered: it stays "not sealed yet".
    assert sealed.verify(anchor=False) == 2


def test_anchor_command_will_not_bless_rows_it_has_not_checked(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor command refuses rows past the newest point unless told to trust them."""
    writer = SQLiteEventStore(sealed.database)
    writer.open()
    writer.save([sample_events(1, run_id="forged")[0]])  # a validly sealed row past the anchor
    writer.close()
    capsys.readouterr()
    base = ["anchor", "--database", str(sealed.database), "--to", str(sealed.anchor), "--quiet"]
    assert cli.main(base) == 1
    assert "have not been checked against the logs" in _out(capsys)
    assert FileAnchor(sealed.anchor).latest().seq == 4  # type: ignore[union-attr]
    assert cli.main([*base, "--accept-unchecked-rows"]) == 0  # a deliberate, explicit choice
    assert FileAnchor(sealed.anchor).latest().seq == 5  # type: ignore[union-attr]


def test_a_publish_skipped_by_the_interval_is_retried_while_idle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A publish skipped by the interval is retried while the importer is idle, without a new
    event.
    """
    monkeypatch.setattr(importer_module, "ANCHOR_INTERVAL_SECONDS", 0.4)
    full, _ = _record_run(tmp_path / "full", payloads=False)
    lines = full.read_text(encoding="utf-8").splitlines(keepends=True)
    live = tmp_path / "live.jsonl"
    live.write_text("".join(lines[:2]), encoding="utf-8")
    anchor = FileAnchor(tmp_path / "anchors.jsonl")
    importer = RuntimeLogImporter(
        live, None, [], store=SQLiteEventStore(tmp_path / "events.db"), anchor=anchor,
        follow=True, poll_interval=0.02, payload_grace=0.05,
    )
    thread = threading.Thread(target=importer.run)
    thread.start()

    def anchored_at() -> int:
        """The sequence number of the newest anchor point (0 when there is none)."""
        point = anchor.latest()
        return point.seq if point else 0

    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and anchored_at() < 2:
            time.sleep(0.02)
        assert anchored_at() == 2
        with live.open("a", encoding="utf-8") as stream:
            stream.write("".join(lines[2:]))  # saved inside the interval, so its publish is skipped
        while time.monotonic() < deadline and anchored_at() < 4:
            time.sleep(0.05)
        assert anchored_at() == 4  # published while the importer is still running and idle
    finally:
        importer.stop()
        thread.join(10)


def test_attack_tool_local_mode_passes_against_a_sealed_store(sealed: Sealed) -> None:
    """The attack script's local mode sees every write refused and the store unchanged."""
    pytest.importorskip("fastmcp")
    root = Path(__file__).resolve().parents[1]
    script = root / "docs" / "audit-trail-dev" / "attack_tool.py"
    done = subprocess.run(
        [sys.executable, str(script), "--local", str(sealed.database)],
        capture_output=True, text=True, timeout=120, check=False,
        env={**os.environ, "PYTHONPATH": str(root / "src")},
    )
    assert done.returncode == 0, done.stdout + done.stderr[-600:]
    assert "PASS: 0 of 17 write attempts succeeded" in done.stdout
    assert sealed.rows() == 4 and sealed.verify() == 0


def _add_genuine_event(sealed: Sealed) -> None:
    """Append one more record to the sealed run's trace, as the proxy would for a new tool call."""
    trace = TraceLog(sealed.trace, summary=None)
    trace.call_request(ToolCall("s", "9", "claude", "run_command", "demo", {"command": "pwd"}, "t"))
    trace.close()


def test_anchor_command_on_a_lowered_schema_version_is_tampering(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """anchor --database treats a lowered schema version as tampering (exit 1), not as an old
    file.
    """
    conn = sqlite3.connect(sealed.database)
    conn.execute("PRAGMA user_version = 2")
    conn.close()
    before = sealed.anchor.read_text(encoding="utf-8")
    capsys.readouterr()
    argv = ["anchor", "--database", str(sealed.database), "--to", str(sealed.anchor), "--quiet"]
    assert cli.main(argv) == 1  # an integrity failure, not "not sealed yet" (2)
    out = _out(capsys)
    assert "TAMPERED" in out and "lowered" in out
    assert sealed.anchor.read_text(encoding="utf-8") == before


def test_every_anchor_point_must_still_hold_not_only_the_newest(
    sealed: Sealed, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rewrite published over still conflicts with older anchor points, for verify and the
    importer.
    """
    _add_genuine_event(sealed)
    assert sealed.import_again() == 0  # a second, genuine point: #5
    assert [point.seq for point in FileAnchor(sealed.anchor).points()] == [4, 5]

    # Rewrite and reseal the whole chain, then publish a point over the forgery, which is what an
    # importer that trusted the store would have done. The newest point now matches the forgery.
    conn = _connect_as_attacker(sealed.database)
    conn.execute("UPDATE events SET name = 'cover-up' WHERE event_order = 2")
    _reseal_all(conn)
    _cover_tracks(conn)
    forged_head = conn.execute("SELECT seal_digest FROM events WHERE seal_seq = 5").fetchone()[0]
    conn.close()
    FileAnchor(sealed.anchor).publish(AnchorPoint(
        seq=5, digest=forged_head, records=5, timestamp="2026-01-01T00:00:00Z", ledger="events.db",
        source=SOURCE,
    ))
    capsys.readouterr()
    assert sealed.verify() == 1  # the older points no longer match, so the rewrite shows
    assert "REWRITTEN" in _out(capsys)
    # The importer holds the store to every point at start too, and refuses it.
    assert sealed.import_again() == 1
    assert "changed after it was sealed" in _out(capsys)


def test_importer_will_not_publish_over_a_chain_rewritten_while_it_runs(tmp_path: Path) -> None:
    """A chain rewritten while the importer runs is refused, and the forgery is never anchored."""
    sealed = Sealed(tmp_path)  # anchored at #4
    importer = RuntimeLogImporter(
        sealed.trace, None, [], payloads_path=sealed.payloads,
        store=SQLiteEventStore(sealed.database), anchor=FileAnchor(sealed.anchor),
        follow=True, poll_interval=0.02, payload_grace=0.05,
    )
    errors: list[BaseException] = []

    def run() -> None:
        """Run the importer and keep whatever stopped it, so the test can inspect it."""
        try:
            importer.run()
        except BaseException as error:  # noqa: BLE001 - the test inspects what stopped it
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        time.sleep(0.5)  # the importer has audited the genuine store and is idle
        conn = _connect_as_attacker(sealed.database)
        conn.execute("UPDATE events SET name = 'cover-up' WHERE event_order = 2")
        _reseal_all(conn)  # a consistent chain, rewritten after the importer started
        _cover_tracks(conn)
        conn.close()
        _add_genuine_event(sealed)  # the next genuine event chains onto the forgery
        thread.join(15)
        assert not thread.is_alive(), "the importer should have refused and stopped"
    finally:
        importer.stop()
        thread.join(5)
    assert errors and "changed after it was sealed" in str(errors[0])
    assert FileAnchor(sealed.anchor).latest().seq == 4  # type: ignore[union-attr]


def test_an_unreadable_anchor_is_refused_before_an_old_store_is_opened(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With an anchor that cannot be read, an old store must not be migrated and sealed first."""
    database = tmp_path / "v2.db"
    conn = sqlite3.connect(database, isolation_level=None)
    for step in sqlite_store.MIGRATIONS[:2]:  # the released schema, whose rows are not sealed
        step(conn)
    conn.execute("PRAGMA user_version = 2")
    for event in sample_events(3):
        conn.execute(
            f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({', '.join('?' for _ in COLUMNS)})",
            event_to_row(event, "2026-01-01T00:00:00.000Z"),
        )
    conn.close()
    anchor = tmp_path / "anchors.jsonl"
    anchor.write_text("this is not an anchor point\n", encoding="utf-8")  # cannot be parsed
    logs = tmp_path / "logs"
    trace, _ = _record_run(logs, payloads=False)
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    capsys.readouterr()

    assert _import(logs, trace, database, anchor=anchor) == 1
    assert "cannot be read" in _out(capsys)
    # Migration 3 would have sealed every row it found; the file must be exactly as it was.
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    conn = sqlite3.connect(database)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    conn.close()


def _start_importer(
    sealed: Sealed, monkeypatch: pytest.MonkeyPatch, *, interval: float
) -> tuple[RuntimeLogImporter, threading.Thread, list[BaseException]]:
    """Start a following importer on a sealed run and return it with what stops it."""
    monkeypatch.setattr(importer_module, "ANCHOR_INTERVAL_SECONDS", interval)
    importer = RuntimeLogImporter(
        sealed.trace, None, [], payloads_path=sealed.payloads,
        store=SQLiteEventStore(sealed.database), anchor=FileAnchor(sealed.anchor),
        follow=True, poll_interval=0.02, payload_grace=0.05,
    )
    errors: list[BaseException] = []

    def run() -> None:
        """Run the importer and keep whatever stopped it, so the test can inspect it."""
        try:
            importer.run()
        except BaseException as error:  # noqa: BLE001 - the test inspects what stopped it
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    return importer, thread, errors


def _wait_for_rows(sealed: Sealed, count: int) -> None:
    """Wait until the store holds ``count`` rows, which means the importer has saved them."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and sealed.rows() < count:
        time.sleep(0.05)
    assert sealed.rows() == count


def _rewrite_saved_row(sealed: Sealed) -> None:
    """Change the newest row and reseal, from the genuine digest before it (rows 1 to 4 are intact)."""
    conn = _connect_as_attacker(sealed.database)
    conn.execute("UPDATE events SET name = 'cover-up' WHERE seal_seq = 5")
    _reseal_all(conn)
    _cover_tracks(conn)
    conn.close()


def test_a_row_saved_but_not_yet_anchored_cannot_be_rewritten_and_extended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A saved row no anchor covers yet is re-checked before the next save chains onto it."""
    sealed = Sealed(tmp_path)  # anchored at #4
    importer, thread, errors = _start_importer(sealed, monkeypatch, interval=60)
    try:
        time.sleep(0.5)
        importer._last_publish = time.monotonic()  # the next publish is skipped: #5 stays unanchored
        _add_genuine_event(sealed)
        _wait_for_rows(sealed, 5)  # genuine #5 is saved, and no anchor point covers it
        _rewrite_saved_row(sealed)  # forged #5, resealed from the genuine #4
        _add_genuine_event(sealed)  # the next event would chain onto the forged #5
        thread.join(15)
        assert not thread.is_alive(), "the importer should have refused and stopped"
    finally:
        importer.stop()
        thread.join(5)
    assert errors and "changed before it was anchored" in str(errors[0])
    assert FileAnchor(sealed.anchor).latest().seq == 4  # type: ignore[union-attr]


def test_a_forged_unanchored_row_is_never_published_even_without_a_new_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check also runs just before a publish, so an idle importer does not anchor a forgery."""
    sealed = Sealed(tmp_path)  # anchored at #4
    importer, thread, errors = _start_importer(sealed, monkeypatch, interval=0.4)
    try:
        time.sleep(0.5)
        importer._last_publish = time.monotonic() + 3  # the publish waits a few seconds
        _add_genuine_event(sealed)
        _wait_for_rows(sealed, 5)
        _rewrite_saved_row(sealed)  # before the delayed publish
        thread.join(15)  # no new event: only the delayed publish can notice
        assert not thread.is_alive(), "the importer should have refused and stopped"
    finally:
        importer.stop()
        thread.join(5)
    assert errors and "changed before it was anchored" in str(errors[0])
    assert FileAnchor(sealed.anchor).latest().seq == 4  # type: ignore[union-attr]


def test_a_tail_row_found_at_startup_is_rechecked_before_anything_is_published(
    tmp_path: Path,
) -> None:
    """Rows left past the anchor by a crash are covered by no point, so a later reseal is caught."""
    store, full_trace, anchor = _crashed_store(tmp_path)  # anchored at #2, rows #3 and #4 unanchored
    importer = RuntimeLogImporter(
        full_trace, None, [], store=SQLiteEventStore(store.database), anchor=FileAnchor(anchor)
    )
    assert importer.store is not None
    importer.store.open()
    try:
        importer._audit_store()  # startup: the two tail rows are genuine and match the logs
        assert set(importer._saved_seals) == {3, 4}
        conn = _connect_as_attacker(store.database)
        conn.execute("UPDATE events SET name = 'cover-up' WHERE seal_seq = 4")
        _reseal_all(conn)
        _cover_tracks(conn)
        conn.close()
        with pytest.raises(StoreTampered, match="changed before it was anchored"):
            importer._refuse_if_saved_rows_changed()
    finally:
        importer.store.close()


def test_ctrl_c_with_a_changed_unanchored_row_is_not_a_clean_exit(tmp_path: Path) -> None:
    """The last check on the way out raises instead of being logged, so the CLI exits 1."""
    store, full_trace, anchor = _crashed_store(tmp_path)
    importer = RuntimeLogImporter(
        full_trace, None, [], store=SQLiteEventStore(store.database), anchor=FileAnchor(anchor)
    )
    assert importer.store is not None
    importer.store.open()
    try:
        importer._audit_store()
        importer._tail.clear()  # the logs have been read and matched those rows
        importer._dirty = True  # and a publish is due
        conn = _connect_as_attacker(store.database)
        conn.execute("UPDATE events SET name = 'cover-up' WHERE seal_seq = 4")
        _reseal_all(conn)
        _cover_tracks(conn)
        conn.close()
        with pytest.raises(StoreTampered):
            importer._publish_after_interrupt()
    finally:
        importer.store.close()


def test_an_anchor_that_becomes_unreadable_while_running_is_refused_with_exit_1(
    tmp_path: Path,
) -> None:
    """The same refusal as at start: a StoreRefused, which the CLI reports as exit 1."""
    sealed = Sealed(tmp_path)
    importer = RuntimeLogImporter(
        sealed.trace, None, [], store=SQLiteEventStore(sealed.database),
        anchor=FileAnchor(sealed.anchor),
    )
    assert importer.store is not None
    importer.store.open()
    try:
        sealed.anchor.write_text("this is not an anchor point\n", encoding="utf-8")
        with pytest.raises(StoreRefused, match="cannot be read"):
            importer._refuse_if_rewritten_since_last_point()
    finally:
        importer.store.close()


def test_an_anchor_that_is_not_valid_utf8_is_refused_with_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A binary anchor file is a refused store (exit 1), not a crash that exits 2."""
    sealed = Sealed(tmp_path)
    sealed.anchor.write_bytes(b"\xff\xfe\x00not text")
    capsys.readouterr()
    assert sealed.import_again() == 1
    assert "cannot be read" in _out(capsys)


def test_an_anchor_that_disappears_while_running_is_never_recreated_over(tmp_path: Path) -> None:
    """A deleted anchor file would otherwise be recreated holding only the newest head."""
    sealed = Sealed(tmp_path)
    importer = RuntimeLogImporter(
        sealed.trace, None, [], store=SQLiteEventStore(sealed.database),
        anchor=FileAnchor(sealed.anchor),
    )
    assert importer.store is not None
    importer.store.open()
    try:
        importer._audit_store()  # sees the published point
        sealed.anchor.unlink()
        with pytest.raises(StoreRefused, match="missing or empty"):
            importer._refuse_if_rewritten_since_last_point()
    finally:
        importer.store.close()


def test_an_anchor_that_disappears_stops_the_run_before_it_saves_anything_newer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found missing while running, the importer refuses before saving, not only before publishing."""
    sealed = Sealed(tmp_path)  # anchored at the end of the run
    rows = sealed.rows()
    importer, thread, errors = _start_importer(sealed, monkeypatch, interval=60)
    try:
        time.sleep(0.5)  # it has audited the store and seen the anchor
        sealed.anchor.unlink()
        _add_genuine_event(sealed)
        thread.join(15)
        assert not thread.is_alive(), "the importer should have refused and stopped"
    finally:
        importer.stop()
        thread.join(5)
    assert errors and "missing or empty" in str(errors[0])
    assert sealed.rows() == rows  # the new event was never saved
    assert not sealed.anchor.exists()  # and no anchor was recreated
