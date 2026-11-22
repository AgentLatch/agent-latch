"""The ``--store`` hook: a store package used in place of ``--database``, with the same checks.

The test store here wraps the built-in SQLite store at a path given as an option, so every seal,
refusal and verdict is the real one. What is under test is the plumbing: discovery, options and
secrets, the commands (``import-logs``, ``verify``, ``anchor``, ``audit-tool``, ``stores``), and
seals handed on to connectors that ask for them. No network.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from agent_latch.runtime import cli, connectors, stores
from agent_latch.runtime.connectors import EventBatch
from agent_latch.runtime.sqlite_store import SQLiteEventReader, SQLiteEventStore
from agent_latch.runtime.stores import StoreConfigError
from tests.test_audit_store import _record_run
from tests.test_connectors import FakeConnector, FakeEntry
from tests.test_connectors import _factory_for as connector_factory

SECRET = "pg-password-value-42"


class WrappedStore:
    """A store package's backend: the real SQLite writer and reader at ``options['path']``."""

    store_api = 1

    def __init__(self, options: dict[str, str]) -> None:
        if "path" not in options:
            raise StoreConfigError(f"option 'path' is required (password was {options.get('pw')})")
        self.path = Path(options["path"])
        self.name = f"wrapped-{self.path.name}"

    def writer(self) -> SQLiteEventStore:
        return SQLiteEventStore(self.path)

    def reader(self) -> Any:
        return _Reader(self.path)


class _Reader(SQLiteEventReader):
    """The SQLite reader, plus ``exists`` so a removed store reads as deleted, not as an error."""

    def exists(self) -> bool:
        return self.path.is_file()


class NoQueryReader(_Reader):
    """A reader without SQL (an object store, for example)."""

    query = None  # type: ignore[assignment]


def _install_store(monkeypatch: pytest.MonkeyPatch, factory: Any, name: str = "wrapped") -> None:
    monkeypatch.setattr(stores, "_entry_points", lambda: [FakeEntry(name, factory, package="pro-store")])


@pytest.fixture
def wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_store(monkeypatch, lambda options, context: WrappedStore(dict(options)))


@pytest.fixture
def run(tmp_path: Path) -> dict[str, Path]:
    logs = tmp_path / "logs"
    trace, payloads = _record_run(logs)
    assert payloads is not None
    return {
        "logs": logs, "trace": trace, "payloads": payloads,
        "db": tmp_path / "store" / "events.db", "anchor": tmp_path / "anchor" / "anchors.jsonl",
    }


def _import(run: dict[str, Path], *extra: str, anchor: bool = True) -> int:
    argv = [
        "import-logs", "--dir", str(run["logs"]), "--trace", str(run["trace"]),
        "--payloads", str(run["payloads"]), "--once", "--quiet",
        "--store", "wrapped", "--store-option", f"path={run['db']}", *extra,
    ]
    if anchor:
        argv += ["--anchor", str(run["anchor"])]
    return cli.main(argv)


def _verify(run: dict[str, Path], *, anchor: bool = True) -> int:
    argv = ["verify", "--store", "wrapped", "--store-option", f"path={run['db']}"]
    if anchor:
        argv += ["--anchor", str(run["anchor"])]
    return cli.main(argv)


def _out(capsys: pytest.CaptureFixture[str]) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


# --- listing and options -----------------------------------------------------------------------


def test_stores_lists_without_loading(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    entry = FakeEntry("wrapped", None, package="pro-store", version="2.0.0")
    monkeypatch.setattr(stores, "_entry_points", lambda: [entry])
    assert cli.main(["stores"]) == 0
    out = _out(capsys)
    assert "wrapped" in out and "pro-store 2.0.0" in out
    assert entry.loaded is False


def test_stores_with_none_installed(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    monkeypatch.setattr(stores, "_entry_points", list)
    assert cli.main(["stores"]) == 0
    assert "no stores installed" in _out(capsys)


def test_options_resolve_env_and_never_echo_values() -> None:
    resolved = stores.parse_store_options(["dsn=env:PG", "table=events"], {"PG": SECRET})
    assert resolved.options == {"dsn": SECRET, "table": "events"}
    assert resolved.secrets == (SECRET,)
    with pytest.raises(StoreConfigError) as error:
        stores.parse_store_options(["dsn=env:MISSING"], {})
    assert "MISSING" in str(error.value)
    with pytest.raises(StoreConfigError) as error:
        stores.parse_store_options([f"no-equals-{SECRET}"], {})
    assert SECRET not in str(error.value)


def test_factory_errors_are_scrubbed(monkeypatch: pytest.MonkeyPatch, run: dict[str, Path],
                                     capsys: Any) -> None:
    _install_store(monkeypatch, lambda options, context: WrappedStore(dict(options)))
    monkeypatch.setenv("PW", SECRET)
    code = cli.main(["import-logs", "--dir", str(run["logs"]), "--once", "--quiet",
                     "--store", "wrapped", "--store-option", "pw=env:PW"])
    out = _out(capsys)
    assert code == 2
    assert "option 'path' is required" in out and SECRET not in out


def test_unknown_type_and_wrong_api_exit_2(monkeypatch: pytest.MonkeyPatch, run: dict[str, Path],
                                           capsys: Any) -> None:
    monkeypatch.setattr(stores, "_entry_points", list)
    assert _import(run) == 2
    assert "no installed store of type 'wrapped'" in _out(capsys)

    class Old(WrappedStore):
        store_api = 99

    _install_store(monkeypatch, lambda options, context: Old(dict(options)))
    assert _import(run) == 2
    assert "upgrade AgentLatch" in _out(capsys)
    assert not run["db"].exists()


def test_database_and_store_are_exclusive(wrapped: None, run: dict[str, Path], capsys: Any) -> None:
    assert _import(run, "--database", str(run["db"])) == 2
    assert "--database or --store, not both" in _out(capsys)
    assert cli.main(["verify", "--store-option", "path=x", "--database", str(run["db"])]) == 2
    assert cli.main(["import-logs", "--dir", str(run["logs"]), "--store-option", "a=b"]) == 2


# --- the same pipeline as --database -----------------------------------------------------------


def test_import_verify_anchor_behave_like_database(wrapped: None, run: dict[str, Path],
                                                   capsys: Any) -> None:
    assert _import(run) == 0
    assert run["db"].is_file()
    points = [json.loads(line) for line in run["anchor"].read_text().splitlines()]
    assert points[-1]["source"] == "event-store" and points[-1]["ledger"] == "events.db"
    capsys.readouterr()

    assert _verify(run) == 0
    assert "INTACT" in _out(capsys)
    assert _import(run) == 0  # importing again adds nothing and still verifies
    assert _verify(run) == 0
    assert _verify(run, anchor=False) == 0
    assert "UNANCHORED" in _out(capsys)

    # The anchor command refuses unchecked rows exactly like anchor --database.
    other = run["anchor"].with_name("other.jsonl")
    assert cli.main(["anchor", "--store", "wrapped", "--store-option", f"path={run['db']}",
                     "--to", str(other)]) == 0
    assert other.is_file()


def test_a_changed_store_is_refused_by_import_and_verify(wrapped: None, run: dict[str, Path],
                                                          capsys: Any) -> None:
    assert _import(run) == 0
    conn = sqlite3.connect(run["db"], isolation_level=None)
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET name = 'nothing to see' WHERE event_order = 3")
    conn.close()
    capsys.readouterr()
    assert _import(run) == 1
    assert "changed after it was sealed" in _out(capsys)
    assert _verify(run) == 1
    out = _out(capsys)
    assert "TAMPERED" in out


def test_a_removed_store_with_an_anchor_is_deleted(wrapped: None, run: dict[str, Path],
                                                   capsys: Any) -> None:
    assert _import(run) == 0
    run["db"].unlink()
    capsys.readouterr()
    assert _verify(run) == 1
    assert "DELETED" in _out(capsys)
    assert _verify(run, anchor=False) == 2  # nothing to verify and nothing says it existed


def test_anchor_store_refuses_a_failing_store(wrapped: None, run: dict[str, Path],
                                              capsys: Any) -> None:
    assert _import(run) == 0
    conn = sqlite3.connect(run["db"], isolation_level=None)
    conn.execute("DROP TRIGGER events_no_delete")
    conn.execute("DELETE FROM events WHERE event_order = 2")
    conn.close()
    assert cli.main(["anchor", "--store", "wrapped", "--store-option", f"path={run['db']}",
                     "--to", str(run["anchor"])]) == 1
    assert "not anchored" in _out(capsys)


def test_store_without_a_file_names_its_anchor_points(tmp_path: Path, run: dict[str, Path],
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    class Remote:
        """A writer with no local file (as a database server has), delegating to SQLite."""

        path = None
        name = "remote-db"

        def __init__(self, inner: SQLiteEventStore) -> None:
            self._inner = inner

    # Real methods on the class: the importer's SealedSource check looks at the class, not at
    # __getattr__, so a store package has to define them too.
    for method in ("open", "save", "close", "events", "head", "as_stored", "sealed_rows",
                   "schema_sha256", "expected_schema_sha256", "schema_version", "seals_after",
                   "seal_digest_at", "seals_for", "stored_version"):
        setattr(Remote, method,
                lambda self, *args, _m=method, **kwargs: getattr(self._inner, _m)(*args, **kwargs))

    class Named(WrappedStore):
        def writer(self) -> Any:
            return Remote(SQLiteEventStore(self.path))

    _install_store(monkeypatch, lambda options, context: Named(dict(options)))
    assert _import(run) == 0
    point = json.loads(run["anchor"].read_text().splitlines()[-1])
    assert point["ledger"] == "remote-db"


# --- audit-tool -------------------------------------------------------------------------------


def test_audit_tool_for_a_store(wrapped: None, run: dict[str, Path]) -> None:
    from agent_latch.runtime.audit_tool import build_audit_tool_for_reader

    assert _import(run) == 0
    server = build_audit_tool_for_reader(_Reader(run["db"]))
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert names == {"query_audit_log", "recent_events"}

    plain = build_audit_tool_for_reader(NoQueryReader(run["db"]))
    tools = {tool.name: tool for tool in asyncio.run(plain.list_tools())}
    assert set(tools) == {"recent_events"}
    result = asyncio.run(plain.call_tool("recent_events", {"limit": 2}))
    rows = result.structured_content["result"]
    assert [row["seal_seq"] for row in rows] == [4, 3]


def test_audit_tool_needs_a_source() -> None:
    with pytest.raises(SystemExit):
        cli.main(["audit-tool"])


# --- seals handed on to connectors that ask -----------------------------------------------------


class SealWanting(FakeConnector):
    wants_seals = True


def test_connectors_that_ask_get_seals_and_others_do_not(
    wrapped: None, run: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    wanting, plain = SealWanting(), FakeConnector()
    monkeypatch.setattr(connectors, "_entry_points", lambda: [
        FakeEntry("sealed-otlp", connector_factory(wanting)),
        FakeEntry("plain", connector_factory(plain)),
    ])
    assert _import(run, "--connector", "a=sealed-otlp", "--connector", "b=plain") == 0
    got = [event for batch in wanting.batches for event in batch.events]
    assert len(got) == 4
    reader = SQLiteEventReader(run["db"])
    reader.open()
    try:
        stored = {(row.event["run_id"], row.event["order"]): row.seal for row in reader.sealed_rows()}
    finally:
        reader.close()
    for event in got:
        seal = stored[(event["run_id"], event["order"])]
        assert event["seal"] == {"seq": seal.seq, "prev": seal.prev, "digest": seal.digest}
    plain_events = [event for batch in plain.batches for event in batch.events]
    assert len(plain_events) == 4 and all("seal" not in event for event in plain_events)


def test_seal_wanting_connector_without_a_store_gets_events_as_before(
    run: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    wanting = SealWanting()
    monkeypatch.setattr(connectors, "_entry_points", lambda: [
        FakeEntry("sealed-otlp", connector_factory(wanting))
    ])
    assert cli.main(["import-logs", "--dir", str(run["logs"]), "--trace", str(run["trace"]),
                     "--once", "--quiet", "--connector", "a=sealed-otlp"]) == 0
    events = [event for batch in wanting.batches for event in batch.events]
    assert len(events) == 4 and all("seal" not in event for event in events)


def test_seals_also_come_from_the_built_in_database(run: dict[str, Path],
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    wanting = SealWanting()
    monkeypatch.setattr(connectors, "_entry_points", lambda: [
        FakeEntry("sealed-otlp", connector_factory(wanting))
    ])
    database = run["db"]
    assert cli.main(["import-logs", "--dir", str(run["logs"]), "--trace", str(run["trace"]),
                     "--once", "--quiet", "--database", str(database),
                     "--connector", "a=sealed-otlp"]) == 0
    seqs = sorted(event["seal"]["seq"] for b in wanting.batches for event in b.events)
    assert seqs == [1, 2, 3, 4]
    assert isinstance(wanting.batches[0], EventBatch)


# --- the scanner's runtime report --------------------------------------------------------------


def test_runtime_report_shows_a_store_verdict(wrapped: None, run: dict[str, Path],
                                              capsys: Any) -> None:
    from agent_latch import cli as scanner_cli

    assert _import(run) == 0
    capsys.readouterr()
    results = run["logs"] / "gate-results.csv"
    argv = ["--runtime-result", str(results), str(run["logs"]), "--plain",
            "--store", "wrapped", "--store-option", f"path={run['db']}",
            "--database-anchor", str(run["anchor"])]
    assert scanner_cli.main(argv) in (0, 1)
    assert "INTACT" in _out(capsys)

    conn = sqlite3.connect(run["db"], isolation_level=None)
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET stage = 'x' WHERE event_order = 1")
    conn.close()
    assert scanner_cli.main(argv) == 1
    assert "TAMPERED" in _out(capsys)
    assert scanner_cli.main(["--runtime-result", str(results), "--store-option", "a=b"]) == 2
