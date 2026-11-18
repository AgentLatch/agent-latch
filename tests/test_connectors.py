"""Connector configuration, discovery and delivery from ``import-logs`` (no real connector)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent_latch.runtime import cli, connectors
from agent_latch.runtime.connectors import (
    ConnectorConfigError,
    ConnectorDisabled,
    ConnectorRejected,
    ConnectorRunner,
    ConnectorSettings,
    ConnectorUnavailable,
    EventBatch,
    LoadedConnector,
    installed_connectors,
    load_connectors,
    parse_connector_settings,
    resolve_options,
    scrub,
)
from tests.test_runtime_importer import _record_run, _rows

SECRET = "s3cr3t-token-value"


class FakeConnector:
    """A connector that records what it is given. ``write_errors`` are raised one per call."""

    kind = "exporter"
    connector_api = 1
    path: Path | None = None

    def __init__(self, write_errors: list[Exception] | None = None) -> None:
        self.accepts_payloads = False
        self.batches: list[EventBatch] = []
        self.opened = False
        self.closed = 0
        self.write_errors = list(write_errors or [])
        self.open_error: Exception | None = None

    def open(self) -> None:
        if self.open_error is not None:
            raise self.open_error
        self.opened = True

    def write(self, batch: EventBatch, /) -> int:
        if self.write_errors:
            raise self.write_errors.pop(0)
        self.batches.append(batch)
        return len(batch.events)

    def close(self) -> None:
        self.closed += 1


class FakeEntry:
    """Stands in for an entry point. ``load`` records that the package was imported."""

    def __init__(self, name: str, factory: Any = None, *, package: str = "fake-pkg",
                 version: str = "1.2.0", load_error: Exception | None = None) -> None:
        self.name = name
        self.value = f"{package.replace('-', '_')}:create"
        self.dist = SimpleNamespace(name=package, version=version)
        self._factory, self._load_error = factory, load_error
        self.loaded = False

    def load(self) -> Any:
        self.loaded = True
        if self._load_error is not None:
            raise self._load_error
        return self._factory


def _install(monkeypatch: pytest.MonkeyPatch, *entries: FakeEntry) -> None:
    monkeypatch.setattr(connectors, "_entry_points", lambda: list(entries))


def _factory_for(connector: FakeConnector, seen: list[Any] | None = None) -> Any:
    def create(options: Any, context: Any) -> FakeConnector:
        if seen is not None:
            seen.append((dict(options), context))
        return connector

    return create


# --- selection and settings ------------------------------------------------------------------


def test_connector_name_defaults_to_type_and_options_attach_by_name() -> None:
    found = parse_connector_settings(
        ["otel", "pg=postgres"], ["pg.dsn=env:PG", "otel.endpoint=x", "pg.table=events"]
    )
    assert [(c.name, c.type) for c in found] == [("otel", "otel"), ("pg", "postgres")]
    assert found[1].options == {"dsn": "env:PG", "table": "events"}


def test_two_instances_of_one_type() -> None:
    found = parse_connector_settings(["a=webhook", "b=webhook"], ["a.url=u1", "b.url=u2"])
    assert [(c.name, c.options["url"]) for c in found] == [("a", "u1"), ("b", "u2")]


def test_config_file_selects_connectors_and_command_line_overrides_it(tmp_path: Path) -> None:
    config = tmp_path / "connectors.toml"
    config.write_text(
        '[connectors.pg]\ntype = "postgres"\ntable = "from_file"\npayloads = true\nretries = 3\n'
    )
    found = parse_connector_settings([], ["pg.table=from_cli"], config)
    assert len(found) == 1 and found[0].type == "postgres"
    assert found[0].options == {"table": "from_cli", "payloads": "true", "retries": "3"}


@pytest.mark.parametrize(
    ("selections", "options", "message"),
    [
        ([""], [], "--connector #1: expected [NAME=]TYPE"),
        (["pg="], [], "--connector #1: expected [NAME=]TYPE"),
        (["bad name=x"], [], "is not valid"),
        (["pg=postgres"], ["pg.dsn"], "--connector-option #1: expected NAME.KEY=VALUE"),
        (["pg=postgres"], ["dsn=value"], "expected NAME.KEY=VALUE"),
        (["pg=postgres"], ["other.dsn=value"], "no connector named 'other'"),
        ([], ["pg.dsn=value"], "no connector named 'pg'"),
    ],
)
def test_invalid_selection_and_options_are_explained(
    selections: list[str], options: list[str], message: str
) -> None:
    with pytest.raises(ConnectorConfigError, match=message.replace("[", r"\[").replace("]", r"\]")):
        parse_connector_settings(selections, options)


def test_an_empty_config_file_selects_nothing(tmp_path: Path) -> None:
    empty = tmp_path / "empty.toml"
    empty.write_text("")
    with pytest.raises(ConnectorConfigError, match="no connector is selected"):
        parse_connector_settings([], [], empty)


def test_option_errors_never_repeat_a_value() -> None:
    with pytest.raises(ConnectorConfigError) as error:
        parse_connector_settings(["pg=postgres"], [f"dsn={SECRET}"])
    assert SECRET not in str(error.value)


def test_config_file_problems_are_actionable(tmp_path: Path) -> None:
    with pytest.raises(ConnectorConfigError, match="no file at"):
        parse_connector_settings([], [], tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[connectors.pg\n")
    with pytest.raises(ConnectorConfigError, match="not valid TOML"):
        parse_connector_settings([], [], bad)
    no_type = tmp_path / "no-type.toml"
    no_type.write_text('[connectors.pg]\ntable = "x"\n')
    with pytest.raises(ConnectorConfigError, match=r"needs type"):
        parse_connector_settings([], [], no_type)


# --- secrets and core options ----------------------------------------------------------------


def test_env_references_are_read_by_the_core_and_remembered_as_secrets() -> None:
    settings = ConnectorSettings("pg", "postgres", {"dsn": "env:PG_DSN", "table": "t"})
    resolved = resolve_options(settings, {"PG_DSN": SECRET})
    assert resolved.options == {"dsn": SECRET, "table": "t"}
    assert resolved.secrets == (SECRET,)


def test_missing_env_variable_names_the_variable_only() -> None:
    settings = ConnectorSettings("pg", "postgres", {"dsn": "env:PG_DSN"})
    with pytest.raises(ConnectorConfigError, match="'PG_DSN', which is not set"):
        resolve_options(settings, {})


def test_core_options_are_consumed_and_validated() -> None:
    settings = ConnectorSettings(
        "x", "t", {"payloads": "true", "max_batch_events": "10", "max_pending_batches": "5",
                   "timeout": "2.5", "table": "t"},
    )
    resolved = resolve_options(settings, {})
    assert resolved.payloads and resolved.max_batch_events == 10 and resolved.max_pending_batches == 5
    assert resolved.options == {"timeout": "2.5", "table": "t"}  # timeout is the connector's to enforce
    for key, value in [("payloads", "maybe"), ("max_batch_events", "0"), ("timeout", "-1"),
                       ("max_pending_batches", "many")]:
        with pytest.raises(ConnectorConfigError, match=key):
            resolve_options(ConnectorSettings("x", "t", {key: value}), {})


def test_scrub_hides_every_secret_value() -> None:
    assert scrub(f"login {SECRET} failed, retry {SECRET}", [SECRET, ""]) == "login *** failed, retry ***"


# --- discovery ------------------------------------------------------------------------------


def test_listing_never_imports_a_connector_package(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = FakeEntry("postgres", _factory_for(FakeConnector()))
    _install(monkeypatch, entry)
    found = installed_connectors()
    assert [(c.type, c.package, c.version) for c in found] == [("postgres", "fake-pkg", "1.2.0")]
    assert not entry.loaded


def test_two_packages_registering_one_type_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeEntry("pg", package="one"), FakeEntry("pg", package="two"))
    with pytest.raises(ConnectorConfigError, match=r"registered by two packages \(one and two\)"):
        installed_connectors()


def test_only_selected_connectors_are_loaded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wanted, other = FakeEntry("a", _factory_for(FakeConnector())), FakeEntry("b", _factory_for(FakeConnector()))
    _install(monkeypatch, wanted, other)
    load_connectors([ConnectorSettings("a", "a")], tmp_path)
    assert wanted.loaded and not other.loaded


def test_unknown_type_lists_what_is_installed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install(monkeypatch, FakeEntry("postgres"), FakeEntry("otel"))
    with pytest.raises(ConnectorConfigError) as error:
        load_connectors([ConnectorSettings("x", "splunk")], tmp_path)
    text = str(error.value)
    assert "no installed connector of type 'splunk'" in text
    assert "installed: otel, postgres" in text and "agent-latch-runtime connectors" in text


def test_no_connectors_installed_says_so(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install(monkeypatch)
    with pytest.raises(ConnectorConfigError, match="installed: none installed"):
        load_connectors([ConnectorSettings("x", "pg")], tmp_path)


def test_a_package_that_will_not_import_is_named(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install(monkeypatch, FakeEntry("pg", package="vendor-pg", load_error=ImportError("no psycopg")))
    with pytest.raises(ConnectorConfigError, match=r"package vendor-pg could not be loaded \(ImportError\)"):
        load_connectors([ConnectorSettings("pg", "pg")], tmp_path)


def test_factory_receives_resolved_options_and_a_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[Any] = []
    connector = FakeConnector()
    _install(monkeypatch, FakeEntry("pg", _factory_for(connector, seen)))
    loaded = load_connectors(
        [ConnectorSettings("main", "pg", {"dsn": "env:DSN", "payloads": "true", "table": "t"})],
        tmp_path,
        {"DSN": SECRET},
    )
    options, context = seen[0]
    assert options == {"dsn": SECRET, "table": "t"}
    assert (context.name, context.log_dir, context.connector_api) == ("main", tmp_path, 1)
    assert connector.accepts_payloads is True  # the operator's setting, applied by the core
    assert loaded[0].secrets == (SECRET,)


def test_factory_config_error_is_shown_without_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def create(options: Any, context: Any) -> FakeConnector:
        raise ConnectorConfigError(f"cannot log in with {options['dsn']}")

    _install(monkeypatch, FakeEntry("pg", create))
    with pytest.raises(ConnectorConfigError) as error:
        load_connectors([ConnectorSettings("pg", "pg", {"dsn": "env:DSN"})], tmp_path, {"DSN": SECRET})
    assert "cannot log in with ***" in str(error.value) and SECRET not in str(error.value)


def test_unexpected_factory_failure_shows_the_type_and_masked_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def create(options: Any, context: Any) -> FakeConnector:
        raise RuntimeError(f"boom {options['dsn']}")

    _install(monkeypatch, FakeEntry("pg", create, package="vendor-pg"))
    with pytest.raises(ConnectorConfigError) as error:
        load_connectors([ConnectorSettings("pg", "pg", {"dsn": "env:DSN"})], tmp_path, {"DSN": SECRET})
    text = str(error.value)
    assert "RuntimeError" in text and "vendor-pg" in text and "dsn=***" in text
    assert SECRET not in text


@pytest.mark.parametrize(("declared", "advice"), [(7, "upgrade AgentLatch"), (0, "upgrade fake-pkg")])
def test_connector_api_outside_the_supported_range_says_which_side_to_upgrade(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, declared: int, advice: str
) -> None:
    connector = FakeConnector()
    connector.connector_api = declared
    _install(monkeypatch, FakeEntry("pg", _factory_for(connector)))
    with pytest.raises(ConnectorConfigError, match=advice):
        load_connectors([ConnectorSettings("pg", "pg")], tmp_path)


# --- delivery from import-logs ---------------------------------------------------------------


def _loaded(connector: FakeConnector, name: str = "fake", **kwargs: Any) -> LoadedConnector:
    return LoadedConnector(name=name, type="fake", connector=connector, **kwargs)


def _run_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connector: FakeConnector, *extra: str,
    secret_env: dict[str, str] | None = None,
) -> int:
    _install(monkeypatch, FakeEntry("fake", _factory_for(connector)))
    for key, value in (secret_env or {}).items():
        monkeypatch.setenv(key, value)
    return cli.main([
        "import-logs", "--dir", str(tmp_path), "--once", "--quiet", "--connector", "fake", *extra,
    ])


def test_events_reach_the_connector_without_payloads_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector()
    assert _run_cli(monkeypatch, tmp_path, connector) == 0
    events = [e for batch in connector.batches for e in batch.events]
    assert len(events) == len(_rows(tmp_path / "events.csv")) > 0
    assert all(e["payload"] is None for e in events)
    assert connector.opened and connector.closed == 1
    batch = connector.batches[0]
    assert batch.schema == "agentlatch.runtime.batch/1" and batch.run_id == events[0]["run_id"]
    assert batch.batch_id == f"{batch.run_id}:{events[0]['order']}-{events[-1]['order']}"
    assert [e["order"] for e in events] == sorted(e["order"] for e in events)


def test_payloads_are_sent_only_when_the_operator_opts_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector()
    code = _run_cli(monkeypatch, tmp_path, connector, "--connector-option", "fake.payloads=true")
    assert code == 0
    events = [e for batch in connector.batches for e in batch.events]
    assert any(e["payload"] is not None for e in events)


def test_batches_are_capped_and_never_mix_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector()
    code = _run_cli(monkeypatch, tmp_path, connector, "--connector-option", "fake.max_batch_events=2")
    assert code == 0
    assert all(len(batch.events) <= 2 for batch in connector.batches) and len(connector.batches) > 1


def test_run_without_connector_flags_never_touches_discovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def explode() -> list[Any]:
        raise AssertionError("entry points must not be read without --connector")

    monkeypatch.setattr(connectors, "_entry_points", explode)
    _record_run(tmp_path)
    db = tmp_path / "events.db"
    code = cli.main(["import-logs", "--dir", str(tmp_path), "--once", "--quiet", "--database", str(db)])
    assert code == 0 and db.is_file()  # the SQLite command line is unchanged


def test_sqlite_and_a_connector_work_together(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector()
    db = tmp_path / "events.db"
    assert _run_cli(monkeypatch, tmp_path, connector, "--database", str(db)) == 0
    assert db.is_file() and connector.batches


def test_connector_config_error_exits_2_before_any_file_is_opened(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _record_run(tmp_path)
    _install(monkeypatch)
    code = cli.main(["import-logs", "--dir", str(tmp_path), "--once", "--connector", "nope"])
    err = capsys.readouterr().err
    assert code == 2 and "connector error:" in err and "no installed connector of type 'nope'" in err
    assert not (tmp_path / "events.csv").exists()


def test_open_failure_with_a_config_error_exits_2_and_hides_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector()
    connector.open_error = ConnectorConfigError(f"permission denied for {SECRET}")
    code = _run_cli(
        monkeypatch, tmp_path, connector, "--connector-option", "fake.dsn=env:DSN",
        secret_env={"DSN": SECRET},
    )
    err = capsys.readouterr().err
    assert code == 2 and "permission denied for ***" in err and SECRET not in err
    assert connector.closed == 1  # closed exactly once even after the error


def test_normal_output_never_shows_option_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector(
        write_errors=[ConnectorUnavailable(f"cannot reach host with {SECRET}")] * 10
    )
    _install(monkeypatch, FakeEntry("fake", _factory_for(connector)))
    monkeypatch.setenv("DSN", SECRET)
    code = cli.main([
        "import-logs", "--dir", str(tmp_path), "--once", "--connector", "fake",
        "--connector-option", "fake.dsn=env:DSN",
    ])
    streams = capsys.readouterr()
    assert code == 2  # still undelivered at the end of --once
    assert SECRET not in streams.out + streams.err + caplog.text


def test_once_exits_2_when_events_were_not_delivered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector(write_errors=[ConnectorUnavailable("server is down")] * 10)
    assert _run_cli(monkeypatch, tmp_path, connector) == 2
    err = capsys.readouterr().err
    assert "undelivered" in err and "run import-logs --once again" in err
    assert "server is down" in caplog.text
    assert (tmp_path / "events.csv").is_file()  # the other outputs were still written


def test_a_rejected_batch_is_saved_privately_and_fails_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector(write_errors=[ConnectorRejected("HTTP 400")])
    assert _run_cli(monkeypatch, tmp_path, connector) == 2
    rejected = tmp_path / "fake.rejected.jsonl"
    assert stat.S_IMODE(os.stat(rejected).st_mode) == 0o600
    saved = json.loads(rejected.read_text().splitlines()[0])
    assert saved["schema"] == "agentlatch.runtime.batch/1" and saved["events"]


def test_a_disabled_connector_stops_alone_and_other_outputs_continue(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector(write_errors=[ConnectorDisabled("license expired on 2026-12-01")])
    assert _run_cli(monkeypatch, tmp_path, connector) == 2
    assert "license expired on 2026-12-01" in caplog.text
    assert "off for the rest of the run" in caplog.text
    assert _rows(tmp_path / "events.csv")


def test_an_unexpected_error_shows_only_the_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector(write_errors=[RuntimeError(f"leaked {SECRET}")])
    assert _run_cli(monkeypatch, tmp_path, connector) == 2
    shown = capsys.readouterr().err + caplog.text
    assert "RuntimeError" in shown and SECRET not in shown


def test_connector_path_must_differ_from_other_outputs(tmp_path: Path) -> None:
    from agent_latch.runtime.importer import RuntimeLogImporter

    connector = FakeConnector()
    connector.path = tmp_path / "events.csv"
    with pytest.raises(ValueError, match="must all be different files"):
        RuntimeLogImporter(
            tmp_path / "trace.jsonl", None, [], events_csv=tmp_path / "events.csv",
            connectors=[_loaded(connector)],
        )


# --- the per-connector runner -----------------------------------------------------------------


def _events(count: int, run_id: str = "r1") -> list[dict[str, Any]]:
    return [{"run_id": run_id, "order": i, "payload": {"secret": "x"}} for i in range(1, count + 1)]


def test_retry_waits_with_backoff_then_sends_the_identical_batch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(connectors.time, "monotonic", lambda: clock["now"])
    connector = FakeConnector(write_errors=[ConnectorUnavailable("down"), ConnectorUnavailable("down")])
    runner = ConnectorRunner(_loaded(connector), tmp_path)
    runner.open()
    for event in _events(3):
        runner.add(event)
    runner.deliver(final=False)  # fails, waits 1 s
    assert not connector.batches and runner.undelivered == 3
    runner.deliver(final=False)  # still inside the wait: not even tried
    assert len(connector.write_errors) == 1
    clock["now"] += 1.0
    runner.deliver(final=False)  # fails again, waits 2 s
    clock["now"] += 1.5
    runner.deliver(final=False)
    assert not connector.batches
    clock["now"] += 1.0
    runner.deliver(final=False)
    assert len(connector.batches) == 1 and runner.undelivered == 0 and runner.delivered == 3
    assert connector.batches[0].batch_id == "r1:1-3"


def test_a_store_that_changes_events_then_fails_cannot_alter_the_retry(tmp_path: Path) -> None:
    class Mutating(FakeConnector):
        def write(self, batch: EventBatch, /) -> int:
            batch.events[0]["order"] = 999  # a bad connector editing what it was given
            raise ConnectorUnavailable("down")

    runner = ConnectorRunner(_loaded(Mutating()), tmp_path)
    runner.open()
    for event in _events(2):
        runner.add(event)
    runner.deliver(final=True)
    assert [e["order"] for e in runner._queue[0].events] == [1, 2]


def test_the_waiting_queue_is_bounded_and_drops_the_oldest(tmp_path: Path) -> None:
    connector = FakeConnector(write_errors=[ConnectorUnavailable("down")] * 20)
    runner = ConnectorRunner(_loaded(connector, max_batch_events=1, max_pending_batches=2), tmp_path)
    runner.open()
    for event in _events(5):
        runner.add(event)
    runner.deliver(final=False)
    assert runner.undelivered == 2 and runner.dropped == 3 and runner.has_problems


def test_open_that_is_unavailable_retries_instead_of_stopping(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clock = {"now": 50.0}
    monkeypatch.setattr(connectors.time, "monotonic", lambda: clock["now"])
    connector = FakeConnector()
    connector.open_error = ConnectorUnavailable("not up yet")
    runner = ConnectorRunner(_loaded(connector), tmp_path)
    runner.open()  # does not raise
    runner.add(_events(1)[0])
    runner.deliver(final=False)
    assert not connector.batches
    connector.open_error = None
    clock["now"] += 2
    runner.deliver(final=False)
    assert connector.opened and len(connector.batches) == 1


def test_a_failing_close_is_a_warning_and_counts_as_a_problem(tmp_path: Path) -> None:
    class BadClose(FakeConnector):
        def close(self) -> None:
            raise RuntimeError(SECRET)

    runner = ConnectorRunner(_loaded(BadClose()), tmp_path)
    runner.open()
    runner.close()
    assert runner.close_failed and runner.has_problems


# --- the connectors command ------------------------------------------------------------------


def test_connectors_command_lists_types_without_loading_them(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    entry = FakeEntry("postgres", package="agentlatch-connector-postgres", version="1.0.0")
    _install(monkeypatch, entry)
    assert cli.main(["connectors"]) == 0
    out = capsys.readouterr().out
    assert "postgres" in out and "agentlatch-connector-postgres 1.0.0" in out and not entry.loaded


def test_connectors_command_with_nothing_installed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch)
    assert cli.main(["connectors"]) == 0
    assert "no connectors installed" in capsys.readouterr().out


def test_connectors_command_reports_a_duplicate_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, FakeEntry("pg", package="a"), FakeEntry("pg", package="b"))
    assert cli.main(["connectors"]) == 2
    assert "registered by two packages" in capsys.readouterr().err


# --- review fixes: dropped, cap order, backoff overflow, rejected file ----------------------


def test_events_arriving_after_a_connector_was_disabled_are_counted_as_dropped(
    tmp_path: Path,
) -> None:
    connector = FakeConnector()
    connector.open_error = RuntimeError("boom")
    runner = ConnectorRunner(_loaded(connector), tmp_path)
    runner.open()  # disables the connector before it gets any event
    for event in _events(3):
        runner.add(event)
    assert runner.dropped == 3 and runner.has_problems


def test_once_fails_when_a_connector_could_not_open_and_received_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _record_run(tmp_path)
    connector = FakeConnector()
    connector.open_error = RuntimeError("boom")
    assert _run_cli(monkeypatch, tmp_path, connector) == 2
    assert not connector.batches


def test_the_pending_limit_applies_after_delivery_not_before(tmp_path: Path) -> None:
    connector = FakeConnector()
    runner = ConnectorRunner(_loaded(connector, max_batch_events=1, max_pending_batches=2), tmp_path)
    runner.open()
    for event in _events(5):
        runner.add(event)
    runner.deliver(final=False)  # a healthy connector gets all five before any limit applies
    assert runner.delivered == 5 and runner.dropped == 0 and len(connector.batches) == 5


def test_backoff_never_overflows_during_a_long_outage(tmp_path: Path) -> None:
    runner = ConnectorRunner(_loaded(FakeConnector()), tmp_path)
    for _ in range(3000):  # far past the point where 2**attempts overflows a float
        runner._schedule_retry(100.0)
    assert runner._next_attempt == 160.0  # capped at 60 seconds


def test_a_rejected_batch_that_cannot_be_saved_stays_queued(tmp_path: Path) -> None:
    (tmp_path / "fake.rejected.jsonl").mkdir()  # not a file, so the append fails
    connector = FakeConnector(write_errors=[ConnectorRejected("HTTP 400")])
    runner = ConnectorRunner(_loaded(connector), tmp_path)
    runner.open()
    for event in _events(3):
        runner.add(event)
    runner.deliver(final=True)  # does not raise
    assert runner.undelivered == 3 and runner.rejected == 0 and runner.has_problems


def test_a_failing_rejection_file_does_not_stop_the_other_connectors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _record_run(tmp_path)
    (tmp_path / "bad.rejected.jsonl").mkdir()
    bad = FakeConnector(write_errors=[ConnectorRejected("HTTP 400")])
    good = FakeConnector()
    _install(monkeypatch, FakeEntry("bad", _factory_for(bad)), FakeEntry("good", _factory_for(good)))
    code = cli.main([
        "import-logs", "--dir", str(tmp_path), "--once", "--quiet",
        "--connector", "bad", "--connector", "good",
    ])
    assert code == 2 and good.batches and not bad.batches
    assert "could not be saved" in caplog.text


def test_the_rejection_file_must_not_be_another_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _record_run(tmp_path)
    _install(monkeypatch, FakeEntry("fake", _factory_for(FakeConnector())))
    code = cli.main([
        "import-logs", "--dir", str(tmp_path), "--once", "--quiet",
        "--events-csv", str(tmp_path / "fake.rejected.jsonl"), "--connector", "fake",
    ])
    assert code == 2 and "must all be different files" in capsys.readouterr().err
