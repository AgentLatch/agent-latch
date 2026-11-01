"""Local SQLite storage for normalized MCP events (standard library only).

Each event is one row in ``events``, keyed by ``(run_id, event_order)``: the same pair the importer
uses to avoid repeats, so importing again or restarting never stores an event twice. ``metadata``
and ``payload`` are kept as JSON text, so a stored event reads back exactly as it was imported.

The schema is versioned with ``PRAGMA user_version`` and changed only by the numbered migrations in
``MIGRATIONS``, each applied inside one transaction. The database can hold tool arguments and
outputs (from ``--payloads``), so a new file is created with mode 0600 where the platform supports
it. Nothing here uses the network.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# How long to wait for another connection (for example a viewer) to release the database.
BUSY_TIMEOUT_SECONDS = 30.0

COLUMNS = (
    "run_id", "event_order", "timestamp", "session_id", "request_id", "client_id", "server",
    "method", "stage", "name", "trace_path", "trace_line", "payloads_path", "payloads_line",
    "metadata", "payload", "imported_at",
)
_INSERT = (
    f"INSERT OR IGNORE INTO events ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in COLUMNS)})"
)
_SELECT = f"SELECT {', '.join(COLUMNS)} FROM events ORDER BY run_id, event_order"


def _create_events(conn: sqlite3.Connection) -> None:
    """Migration 1: the events table and its indexes."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            run_id         TEXT    NOT NULL,
            event_order    INTEGER NOT NULL,  -- the event's "order" (a reserved word in SQL)
            timestamp      TEXT,
            session_id     TEXT    NOT NULL,
            request_id     TEXT    NOT NULL,
            client_id      TEXT,
            server         TEXT    NOT NULL,
            method         TEXT    NOT NULL,
            stage          TEXT    NOT NULL,
            name           TEXT,
            trace_path     TEXT    NOT NULL,
            trace_line     INTEGER NOT NULL,
            payloads_path  TEXT,              -- NULL when there is no payload record
            payloads_line  INTEGER,
            metadata       TEXT    NOT NULL,  -- JSON
            payload        TEXT,              -- JSON; NULL without --payloads
            imported_at    TEXT    NOT NULL,
            PRIMARY KEY (run_id, event_order)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS events_server_time ON events (server, timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS events_name ON events (name)")


def _create_event_log_view(conn: sqlite3.Connection) -> None:
    """Migration 2: ``event_log``, a readable view of the events (newest first when sorted)."""
    conn.execute(
        """
        CREATE VIEW IF NOT EXISTS event_log AS
        SELECT timestamp                                   AS time,
               server,
               method,
               stage,
               name                                        AS tool_or_prompt,
               client_id,
               json_extract(metadata, '$.is_error')        AS is_error,
               json_extract(metadata, '$.duration_ms')     AS duration_ms,
               json_extract(metadata, '$.excerpt')         AS excerpt,
               payload IS NOT NULL                         AS has_payload,
               run_id,
               event_order
        FROM events
        """
    )


# Migration N brings the schema from version N-1 to N. Never edit or reorder a released one:
# change the schema by appending a new function, which raises the version by one.
MIGRATIONS: tuple[Callable[[sqlite3.Connection], None], ...] = (
    _create_events,
    _create_event_log_view,
)


def migrate(conn: sqlite3.Connection) -> int:
    """Bring the schema up to date in one transaction; return the version it ends at."""
    target = len(MIGRATIONS)
    conn.execute("BEGIN IMMEDIATE")
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > target:
            raise ValueError(
                f"database schema version {version} is newer than this AgentLatch supports"
                f" ({target}); upgrade AgentLatch or use another --database file"
            )
        for step in MIGRATIONS[version:]:
            step(conn)
        if version != target:
            conn.execute(f"PRAGMA user_version = {target:d}")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return target


def event_to_row(event: Mapping[str, Any], imported_at: str) -> tuple[Any, ...]:
    trace = event["trace"]
    payloads = event.get("payloads")
    payload = event.get("payload")
    return (
        event["run_id"], int(event["order"]), event.get("timestamp"), event["session_id"],
        event["request_id"], event.get("client_id"), event["server"], event["method"],
        event["stage"], event.get("name"), trace["path"], trace["line"],
        payloads["path"] if payloads else None, payloads["line"] if payloads else None,
        _to_json(event.get("metadata") or {}), None if payload is None else _to_json(payload),
        imported_at,
    )


def row_to_event(row: tuple[Any, ...]) -> dict[str, Any]:
    """Rebuild the normalized event, with its keys in the normalizer's order."""
    values = dict(zip(COLUMNS, row, strict=True))
    has_payload = values["payloads_path"] is not None
    return {
        "run_id": values["run_id"],
        "order": values["event_order"],
        "timestamp": values["timestamp"],
        "session_id": values["session_id"],
        "request_id": values["request_id"],
        "client_id": values["client_id"],
        "server": values["server"],
        "method": values["method"],
        "stage": values["stage"],
        "name": values["name"],
        "trace": {"path": values["trace_path"], "line": values["trace_line"]},
        "payloads": (
            {"path": values["payloads_path"], "line": values["payloads_line"]}
            if has_payload else None
        ),
        "metadata": json.loads(values["metadata"]),
        "payload": None if values["payload"] is None else json.loads(values["payload"]),
    }


class SQLiteEventStore:
    """Keeps normalized events in a local SQLite file. Implements the importer's EventStore."""

    def __init__(self, path: Path, *, timeout: float = BUSY_TIMEOUT_SECONDS) -> None:
        self.path = path
        self.timeout = timeout
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        _create_private(self.path)
        # Autocommit mode: every transaction below is opened and closed explicitly.
        conn = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        try:
            migrate(conn)
        except sqlite3.DatabaseError as error:
            conn.close()
            raise ValueError(
                f"{self.path} is not a usable AgentLatch database ({type(error).__name__}: {error})"
            ) from error
        except BaseException:
            conn.close()
            raise
        self._conn = conn

    def save(self, events: Iterable[Mapping[str, Any]]) -> int:
        """Store events in one transaction, skipping known ones; return how many were new."""
        conn = self._connection()
        imported_at = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        rows = [event_to_row(event, imported_at) for event in events]
        if not rows:
            return 0
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                before = conn.total_changes
                conn.executemany(_INSERT, rows)
                inserted = conn.total_changes - before
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        except sqlite3.Error as error:
            # OSError, so callers treat it like any other storage failure; the batch is unchanged.
            raise OSError(
                f"could not save events to {self.path} ({type(error).__name__}: {error})"
            ) from error
        return inserted

    def events(self) -> Iterator[dict[str, Any]]:
        """Every stored event, in (run_id, order) order."""
        for row in self._connection().execute(_SELECT):
            yield row_to_event(row)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("SQLiteEventStore is not open")
        return self._conn


def _create_private(path: Path) -> None:
    """Create the database file with mode 0600 if it does not exist yet (POSIX only)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)
