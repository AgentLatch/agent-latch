"""Local SQLite storage for normalized MCP events (standard library only).

Each event is one row in ``events``, keyed by ``(run_id, event_order)``: the same pair the importer
uses to avoid repeats, so importing again or restarting never stores an event twice. ``metadata``
and ``payload`` are kept as JSON text, so a stored event reads back exactly as it was imported.

The schema is versioned with ``PRAGMA user_version`` and changed only by the numbered migrations in
``MIGRATIONS``, each applied inside one transaction. The database can hold tool arguments and
outputs (from ``--payloads``), so a new file is created with mode 0600 where the platform supports
it. Nothing here uses the network.

Every row is sealed when it is saved (see ``ledger/event_seal.py``): three plain columns,
``seal_seq``, ``seal_prev`` and ``seal_digest``, computed in Python, never by SQLite. The triggers
from migration 4 only stop careless ``UPDATE`` and ``DELETE`` statements; anyone who can write the
file can drop them, and the seals and the schema check catch that. ``SQLiteEventReader`` opens the
file read-only and refuses every statement that is not a read, so a tool that holds only a reader
cannot change the store even when it runs raw SQL.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_latch.runtime.ledger.canonical import dumps
from agent_latch.runtime.ledger.event_seal import Seal, StoredRow, next_seal

# How long to wait for another connection (for example a viewer) to release the database.
BUSY_TIMEOUT_SECONDS = 30.0

COLUMNS = (
    "run_id", "event_order", "timestamp", "session_id", "request_id", "client_id", "server",
    "method", "stage", "name", "trace_path", "trace_line", "payloads_path", "payloads_line",
    "metadata", "payload", "imported_at",
)
SEAL_COLUMNS = ("seal_seq", "seal_prev", "seal_digest")
_ALL_COLUMNS = (*COLUMNS, *SEAL_COLUMNS)
_INSERT = (
    f"INSERT OR IGNORE INTO events ({', '.join(_ALL_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in _ALL_COLUMNS)})"
)
_SELECT = f"SELECT {', '.join(COLUMNS)} FROM events ORDER BY run_id, event_order"
_SELECT_SEALED = f"SELECT {', '.join(_ALL_COLUMNS)} FROM events ORDER BY seal_seq"
_HEAD = (
    "SELECT seal_seq, seal_prev, seal_digest FROM events WHERE seal_seq IS NOT NULL"
    " ORDER BY seal_seq DESC LIMIT 1"
)
# SQLite authorizer action codes a read-only connection may use: everything else is refused.
_SQLITE_READ, _SQLITE_SELECT, _SQLITE_FUNCTION, _SQLITE_RECURSIVE = 20, 21, 31, 33
_READ_ONLY_ACTIONS = frozenset({_SQLITE_READ, _SQLITE_SELECT, _SQLITE_FUNCTION, _SQLITE_RECURSIVE})
QUERY_ROW_LIMIT = 200


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


def _add_seals(conn: sqlite3.Connection) -> None:
    """Migration 3: the three seal columns, and a seal for every row already stored.

    Older rows are sealed once, in ``(run_id, event_order)`` order, not by rowid (which a VACUUM
    can renumber). That seal vouches for the rows only from now on: it cannot prove they were not
    changed before this upgrade. The triggers come in migration 4, so this UPDATE is allowed.
    """
    conn.execute("ALTER TABLE events ADD COLUMN seal_seq INTEGER")
    conn.execute("ALTER TABLE events ADD COLUMN seal_prev TEXT")
    conn.execute("ALTER TABLE events ADD COLUMN seal_digest TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS events_seal_seq ON events (seal_seq)")
    head: Seal | None = None
    updates = []
    for row in conn.execute(f"SELECT {', '.join(COLUMNS)} FROM events ORDER BY run_id, event_order"):
        head = next_seal(head, row_to_event(row), row[-1])
        updates.append((head.seq, head.prev, head.digest, row[0], row[1]))
    conn.executemany(
        "UPDATE events SET seal_seq = ?, seal_prev = ?, seal_digest = ?"
        " WHERE run_id = ? AND event_order = ?",
        updates,
    )


def _add_append_only_triggers(conn: sqlite3.Connection) -> None:
    """Migration 4: abort any UPDATE or DELETE on ``events``.

    A guard against careless or accidental SQL only. Whoever can write the file can drop these;
    the seals and the schema check then report it.
    """
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events"
        " BEGIN SELECT RAISE(ABORT, 'events are append-only: UPDATE is not allowed'); END"
    )
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events"
        " BEGIN SELECT RAISE(ABORT, 'events are append-only: DELETE is not allowed'); END"
    )


# Migration N brings the schema from version N-1 to N. Never edit or reorder a released one:
# change the schema by appending a new function, which raises the version by one.
MIGRATIONS: tuple[Callable[[sqlite3.Connection], None], ...] = (
    _create_events,
    _create_event_log_view,
    _add_seals,
    _add_append_only_triggers,
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


def stored_schema_version(path: Path) -> int | None:
    """The schema version a file says it is at, read without migrating or writing it.

    ``None`` when the file is missing or is not a SQLite database. The version is only a number an
    attacker can lower, so it is never trusted alone: an anchor records the version it was
    published at, and a file that reports less than that has been tampered with.
    """
    try:
        conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def schema_fingerprint(conn: sqlite3.Connection) -> str:
    """SHA-256 of every table, index, view and trigger definition, as SQLite stores it."""
    rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master"
        " WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    return hashlib.sha256(dumps([list(row) for row in rows])).hexdigest()


def expected_schema_sha256() -> str:
    """The fingerprint of a database that went through exactly the current migrations."""
    conn = sqlite3.connect(":memory:", isolation_level=None)
    try:
        migrate(conn)
        return schema_fingerprint(conn)
    finally:
        conn.close()


def _seal_from(values: tuple[Any, ...]) -> Seal | None:
    """A ``Seal`` from the three stored values, or ``None`` when any is missing or mistyped."""
    seq, prev, digest = values
    if isinstance(seq, int) and not isinstance(seq, bool) and isinstance(prev, str) and isinstance(
        digest, str
    ):
        return Seal(seq=seq, prev=prev, digest=digest)
    return None


class _Reading:
    """Read methods shared by the writer and the read-only reader."""

    path: Path

    def _connection(self) -> sqlite3.Connection:
        raise NotImplementedError

    def events(self) -> Iterator[dict[str, Any]]:
        """Every stored event, in (run_id, order) order."""
        for row in self._connection().execute(_SELECT):
            yield row_to_event(row)

    def head(self) -> Seal | None:
        """The newest seal, or None while nothing is stored."""
        row = self._connection().execute(_HEAD).fetchone()
        return None if row is None else _seal_from(tuple(row))

    def sealed_rows(self) -> Iterator[StoredRow]:
        """Every row with its seal, in seal order. An unreadable row is yielded as such."""
        try:
            cursor = self._connection().execute(_SELECT_SEALED)
        except sqlite3.OperationalError:
            return  # the table or a column is gone; the schema check reports it
        for row in cursor:
            values = tuple(row)
            seal = _seal_from(values[len(COLUMNS):])
            try:
                event = row_to_event(values[: len(COLUMNS)])
            except (ValueError, KeyError, TypeError):
                event = {"unreadable_row": [str(values[0]), str(values[1])]}
            yield StoredRow(seal=seal, event=event, imported_at=str(values[len(COLUMNS) - 1]))

    def schema_sha256(self) -> str:
        return schema_fingerprint(self._connection())

    def expected_schema_sha256(self) -> str:
        return expected_schema_sha256()

    def schema_version(self) -> int:
        return len(MIGRATIONS)


class SQLiteEventStore(_Reading):
    """Keeps normalized events in a local SQLite file. Implements the importer's EventWriter."""

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
        """Seal and store events in one transaction, skipping known ones; return how many were new.

        The seals are made inside the same ``BEGIN IMMEDIATE`` transaction as the inserts: the
        newest seal is read once the write lock is held (so a second writer waits instead of
        forking the chain), and a number is given only to a row that is really inserted.
        """
        conn = self._connection()
        imported_at = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        rows = [event_to_row(event, imported_at) for event in events]
        if not rows:
            return 0
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                found = conn.execute(_HEAD).fetchone()
                head = None if found is None else _seal_from(tuple(found))
                inserted = 0
                for row in rows:
                    # Seal what a later read will return, not the caller's object.
                    seal = next_seal(head, row_to_event(row), imported_at)
                    cursor = conn.execute(_INSERT, (*row, seal.seq, seal.prev, seal.digest))
                    if cursor.rowcount == 1:
                        head = seal
                        inserted += 1
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

    def stored_version(self) -> int | None:
        """The schema version the file reports now, read before ``open`` can migrate it."""
        return stored_schema_version(self.path)

    def as_stored(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """The event as a later read returns it, so it can be compared with a stored row."""
        return row_to_event(event_to_row(event, ""))

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("SQLiteEventStore is not open")
        return self._conn


def _read_only_authorizer(
    action: int, arg1: str | None, arg2: str | None, db: str | None, source: str | None
) -> int:
    """SQLite authorizer: allow reads and refuse every other kind of statement."""
    return sqlite3.SQLITE_OK if action in _READ_ONLY_ACTIONS else sqlite3.SQLITE_DENY


class SQLiteEventReader(_Reading):
    """Reads a store without any way to change it. Give this, never the writer, to a tool.

    The connection is opened read-only (``mode=ro``), set to ``query_only``, and guarded by an
    authorizer that refuses every statement except a read, so even a raw SQL query cannot
    ``DELETE``, ``UPDATE``, ``DROP``, ``ALTER``, ``ATTACH`` or change a ``PRAGMA``. It never
    migrates: a database that is not at the current schema version is refused, because only the
    writer (``import-logs``) upgrades and seals one.
    """

    def __init__(self, path: Path, *, timeout: float = BUSY_TIMEOUT_SECONDS) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._conn: sqlite3.Connection | None = None
        # An MCP server runs a sync tool on a worker thread, not the thread that opened the
        # reader, so the connection may cross threads; the lock keeps queries one at a time.
        self._lock = threading.Lock()

    def open(self) -> None:
        """Open the file read-only; refuse a missing, unsealed, newer or foreign database."""
        if not self.path.is_file():
            raise ValueError(f"no event store at {self.path}")
        uri = f"{self.path.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(
            uri, uri=True, timeout=self.timeout, isolation_level=None, check_same_thread=False
        )
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            target = len(MIGRATIONS)
            if version > target:
                raise ValueError(
                    f"database schema version {version} is newer than this AgentLatch supports"
                    f" ({target}); upgrade AgentLatch"
                )
            if version < target:
                raise ValueError(
                    f"{self.path} is at schema version {version}, and this AgentLatch reads"
                    f" version {target}. It is not sealed yet: run import-logs --database once"
                    " to upgrade and seal it"
                )
            conn.execute("PRAGMA query_only = ON")
            conn.set_authorizer(_read_only_authorizer)
        except sqlite3.DatabaseError as error:
            conn.close()
            raise ValueError(
                f"{self.path} is not a usable AgentLatch database ({type(error).__name__}: {error})"
            ) from error
        except BaseException:
            conn.close()
            raise
        self._conn = conn

    def query(self, sql: str, *, limit: int = QUERY_ROW_LIMIT) -> list[dict[str, Any]]:
        """Run one read-only SQL statement and return at most ``limit`` rows as dicts."""
        with self._lock:
            cursor = self._connection().execute(sql)
            names = [column[0] for column in cursor.description or ()]
            return [dict(zip(names, row, strict=True)) for row in cursor.fetchmany(limit)]

    def close(self) -> None:
        """Close the connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _connection(self) -> sqlite3.Connection:
        """The open connection; raises when ``open`` has not been called."""
        if self._conn is None:
            raise RuntimeError("SQLiteEventReader is not open")
        return self._conn


def _create_private(path: Path) -> None:
    """Create the database file with mode 0600 if it does not exist yet (POSIX only)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)
