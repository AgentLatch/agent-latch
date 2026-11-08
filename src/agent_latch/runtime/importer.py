"""RuntimeLogImporter: turn runtime trace and payload logs into readable events and gate results.

It tails the proxy's trace file (and, optionally, its payloads file), joins each trace record with
its payload record (``MCPEventNormalizer``), appends one row per event to an events CSV, prints a
one-line summary per event, and hands the same normalized event to every installed gate in turn,
appending one CSV row per gate result as soon as that gate finishes.

It reads only files the proxy has already written, so it runs in parallel with the MCP flow and
can neither delay nor change it. A gate that raises is recorded as an error result and the
remaining gates still run. Restarting is safe: results already in the CSV are not repeated.

With an ``EventWriter`` (for example ``SQLiteEventStore``), every normalized event is also saved
there, one transaction per pass. A save that fails while following is retried on the next pass,
so the store catches up once it is reachable again; a restart catches up from the files.

A store that seals its rows (``ledger/event_seal.py``) is checked before anything is added: a
store that no longer matches its seals or its schema is refused (``StoreTampered``), and nothing is
repaired or re-sealed. With an ``anchor`` the newest seal is also published after saves, and the
store must still match the newest published point. A store found *ahead* of its anchor (a crash
between saving and publishing) is accepted only if every extra row equals the event rebuilt from
the trace and payload files; otherwise it is refused.
"""

from __future__ import annotations

import copy
import csv
import importlib
import json
import logging
import os
import pkgutil
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO

from agent_latch.runtime.ledger.anchor import Anchor, AnchorError, point_for
from agent_latch.runtime.ledger.canonical import dumps
from agent_latch.runtime.ledger.event_seal import (
    SOURCE,
    SealedSource,
    StoreIntegrityError,
    StoreRefused,
    StoreTampered,
    anchor_history_issues,
    changed_message,
    downgrade_issues,
    schema_issues,
    walk_chain,
)
from agent_latch.runtime.ledger.verify import Issue
from agent_latch.runtime.normalizer import (
    PAYLOAD_METHODS,
    EventKey,
    MCPEventNormalizer,
    is_payload_record,
    is_trace_record,
    payload_key,
    run_id_for,
    trace_key,
)
from agent_latch.runtime.trace import summarize_record

log = logging.getLogger("agent_latch.runtime")

CSV_COLUMNS = ("run_id", "order", "gate_id", "result_json")
EVENT_COLUMNS = (
    "run_id", "order", "timestamp", "session_id", "request_id", "server", "method", "stage",
    "name", "outcome", "duration_ms", "output_bytes", "has_payload", "excerpt",
)
# A spreadsheet runs a cell that starts with one of these as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
POLL_INTERVAL_SECONDS = 0.1
# With --anchor, new seals are published at most this often while following, and once at the end.
ANCHOR_INTERVAL_SECONDS = 5.0
# How long a trace record waits for its payload record before moving on without it (follow mode).
PAYLOAD_GRACE_SECONDS = 2.0
_BATCH_LINES = 1000


class Gate(Protocol):
    """Contract implemented by a runtime gate plugin."""

    gate_id: str

    def evaluate(self, event: dict[str, Any], /) -> Mapping[str, Any]: ...


class EventWriter(Protocol):
    """Where normalized events are kept. ``SQLiteEventStore`` is the local one.

    Another destination (a warehouse, or an opt-in trace exporter) implements this same contract.
    ``save`` adds only events whose key is new (saving a key again keeps the first write) and
    returns how many were new; it raises ``OSError`` when the batch was not stored. Only
    ``import-logs`` holds a writer. A store that also seals its rows provides what
    ``event_seal.SealedSource`` asks for, plus ``head()`` and ``as_stored()``, and gets the
    pre-save check and the anchor.
    """

    path: Path | None

    def open(self) -> None: ...

    def save(self, events: list[dict[str, Any]], /) -> int: ...

    def close(self) -> None: ...


class EventReader(Protocol):
    """Read-only view of a store, for agent-facing tools and dashboards. No write methods.

    ``SQLiteEventReader`` opens the file read-only and refuses every statement that is not a read.
    """

    path: Path | None

    def open(self) -> None: ...

    def events(self) -> Iterator[dict[str, Any]]: ...

    def head(self) -> Any: ...

    def close(self) -> None: ...


# The name this contract had before the writer and reader were split.
EventStore = EventWriter


@dataclass(frozen=True)
class GatePlugin:
    gate_id: str
    evaluate: Callable[[dict[str, Any]], Mapping[str, Any]]


def discover_gates() -> list[GatePlugin]:
    """Load gate modules from ``agent_latch.gates`` in deterministic order."""
    package = importlib.import_module("agent_latch.gates")
    package_path = getattr(package, "__path__", None)
    if package_path is None:
        raise ValueError("agent_latch.gates is not a package")

    plugins: list[GatePlugin] = []
    for module_info in sorted(pkgutil.iter_modules(package_path), key=lambda item: item.name):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{package.__name__}.{module_info.name}")
        gate_id = getattr(module, "GATE_ID", None)
        evaluate = getattr(module, "evaluate", None)
        if not isinstance(gate_id, str) or not gate_id.strip() or not callable(evaluate):
            raise ValueError(
                f"gate module {module.__name__} must define non-empty GATE_ID and evaluate(event)"
            )
        plugins.append(GatePlugin(gate_id=gate_id, evaluate=evaluate))

    ids = [plugin.gate_id for plugin in plugins]
    if len(ids) != len(set(ids)):
        raise ValueError("gate plugin GATE_ID values must be unique")
    return plugins


class _LineTail:
    """Reads complete new lines from a file that may still be growing or not exist yet."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.line_no = 0
        self._stream: TextIO | None = None
        self._pending = ""
        self._ready: deque[tuple[int, str]] = deque()

    def read(self, limit: int = _BATCH_LINES) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        while len(out) < limit:
            if self._ready:
                out.append(self._ready.popleft())
            elif not self._fill():
                break
        return out

    def finish(self) -> None:
        """Treat an unterminated last line as complete (one-shot mode only)."""
        if self._pending:
            self.line_no += 1
            self._ready.append((self.line_no, self._pending))
            self._pending = ""

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _fill(self) -> bool:
        if self._stream is None:
            try:
                self._stream = self.path.open("r", encoding="utf-8", newline="")
            except FileNotFoundError:
                return False
        chunk = self._stream.read(64 * 1024)
        if not chunk:
            return False
        parts = (self._pending + chunk).split("\n")
        self._pending = parts.pop()
        for part in parts:
            self.line_no += 1
            self._ready.append((self.line_no, part))
        return True


def _open_private(path: Path) -> TextIO:
    """Open for append and read, creating the file with mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    return os.fdopen(fd, "a+", encoding="utf-8", newline="")


def _parse(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


class RuntimeLogImporter:
    """Joins trace and payload logs into normalized events and runs every gate on each one.

    ``events_csv`` gets one row per event whether or not any gate is installed; ``output_csv``
    gets one row per gate result and is only created when there are gates. ``summary`` (for
    example ``sys.stderr``) gets one line per newly processed event. ``store`` keeps the same
    events; it is optional and local unless that store itself says otherwise.

    ``follow=True`` keeps waiting for appended lines until ``stop()`` is called (or the process is
    interrupted); ``follow=False`` processes what is in the files now and returns.
    """

    def __init__(
        self,
        trace_path: Path,
        output_csv: Path | None,
        gates: Iterable[Gate],
        *,
        payloads_path: Path | None = None,
        events_csv: Path | None = None,
        normalized_path: Path | None = None,
        summary: TextIO | None = None,
        store: EventWriter | None = None,
        anchor: Anchor | None = None,
        run_id: str | None = None,
        follow: bool = True,
        poll_interval: float = POLL_INTERVAL_SECONDS,
        payload_grace: float = PAYLOAD_GRACE_SECONDS,
    ) -> None:
        """Set up the importer. ``store`` and ``anchor`` are optional, and an anchor needs a
        store.
        """
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        if anchor is not None and store is None:
            raise ValueError("an anchor needs a store: give --database with --anchor")
        store_path = store.path if store is not None else None
        anchor_path = anchor.path if anchor is not None else None
        paths = [
            p for p in (
                trace_path, payloads_path, output_csv, events_csv, normalized_path, store_path,
                anchor_path,
            ) if p
        ]
        if len({p.resolve() for p in paths}) != len(paths):
            raise ValueError("trace, payloads and output files must all be different files")
        self.trace_path = trace_path
        self.payloads_path = payloads_path
        self.output_csv = output_csv
        self.events_csv = events_csv
        self.normalized_path = normalized_path
        self.summary = summary
        self.store = store
        self.anchor = anchor
        self.gates = list(gates)
        self.follow = follow
        self.poll_interval = poll_interval
        self.payload_grace = payload_grace
        self._run_id = run_id
        self._stop = threading.Event()
        self._trace = _LineTail(trace_path)
        self._payloads = _LineTail(payloads_path) if payloads_path else None
        self._pending: deque[tuple[int, dict[str, Any], float]] = deque()
        self._queues: dict[EventKey, deque[tuple[int, dict[str, Any]]]] = {}
        self._normalizer: MCPEventNormalizer | None = None
        self._csv: TextIO | None = None
        self._writer: csv.DictWriter[str] | None = None
        self._events: TextIO | None = None
        self._events_writer: csv.DictWriter[str] | None = None
        self._normalized: TextIO | None = None
        self._done: set[tuple[str, ...]] = set()
        self._events_done: set[tuple[str, ...]] = set()
        self._normalized_done: set[tuple[str, str]] = set()
        self._unsaved: list[dict[str, Any]] = []  # events waiting for the store
        self._store_failing = False
        # Rows found past the newest anchor, by (run_id, order): each must equal the event rebuilt
        # from the logs before the store is extended or anchored again.
        self._tail: dict[tuple[str, int], dict[str, Any]] = {}
        self._dirty = False  # new seals not yet published
        self._last_publish = 0.0
        # The seal of every row this importer saved since it last published, by number. A row
        # saved but not yet anchored is covered by no anchor point, so the importer itself
        # remembers it and checks it again before it saves or publishes anything newer.
        self._saved_seals: dict[int, str] = {}

    def stop(self) -> None:
        """Ask a following importer to finish its current pass and return."""
        self._stop.set()

    def run(self) -> None:
        """Follow or process the logs, saving events and publishing anchors, and always close the
        outputs.
        """
        try:
            self._open_outputs()
            if not (
                self.gates or self.events_csv or self.normalized_path or self.summary or self.store
            ):
                log.warning("agent-latch-runtime: no gates and no outputs; nothing will be written")
            while not self._stop.is_set():
                progressed = self._ingest()
                progressed = self._drain(final=False) or progressed
                self._save_events(final=False)
                if progressed:
                    continue
                if not self.follow:
                    break
                if not self._pending and not self._unsaved:
                    self._require_tail_matched()  # every log line has been read by now
                    self._publish(force=False)  # retry a publish the interval skipped
                self._stop.wait(self.poll_interval)
            if self.follow:
                self._ingest()
                self._drain(final=False)
                self._save_events(final=False)
                if self._unsaved:
                    log.warning(
                        "agent-latch-runtime: %d event(s) not saved to the database; they will be"
                        " saved on the next run",
                        len(self._unsaved),
                    )
                self._publish(force=True)
            else:
                self._finish()
                self._publish(force=True)
        except KeyboardInterrupt:
            self._publish_after_interrupt()
            raise
        finally:
            self._close()

    def _finish(self) -> None:
        """Read what is left in the files, then do the last drain and the last store save."""
        self._trace.finish()
        if self._payloads is not None:
            self._payloads.finish()
        while self._ingest():
            pass
        self._drain(final=True)
        self._save_events(final=True)
        self._require_tail_matched()
        unmatched = sum(len(queue) for queue in self._queues.values())
        if unmatched:
            log.warning("agent-latch-runtime: %d payload record(s) had no trace record", unmatched)

    def _open_outputs(self) -> None:
        """Open the store first (refusing a changed one), then the CSV and JSONL outputs."""
        if self.store is not None:
            self._refuse_lowered_version()  # before open: opening an old file migrates it
            self.store.open()  # first, so a bad database leaves no other file open
            self._audit_store()
        if self.events_csv is not None:
            self._events = _open_private(self.events_csv)
            self._events_writer, self._events_done = _csv_writer(
                self._events, EVENT_COLUMNS, ("run_id", "order")
            )
        if self.gates and self.output_csv is not None:
            self._csv = _open_private(self.output_csv)
            self._writer, self._done = _csv_writer(
                self._csv, CSV_COLUMNS, ("run_id", "order", "gate_id")
            )
        if self.normalized_path is not None:
            self._normalized = _open_private(self.normalized_path)
            self._normalized_done = _existing_events(self._normalized)

    def _close(self) -> None:
        self._trace.close()
        if self._payloads is not None:
            self._payloads.close()
        for stream in (self._csv, self._events, self._normalized):
            if stream is not None:
                stream.close()
        self._csv = self._events = self._normalized = None
        self._writer = self._events_writer = None
        if self.store is not None:
            self.store.close()

    def _save_events(self, *, final: bool) -> None:
        """Save waiting events in one store transaction; keep them for a retry if that fails."""
        if self.store is None or not self._unsaved:
            return
        self._match_tail(self._unsaved)
        self._refuse_if_saved_rows_changed()  # before the next save chains onto them
        before = self._head_seq()
        try:
            inserted = self.store.save(self._unsaved)
        except OSError as error:
            if final:
                raise
            if not self._store_failing:
                log.warning("agent-latch-runtime: %s; retrying", error)
                self._store_failing = True
            return
        if inserted:
            self._dirty = True
            self._remember_saved_seals(before)
        if self._store_failing:
            log.warning(
                "agent-latch-runtime: database reachable again; saved %d waiting event(s)",
                len(self._unsaved),
            )
            self._store_failing = False
        self._unsaved = []
        self._publish(force=False)

    def _refuse_lowered_version(self) -> None:
        """Refuse before the store is opened when its anchor is unreadable or its version was lowered.

        Opening an older file runs the migrations, and migration 3 would seal every row it finds,
        including rows an attacker changed after lowering the version. So these checks come first,
        and an anchor that cannot be read stops the import before the file is touched at all.
        """
        store, anchor = self.store, self.anchor
        if store is None or anchor is None:
            return
        try:
            point = anchor.latest()
        except (AnchorError, OSError) as error:
            raise StoreRefused(f"the anchor {anchor.path} cannot be read: {error}") from error
        stored_version = getattr(store, "stored_version", None)
        if stored_version is None:
            return
        issues = downgrade_issues(stored_version(), point)
        if issues:
            raise StoreTampered(changed_message(issues))

    def _audit_store(self) -> None:
        """Refuse a store that no longer matches its seals, schema or anchor. Writes nothing."""
        store = self.store
        if store is None or not isinstance(store, SealedSource):
            return  # a store that does not seal its rows has nothing to check
        points: list[Any] = []
        if self.anchor is not None:
            try:
                every = getattr(self.anchor, "points", None)
                latest = self.anchor.latest()
                points = list(every()) if every is not None else ([latest] if latest else [])
            except (AnchorError, OSError) as error:
                raise StoreRefused(f"the anchor {self.anchor.path} cannot be read: {error}") from error
            if any(each.source != SOURCE for each in points):
                raise StoreRefused(
                    f"the anchor {self.anchor.path} belongs to a trace ledger; use a separate"
                    " anchor file for the event store"
                )
        point = points[-1] if points else None
        chain = walk_chain(store.sealed_rows(), track_seqs=[each.seq for each in points])
        issues = [*chain.issues, *schema_issues(store, point)]
        issues += anchor_history_issues(points, chain)  # every point ever published, not just the last
        if issues:
            raise StoreTampered(changed_message(issues))
        if self.anchor is not None and chain.head is not None and point is None:
            raise StoreRefused(
                f"the anchor {self.anchor.path} is missing or empty, but the event store already"
                " holds sealed rows, which looks the same as a deleted anchor. Nothing was added."
                " If an anchor existed, restore it or investigate before anything else. Only if"
                " this store was never anchored, run"
                " `agent-latch-runtime anchor --database FILE --to PATH` once"
            )
        if point is not None and chain.head is not None and chain.head.seq > point.seq:
            # A crash between saving and publishing leaves rows past the anchor. They are kept
            # only if the logs rebuild exactly the same events.
            for row in store.sealed_rows():
                if row.seal is not None and row.seal.seq > point.seq:
                    key = (str(row.event["run_id"]), int(row.event["order"]))
                    self._tail[key] = row.event
                    # Not covered by any anchor point yet, so re-check it before anything newer
                    # chains onto it or a point is published over it.
                    self._saved_seals[row.seal.seq] = row.seal.digest

    def _match_tail(self, events: list[dict[str, Any]]) -> None:
        """Check events against the rows found past the anchor; a difference means tampering."""
        if not self._tail or self.store is None:
            return
        as_stored = self.store.as_stored  # type: ignore[attr-defined]
        for event in events:
            key = (str(event["run_id"]), int(event["order"]))
            stored = self._tail.get(key)
            if stored is None:
                continue
            if dumps(as_stored(event)) != dumps(stored):
                raise StoreTampered(
                    changed_message([])
                    + f" (the row for run {key[0]} event {key[1]} past the anchor differs from"
                    " what the trace and payload files rebuild)"
                )
            del self._tail[key]
            if not self._tail:
                self._dirty = True  # the extra rows are now vouched for; anchor them

    def _require_tail_matched(self) -> None:
        """Raise when rows past the anchor have no matching trace record after every log line was
        read.
        """
        if self._tail:
            raise StoreTampered(
                changed_message([])
                + f" ({len(self._tail)} row(s) past the anchor have no matching trace record)"
            )

    def _publish(self, *, force: bool) -> None:
        """Publish the newest seal when there are new ones, at most every few seconds."""
        if self.anchor is None or self.store is None or not self._dirty or self._tail:
            return
        if not force and time.monotonic() - self._last_publish < ANCHOR_INTERVAL_SECONDS:
            return
        store = self.store
        head = store.head()  # type: ignore[attr-defined]
        if head is None:
            return
        self._refuse_if_saved_rows_changed()
        self._refuse_if_rewritten_since_last_point()
        point = point_for(
            store.path or Path("events"),
            seq=head.seq,
            digest=head.digest,
            records=head.seq,
            source=SOURCE,
            schema_sha256=store.schema_sha256(),  # type: ignore[attr-defined]
            schema_version=store.schema_version(),  # type: ignore[attr-defined]
        )
        self.anchor.publish(point)
        self._saved_seals.clear()  # every row saved so far is now covered by an anchor point
        self._dirty = False
        self._last_publish = time.monotonic()

    def _head_seq(self) -> int:
        """The newest seal number in the store, or 0 (a store that does not seal has none)."""
        head = getattr(self.store, "head", None)
        seal = head() if head is not None else None
        return 0 if seal is None else int(seal.seq)

    def _remember_saved_seals(self, before: int) -> None:
        """Record the seals the save just added, so they can be checked again before publishing."""
        seals_after = getattr(self.store, "seals_after", None)
        if self.anchor is not None and seals_after is not None:  # no anchor: nothing to protect
            self._saved_seals.update(seals_after(before))

    def _refuse_if_saved_rows_changed(self) -> None:
        """Refuse when a row this importer saved, and has not published yet, has been changed.

        These rows sit after the newest anchor point, so no point covers them. Without this check,
        someone could rewrite and reseal one of them from the genuine digest before it, and the next
        genuine event would chain onto the forgery and be published.
        """
        digest_at = getattr(self.store, "seal_digest_at", None)
        if digest_at is None:
            return
        for seq, digest in self._saved_seals.items():
            if digest_at(seq) != digest:
                raise StoreTampered(
                    changed_message(
                        [
                            Issue(
                                "edited",
                                seq,
                                "this row was saved by this run and changed before it was anchored",
                            )
                        ]
                    )
                )

    def _refuse_if_rewritten_since_last_point(self) -> None:
        """Never publish a head that sits on a chain which no longer matches the newest point.

        The store is audited when the importer starts. If an anchored row is rewritten and resealed
        while it runs, the next genuine event would chain onto the forgery, and publishing that
        head would make the forgery the newest anchor. So the point published last is checked
        against the store again, just before a new one is written. (A rewrite after this check is
        still caught later, because ``verify`` holds the store to every point, not only the last.)
        """
        digest_at = getattr(self.store, "seal_digest_at", None)
        if self.anchor is None or digest_at is None:
            return
        try:
            latest = self.anchor.latest()
        except (AnchorError, OSError) as error:
            raise StoreRefused(f"the anchor {self.anchor.path} cannot be read: {error}") from error
        if latest is None or latest.source != SOURCE:
            return
        if digest_at(latest.seq) != latest.digest:
            raise StoreTampered(
                changed_message(
                    [
                        Issue(
                            "rewritten",
                            latest.seq,
                            f"record #{latest.seq} no longer matches the anchor point published"
                            f" at {latest.timestamp}; nothing newer was published",
                        )
                    ]
                )
            )

    def _publish_after_interrupt(self) -> None:
        """Ctrl+C while following: save what is waiting and publish, so a restart starts clean."""
        try:
            self._save_events(final=False)
            self._publish(force=True)
        except StoreIntegrityError:
            raise  # a changed store is never a clean exit: the CLI reports it with exit 1
        except (OSError, RuntimeError) as error:
            log.warning("agent-latch-runtime: could not publish the anchor on exit: %s", error)

    def _ingest(self) -> bool:
        progressed = False
        for line_no, text in self._trace.read():
            progressed = True
            record = _parse(text)
            if not is_trace_record(record):
                if text.strip():
                    log.warning("agent-latch-runtime: skipping trace line %d (not a record)", line_no)
                continue
            if self._normalizer is None:
                self._run_id = self._run_id or run_id_for(text)
                self._normalizer = MCPEventNormalizer(
                    self._run_id,
                    trace_name=self.trace_path.name,
                    payloads_name=self.payloads_path.name if self.payloads_path else None,
                )
            self._pending.append((line_no, record, time.monotonic()))
        if self._payloads is not None:
            for line_no, text in self._payloads.read():
                progressed = True
                record = _parse(text)
                if not is_payload_record(record):
                    if text.strip():
                        log.warning(
                            "agent-latch-runtime: skipping payload line %d (not a record)", line_no
                        )
                    continue
                self._queues.setdefault(payload_key(record), deque()).append((line_no, record))
        return progressed

    def _drain(self, *, final: bool) -> bool:
        progressed = False
        while self._pending:
            line_no, trace, arrived = self._pending[0]
            payload_line, payload = None, None
            if self._payloads is not None and trace["method"] in PAYLOAD_METHODS:
                key = trace_key(trace)
                queue = self._queues.get(key)
                if queue:
                    payload_line, payload = queue.popleft()
                    if not queue:
                        del self._queues[key]
                elif not final and not (
                    self.follow and time.monotonic() - arrived > self.payload_grace
                ):
                    break
            self._pending.popleft()
            self._emit(line_no, trace, payload_line, payload)
            progressed = True
        return progressed

    def _emit(
        self,
        line_no: int,
        trace: dict[str, Any],
        payload_line: int | None,
        payload: dict[str, Any] | None,
    ) -> None:
        assert self._normalizer is not None
        event = self._normalizer.normalize(
            trace_line=line_no, trace=trace, payload_line=payload_line, payload=payload
        )
        run_id, order = event["run_id"], str(event["order"])
        # Only events new to some output are summarized, so a restart does not repeat old lines.
        fresh = not (self._events or self._csv or self._normalized)
        if self._normalized is not None and (run_id, order) not in self._normalized_done:
            self._normalized.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._normalized.flush()
            fresh = True
        if (
            self._events is not None
            and self._events_writer is not None
            and (run_id, order) not in self._events_done
        ):
            self._events_writer.writerow(_event_row(event))
            self._events.flush()
            fresh = True
        if self.store is not None:
            self._unsaved.append(copy.deepcopy(event))  # saved at the end of this pass
        findings = errors = 0
        if self._csv is not None and self._writer is not None:
            for gate in self.gates:
                if (run_id, order, gate.gate_id) in self._done:
                    continue
                result = _evaluate(gate, event)
                findings += len(result["findings"])
                errors += result["status"] == "error"
                self._writer.writerow({
                    "run_id": run_id,
                    "order": order,
                    "gate_id": gate.gate_id,
                    "result_json": json.dumps(result, ensure_ascii=False, separators=(",", ":")),
                })
                self._csv.flush()
                fresh = True
        if self.summary is not None and fresh:
            line = f"#{order} {event['server']}: {summarize_record(trace)}"
            if event["payload"] is not None:
                line += " [payload]"
            if self._csv is not None:
                line += f" | gates: {findings} finding(s)"
                if errors:
                    line += f", {errors} error(s)"
            self.summary.write(f"agent-latch-runtime: {line}\n")
            self.summary.flush()


def _csv_writer(
    output: TextIO, columns: tuple[str, ...], key: tuple[str, ...]
) -> tuple[csv.DictWriter[str], set[tuple[str, ...]]]:
    """Writer appending to ``output`` (header written if empty) and the keys already in it."""
    output.seek(0)
    if not output.readline():
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        output.flush()
        return writer, set()
    output.seek(0)
    reader = csv.DictReader(output)
    if tuple(reader.fieldnames or ()) != columns:
        raise ValueError(
            f"CSV header must be {','.join(columns)}; found {','.join(reader.fieldnames or ())}"
        )
    done = {tuple(row[field] for field in key) for row in reader}
    output.seek(0, 2)
    return csv.DictWriter(output, fieldnames=columns), done


def _cell(value: Any) -> str:
    """CSV cell text; values from MCP traffic must not run as spreadsheet formulas."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def _event_row(event: Mapping[str, Any]) -> dict[str, str]:
    meta = event["metadata"]
    stage = event["stage"]
    if stage == "error":
        outcome = f"error ({meta.get('error_type')})" if meta.get("error_type") else "error"
    elif meta.get("is_error") is True:
        outcome = "error result"
    elif stage == "response":
        outcome = "ok"
    else:
        outcome = ""
    return {
        "run_id": _cell(event["run_id"]),
        "order": _cell(event["order"]),
        "timestamp": _cell(event["timestamp"]),
        "session_id": _cell(event["session_id"]),
        "request_id": _cell(event["request_id"]),
        "server": _cell(event["server"]),
        "method": _cell(event["method"]),
        "stage": _cell(stage),
        "name": _cell(event["name"]),
        "outcome": outcome,
        "duration_ms": _cell(meta.get("duration_ms")),
        "output_bytes": _cell(meta.get("output_bytes")),
        "has_payload": "yes" if event["payload"] is not None else "no",
        "excerpt": _cell(meta.get("excerpt")),
    }


def _existing_events(stream: TextIO) -> set[tuple[str, str]]:
    stream.seek(0)
    seen: set[tuple[str, str]] = set()
    for line in stream:
        record = _parse(line)
        if isinstance(record, dict) and "run_id" in record and "order" in record:
            seen.add((str(record["run_id"]), str(record["order"])))
    stream.seek(0, 2)
    return seen


def _evaluate(gate: Gate, event: dict[str, Any]) -> dict[str, Any]:
    try:
        gate_result = gate.evaluate(copy.deepcopy(event))
        if not isinstance(gate_result, Mapping):
            raise TypeError("evaluate(event) must return a JSON object")
        findings = gate_result.get("findings")
        if not isinstance(findings, list):
            raise TypeError("evaluate(event) result must contain a findings list")
        result: dict[str, Any] = {
            "gate_id": gate.gate_id,
            "status": "ok",
            "findings": findings,
            "error": None,
        }
        return json.loads(json.dumps(result, ensure_ascii=False, allow_nan=False))
    except Exception as error:  # noqa: BLE001 - one gate failure must not stop later gates
        log.warning(
            "agent-latch-runtime: gate %r failed (%s)", gate.gate_id, type(error).__name__
        )
        return {
            "gate_id": gate.gate_id,
            "status": "error",
            "findings": [],
            "error": {"type": type(error).__name__},
        }
