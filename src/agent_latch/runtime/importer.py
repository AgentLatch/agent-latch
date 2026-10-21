"""RuntimeLogImporter: turn runtime trace and payload logs into gate results.

It tails the proxy's trace file (and, optionally, its payloads file), joins each trace record with
its payload record (``MCPEventNormalizer``), hands the same normalized event to every gate in
turn, and appends one CSV row per gate result as soon as that gate finishes.

It reads only files the proxy has already written, so it runs in parallel with the MCP flow and
can neither delay nor change it. A gate that raises is recorded as an error result and the
remaining gates still run. Restarting is safe: results already in the CSV are not repeated.
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
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO

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

log = logging.getLogger("agent_latch.runtime")

CSV_COLUMNS = ("run_id", "order", "gate_id", "result_json")
POLL_INTERVAL_SECONDS = 0.1
# How long a trace record waits for its payload record before moving on without it (follow mode).
PAYLOAD_GRACE_SECONDS = 2.0
_BATCH_LINES = 1000


class Gate(Protocol):
    """Contract implemented by a runtime gate plugin."""

    gate_id: str

    def evaluate(self, event: dict[str, Any], /) -> Mapping[str, Any]: ...


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

    ``follow=True`` keeps waiting for appended lines until ``stop()`` is called (or the process is
    interrupted); ``follow=False`` processes what is in the files now and returns.
    """

    def __init__(
        self,
        trace_path: Path,
        output_csv: Path,
        gates: Iterable[Gate],
        *,
        payloads_path: Path | None = None,
        normalized_path: Path | None = None,
        run_id: str | None = None,
        follow: bool = True,
        poll_interval: float = POLL_INTERVAL_SECONDS,
        payload_grace: float = PAYLOAD_GRACE_SECONDS,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        paths = [p for p in (trace_path, payloads_path, output_csv, normalized_path) if p]
        if len({p.resolve() for p in paths}) != len(paths):
            raise ValueError("trace, payloads and output files must all be different files")
        self.trace_path = trace_path
        self.payloads_path = payloads_path
        self.output_csv = output_csv
        self.normalized_path = normalized_path
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
        self._normalized: TextIO | None = None
        self._done: set[tuple[str, str, str]] = set()
        self._normalized_done: set[tuple[str, str]] = set()

    def stop(self) -> None:
        """Ask a following importer to finish its current pass and return."""
        self._stop.set()

    def run(self) -> None:
        self._open_outputs()
        if not self.gates:
            log.warning("agent-latch-runtime: no gates are installed; events will produce no rows")
        try:
            while not self._stop.is_set():
                progressed = self._ingest()
                progressed = self._drain(final=False) or progressed
                if progressed:
                    continue
                if not self.follow:
                    break
                self._stop.wait(self.poll_interval)
            if self.follow:
                self._ingest()
                self._drain(final=False)
            else:
                self._finish()
        finally:
            self._close()

    def _finish(self) -> None:
        self._trace.finish()
        if self._payloads is not None:
            self._payloads.finish()
        while self._ingest():
            pass
        self._drain(final=True)
        unmatched = sum(len(queue) for queue in self._queues.values())
        if unmatched:
            log.warning("agent-latch-runtime: %d payload record(s) had no trace record", unmatched)

    def _open_outputs(self) -> None:
        self._csv = _open_private(self.output_csv)
        self._writer = self._csv_writer(self._csv)
        if self.normalized_path is not None:
            self._normalized = _open_private(self.normalized_path)
            self._normalized_done = _existing_events(self._normalized)

    def _csv_writer(self, output: TextIO) -> csv.DictWriter[str]:
        output.seek(0)
        if not output.readline():
            writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            output.flush()
            return writer
        output.seek(0)
        reader = csv.DictReader(output)
        if tuple(reader.fieldnames or ()) != CSV_COLUMNS:
            raise ValueError(
                f"CSV header must be {','.join(CSV_COLUMNS)};"
                f" found {','.join(reader.fieldnames or ())}"
            )
        self._done = {(r["run_id"], r["order"], r["gate_id"]) for r in reader}
        output.seek(0, 2)
        return csv.DictWriter(output, fieldnames=CSV_COLUMNS)

    def _close(self) -> None:
        self._trace.close()
        if self._payloads is not None:
            self._payloads.close()
        for stream in (self._csv, self._normalized):
            if stream is not None:
                stream.close()
        self._csv = self._normalized = self._writer = None

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
        assert self._normalizer is not None and self._writer is not None and self._csv is not None
        event = self._normalizer.normalize(
            trace_line=line_no, trace=trace, payload_line=payload_line, payload=payload
        )
        run_id, order = event["run_id"], str(event["order"])
        if self._normalized is not None and (run_id, order) not in self._normalized_done:
            self._normalized.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._normalized.flush()
        for gate in self.gates:
            if (run_id, order, gate.gate_id) in self._done:
                continue
            result = _evaluate(gate, event)
            self._writer.writerow({
                "run_id": run_id,
                "order": order,
                "gate_id": gate.gate_id,
                "result_json": json.dumps(result, ensure_ascii=False, separators=(",", ":")),
            })
            self._csv.flush()


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
