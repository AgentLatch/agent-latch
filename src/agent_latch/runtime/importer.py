"""Import runtime payload events and run installed gate plugins in sequence."""

from __future__ import annotations

import copy
import csv
import importlib
import json
import logging
import os
import pkgutil
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO

from agent_latch.runtime.events import PAYLOAD_SCHEMA

log = logging.getLogger("agent_latch.runtime")

CSV_COLUMNS = ("record_id", "seq", "gate_id", "result_json")
POLL_INTERVAL_SECONDS = 0.1


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
    for module_info in sorted(
        pkgutil.iter_modules(package_path), key=lambda item: item.name
    ):
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


def follow_payloads(
    input_path: Path,
    output_path: Path,
    gates: Iterable[Gate],
    *,
    follow: bool = True,
    poll_interval: float = POLL_INTERVAL_SECONDS,
) -> None:
    """Process complete payload JSONL records, optionally waiting for appended records."""
    if poll_interval <= 0:
        raise ValueError("poll_interval must be greater than zero")
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input payloads and output CSV must be different files")

    gate_list = list(gates)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        output_path,
        os.O_RDWR | os.O_CREAT | os.O_APPEND,
        0o600,
    )
    with os.fdopen(fd, "a+", encoding="utf-8", newline="") as output_file:
        writer = _csv_writer(output_file)
        output_file.seek(0, 2)
        if not gate_list:
            log.warning("agent-latch-runtime: no gates are installed; events will produce no rows")

        pending = ""
        stream: TextIO | None = None
        try:
            while True:
                if stream is None:
                    try:
                        stream = input_path.open("r", encoding="utf-8", newline="")
                    except FileNotFoundError:
                        if not follow:
                            raise
                        time.sleep(poll_interval)
                        continue

                chunk = stream.read(64 * 1024)
                if chunk:
                    pending += chunk
                    lines = pending.split("\n")
                    pending = lines.pop()
                    for line in lines:
                        _process_line(line, writer, output_file, gate_list)
                    continue

                if not follow:
                    if pending:
                        _process_line(pending, writer, output_file, gate_list)
                    break
                time.sleep(poll_interval)
        finally:
            if stream is not None:
                stream.close()


def _csv_writer(output_file: TextIO) -> csv.DictWriter[str]:
    output_file.seek(0)
    first_line = output_file.readline()
    if not first_line:
        writer = csv.DictWriter(output_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        output_file.flush()
        return writer

    output_file.seek(0)
    reader = csv.reader(output_file)
    existing_columns = next(reader, [])
    if tuple(existing_columns) != CSV_COLUMNS:
        raise ValueError(
            f"CSV header must be {','.join(CSV_COLUMNS)}; found {','.join(existing_columns)}"
        )
    output_file.seek(0, 2)
    return csv.DictWriter(output_file, fieldnames=CSV_COLUMNS)


def _process_line(
    line: str,
    writer: csv.DictWriter[str],
    output_file: TextIO,
    gates: list[Gate],
) -> None:
    if not line.strip():
        return
    try:
        event = json.loads(line)
    except json.JSONDecodeError as error:
        log.warning("agent-latch-runtime: skipping invalid payload JSONL line (%s)", error)
        return
    if not _valid_event(event):
        log.warning("agent-latch-runtime: skipping payload with an unsupported event shape")
        return

    for gate in gates:
        result = _evaluate(gate, event)
        writer.writerow({
            "record_id": event["record_id"],
            "seq": event["seq"],
            "gate_id": gate.gate_id,
            "result_json": json.dumps(result, ensure_ascii=False, separators=(",", ":")),
        })
        output_file.flush()


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
        serialized = json.dumps(result, ensure_ascii=False, allow_nan=False)
        return json.loads(serialized)
    except Exception as error:  # noqa: BLE001 - one gate failure must not stop later gates
        log.warning(
            "agent-latch-runtime: gate %r failed (%s)",
            gate.gate_id,
            type(error).__name__,
        )
        return {
            "gate_id": gate.gate_id,
            "status": "error",
            "findings": [],
            "error": {"type": type(error).__name__},
        }


def _valid_event(event: Any) -> bool:
    return (
        isinstance(event, dict)
        and event.get("schema") == PAYLOAD_SCHEMA
        and isinstance(event.get("record_id"), str)
        and isinstance(event.get("seq"), int)
        and isinstance(event.get("payload"), dict)
    )
