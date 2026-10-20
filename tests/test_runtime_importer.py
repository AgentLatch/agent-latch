"""Tests for runtime payload importing and the gate plugin contract."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from agent_latch.runtime.events import PAYLOAD_SCHEMA
from agent_latch.runtime.importer import GatePlugin, discover_gates, follow_payloads


def _event(seq: int = 1) -> dict[str, Any]:
    return {
        "schema": PAYLOAD_SCHEMA,
        "record_id": f"record-{seq}",
        "seq": seq,
        "timestamp": "2026-10-20T15:00:00.000Z",
        "session_id": "session",
        "request_id": str(seq),
        "client_id": None,
        "server": "weather",
        "method": "tools/call",
        "stage": "request",
        "payload": {"tool": "weather", "arguments": {"city": "London"}},
    }


def test_importer_calls_each_gate_with_an_independent_copy_and_writes_each_result(
    tmp_path: Path,
) -> None:
    payload_path = tmp_path / "payloads.jsonl"
    output_path = tmp_path / "results.csv"
    original_event = _event()
    payload_path.write_text(json.dumps(original_event) + "\n", encoding="utf-8")
    received: list[dict[str, Any]] = []

    def first(event: dict[str, Any]) -> dict[str, Any]:
        received.append(event)
        event["payload"]["arguments"]["city"] = "mutated"
        return {"findings": [{"rule_id": "ASI01"}]}

    def second(event: dict[str, Any]) -> dict[str, Any]:
        received.append(event)
        return {"findings": []}

    follow_payloads(
        payload_path,
        output_path,
        [GatePlugin("first", first), GatePlugin("second", second)],
        follow=False,
    )

    assert received[0] is not received[1]
    assert received[0]["payload"]["arguments"]["city"] == "mutated"
    assert received[1]["payload"]["arguments"]["city"] == "London"
    with output_path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))
    assert [row["gate_id"] for row in rows] == ["first", "second"]
    assert all(row["record_id"] == "record-1" and row["seq"] == "1" for row in rows)
    first_result, second_result = [json.loads(row["result_json"]) for row in rows]
    assert first_result == {
        "gate_id": "first",
        "status": "ok",
        "findings": [{"rule_id": "ASI01"}],
        "error": None,
    }
    assert second_result["findings"] == []


def test_gate_failure_writes_error_result_then_continues(tmp_path: Path) -> None:
    payload_path = tmp_path / "payloads.jsonl"
    output_path = tmp_path / "results.csv"
    payload_path.write_text(json.dumps(_event()) + "\n", encoding="utf-8")
    called: list[str] = []

    def failing(_event: dict[str, Any]) -> dict[str, Any]:
        called.append("failing")
        raise RuntimeError("details must not leak into output")

    def succeeding(_event: dict[str, Any]) -> dict[str, Any]:
        called.append("succeeding")
        return {"findings": []}

    follow_payloads(
        payload_path,
        output_path,
        [GatePlugin("failure", failing), GatePlugin("success", succeeding)],
        follow=False,
    )

    with output_path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))
    failure_result = json.loads(rows[0]["result_json"])
    assert called == ["failing", "succeeding"]
    assert failure_result["status"] == "error"
    assert failure_result["error"] == {"type": "RuntimeError"}
    assert "details must not leak" not in rows[0]["result_json"]
    assert json.loads(rows[1]["result_json"])["status"] == "ok"


def test_importer_rejects_mismatched_csv_header_and_same_input_output(tmp_path: Path) -> None:
    payload_path = tmp_path / "payloads.jsonl"
    output_path = tmp_path / "results.csv"
    payload_path.write_text(json.dumps(_event()) + "\n", encoding="utf-8")
    output_path.write_text("wrong,header\n", encoding="utf-8")

    try:
        follow_payloads(payload_path, output_path, [], follow=False)
    except ValueError as error:
        assert "CSV header must be" in str(error)
    else:
        raise AssertionError("mismatched CSV headers should fail")

    try:
        follow_payloads(payload_path, payload_path, [], follow=False)
    except ValueError as error:
        assert "different files" in str(error)
    else:
        raise AssertionError("input and output paths should not match")


def test_gate_discovery_returns_no_implemented_gates_yet() -> None:
    assert discover_gates() == []
