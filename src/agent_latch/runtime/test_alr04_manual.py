"""Manually test the existing ALR04 gate against one normalized JSON/JSONL file.

PyCharm: set INPUT_FILE, right-click this file and select Run.
CLI: python test_alr04_manual_v2.py "C:\\path\\to\\normalized.jsonl"

Produces ONE editable CSV next to the input. Fill EXPECTED_OUTCOME with FAIL or PASS
for each SCANNED tool-definition row. Labels survive reruns of the same dataset.
FAIL = malicious tool definition; PASS = benign tool definition.
INCONCLUSIVE and NOT_EVALUATED are preserved as distinct predictions.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# Change this path for each test, or supply the filename as a PyCharm program argument.
INPUT_FILE = Path(__file__).resolve().parent / "alr04_normalized_events.json"
OUTPUT_FILE: str | None = None  # None -> <input_filename>_alr04_results.csv

# Keep this script alongside the existing alr04.py file.
import alr04

COLUMNS = (
    "test_case_id", "traffic_index", "order", "run_id", "timestamp", "session_id",
    "request_id", "server", "method", "stage", "event_name", "tool",
    "expected_outcome", "actual_outcome", "match", "inspection_status",
    "primary_reason", "fail_rules", "review_rules", "triggered_categories",
    "evidence_summary", "coverage_notes", "max_score", "definition_sha256",
    "findings_count", "details_json", "error",
)


def read_events(path: Path) -> Iterator[dict[str, Any]]:
    """Yield objects from JSON array, one JSON object, or JSONL."""
    with path.open("r", encoding="utf-8-sig") as stream:
        if path.suffix.lower() == ".jsonl":
            for number, line in enumerate(stream, 1):
                if line.strip():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"Invalid JSONL at line {number}: {exc}") from exc
                    if not isinstance(event, dict):
                        raise TypeError(f"JSONL line {number} must be an object")
                    yield event
        else:
            items = json.load(stream)
            if isinstance(items, dict):
                items = [items]
            if not isinstance(items, list):
                raise TypeError("Input must be an object, array of objects, or JSONL")
            for number, event in enumerate(items, 1):
                if not isinstance(event, dict):
                    raise TypeError(f"JSON event {number} must be an object")
                yield event


def extract_definitions(event: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Identify inputs eligible for ALR04 without modifying them."""
    method, stage = event.get("method"), event.get("stage")
    if (method, stage) not in {("tools/list", "response"), ("tools/call", "request")}:
        return "OUT_OF_SCOPE", []
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return "MISSING_PAYLOAD", []
    if method == "tools/list":
        tools = payload.get("tools")
        if not isinstance(tools, list):
            return "INVALID_TOOL_LIST", []
        valid = [t for t in tools[:alr04.MAX_TOOLS]
                 if isinstance(t, dict) and isinstance(t.get("name"), str)]
        return ("ELIGIBLE" if valid else "NO_VALID_DEFINITIONS"), valid
    cached = payload.get("tool_definition")
    if cached is None:
        return "NO_CACHED_DEFINITION", []
    if not isinstance(cached, dict) or not isinstance(payload.get("tool"), str):
        return "INVALID_CACHED_DEFINITION", []
    return "ELIGIBLE", [{**cached, "name": payload["tool"]}]


def worst(records: list[dict[str, Any]]) -> str:
    outcomes = {r.get("outcome") for r in records}
    return "FAIL" if "FAIL" in outcomes else "INCONCLUSIVE" if "INCONCLUSIVE" in outcomes else "PASS"


def load_existing_labels(path: Path) -> dict[str, str]:
    """Preserve hand-labelled expected outcomes on reruns; never infer ground truth."""
    labels: dict[str, str] = {}
    if path.is_file():
        with path.open("r", newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames and {"test_case_id", "expected_outcome"}.issubset(reader.fieldnames):
                for row in reader:
                    expected = (row.get("expected_outcome") or "").strip().upper()
                    if expected in {"PASS", "FAIL"}:
                        labels[row["test_case_id"]] = expected
    return labels


def match_value(expected: str, actual: str) -> str:
    if not expected:
        return "UNLABELLED"
    if actual in {"NOT_EVALUATED", "ERROR", "INCONCLUSIVE"}:
        return "NOT_SCORED"
    return "CORRECT" if actual == expected else "INCORRECT"


def details(records: list[dict[str, Any]]) -> dict[str, str | int | float]:
    """Flatten verdict reasoning; keep complete original records in details_json."""
    attention = [r for r in records if r.get("family") != "scan_summary"]
    relevant = [r for r in attention if r.get("outcome") in {"FAIL", "INCONCLUSIVE"}]
    important = relevant or attention
    reasons = list(dict.fromkeys(str(r.get("decision_reason", "")) for r in important
                                if r.get("decision_reason")))
    categories = list(dict.fromkeys(str(r.get("family", "")) for r in relevant if r.get("family")))
    evidence = []
    for r in important:
        for item in r.get("evidence", []) or []:
            if isinstance(item, dict):
                label = f"{item.get('signal', 'signal')} @ {item.get('field', '?')}"
                if label not in evidence:
                    evidence.append(label)
            if len(evidence) >= 6:
                break
        if len(evidence) >= 6:
            break
    notes = sorted({str(note) for r in attention for note in r.get("coverage_notes", []) or []})
    scores = [float(r["score"]) for r in attention if isinstance(r.get("score"), (float, int))]
    return {
        "primary_reason": " | ".join(reasons[:4]),
        "fail_rules": " | ".join(str(r.get("rule_id", "")) for r in attention if r.get("outcome") == "FAIL"),
        "review_rules": " | ".join(str(r.get("rule_id", "")) for r in attention if r.get("outcome") == "INCONCLUSIVE"),
        "triggered_categories": " | ".join(categories),
        "evidence_summary": " | ".join(evidence),
        "coverage_notes": " | ".join(notes),
        "max_score": max(scores) if scores else "",
        "findings_count": len(attention),
        "details_json": json.dumps(attention, ensure_ascii=False, separators=(",", ":")),
    }


def run(input_path: Path, output_path: Path) -> Counter:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Output path must differ from input")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    saved_labels = load_existing_labels(output_path)
    alr04.reset_state()
    seen_definitions: set[tuple[str, str, str]] = set()
    seen_tool_names: set[tuple[str, str]] = set()
    counters: Counter = Counter()
    duplicate_ids: defaultdict[str, int] = defaultdict(int)
    temp_path = output_path.with_name(output_path.name + ".tmp")
    try:
        with temp_path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS)
            writer.writeheader()

            def emit(base: dict[str, Any], suffix: str, actual: str, status: str,
                     findings: list[dict[str, Any]], error: str = "", sha: str = "") -> None:
                # Deterministic row ID; differentiates multiple definitions in one traffic event.
                raw_id = f"{base['traffic_index']}:{suffix}"
                duplicate_ids[raw_id] += 1
                case_id = raw_id if duplicate_ids[raw_id] == 1 else f"{raw_id}#{duplicate_ids[raw_id]}"
                expected = saved_labels.get(case_id, "")
                writer.writerow({
                    **base, "test_case_id": case_id, "expected_outcome": expected,
                    "actual_outcome": actual, "match": match_value(expected, actual),
                    "inspection_status": status, "definition_sha256": sha,
                    **details(findings), "error": error,
                })
                counters[f"actual_{actual}"] += 1
                counters["rows"] += 1
                if expected:
                    counters["labelled"] += 1

            for index, event in enumerate(read_events(input_path), 1):
                counters["traffic_events"] += 1
                status, tools = extract_definitions(event)
                server = str(event.get("server") or "")
                base = {"traffic_index": index,
                        **{k: event.get(k, "") for k in ("order", "run_id", "timestamp", "session_id", "request_id", "method", "stage")},
                        "server": server, "event_name": event.get("name") or "", "tool": ""}
                try:
                    records = alr04.evaluate(event)["findings"]
                    if not isinstance(records, list):
                        raise TypeError("Gate findings must be a list")
                    error = ""
                except (AttributeError, TypeError, ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
                    records, error = [], type(exc).__name__
                    counters["gate_errors"] += 1
                summary = next((r for r in records if r.get("family") == "scan_summary"), None)
                event_records = [r for r in records if not (r.get("entity") or {}).get("tool")
                                 and r.get("family") != "scan_summary"]
                if not tools:
                    actual = "ERROR" if error else worst(event_records) if event_records else "NOT_EVALUATED"
                    emit(base, "event", actual, "ERROR" if error else status, event_records, error)
                    continue
                for tool in tools:
                    name = tool["name"]
                    sha = alr04.definition_hash(tool)
                    key = (server, name, sha)
                    already_seen = key in seen_definitions or (
                        event.get("method") == "tools/call" and (server, name) in seen_tool_names)
                    matched = [r for r in records if (r.get("entity") or {}).get("tool") == name
                               and r.get("family") != "scan_summary"]
                    if error:
                        inspect, actual = "ERROR", "ERROR"
                    elif already_seen:
                        inspect, actual = "SKIPPED_ALREADY_SEEN", "NOT_EVALUATED"
                        matched = []
                    elif matched:
                        inspect, actual = "SCANNED", worst(matched)
                    elif summary is not None:
                        inspect, actual = "SCANNED_NO_ALERTS", "PASS"
                    else:
                        inspect, actual = "NOT_CONFIRMED", "NOT_EVALUATED"
                    if not error and not already_seen and inspect.startswith("SCANNED"):
                        seen_definitions.add(key)
                        seen_tool_names.add((server, name))
                    emit({**base, "tool": name}, name, actual, inspect, matched, error, sha)
        os.replace(temp_path, output_path)
    except (AttributeError, OSError, TypeError, ValueError, KeyError, IndexError, json.JSONDecodeError):
        temp_path.unlink(missing_ok=True)
        raise
    return counters


def main() -> None:
    parser = argparse.ArgumentParser(description="Manually test existing ALR04 and export one labelled CSV")
    parser.add_argument("input", nargs="?", help="Absolute or relative normalized JSON/JSONL path")
    parser.add_argument("--output", help="Optional output CSV file path")
    args = parser.parse_args()
    source = Path(args.input or INPUT_FILE).expanduser()
    destination = (Path(args.output or OUTPUT_FILE) if args.output or OUTPUT_FILE
                   else source.with_name(source.stem + "_alr04_results.csv"))
    counts = run(source, destination)
    print(f"Input: {source}\nCSV: {destination}")
    print(f"Traffic events: {counts['traffic_events']} | CSV rows: {counts['rows']} | Errors: {counts['gate_errors']}")
    print("Verdicts: " + ", ".join(f"{name}={counts[f'actual_{name}']}" for name in
                                  ("PASS", "FAIL", "INCONCLUSIVE", "NOT_EVALUATED", "ERROR")))
    print(f"Ground-truth labels preserved: {counts['labelled']}. Fill expected_outcome (PASS/FAIL) in the CSV.")


if __name__ == "__main__":
    main()
