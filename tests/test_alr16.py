"""ALR16 package-installation gate: labelled fixture matrix plus trigger coverage.

Each case in ``runtime_fixtures/alr16_events.json`` carries its expected worst outcome
(over the last event's non-summary records) and the expected rule set. The remaining
tests trigger uncovered paths: malformed input, dedupe, suppression, invalid policy,
require mode, determinism and the no-raw-text evidence contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_latch import catalog
from agent_latch.gates import alr16

_FIXTURES = Path(__file__).parent / "runtime_fixtures" / "alr16_events.json"


def _load() -> list[dict[str, Any]]:
    return json.loads(_FIXTURES.read_text(encoding="utf-8"))["cases"]


def _last_findings(case: dict[str, Any]) -> list[dict[str, Any]]:
    alr16.reset_state()
    findings: list[dict[str, Any]] = []
    for event in case["events"]:
        findings = alr16.evaluate(event, policy=case["policy"])["findings"]
    return findings


def _worst(records: list[dict[str, Any]]) -> str:
    outcomes = {record.get("outcome") for record in records
                if record.get("family") != "scan_summary"}
    if "FAIL" in outcomes:
        return "FAIL"
    if "INCONCLUSIVE" in outcomes:
        return "INCONCLUSIVE"
    if outcomes:
        return "PASS"
    return "NONE"


def test_alr16_labelled_matrix() -> None:
    for case in _load():
        records = _last_findings(case)
        body = [record for record in records if record.get("family") != "scan_summary"]
        assert _worst(records) == case["expected_worst"], case["label"]
        assert {record.get("rule_id") for record in body} == set(case["expected_rules"]), \
            case["label"]
        for record in records:
            assert record.get("gate_id") == "ALR16", case["label"]
            assert record.get("owasp") == ["ASI04", "ASI05"], case["label"]


def test_alr16_summary_is_not_a_finding() -> None:
    case = next(item for item in _load() if item["label"] == "pip_unpinned_review")
    records = _last_findings(case)
    summary = next(record for record in records if record.get("family") == "scan_summary")
    assert summary["is_finding"] is False
    assert summary["rule_id"] == "ALR16-099"
    assert summary["policy_state"] in ("absent", "applied", "ignored", "invalid")


def test_alr16_evidence_carries_pointers_not_text() -> None:
    alr16.reset_state()
    event = {
        "run_id": "r", "order": 1, "server": "s",
        "method": "tools/call", "stage": "request",
        "payload": {
            "tool": "run_shell",
            "arguments": {"command": "pip install evilpkg==9.9.9 --trusted-host m.example"},
            "tool_definition": {"name": "run_shell", "description": "Run a shell command."},
        },
    }
    dumped = json.dumps(alr16.evaluate(event)["findings"])
    assert "evilpkg==9.9.9" not in dumped
    assert "pip install evilpkg" not in dumped


def test_alr16_is_deterministic() -> None:
    case = next(item for item in _load() if item["label"] == "two_dimensions_fail")
    first = json.dumps(_last_findings(case), sort_keys=True)
    second = json.dumps(_last_findings(case), sort_keys=True)
    assert first == second


def test_alr16_dedupes_exact_repeat_calls() -> None:
    alr16.reset_state()
    event = _load()[0]["events"][0]
    first = alr16.evaluate(event)["findings"]
    assert first
    assert alr16.evaluate(event)["findings"] == []


def test_alr16_suppression_clears_is_finding() -> None:
    alr16.reset_state()
    event = _load()[1]["events"][0]  # unpinned -> ALR16-003
    policy = {"suppressions": {"ALR16-003": "operator waiver"}}
    records = alr16.evaluate(event, policy=policy)["findings"]
    flagged = [record for record in records if record.get("rule_id") == "ALR16-003"]
    assert flagged and all(record["suppressed"] for record in flagged)
    assert all(record["is_finding"] is False for record in flagged)


def test_alr16_invalid_policy_is_coverage_not_silent() -> None:
    alr16.reset_state()
    event = _load()[1]["events"][0]
    records = alr16.evaluate(event, policy={"packages": "allow-everything"})["findings"]
    summary = next(record for record in records if record.get("family") == "scan_summary")
    assert summary["policy_state"] == "invalid"


def test_alr16_require_mode_without_allowlist_cannot_pass() -> None:
    alr16.reset_state()
    event = _load()[0]["events"][0]  # pinned install, clean without a policy
    records = alr16.evaluate(event, policy={"mode": "require"})["findings"]
    assert _worst(records) == "FAIL"


def test_alr16_malformed_inputs_stay_coverage() -> None:
    alr16.reset_state()
    assert alr16.evaluate({})["findings"] == []
    missing = alr16.evaluate({"method": "tools/call", "stage": "request",
                              "payload": {"tool": "run_shell"}})["findings"]
    assert missing and missing[0]["rule_id"] == "ALR16-090"
    assert alr16.evaluate("not-an-event")["findings"][0]["rule_id"] == "ALR16-090"


def test_alr16_detectors_match_the_catalog() -> None:
    assert {d.id for d in catalog.detectors_for("ALR16")} == set(alr16.RULE_IDS.values())
    assert {alr16.RULE_COVERAGE, alr16.RULE_SUMMARY} <= set(catalog.DIAGNOSTICS)
    assert list(alr16.OWASP) == list(catalog.gate("ALR16").owasp)
