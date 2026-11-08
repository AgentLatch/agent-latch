"""ALR03-003 evaluation against the labeled identity dataset.

Runs every labeled case through the real ``alr03.evaluate`` path (a case counts as detected
when ALR03-003 reports a finding) and asserts the ticket thresholds on the held-out split: at least 80% recall on malicious identities, at most 10% false positives on
benign ones. The dataset is labeled by rubric at authoring time; matching these thresholds
demonstrates the combined detector behaves as measured, not that coverage is comprehensive.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_latch.gates import alr03

_DATASET = Path(__file__).parent / "runtime_fixtures" / "alr03_eval_identities.json"


def _event(case: dict) -> dict:
    return {
        "run_id": "eval",
        "order": 1,
        "method": "initialize",
        "stage": "response",
        "server": case["proxy_label"],
        "record_id": case["id"],
        "payload": {
            "protocol_version": "2026-07-28",
            "client": {"name": "eval-client", "version": "1.0.0"},
            "server_info": case["server_info"],
        },
    }


def run_case(case: dict) -> dict:
    """Prime the gate with the case's prior names, then evaluate the case's handshake."""
    alr03.reset_state()
    for name in case.get("prior_names", []):
        prime = dict(_event(case))
        prime["server"] = name
        prime["payload"] = {**prime["payload"], "server_info": {"name": name, "version": "1.0.0"}}
        alr03.evaluate(prime)
    findings = alr03.evaluate(_event(case))["findings"]
    hits = [f for f in findings
            if f["rule_id"] == alr03.RULE_IDS["server_name_impersonation"] and f["is_finding"]]
    worst = "PASS"
    for hit in hits:
        if hit["outcome"] == "FAIL":
            worst = "FAIL"
            break
        worst = "INCONCLUSIVE"
    return {"detected": bool(hits), "outcome": worst, "signals": [
        e["signal"] for hit in hits for e in hit["evidence"] if not e["signal"].startswith("resembles_")
    ]}


def evaluate_split(cases: list[dict]) -> dict:
    malicious = [c for c in cases if c["label"] == "malicious"]
    benign = [c for c in cases if c["label"] == "benign"]
    results = {c["id"]: run_case(c) for c in cases}
    detected_m = [c for c in malicious if results[c["id"]]["detected"]]
    flagged_b = [c for c in benign if results[c["id"]]["detected"]]
    return {
        "total": len(cases),
        "malicious": len(malicious),
        "benign": len(benign),
        "recall": len(detected_m) / len(malicious) if malicious else 0.0,
        "false_positive_rate": len(flagged_b) / len(benign) if benign else 0.0,
        "missed": [(c["id"], c["technique"]) for c in malicious if not results[c["id"]]["detected"]],
        "false_positives": [(c["id"], c["technique"]) for c in benign if results[c["id"]]["detected"]],
        "newly_detected": [
            (c["id"], c["technique"], results[c["id"]]["outcome"], results[c["id"]]["signals"])
            for c in malicious if results[c["id"]]["detected"]
        ],
    }


def test_held_out_split_meets_recall_and_false_positive_targets() -> None:
    cases = json.loads(_DATASET.read_text(encoding="utf-8"))["cases"]
    holdout = evaluate_split([c for c in cases if c["split"] == "holdout"])

    assert holdout["malicious"] >= 10 and holdout["benign"] >= 10
    assert holdout["recall"] >= 0.80, holdout["missed"]
    assert holdout["false_positive_rate"] <= 0.10, holdout["false_positives"]


def test_every_malicious_technique_is_represented() -> None:
    cases = json.loads(_DATASET.read_text(encoding="utf-8"))["cases"]
    techniques = {c["technique"].split("+")[0] for c in cases if c["label"] == "malicious"}
    assert {"transposition", "homoglyph", "leet", "deletion", "insertion", "substitution"} <= techniques


def test_evaluation_uses_the_real_gate_path() -> None:
    """The harness drives alr03.evaluate, so the measured path is the shipped one."""
    case = {
        "id": "smoke", "proxy_label": "github", "prior_names": [],
        "server_info": {"name": "gihtub", "version": "1.0.0"},
    }
    result = run_case(case)
    assert result["detected"] is True and result["outcome"] == "FAIL"
    alr03.reset_state()
