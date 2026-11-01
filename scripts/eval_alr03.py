"""Evaluate ALR03 server-name impersonation detection against a labeled identity dataset.

Reproducible command (from the repository root, package installed or ``src`` on PYTHONPATH):

    python scripts/eval_alr03.py

Reads ``tests/runtime_fixtures/alr03_eval_identities.json`` (labeled by rubric; see its
``labeling_method``), runs every case through the real ``alr03.evaluate`` path, and prints
recall and false-positive rate for the held-out split, plus the tuning split for reference.
A case counts as detected when ALR03-003 reports a finding (FAIL or INCONCLUSIVE).

The report is a measurement on a small synthetic dataset, not proof of comprehensive coverage.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_latch.gates import alr03

DATASET = Path(__file__).resolve().parents[1] / "tests" / "runtime_fixtures" / (
    "alr03_eval_identities.json"
)


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


def main() -> int:
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    cases = dataset["cases"]
    tune = evaluate_split([c for c in cases if c["split"] == "tune"])
    holdout = evaluate_split([c for c in cases if c["split"] == "holdout"])

    print("ALR03-003 server name impersonation — evaluation")
    print(f"Dataset: {DATASET.name} ({len(cases)} cases, labeled by rubric at authoring time)")
    print(f"Labeling: {dataset['labeling_method'][:120]}...")
    print()
    for name, report in (("tune", tune), ("holdout", holdout)):
        print(f"[{name}] {report['total']} cases "
              f"({report['malicious']} malicious, {report['benign']} benign)")
        print(f"  recall:              {report['recall']:.0%} "
              f"({report['malicious'] - len(report['missed'])}/{report['malicious']})")
        print(f"  false-positive rate: {report['false_positive_rate']:.0%} "
              f"({len(report['false_positives'])}/{report['benign']})")
        for case_id, technique, outcome, signals in report["newly_detected"]:
            print(f"  detected: {case_id} ({technique}) {outcome} via {', '.join(signals)}")
        for case_id, technique in report["missed"]:
            print(f"  MISSED: {case_id} ({technique})")
        for case_id, technique in report["false_positives"]:
            print(f"  FALSE POSITIVE: {case_id} ({technique})")
        print()
    print("Limitations: small synthetic self-labeled dataset; similarity-based detection cannot "
          "see impostors with wholly original names; results are not proof of comprehensive "
          "security coverage.")
    ok = holdout["recall"] >= 0.80 and holdout["false_positive_rate"] <= 0.10
    print(f"Targets: recall >= 80% and FP <= 10% on holdout -> {'MET' if ok else 'NOT MET'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
