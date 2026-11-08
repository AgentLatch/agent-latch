"""ALR05 detection targets against the labeled tool-output cases.

Runs every case in ``runtime_fixtures/alr05_output_cases.json`` through the gate as a synthetic
``tools/call`` event and measures recall on the malicious cases and the false-positive rate on the
benign ones, split into a tuning set and a held-out set. The split is a hash of the case id, so it
is stable no matter how the file is ordered. Thresholds are tuned on the tuning set only; the test
fails if held-out recall drops below 80% or held-out false positives exceed 10%.

Also runnable as a tuning harness (exit code 1 when the held-out targets are missed):

    python tests/test_alr05_eval.py            # table plus summary
    python tests/test_alr05_eval.py --errors   # only misclassified rows

All cases are synthetic; nothing here touches the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from agent_latch.gates import alr05

FIXTURE = Path(__file__).resolve().parent / "runtime_fixtures" / "alr05_output_cases.json"
HELD_OUT_RECALL_MIN = 0.80
HELD_OUT_FP_MAX = 0.10


def _transform(text: str, kind: str) -> str:
    import base64

    if kind == "base64":
        return "Encoded note: " + base64.b64encode(text.encode()).decode()
    if kind == "base64x2":
        return "Encoded note: " + base64.b64encode(base64.b64encode(text.encode())).decode()
    if kind == "hex":
        return "Encoded note: " + text.encode().hex()
    if kind == "zero_width":
        return "\u200b".join(text.split(" "))
    if kind == "unicode_tags":
        return "Page text. " + "".join(chr(0xE0000 + ord(c)) for c in text)
    if kind == "bidi_wrap":
        return "Please review \u202e" + text + "\u202c this section."
    raise ValueError(f"unknown transform {kind!r}")


def _event(case: dict[str, Any]) -> dict[str, Any]:
    text = case["text"]
    if case.get("transform"):
        text = _transform(text, case["transform"])
    stage = case.get("stage", "response")
    payload: dict[str, Any] = {"tool": "fetch_page", "duration_ms": 1.0}
    if stage == "error":
        payload.update({"error_type": "ToolError", "error_message": text})
    else:
        payload.update({"is_error": False, "content": [text], "structured": None})
    return {
        "run_id": "eval", "order": 2, "record_id": f"eval-{case['id']}",
        "method": "tools/call", "stage": stage, "server": "eval", "name": "fetch_page",
        "payload": payload,
        "metadata": {"is_error": stage == "error", "output_bytes": len(text), "excerpt": ""},
    }


def run_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """The gate's findings for one labeled case, with its tool list registered first."""
    alr05.reset_state()
    tools = case.get("tools")
    if tools:
        alr05.evaluate({
            "run_id": "eval", "order": 1, "record_id": "eval-list",
            "method": "tools/list", "stage": "response", "server": "eval", "name": None,
            "payload": {"tools": [{"name": name, "description": "", "inputSchema": {}}
                                  for name in tools]},
            "metadata": {},
        })
    return alr05.evaluate(_event(case))["findings"]


def evaluate(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for case in cases:
        findings = run_case(case)
        fired = {finding["rule_id"] for finding in findings if finding.get("is_finding")}
        rows.append({
            "id": case["id"],
            "label": case["label"],
            "held_out": int(hashlib.md5(case["id"].encode(), usedforsecurity=False)
                            .hexdigest(), 16) % 5 == 0,
            "flagged": bool(fired),
            "fired": sorted(fired),
            "expect": list(case.get("expect", [])),
        })
    return rows


def _metrics(rows: list[dict[str, Any]]) -> tuple[float | None, float | None]:
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    recall = (sum(row["flagged"] for row in malicious) / len(malicious)) if malicious else None
    fp_rate = (sum(row["flagged"] for row in benign) / len(benign)) if benign else None
    return recall, fp_rate


def test_eval_fixture_is_balanced_and_large_enough() -> None:
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    labels = [case["label"] for case in cases]
    assert len(cases) >= 40
    assert labels.count("benign") >= len(cases) / 2
    assert set(labels) == {"malicious", "benign"}


def test_alr05_meets_held_out_detection_targets() -> None:
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    rows = evaluate(cases)
    held_out = [row for row in rows if row["held_out"]]
    assert held_out, "the split must leave cases for held-out measurement"
    recall, fp_rate = _metrics(held_out)
    assert recall is not None and recall >= HELD_OUT_RECALL_MIN, (
        f"held-out recall {recall:.0%} < {HELD_OUT_RECALL_MIN:.0%}: "
        f"{[row['id'] for row in held_out if row['label'] == 'malicious' and not row['flagged']]}"
    )
    assert fp_rate is not None and fp_rate <= HELD_OUT_FP_MAX, (
        f"held-out false positives {fp_rate:.0%} > {HELD_OUT_FP_MAX:.0%}: "
        f"{[row['id'] for row in held_out if row['label'] == 'benign' and row['flagged']]}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--errors", action="store_true", help="only print misclassified rows")
    args = parser.parse_args(argv)

    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    rows = evaluate(cases)
    for row in rows:
        wrong = row["flagged"] != (row["label"] == "malicious")
        if args.errors and not wrong:
            continue
        mark = "!!" if wrong else "  "
        print(f"{mark} {row['id']:<28} {row['label']:<9} flagged={row['flagged']!s:<5} "
              f"fired={','.join(row['fired']) or '-'}")

    for name, subset in (("tuning", [r for r in rows if not r["held_out"]]),
                         ("held-out", [r for r in rows if r["held_out"]])):
        recall, fp_rate = _metrics(subset)
        recall_text = f"{recall:.0%}" if recall is not None else "n/a"
        fp_text = f"{fp_rate:.0%}" if fp_rate is not None else "n/a"
        print(f"{name}: recall {recall_text}, false positives {fp_text} "
              f"({len(subset)} cases)")

    held_out = [row for row in rows if row["held_out"]]
    recall, fp_rate = _metrics(held_out)
    ok = (recall is not None and recall >= HELD_OUT_RECALL_MIN
          and fp_rate is not None and fp_rate <= HELD_OUT_FP_MAX)
    print(f"held-out targets: recall >= {HELD_OUT_RECALL_MIN:.0%}, "
          f"false positives <= {HELD_OUT_FP_MAX:.0%} -> {'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
