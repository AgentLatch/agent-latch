"""ALR05 detection targets against the labeled output cases (scripts/eval_alr05.py).

The held-out split (a hash of the case id) is never tuned on directly: thresholds are set on the
tuning set, and this test fails if held-out recall drops below 80% or held-out false positives
exceed 10%. All cases are synthetic; nothing here touches the network.
"""

from __future__ import annotations

import json

from scripts.eval_alr05 import (
    FIXTURE,
    HELD_OUT_FP_MAX,
    HELD_OUT_RECALL_MIN,
    _metrics,
    evaluate,
)


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
