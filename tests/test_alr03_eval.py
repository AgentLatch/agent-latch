"""ALR03-003 evaluation against the labeled identity dataset.

Runs the same harness as ``scripts/eval_alr03.py`` and asserts the ticket thresholds on the
held-out split: at least 80% recall on malicious identities, at most 10% false positives on
benign ones. The dataset is labeled by rubric at authoring time; matching these thresholds
demonstrates the combined detector behaves as measured, not that coverage is comprehensive.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_latch.gates import alr03

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import eval_alr03

_DATASET = Path(__file__).parent / "runtime_fixtures" / "alr03_eval_identities.json"


def test_held_out_split_meets_recall_and_false_positive_targets() -> None:
    cases = json.loads(_DATASET.read_text(encoding="utf-8"))["cases"]
    holdout = eval_alr03.evaluate_split([c for c in cases if c["split"] == "holdout"])

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
    result = eval_alr03.run_case(case)
    assert result["detected"] is True and result["outcome"] == "FAIL"
    alr03.reset_state()
