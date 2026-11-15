"""ALR10 validation on a separate fixture set, for requests and for tool output.

``runtime_fixtures/alr10_heldout.json`` is kept apart from the inline corpus in ``test_alr10.py``
and was not used to tune the masking patterns. It is still small and written by the same people
as the gate, so it checks for regressions and shows the measured rates; it is not evidence of
performance on real traffic. Measured when it was added: request recall 7/12, response recall
8/10, no false positives in either direction; the thresholds below sit under those numbers. Some cases are formats the masking does not recognize (see
``KNOWN_MISSES``): they are listed so the blind spots stay visible instead of being dropped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_latch.gates import alr10
from agent_latch.runtime.payloads import masked_record

FIXTURE = Path(__file__).parent / "runtime_fixtures" / "alr10_heldout.json"

# Secrets in the fixture whose shape the masking patterns do not cover today. The test asserts
# they are still missed, so a pattern improvement shows up as a deliberate change here.
KNOWN_MISSES = {
    "credentials inside a URL",
    "GitLab personal access token",
    "Stripe-style live key",
    "Google API key",
    "npm token (shape not covered)",
    "AWS secret in an env assignment",
    "env-style password line",
}


def _resolve(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"parts"}:
            return "".join(value["parts"])
        return {key: _resolve(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item) for item in value]
    return value


def _cases() -> list[dict[str, Any]]:
    return [_resolve(case) for case in json.loads(FIXTURE.read_text("utf-8"))["cases"]]


def _event(case: dict[str, Any], order: int) -> dict[str, Any]:
    section, value = case["section"], case["value"]
    if case["direction"] == "request":
        stage = "request"
        body: dict[str, Any] = {"tool": "t", "arguments": value, "tool_definition": None}
    elif section == "error_message":
        stage = "error"
        body = {"tool": "t", "error_message": value}
    else:
        stage = "response"
        body = {"tool": "t", "is_error": False, "content": [], "structured": None,
                "duration_ms": 1.0, section: value}
    masked = masked_record({"payload": body}, 4000)["payload"]
    return {
        "run_id": "r", "order": order, "timestamp": "t", "session_id": "s", "request_id": str(order),
        "client_id": None, "server": "demo", "method": "tools/call", "stage": stage, "name": "t",
        "metadata": {}, "payload": masked,
    }


def _flagged(case: dict[str, Any], order: int) -> bool:
    found = alr10.evaluate(_event(case, order))["findings"]
    want = "ALR10-R01" if case["direction"] == "request" else "ALR10-R02"
    return any(f["rule_id"] == want and f["is_finding"] for f in found)


def _rates(direction: str) -> tuple[float, float, list[str], list[str]]:
    secrets = benign = hit = false_hit = 0
    missed: list[str] = []
    false_positives: list[str] = []
    for order, case in enumerate(_cases(), 1):
        if case["direction"] != direction:
            continue
        flagged = _flagged(case, order)
        if case["expect"] == "secret":
            secrets += 1
            hit += flagged
            if not flagged:
                missed.append(case["note"])
        else:
            benign += 1
            false_hit += flagged
            if flagged:
                false_positives.append(case["note"])
    return hit / secrets, false_hit / benign, missed, false_positives


def test_heldout_set_covers_both_directions() -> None:
    cases = _cases()
    for direction in ("request", "response"):
        kinds = [c["expect"] for c in cases if c["direction"] == direction]
        assert kinds.count("secret") >= 10 and kinds.count("benign") >= 12


def test_heldout_request_side_rates() -> None:
    recall, fp_rate, missed, false_positives = _rates("request")
    assert recall >= 0.50, f"request recall {recall:.2f}, missed {missed}"
    assert fp_rate <= 0.10, f"request false positives {fp_rate:.2f}: {false_positives}"


def test_heldout_response_side_rates() -> None:
    recall, fp_rate, missed, false_positives = _rates("response")
    assert recall >= 0.75, f"response recall {recall:.2f}, missed {missed}"
    assert fp_rate <= 0.10, f"response false positives {fp_rate:.2f}: {false_positives}"


def test_known_misses_are_exactly_the_documented_blind_spots() -> None:
    missed = {
        case["note"]
        for order, case in enumerate(_cases(), 1)
        if case["expect"] == "secret" and not _flagged(case, order)
    }
    assert missed == KNOWN_MISSES
