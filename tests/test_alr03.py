"""ALR03 endpoint-trust gate: server identification and identity-change detection.

Synthetic handshake events only; no network. The gate reads ``initialize`` events whose payload
carries the client and server ``Implementation`` (name/version) recorded by the middleware.
"""

from __future__ import annotations

from typing import Any

from agent_latch.gates import alr03


def _event(server: str, server_info: dict[str, str] | None,
           client: dict[str, str] | None = None, *, with_payload: bool = True) -> dict[str, Any]:
    event: dict[str, Any] = {
        "run_id": "run",
        "order": 1,
        "method": "initialize",
        "stage": "response",
        "server": server,
        "record_id": "rec-1",
    }
    if with_payload:
        event["payload"] = {
            "protocol_version": "2026-07-28",
            "client": client or {"name": "mcp", "version": "0.1.0"},
            "server_info": server_info,
        }
    else:
        event["payload"] = None
    return event


def _by_rule(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {f["rule_id"]: f for f in findings}


def test_identified_server_passes_identification() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(_event("weather", {"name": "weather", "version": "4.1.0"}))["findings"]
    by_rule = _by_rule(findings)

    identification = by_rule[alr03.RULE_IDS["server_identification"]]
    assert identification["outcome"] == "PASS"
    assert identification["is_finding"] is False
    # A PASS identification is not a finding, so the summary is the only other record.
    assert by_rule[alr03.RULE_SUMMARY]["outcome"] == "PASS"


def test_unidentified_server_fails_identification() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(_event("weather", {"name": "", "version": "4.1.0"}))["findings"]
    identification = _by_rule(findings)[alr03.RULE_IDS["server_identification"]]

    assert identification["outcome"] == "FAIL"
    assert identification["is_finding"] is True
    assert identification["severity"] == "high"


def test_missing_server_info_is_a_coverage_finding() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(_event("weather", None))["findings"]

    assert findings[0]["rule_id"] == alr03.RULE_COVERAGE
    assert findings[0]["outcome"] == "INCONCLUSIVE"


def test_missing_payload_is_a_coverage_finding() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(_event("weather", None, with_payload=False))["findings"]

    assert findings[0]["rule_id"] == alr03.RULE_COVERAGE


def test_identity_change_is_flagged_and_stable_identity_is_not() -> None:
    alr03.reset_state()
    first = alr03.evaluate(_event("weather", {"name": "weather", "version": "4.1.0"}))["findings"]
    # Same identity again: no change finding.
    second = alr03.evaluate(_event("weather", {"name": "weather", "version": "4.1.0"}))["findings"]
    # Changed version: an identity-change finding.
    third = alr03.evaluate(_event("weather", {"name": "weather", "version": "9.9.9"}))["findings"]

    assert alr03.RULE_IDS["server_identity_change"] not in _by_rule(first)
    assert alr03.RULE_IDS["server_identity_change"] not in _by_rule(second)
    change = _by_rule(third)[alr03.RULE_IDS["server_identity_change"]]
    assert change["outcome"] == "FAIL"
    assert change["is_finding"] is True


def test_non_initialize_events_are_out_of_scope() -> None:
    alr03.reset_state()
    event = {"method": "tools/list", "stage": "response", "server": "weather", "payload": {}}
    assert alr03.evaluate(event) == {"findings": []}


def test_malformed_event_is_a_coverage_finding() -> None:
    alr03.reset_state()
    findings = alr03.evaluate("not-a-mapping")["findings"]  # type: ignore[arg-type]
    assert findings[0]["rule_id"] == alr03.RULE_COVERAGE


def test_startup_capabilities_declares_unsupported_checks() -> None:
    capabilities = {c["check"]: c["outcome"] for c in alr03.startup_capabilities()}
    assert capabilities["server_identification"] == "SUPPORTED"
    assert capabilities["transport_authentication"] == "UNSUPPORTED"
