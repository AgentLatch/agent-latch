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
    assert capabilities["server_name_impersonation"] == "SUPPORTED"
    assert capabilities["transport_authentication"] == "UNSUPPORTED"


# --- ALR03-003 server name impersonation (non-regex similarity) ---------------------------------


def _impersonation(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    return _by_rule(findings).get(alr03.RULE_IDS["server_name_impersonation"])


def test_lookalike_of_the_proxy_label_fails() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(_event("github", {"name": "gihtub", "version": "1.0.0"}))["findings"]

    finding = _impersonation(findings)
    assert finding is not None
    assert finding["outcome"] == "FAIL"
    assert finding["is_finding"] is True
    assert finding["severity"] == "high"
    # Evidence carries hashes and signal names, never the names themselves.
    assert "gihtub" not in str(finding["evidence"])


def test_homoglyph_of_a_known_name_fails() -> None:
    alr03.reset_state()
    alr03.evaluate(_event("slack", {"name": "slack", "version": "1.0.0"}))
    findings = alr03.evaluate(
        _event("gateway", {"name": "sl\u0430ck", "version": "9.9.9"})  # Cyrillic а
    )["findings"]

    finding = _impersonation(findings)
    assert finding is not None and finding["outcome"] == "FAIL"
    assert any(e["signal"] == "homoglyph_skeleton" for e in finding["evidence"])


def test_lookalike_hidden_in_the_title_field_fails() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(
        _event("jira", {"name": "internal-tools", "title": "jir\u0430", "version": "1.0.0"})
    )["findings"]

    finding = _impersonation(findings)
    assert finding is not None
    assert any(e["field"] == "title" for e in finding["evidence"])


def test_benign_identities_are_not_flagged() -> None:
    alr03.reset_state()
    alr03.evaluate(_event("github", {"name": "github", "version": "1.0.0"}))
    benign = [
        {"name": "github", "version": "2.0.0"},          # same name, new version
        {"name": "GitHub", "version": "1.0.0"},          # case only
        {"name": "@modelcontextprotocol/server-github", "version": "1.0.0"},  # namespaced
        {"name": "notion", "version": "1.0.0"},          # distinct
        {"name": "fake-weather", "version": "4.1.4"},    # label is a short alias
    ]
    for server_info in benign:
        findings = alr03.evaluate(_event("weather", server_info))["findings"]
        assert _impersonation(findings) is None, server_info


def test_separator_style_difference_is_not_impersonation() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(
        _event("google maps", {"name": "google-maps", "version": "1.0.0"})
    )["findings"]
    assert _impersonation(findings) is None


def test_score_combination_boosts_independent_signals() -> None:
    single = alr03.impersonation_verdict([("edit_distance_two", 0.70, False)])
    combined = alr03.impersonation_verdict(
        [("edit_distance_two", 0.70, False), ("bigram_near_match", 0.60, False)]
    )

    assert single[0] == "INCONCLUSIVE" and single[1] == 0.70
    assert combined[1] == round(0.70 + alr03.IMPERSONATION_BOOST, 3)
    assert combined[2] == "independent_corroboration"
    assert alr03.impersonation_verdict([]) == ("PASS", 0.0, "clear")


def test_short_names_do_not_trigger_distance_signals() -> None:
    alr03.reset_state()
    findings = alr03.evaluate(_event("git", {"name": "gut", "version": "1.0.0"}))["findings"]
    assert _impersonation(findings) is None


def test_baseline_rules_are_unchanged_by_the_new_method() -> None:
    """ALR03-001/002 behave exactly as before when no look-alike is present."""
    alr03.reset_state()
    first = alr03.evaluate(_event("weather", {"name": "weather", "version": "4.1.0"}))["findings"]
    assert _by_rule(first)[alr03.RULE_IDS["server_identification"]]["outcome"] == "PASS"
    assert alr03.RULE_IDS["server_identity_change"] not in _by_rule(first)

    second = alr03.evaluate(_event("weather", {"name": "weather", "version": "9.9.9"}))["findings"]
    assert _by_rule(second)[alr03.RULE_IDS["server_identity_change"]]["outcome"] == "FAIL"
    # A version change alone is not name impersonation.
    assert _impersonation(second) is None


def test_escaped_invisible_character_still_counts_as_impersonation() -> None:
    """The trace stores ``safe_text`` escapes; the gate compares what a reader would see."""
    from agent_latch.runtime.redact import safe_text

    declared = safe_text("githu\u200bb")
    assert "\\u200b" in declared
    findings = alr03.evaluate(_event("github", {"name": declared, "version": "1.0"}))["findings"]
    assert any(f.get("rule_id") == "ALR03-003" for f in findings), findings
