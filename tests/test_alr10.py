"""ALR10 secret-boundary gate tests: masked-location metadata, detection quality, no leaks."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from agent_latch.cli import main as cli_main
from agent_latch.gates import alr10
from agent_latch.gates.alr04 import reset_state
from agent_latch.runtime.events import ToolCall, ToolInfo, ToolOutput
from agent_latch.runtime.importer import RuntimeLogImporter, discover_gates
from agent_latch.runtime.payloads import PayloadFile, PayloadTap, masked_record
from agent_latch.runtime.redact import MASK, mask_secrets
from agent_latch.runtime.sqlite_store import SQLiteEventStore
from agent_latch.runtime.trace import TraceLog

# Fake, unique, token-shaped canary; concatenated so secret scanners never see a whole token.
CANARY = "ghp_" + "LeakCanary0042" * 2


def _event(
    stage: str,
    payload: dict[str, Any] | None,
    *,
    tool: str = "search_records",
    server: str = "demo",
    transport: str | None = None,
    order: int = 1,
) -> dict[str, Any]:
    return {
        "run_id": "run1", "order": order, "timestamp": "t", "session_id": "s",
        "request_id": str(order), "client_id": None, "server": server, "method": "tools/call",
        "stage": stage, "name": tool,
        "metadata": {"transport": transport} if transport else {},
        "payload": payload,
    }


def _masked_body(payload: dict[str, Any]) -> dict[str, Any]:
    """What the payload file would store for this payload body, metadata included."""
    return masked_record({"payload": payload}, 4000)["payload"]


def _request(arguments: dict[str, Any], *, definition: Any = None, **kwargs: Any) -> dict[str, Any]:
    tool = kwargs.get("tool", "search_records")
    body = _masked_body({"tool": tool, "arguments": arguments, "tool_definition": definition})
    return _event("request", body, **kwargs)


def _response(
    texts: tuple[str, ...] = (), structured: Any = None, **kwargs: Any
) -> dict[str, Any]:
    tool = kwargs.get("tool", "search_records")
    body = _masked_body({
        "tool": tool, "is_error": False, "content": list(texts), "structured": structured,
        "duration_ms": 1.0,
    })
    return _event("response", body, **kwargs)


def _findings(event: dict[str, Any], **kwargs: Any) -> list[dict[str, Any]]:
    return alr10.evaluate(event, **kwargs)["findings"]


def test_mask_value_reports_kind_and_path_of_every_masked_spot() -> None:
    body = _masked_body({
        "tool": "t",
        "arguments": {
            "api_key": "plainvalue",
            "token": CANARY,
            "note": "use sk-" + "ABCDEFGHIJKLMNOP1234",
            "nested": [{"password": "hunter2hunter2"}],
            "city": "London",
        },
        "tool_definition": None,
    })
    assert body["arguments"]["api_key"] == MASK and body["arguments"]["city"] == "London"
    spots = {(item["path"], item["kind"]) for item in body["masked"]}
    assert spots == {
        ("$/arguments/api_key", "key_name"),
        ("$/arguments/token", "token:github"),  # the shape survives even under a secret key
        ("$/arguments/note", "token:openai"),
        ("$/arguments/nested/0/password", "key_name"),
    }
    assert CANARY not in json.dumps(body)
    clean = _masked_body({"tool": "t", "arguments": {"city": "London"}, "tool_definition": None})
    assert "masked" not in clean  # nothing masked, nothing claimed


# --- labeled corpus: recall and false positives --------------------------------------------------

_SECRET_ARGUMENTS: list[dict[str, Any]] = [
    {"api_key": "zq18service7key"},
    {"password": "hunter2hunter2"},
    {"authorization": "Bearer " + "abcdefghijklmnop"},
    {"client_secret": "oddvalue12345"},
    {"access_token": "valuevaluevalue"},
    {"private_key": "shhh-value-1234"},
    {"query": "use sk-" + "ABCDEFGHIJKLMNOP1234"},
    {"note": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K"},
    {"body": "github_pat_" + "22AB" * 6},
    {"msg": "xoxb-" + "123456789-abcdefghij"},
    {"cfg": "key id AKIA" + "ABCDEFGHIJKLMNOP"},
    {"claims": "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0In0" + "." + "c2lnbmF0dXJl"},
    {"pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"},
    {"text": 'api_key="s3cr3tv4lu3"'},
    {"header": "Authorization: Bearer " + "abcd1234efgh5678"},
    {"config": "password = " + "sup3rs3cret99"},
    {"header": "Authorization: Basic " + "dXNlcjpwYXNz"},
]
_BENIGN_ARGUMENTS: list[dict[str, Any]] = [
    {"id": "123e4567-e89b-12d3-a456-426614174000"},
    {"sha": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a94a8fe5ccb19ba61c4c0873"},
    {"commit": "deadbeefcafebabe1234"},
    {"image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4"
              "2mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="},
    {"hash": "c2FtcGxlIGRhdGEgZm9yIHRlc3Rpbmc="},
    {"query": "is:open label:bug repo:acme/app"},
    {"token_count": 42},
    {"text": "Please rotate your password regularly."},
    {"url": "https://api.example.com/v2/items?page=3&sort=asc"},
    {"email": "dev@example.com"},
    {"version": "v2.11.3-beta.1"},
    {"path": "C:/Users/dev/project/readme.md"},
    {"mac": "00:1B:44:11:3A:B7"},
    {"timestamp": "2026-11-05T19:25:01Z"},
    {"customer": "cus_9aXkTpQ27misc"},
    {"description": "a perfectly ordinary argument " * 8},
    {"topic": "basic authentication tutorial"},
]


def test_basic_authentication_prose_is_benign_in_both_directions() -> None:
    assert _findings(_request({"topic": "basic authentication tutorial"})) == []
    assert _findings(_response(("A basic authentication tutorial.",))) == []
    assert _findings(_request({"topic": "Learn basic authentication."})) == []


def test_basic_credential_is_still_found_in_both_directions() -> None:
    credential = "Authorization: Basic " + "dXNlcjpwYXNz"
    assert [f["rule_id"] for f in _findings(_request({"header": credential}))] == ["ALR10-R01"]
    assert [f["rule_id"] for f in _findings(_response((credential,)))] == ["ALR10-R02"]


def test_all_lowercase_basic_credential_is_still_found_in_both_directions() -> None:
    credential = "Authorization: Basic " + "abcdefghijkl"
    assert [f["rule_id"] for f in _findings(_request({"header": credential}))] == ["ALR10-R01"]
    assert [f["rule_id"] for f in _findings(_response((credential,)))] == ["ALR10-R02"]
    assert mask_secrets("basic tutorial") == "basic [REDACTED]"


def test_labeled_corpus_recall_and_false_positive_rates() -> None:
    cases = [(args, True) for args in _SECRET_ARGUMENTS]
    cases += [(args, False) for args in _BENIGN_ARGUMENTS]
    assert len(cases) >= 30

    detected = missed = false_positives = 0
    for order, (arguments, is_secret) in enumerate(cases, 1):
        found = _findings(_request(arguments, order=order))
        hit = any(f["rule_id"] == "ALR10-R01" and f["is_finding"] for f in found)
        if is_secret:
            detected += hit
            missed += not hit
        else:
            false_positives += hit
    recall = detected / len(_SECRET_ARGUMENTS)
    fp_rate = false_positives / len(_BENIGN_ARGUMENTS)
    assert recall >= 0.85, f"recall {recall:.2f} ({missed} missed)"
    assert fp_rate <= 0.10, f"false-positive rate {fp_rate:.2f}"


def test_token_shaped_argument_is_high_and_key_name_to_local_server_is_medium() -> None:
    high = _findings(_request({"note": "use sk-" + "ABCDEFGHIJKLMNOP1234"}))
    assert [(f["rule_id"], f["outcome"], f["severity"]) for f in high] == [
        ("ALR10-R01", "FAIL", "high")
    ]
    medium = _findings(_request({"api_key": "plainvalue"}))
    assert [(f["rule_id"], f["severity"]) for f in medium] == [("ALR10-R01", "medium")]
    assert medium[0]["evidence"] == [
        {"signal": "key_name", "field": "$/arguments/api_key", "source": "masking"}
    ]
    assert "ASI03" in medium[0]["owasp"]


def test_any_secret_to_a_remote_server_is_high() -> None:
    found = _findings(_request({"api_key": "plainvalue"}, transport="http"))
    assert found[0]["severity"] == "high" and found[0]["outcome"] == "FAIL"
    assert _findings(_request({"api_key": "plainvalue"}, transport="stdio"))[0]["severity"] == "medium"


def test_tool_output_with_a_secret_is_reported() -> None:
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    found = _findings(_response((f"aws_access_key_id = {aws}",)))
    assert [(f["rule_id"], f["severity"]) for f in found] == [("ALR10-R02", "high")]
    assert found[0]["evidence"][0]["field"] == "$/content/0"
    structured = _findings(_response((), {"user": "alice", "password": "hunter2hunter2"}))
    assert [(f["rule_id"], f["severity"]) for f in structured] == [("ALR10-R02", "medium")]
    assert structured[0]["evidence"][0]["field"] == "$/structured/password"


def test_old_records_without_masked_metadata_still_fire_on_the_marker() -> None:
    body = {"tool": "search_records", "arguments": {"api_key": MASK}, "tool_definition": None}
    found = _findings(_event("request", body))
    assert [(f["rule_id"], f["outcome"], f["severity"]) for f in found] == [
        ("ALR10-R01", "FAIL", "medium")
    ]
    assert found[0]["evidence"] == [
        {"signal": "redacted_marker", "field": "$/arguments/api_key", "source": "marker"}
    ]


def test_unmasked_token_in_a_foreign_record_is_reported_by_kind_only() -> None:
    body = {"tool": "t", "arguments": {"q": "sk-" + "ABCDEFGHIJKLMNOP1234"}, "tool_definition": None}
    found = _findings(_event("request", body))
    assert found[0]["severity"] == "high"
    assert found[0]["evidence"][0]["signal"] == "unmasked:token:openai"
    assert "ABCDEFGHIJKLMNOP1234" not in json.dumps(found)


def test_auth_purpose_tools_are_inconclusive_low_but_still_reported() -> None:
    by_name = _findings(_request({"password": "hunter2hunter2"}, tool="user_login"))
    assert [(f["outcome"], f["severity"], f["is_finding"]) for f in by_name] == [
        ("INCONCLUSIVE", "low", True)
    ]
    definition = {"input_schema": {"properties": {"password": {}, "user": {}}}}
    by_schema = _findings(_request({"password": "hunter2hunter2"}, definition=definition,
                                   tool="create_session"))
    assert by_schema[0]["outcome"] == "INCONCLUSIVE" and by_schema[0]["severity"] == "low"


def test_operator_allowlist_turns_an_expected_case_into_pass_with_a_note() -> None:
    policy = {"allowed_secret_tools": [{"server": "demo", "tool": "search_records"}]}
    found = _findings(_request({"api_key": "plainvalue"}), policy=policy)
    assert [(f["outcome"], f["is_finding"]) for f in found] == [("PASS", False)]
    assert found[0]["note"] == "allowed by policy.allowed_secret_tools"
    other = _findings(_request({"api_key": "plainvalue"}, server="other"), policy=policy)
    assert other[0]["outcome"] == "FAIL"  # the allowlist is exact, per server and tool


def test_missing_payloads_yield_a_coverage_record_not_a_pass() -> None:
    found = _findings(_event("request", None))
    assert [(f["rule_id"], f["outcome"], f["is_finding"]) for f in found] == [
        ("ALR10-R90", "INCONCLUSIVE", True)
    ]
    assert _findings({"method": "tools/list", "stage": "response", "payload": None}) == []


def test_clean_calls_produce_no_records() -> None:
    assert _findings(_request({"city": "London"})) == []
    assert _findings(_response(("rainy, 18 degrees",))) == []


def test_no_secret_value_appears_in_any_gate_output_file_or_report(
    tmp_path: Path, capsys
) -> None:
    reset_state()
    trace_path, payloads_path = tmp_path / "trace.jsonl", tmp_path / "payloads.jsonl"
    trace = TraceLog(trace_path, summary=None, transport="http")
    payload_file = PayloadFile(payloads_path)
    tap = PayloadTap([payload_file])
    tools = [ToolInfo("search_issues", "demo", "Search issues.", {"type": "object"})]
    trace.tools_listed(session_id="s", request_id="1", server="demo", tools=tools)
    tap.tools_listed(session_id="s", request_id="1", client_id=None, server="demo", tools=tools)
    call = ToolCall("s", "2", None, "search_issues", "demo",
                    {"query": "is:open", "token": CANARY}, "t")
    trace.call_request(call)
    tap.call_request(call)
    output = ToolOutput((f"authenticated with {CANARY}",), None, False)
    trace.call_response(call, output, 1.0)
    tap.call_response(call, output, 1.0)
    trace.close()
    payload_file.close()

    events_csv = tmp_path / "events.csv"
    results_csv = tmp_path / "gate-results.csv"
    normalized = tmp_path / "normalized.jsonl"
    database = tmp_path / "runtime.db"
    RuntimeLogImporter(
        trace_path, results_csv, discover_gates(), payloads_path=payloads_path,
        events_csv=events_csv, normalized_path=normalized, store=SQLiteEventStore(database),
        follow=False,
    ).run()

    with results_csv.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    found = [
        finding
        for row in rows
        for finding in json.loads(row["result_json"])["findings"]
        if finding.get("gate_id") == "ALR10"
    ]
    assert {f["rule_id"] for f in found} == {"ALR10-R01", "ALR10-R02"}
    request = next(f for f in found if f["rule_id"] == "ALR10-R01")
    assert request["outcome"] == "FAIL" and request["severity"] == "high"
    assert {"signal": "token:github", "field": "$/arguments/token", "source": "masking"} in (
        request["evidence"]
    )

    assert cli_main([str(tmp_path), "--runtime-result", str(results_csv), "--plain",
                     "--fail-on", "none"]) == 0
    captured = capsys.readouterr()
    assert "ALR10-R01" in captured.out and "ALR10-R02" in captured.out

    canary = CANARY.encode("utf-8")
    for path in (trace_path, payloads_path, events_csv, results_csv, normalized, database):
        assert canary not in path.read_bytes(), f"the planted token leaked into {path.name}"
    assert CANARY not in captured.out and CANARY not in captured.err
