"""ALR03 Tool and Agent Endpoint Trust: is the MCP server identified, and is it the same one?

Reads the connection handshake (``initialize`` / ``server/discover``), which the middleware
records as an ``initialize`` event carrying the client and server ``Implementation`` (name and
version) and the negotiated protocol version. From that the gate checks:

- ``ALR03-001`` server identification: the handshake names the server (and, for review, the
  client). An unidentified endpoint cannot be told apart from an impostor.
- ``ALR03-002`` server identity change: the same logical server (the proxy's ``server`` label)
  presented a different name or version than an earlier run. A changed identity can mean a
  compromised or swapped server and deserves review before its tools are trusted.

Scope. This gate looks only at who an endpoint claims to be. It deliberately does not:

- judge what a tool definition *says* (instruction-like content is ALR04)
- pin or detect changes to a server's *tool list* (tool integrity is ALR02)
- authenticate the transport, or judge TLS / plain HTTP (secure transport is ALR12)
- observe what the agent did with the connection (needs cross-event correlation)

Monitor only. A finding records that an endpoint was unidentified or that its identity changed;
it never blocks the connection, and a PASS is not proof that a server is trustworthy. The gate
does not clear a server.

Known blind spots: identity is self-declared by the server (a malicious server can lie about its
name and version); the change baseline is in-memory, so it only compares connections within one
importer run unless a store keeps prior events; and a server that never completes a handshake
this gate sees is invisible to it.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from threading import RLock
from typing import Any

from agent_latch.catalog import gate
from agent_latch.gates.alr04 import digest, safe

GATE_ID = "ALR03"
# Every ALR03 check cites its gate's OWASP categories (agent_latch.catalog).
OWASP = list(gate(GATE_ID).owasp)

CATEGORIES = (
    "server_identification",
    "server_identity_change",
)
RULE_IDS = {name: f"ALR03-{i:03d}" for i, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR03-090"
RULE_SUMMARY = "ALR03-099"

MAX_REMEMBERED = 2048
MAX_SERVERS = 1024


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _result(*, category: str, server: str, event: Mapping[str, Any], outcome: str,
            severity: str, message: str, evidence: list[dict[str, Any]],
            policy: Mapping[str, Any] | None) -> dict[str, Any]:
    rule_id = RULE_IDS[category]
    suppressions = (policy or {}).get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    suppressed = isinstance(reason, str) and bool(reason.strip())
    return {
        "gate_id": GATE_ID, "rule_id": rule_id, "family": category,
        "entity": {"server": safe(server), "tool": ""},
        "record_id": _pointer(event), "outcome": outcome,
        "is_finding": outcome != "PASS" and not suppressed,
        "suppressed": suppressed,
        "suppression_reason": safe(reason, 160) if suppressed else None,
        "severity": severity,
        "evidence": evidence, "evidence_count": len(evidence),
        "owasp": OWASP,
        "message": message,
    }


def _coverage_record(event: Mapping[str, Any], reason: str, *, server: str = "") -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": RULE_COVERAGE, "family": "coverage",
        "entity": {"server": safe(server), "tool": ""}, "record_id": _pointer(event),
        "outcome": "INCONCLUSIVE", "is_finding": True, "suppressed": False,
        "severity": "medium", "decision_reason": reason, "coverage_notes": [reason],
        "owasp": OWASP, "evidence": [], "evidence_count": 0,
        "message": "The handshake was not fully captured, so the endpoint cannot be identified.",
    }


def _summary_record(event: Mapping[str, Any], server: str, *, outcome: str) -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": RULE_SUMMARY, "family": "scan_summary",
        "entity": {"server": safe(server), "tool": ""}, "record_id": _pointer(event),
        "outcome": outcome, "is_finding": False, "suppressed": False, "severity": "info",
        "owasp": OWASP, "evidence": [], "evidence_count": 0,
        "message": "Handshake trust summary for this event.",
    }


def _identity_text(info: Mapping[str, Any]) -> str:
    """Stable string to hash for an identity; only name/version, never secret material."""
    name = info.get("name") if isinstance(info.get("name"), str) else ""
    version = info.get("version") if isinstance(info.get("version"), str) else ""
    return f"{name}@{version}"


# --- cross-run identity baseline ---------------------------------------------------------------

_lock = RLock()
# server label -> {"name":..., "version":...} of the identity first seen this importer run.
_seen: OrderedDict[str, dict[str, str]] = OrderedDict()


def reset_state() -> None:
    """Forget the identity baseline (tests, or a new importer run)."""
    with _lock:
        _seen.clear()


def _remember_identity(server: str, identity: dict[str, str]) -> dict[str, str] | None:
    """Return the prior identity for ``server`` if it differs, else record and return None."""
    with _lock:
        prior = _seen.get(server)
        if prior is None:
            _seen[server] = identity
            while len(_seen) > MAX_SERVERS:
                _seen.popitem(last=False)
            return None
        _seen.move_to_end(server)
        return prior if prior != identity else None


def startup_capabilities() -> list[dict[str, str]]:
    """What this gate cannot check, for a dispatcher to report up front instead of a silent PASS."""
    return [
        {"check": "server_identification", "outcome": "SUPPORTED"},
        {"check": "server_identity_change", "outcome": "SUPPORTED"},
        {"check": "transport_authentication", "outcome": "UNSUPPORTED",
         "reason": "TLS and credential verification belong to secure transport (ALR12)."},
        {"check": "tool_list_integrity", "outcome": "UNSUPPORTED",
         "reason": "Tool definition pinning and change detection belong to ALR02."},
        {"check": "cross_run_baseline", "outcome": "PARTIAL",
         "reason": "Identity is compared within one importer run; a persistent baseline needs a "
                   "store of prior handshakes."},
    ]


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Findings for one importer event. ``policy`` must be trusted operator configuration."""
    if not isinstance(event, Mapping):
        return {"findings": [_coverage_record({}, "malformed_event")]}
    if event.get("method") != "initialize":
        return {"findings": []}  # not an ALR03 input; not a PASS either

    server = str(event.get("server") or "")
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        return {"findings": [_coverage_record(event, "payload_unavailable", server=server)]}

    server_info = payload.get("server_info")
    client = payload.get("client")
    if not isinstance(server_info, Mapping):
        return {"findings": [_coverage_record(event, "missing_server_info", server=server)]}
    client_info = client if isinstance(client, Mapping) else {}

    findings: list[dict[str, Any]] = []
    worst = "PASS"

    # ALR03-001: is the server identified?
    server_name = server_info.get("name")
    identified = isinstance(server_name, str) and bool(server_name.strip())
    id_evidence = [
        {"signal": "server_info", "field": "server_info",
         "sha256": digest(_identity_text(server_info))},
    ]
    if isinstance(client_info.get("name"), str) and client_info.get("name"):
        id_evidence.append({"signal": "client_info", "field": "client",
                            "sha256": digest(_identity_text(client_info))})
    if identified:
        findings.append(_result(
            category="server_identification", server=server, event=event, outcome="PASS",
            severity="info", evidence=id_evidence, policy=policy,
            message="The server identified itself in the handshake.",
        ))
    else:
        findings.append(_result(
            category="server_identification", server=server, event=event, outcome="FAIL",
            severity="high", evidence=id_evidence, policy=policy,
            message="The server did not identify itself in the handshake; an unidentified "
                    "endpoint cannot be distinguished from an impostor.",
        ))
        worst = "FAIL"

    # ALR03-002: did this server's identity change versus earlier in the run?
    identity = {
        "name": server_name if isinstance(server_name, str) else "",
        "version": server_info.get("version") if isinstance(server_info.get("version"), str) else "",
    }
    prior = _remember_identity(server, identity)
    if prior is not None:
        findings.append(_result(
            category="server_identity_change", server=server, event=event, outcome="FAIL",
            severity="high", policy=policy,
            evidence=[
                {"signal": "prior_identity", "field": "server_info",
                 "sha256": digest(_identity_text(prior))},
                {"signal": "current_identity", "field": "server_info",
                 "sha256": digest(_identity_text(identity))},
            ],
            message="The server's name or version changed versus an earlier connection this run; "
                    "re-approve the endpoint before trusting its tools.",
        ))
        worst = "FAIL"

    findings.append(_summary_record(event, server, outcome=worst))
    return {"findings": findings}
