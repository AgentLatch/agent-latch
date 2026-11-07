"""ALR03 Tool and Agent Endpoint Trust: is the MCP server identified, and is it the same one?

Reads the connection handshake (``initialize`` / ``server/discover``), which the middleware
records as an ``initialize`` event carrying the client and server ``Implementation`` (name and
version) and the negotiated protocol version. From that the gate checks:

- ``ALR03-001`` server identification: the handshake names the server (and, for review, the
  client). An unidentified endpoint cannot be told apart from an impostor.
- ``ALR03-002`` server identity change: the same logical server (the proxy's ``server`` label)
  presented a different name or version than an earlier run. A changed identity can mean a
  compromised or swapped server and deserves review before its tools are trusted.
- ``ALR03-003`` server name impersonation: the self-declared name (or title) is a look-alike of
  the operator's proxy label or of a name seen earlier in the run — a typosquat such as
  ``gihtub`` or a homoglyph such as ``slаck`` with a Cyrillic ``а``. Detection is string
  similarity only: Unicode confusable folding, Damerau optimal-string-alignment distance and
  bigram Jaccard overlap. No regular expressions are used for signal extraction or
  classification, so reworded or visually disguised names that phrase lists miss are still
  caught.

Scope. This gate looks only at who an endpoint claims to be. It deliberately does not:

- judge what a tool definition *says* (instruction-like content is ALR04)
- pin or detect changes to a server's *tool list* (tool integrity is ALR02)
- authenticate the transport, or judge TLS / plain HTTP (secure transport is ALR12)
- observe what the agent did with the connection (needs cross-event correlation)

Monitor only. A finding records that an endpoint was unidentified or that its identity changed;
it never blocks the connection, and a PASS is not proof that a server is trustworthy. The gate
does not clear a server.

Known blind spots: identity is self-declared by the server (a malicious server can lie about its
name and version); the change and impersonation baselines are in-memory, so they only compare
connections within one importer run unless a store keeps prior events; a server that never
completes a handshake this gate sees is invisible to it; and impersonation looks only at
look-alike names — an impostor that picks a wholly original name, or one that differs by
separators or word order alone, is not flagged.
"""

from __future__ import annotations

import unicodedata
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
    "server_name_impersonation",
)
RULE_IDS = {name: f"ALR03-{i:03d}" for i, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR03-090"
RULE_SUMMARY = "ALR03-099"

MAX_REMEMBERED = 2048
MAX_SERVERS = 1024
MAX_KNOWN_NAMES = 1024
MAX_NAME_CHARS = 120
MIN_SIMILARITY_LENGTH = 4
MAX_COMPARED_NAMES = 512

# Impersonation score bands: hard-look-alike evidence fails on its own; weaker similarity is
# reported for review. Two independent signal classes against the same reference corroborate.
IMPERSONATION_FAIL_AT = 0.85
IMPERSONATION_REVIEW_AT = 0.55
IMPERSONATION_BOOST = 0.10


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


# --- impersonation signals: string similarity only, no regular expressions ----------------------

# Well-known look-alikes (Unicode TR39 style): Cyrillic/Greek homoglyphs and leet substitutions.
_CONFUSABLE_FROM = "аеорсхуіјѕԁһӏАВЕКМНОРСТХУΑΒΕΖΗΙΚΜΝΟΡΤΥΧοναρτιυκ0134578@$!"
_CONFUSABLE_TO = "aeopcxyijsdhlABEKMHOPCTXYABEZHIKMNOPTYXovaptiukoleastbasi"
_CONFUSABLE_FOLD = {ord(a): b for a, b in zip(_CONFUSABLE_FROM, _CONFUSABLE_TO, strict=True)}
# Separator-only differences ("google maps" vs "google-maps") are styling, not impersonation.
_SEPARATORS = {ord(c): None for c in " -_./"}


def _skeleton(name: str) -> str:
    """Confusable-folded form: two names with the same skeleton look alike to a reader."""
    return unicodedata.normalize("NFKC", name).casefold().translate(_CONFUSABLE_FOLD)


def _osa_distance(a: str, b: str, cutoff: int = 3) -> int:
    """Damerau optimal-string-alignment distance, early-exiting above ``cutoff``."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cutoff:
        return cutoff + 1
    previous = list(range(len(b) + 1))
    before: list[int] = []
    for i, ca in enumerate(a, 1):
        row = [i] + [0] * len(b)
        best = row[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            value = min(previous[j] + 1, row[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and cb == a[i - 2]:
                value = min(value, before[j - 2] + 1)  # transposition
            row[j] = value
            best = min(best, value)
        if best > cutoff:
            return cutoff + 1
        before, previous = previous, row
    return previous[-1]


def _bigram_jaccard(a: str, b: str) -> float:
    """Character-bigram overlap; catches near-misses that single edits understate."""
    grams_a = {a[i:i + 2] for i in range(len(a) - 1)} or {a}
    grams_b = {b[i:i + 2] for i in range(len(b) - 1)} or {b}
    return len(grams_a & grams_b) / len(grams_a | grams_b)


def _contained(a: str, b: str) -> bool:
    """One name inside the other with room to spare: namespacing, not squatting.

    ``@scope/server-github`` contains ``github`` and ``fake-weather`` contains ``weather``; both
    are ordinary. A one-edit difference (``githu`` inside ``github``) is a classic deletion
    typosquat, so containment only excuses a pair when the length gap is more than two.
    """
    return a != b and (a in b or b in a) and abs(len(a) - len(b)) > 2


def impersonation_signals(declared: str, reference: str) -> list[tuple[str, float, bool]]:
    """(signal, weight, hard) triples for a look-alike pair; empty for an innocent pair.

    Pure string similarity: confusable skeletons, bounded edit distance, bigram overlap.
    """
    declared, reference = declared.strip(), reference.strip()
    if not declared or not reference:
        return []
    low_a, low_b = declared.casefold(), reference.casefold()
    if low_a == low_b or low_a.translate(_SEPARATORS) == low_b.translate(_SEPARATORS):
        return []  # same name; case, styling or separator differences are not impersonation
    signals: list[tuple[str, float, bool]] = []
    if _skeleton(declared) == _skeleton(reference):
        # Reads identically but is written differently: a homoglyph or leet look-alike.
        signals.append(("homoglyph_skeleton", 0.95, True))
    if min(len(declared), len(reference)) >= MIN_SIMILARITY_LENGTH and not _contained(low_a, low_b):
        distance = _osa_distance(low_a, low_b)
        overlap = _bigram_jaccard(low_a, low_b)
        if distance == 1:
            signals.append(("edit_distance_one", 0.85, True))
        elif distance == 2 and overlap >= 0.6:
            signals.append(("edit_distance_two", 0.70, False))
        if overlap >= 0.75 and distance <= 3 and abs(len(declared) - len(reference)) <= 2:
            signals.append(("bigram_near_match", 0.60, False))
    return signals


def impersonation_verdict(
    signals: list[tuple[str, float, bool]],
) -> tuple[str, float, str]:
    """(outcome, score, reason): strongest signal, boosted by independent corroboration."""
    if not signals:
        return "PASS", 0.0, "clear"
    score = max(weight for _, weight, _ in signals)
    if len({signal for signal, _, _ in signals}) >= 2:
        score = min(1.0, score + IMPERSONATION_BOOST)
        reason = "independent_corroboration"
    else:
        reason = "single_signal"
    score = round(score, 3)
    if score >= IMPERSONATION_FAIL_AT:
        return "FAIL", score, reason
    if score >= IMPERSONATION_REVIEW_AT:
        return "INCONCLUSIVE", score, reason
    return "PASS", score, reason


# --- cross-run identity baseline ---------------------------------------------------------------

_lock = RLock()
# server label -> {"name":..., "version":...} of the identity first seen this importer run.
_seen: OrderedDict[str, dict[str, str]] = OrderedDict()
# Every distinct self-declared server name seen this run; impersonation is checked against it.
_known_names: OrderedDict[str, bool] = OrderedDict()


def reset_state() -> None:
    """Forget the identity baseline (tests, or a new importer run)."""
    with _lock:
        _seen.clear()
        _known_names.clear()


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


def _known_name_snapshot() -> list[str]:
    with _lock:
        return list(_known_names)[-MAX_COMPARED_NAMES:]


def _remember_name(name: str) -> None:
    with _lock:
        if name in _known_names:
            _known_names.move_to_end(name)
            return
        _known_names[name] = True
        while len(_known_names) > MAX_KNOWN_NAMES:
            _known_names.popitem(last=False)


def startup_capabilities() -> list[dict[str, str]]:
    """What this gate cannot check, for a dispatcher to report up front instead of a silent PASS."""
    return [
        {"check": "server_identification", "outcome": "SUPPORTED"},
        {"check": "server_identity_change", "outcome": "SUPPORTED"},
        {"check": "server_name_impersonation", "outcome": "SUPPORTED"},
        {"check": "transport_authentication", "outcome": "UNSUPPORTED",
         "reason": "TLS and credential verification belong to secure transport (ALR12)."},
        {"check": "tool_list_integrity", "outcome": "UNSUPPORTED",
         "reason": "Tool definition pinning and change detection belong to ALR02."},
        {"check": "novel_name_impostor", "outcome": "UNSUPPORTED",
         "reason": "Impersonation is similarity-based; an impostor with a wholly original name "
                   "leaves no look-alike signal."},
        {"check": "cross_run_baseline", "outcome": "PARTIAL",
         "reason": "Identity is compared within one importer run; a persistent baseline needs a "
                   "store of prior handshakes."},
    ]


def _impersonation_finding(*, server: str, event: Mapping[str, Any], declared: str,
                           field: str, reference: str, reference_kind: str,
                           signals: list[tuple[str, float, bool]], outcome: str, score: float,
                           reason: str, policy: Mapping[str, Any] | None) -> dict[str, Any]:
    evidence = [
        {"signal": signal, "field": field, "sha256": digest(f"{declared}|{reference}"),
         "strength": "hard" if hard else "soft"}
        for signal, _, hard in signals
    ]
    evidence.append({"signal": f"resembles_{reference_kind}", "field": field,
                     "sha256": digest(reference), "strength": "soft"})
    resembles = ("the proxy label" if reference_kind == "proxy_label"
                 else "a name seen earlier this run")
    message = {
        "FAIL": f"The server's declared name is a look-alike of {resembles}; "
                "possible impersonation.",
        "INCONCLUSIVE": "The server's declared name is similar to a known name; review whether "
                        "this endpoint is the server it claims to be.",
    }[outcome]
    result = _result(
        category="server_name_impersonation", server=server, event=event, outcome=outcome,
        severity="high" if outcome == "FAIL" else "medium", message=message,
        evidence=evidence, policy=policy,
    )
    result["score"] = score
    result["decision_reason"] = reason
    return result


def _check_impersonation(server: str, event: Mapping[str, Any], server_info: Mapping[str, Any],
                         policy: Mapping[str, Any] | None) -> tuple[list[dict[str, Any]], str]:
    """ALR03-003: compare the declared name/title with the proxy label and known names."""
    findings: list[dict[str, Any]] = []
    worst = "PASS"
    references = [("proxy_label", server)] if server.strip() else []
    references += [("known_name", name) for name in _known_name_snapshot()]
    declared_fields = [
        (field, server_info.get(field)) for field in ("name", "title")
    ]
    for field, value in declared_fields:
        if not isinstance(value, str) or not value.strip():
            continue
        declared = value[:MAX_NAME_CHARS]
        best: tuple[str, str, list[tuple[str, float, bool]]] | None = None
        for reference_kind, reference in references:
            signals = impersonation_signals(declared, reference[:MAX_NAME_CHARS])
            if not signals:
                continue
            if best is None or max(w for _, w, _ in signals) > max(w for _, w, _ in best[2]):
                best = (reference_kind, reference, signals)
        if best is None:
            continue
        reference_kind, reference, signals = best
        outcome, score, reason = impersonation_verdict(signals)
        if outcome == "PASS":
            continue
        findings.append(_impersonation_finding(
            server=server, event=event, declared=declared, field=field, reference=reference,
            reference_kind=reference_kind, signals=signals, outcome=outcome, score=score,
            reason=reason, policy=policy,
        ))
        if outcome == "FAIL" or (outcome == "INCONCLUSIVE" and worst == "PASS"):
            worst = outcome
    return findings, worst


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

    # ALR03-003: is the declared name a look-alike of the proxy label or a known name?
    if identified:
        impersonation, imp_worst = _check_impersonation(server, event, server_info, policy)
        findings.extend(impersonation)
        if imp_worst == "FAIL" or (imp_worst == "INCONCLUSIVE" and worst == "PASS"):
            worst = imp_worst
        for field in ("name", "title"):
            value = server_info.get(field)
            if isinstance(value, str) and value.strip():
                _remember_name(value.strip()[:MAX_NAME_CHARS])

    findings.append(_summary_record(event, server, outcome=worst))
    return {"findings": findings}
