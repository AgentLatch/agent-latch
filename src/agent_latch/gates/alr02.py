"""ALR02 Tool Definition Integrity: did the advertised tool surface change from what was approved?

Reads each complete ``tools/list`` response, reduces every tool to a SHA-256 fingerprint of its
stable advertised fields (server label, tool reference, title, description, input and output
schema, annotations, ``_meta``; see ``agent_latch.runtime.tool_baseline``), and compares the set
with a baseline the operator approved. It reports:

- ``ALR02-001`` a tool in the baseline is advertised with a different definition (high)
- ``ALR02-002`` a tool that is not in the baseline is advertised (medium)
- ``ALR02-003`` a tool in the baseline is no longer advertised (medium)

A finding holds the server label, the tool reference, the change type and hashes. It never holds a
description, a schema or any other definition text.

Trust model
    The baseline is read from the file named by the operator policy key ``alr02_baseline``
    (``import-logs --policy``). It is never discovered, never taken from traffic, and a file with
    status ``candidate`` is refused. ``agent-latch-runtime baseline capture`` writes a candidate,
    and only ``baseline approve`` (an explicit operator command) makes one trusted. ``import-logs``
    refuses a baseline that sits inside a folder the monitored process writes. This gate never
    writes a file.

Inconclusive, never a pass
    ``ALR02-090`` is a coverage record. It is raised when the comparison cannot be made: no
    baseline configured or no entry for the server, an unreadable or candidate baseline, no payload
    record (``--payloads`` missing), an ambiguous server label or tool reference, a malformed
    definition, a list that continues on another page, or text cut by ``--payload-max-chars``.
    Nothing is compared in those cases, so a removed tool is never reported from a partial list.
    A complete comparison writes ``ALR02-099`` with the counts; a match is stated as a match and
    nothing more.

Scope. This gate detects change, not harm. It deliberately does not:

- judge what a definition says (instruction-like content is ALR04, which runs independently and
  still reports a definition that matches its baseline)
- judge who the server is (ALR03) or the transport (ALR12)
- show that a tool behaves as advertised: a matching hash says the description did not change

Monitor only. Nothing here blocks a call or changes traffic.

Known blind spots: the proxy records the definition after secret masking and truncation, so a
change inside a masked value is invisible; a server can advertise a different list to different
clients or sessions; a list that changes between two ``tools/list`` calls is compared each time;
only ``tools/list`` is compared, not the definition cached on a ``tools/call`` request; and the
baseline covers the servers it names, so a server missing from it is reported as inconclusive.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from threading import RLock
from typing import Any

from agent_latch.catalog import gate
from agent_latch.gates.alr04 import safe
from agent_latch.runtime.tool_baseline import (
    Baseline,
    BaselineError,
    Snapshot,
    load_baseline,
    snapshot_from_tools,
)

GATE_ID = "ALR02"
# Every ALR02 check cites its gate's OWASP categories (agent_latch.catalog).
OWASP = list(gate(GATE_ID).owasp)

CHANGED, ADDED, REMOVED = "changed", "added", "removed"
RULE_IDS = {CHANGED: "ALR02-001", ADDED: "ALR02-002", REMOVED: "ALR02-003"}
SEVERITY = {CHANGED: "high", ADDED: "medium", REMOVED: "medium"}
FAMILY = {CHANGED: "tool_changed", ADDED: "tool_added", REMOVED: "tool_removed"}
RULE_COVERAGE = "ALR02-090"
RULE_SUMMARY = "ALR02-099"
POLICY_KEY = "alr02_baseline"

MAX_REMEMBERED = 4096
MAX_SERVERS = 1024

_LOCK = RLock()
_declared: dict[str, set[str]] = {}  # server label -> names it declared in `initialize`
_reported: set[tuple[str, str, str, str]] = set()  # (server, tool, change, observed hash)
_cache: dict[str, tuple[tuple[int, ...], Baseline]] = {}


def reset_state() -> None:
    """Forget what earlier events showed. Tests call this; the importer does not need to."""
    with _LOCK:
        _declared.clear()
        _reported.clear()
        _cache.clear()


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _base(rule_id: str, family: str, server: str, tool: str, event: Mapping[str, Any]) -> dict:
    return {
        "gate_id": GATE_ID, "rule_id": rule_id, "family": family,
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "owasp": OWASP,
    }


def _suppression(policy: Mapping[str, Any] | None, rule_id: str) -> str | None:
    suppressions = (policy or {}).get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    return reason if isinstance(reason, str) and reason.strip() else None


def _coverage(event: Mapping[str, Any], reasons: list[str], server: str = "",
              snapshot: Snapshot | None = None) -> dict[str, Any]:
    record = _base(RULE_COVERAGE, "coverage", server, "", event) | {
        "outcome": "INCONCLUSIVE", "is_finding": True, "suppressed": False,
        "severity": "medium", "decision_reason": reasons[0], "coverage_notes": reasons,
        "evidence": [], "evidence_count": 0,
        "message": ("The tool list was not compared with an approved baseline: "
                    + ", ".join(reasons) + ". This is not a pass."),
    }
    if snapshot is not None and snapshot.tools:
        # Hashes only: enough to capture a candidate or to see the list is the same one.
        record["snapshot_sha256"] = snapshot.digest
        record["tool_count"] = len(snapshot.tools)
    return record


def _finding(change: str, server: str, tool: str, event: Mapping[str, Any],
             baseline_hash: str | None, observed_hash: str | None,
             policy: Mapping[str, Any] | None) -> dict[str, Any]:
    rule_id = RULE_IDS[change]
    reason = _suppression(policy, rule_id)
    evidence = [{"signal": f"definition_{change}", "field": "definition",
                 "baseline_sha256": baseline_hash, "observed_sha256": observed_hash}]
    return _base(rule_id, FAMILY[change], server, tool, event) | {
        "change_type": change, "outcome": "FAIL",
        "is_finding": reason is None, "suppressed": reason is not None,
        "suppression_reason": safe(reason, 160) if reason else None,
        "severity": SEVERITY[change], "evidence": evidence, "evidence_count": 1,
        "baseline_sha256": baseline_hash, "observed_sha256": observed_hash,
        "message": f"Tool {safe(tool)!r} of {safe(server)!r} was {change} "
                   "compared with the approved baseline.",
    }


def _summary(event: Mapping[str, Any], server: str, counts: Mapping[str, int],
             snapshot: Snapshot) -> dict[str, Any]:
    drift = counts[CHANGED] + counts[ADDED] + counts[REMOVED]
    return _base(RULE_SUMMARY, "scan_summary", server, "", event) | {
        "outcome": "FAIL" if drift else "PASS", "is_finding": False, "suppressed": False,
        "severity": "info", "evidence": [], "evidence_count": 0,
        "snapshot_sha256": snapshot.digest, "tool_count": len(snapshot.tools),
        "counts": dict(counts),
        "message": (f"Compared {len(snapshot.tools)} advertised tool(s) with the approved "
                    f"baseline: {counts['unchanged']} unchanged, {counts[CHANGED]} changed, "
                    f"{counts[ADDED]} added, {counts[REMOVED]} removed. A match shows the "
                    "definitions did not change, not that the tools behave as advertised."),
    }


def _load(policy: Mapping[str, Any] | None) -> Baseline:
    configured = (policy or {}).get(POLICY_KEY)
    if not isinstance(configured, str) or not configured.strip():
        raise BaselineError("baseline_not_configured", "no baseline in the operator policy")
    path = Path(configured).expanduser()
    key = str(path.resolve())
    try:
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            stamp = (info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns, info.st_size)
            with _LOCK:
                cached = _cache.get(key)
                if cached and cached[0] == stamp:
                    return cached[1]
            baseline = load_baseline(path, stream=stream)
    except OSError as error:
        raise BaselineError("baseline_unreadable", "the baseline file cannot be read") from error
    with _LOCK:
        _cache[key] = (stamp, baseline)
    return baseline


def _remember(key: tuple[str, str, str, str]) -> bool:
    """True when this exact change was already reported (a client listing tools again)."""
    with _LOCK:
        if key in _reported:
            return True
        if len(_reported) >= MAX_REMEMBERED:
            _reported.clear()
        _reported.add(key)
        return False


def _note_handshake(event: Mapping[str, Any]) -> None:
    payload = event.get("payload")
    info = payload.get("server_info") if isinstance(payload, Mapping) else None
    name = info.get("name") if isinstance(info, Mapping) else None
    label = event.get("server")
    if isinstance(label, str) and isinstance(name, str) and name:
        with _LOCK:
            if label in _declared or len(_declared) < MAX_SERVERS:
                _declared.setdefault(label, set()).add(safe(name, 200))


def compare(server: str, snapshot: Snapshot, baseline: Mapping[str, str],
            event: Mapping[str, Any], policy: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Drift records, then the summary, for a complete snapshot against its baseline entry."""
    counts = {"unchanged": 0, CHANGED: 0, ADDED: 0, REMOVED: 0}
    records: list[dict[str, Any]] = []
    for tool, observed in sorted(snapshot.tools.items()):
        expected = baseline.get(tool)
        change = ADDED if expected is None else CHANGED if expected != observed else None
        if change is None:
            counts["unchanged"] += 1
            continue
        counts[change] += 1
        if not _remember((server, tool, change, observed)):
            records.append(_finding(change, server, tool, event, expected, observed, policy))
    for tool, expected in sorted(baseline.items()):
        if tool not in snapshot.tools:
            counts[REMOVED] += 1
            if not _remember((server, tool, REMOVED, expected)):
                records.append(_finding(REMOVED, server, tool, event, expected, None, policy))
    records.append(_summary(event, server, counts, snapshot))
    return records


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Records for one normalised event. Only ``tools/list`` responses are inputs; any other
    event returns no records, which means "not my input", never "safe". ``policy`` is trusted
    operator configuration, never event content."""
    if not isinstance(event, Mapping):
        return {"findings": [_coverage({}, ["malformed_event"])]}
    method, stage = event.get("method"), event.get("stage")
    if method == "initialize":
        _note_handshake(event)
        return {"findings": []}
    if not (method == "tools/list" and stage == "response"):
        return {"findings": []}

    label = event.get("server")
    server = label.strip() if isinstance(label, str) else ""
    payload = event.get("payload")
    if not server:
        return {"findings": [_coverage(event, ["ambiguous_server_identity"])]}
    if not isinstance(payload, Mapping):
        return {"findings": [_coverage(event, ["payload_unavailable"], server)]}
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return {"findings": [_coverage(event, ["missing_or_invalid_tools_list"], server)]}

    cursor = bool(payload.get("next_cursor") or payload.get("nextCursor"))
    snapshot = snapshot_from_tools(server, tools, next_cursor=cursor)
    reasons = snapshot.problems
    with _LOCK:
        if len(_declared.get(server, ())) > 1:
            reasons.insert(0, "ambiguous_server_identity")
    entry = None
    try:
        baseline = _load(policy)
    except BaselineError as error:
        reasons.insert(0, error.code)
    else:
        entry = baseline.servers.get(server)
        if entry is None:
            reasons.insert(0, "no_baseline_for_server")
    if reasons or entry is None:
        return {"findings": [_coverage(event, reasons, server, snapshot)]}
    return {"findings": compare(server, snapshot, entry.tools, event, policy)}
