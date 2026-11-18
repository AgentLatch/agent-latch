"""ALR02 Tool Definition Integrity: tool definitions are pinned and changes are detected.

Reads ``tools/list`` responses from the payload record (the definitions an MCP server hands the
agent) and compares each tool with what was seen before. Three detectors:

- ``ALR02-R01`` definition changed during the run: a tool listed earlier now has a different
  description, input schema or annotations (the "rug pull": a server that behaves until it is
  trusted). Needs no policy.
- ``ALR02-R02`` definition differs from the operator's pin: ``policy.pinned_tools`` records the
  SHA-256 the operator reviewed for a ``server``/``tool`` pair, and the listed definition does
  not match it.
- ``ALR02-R03`` tool is not pinned: the operator pinned some tools of this server, and this one
  is not among them, so nobody reviewed it.

Operator pins. ``policy.pinned_tools`` is a list of ``{server, tool, sha256}`` in the file given
to ``import-logs --policy``. It is trusted operator configuration and must never come from the
monitored project or from MCP traffic. ``python -m agent_latch.gates.alr02 normalized.jsonl``
prints the current digest of every listed tool, to review and copy into the policy.

Coverage (``ALR02-090``). Definitions are in the payload file only; without ``--payloads`` there
is nothing to compare, and the gate emits one coverage record per run. A malformed
``pinned_tools`` entry is reported once per run, never ignored silently. ``ALR02-099`` is a
per-list summary (tools seen, pinned, changed).

Scope. The gate compares definitions with each other and with the operator's pins. It does not:

- judge what a definition *says* (instruction-like or hidden text is ALR04)
- judge server identity (ALR03) or transport security (ALR12)
- see a tool list the proxy never carried, or a change between two runs unless the operator
  pinned it (state lives for one importer run)
- notice a pinned tool that disappeared from the list (removal is not a change in its text)

Monitor only. A finding records that a definition differs from a reference; it never blocks the
call, and a clean run is not proof that the definitions are safe, only that they did not change
or match the pin. Findings hold field names and hashes, never the definition text.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import OrderedDict
from collections.abc import Mapping
from pathlib import Path
from threading import RLock
from typing import Any

from agent_latch.catalog import gate
from agent_latch.runtime.text.engine import safe

GATE_ID = "ALR02"
OWASP = list(gate(GATE_ID).owasp)

CATEGORIES = ("definition_changed", "pin_mismatch", "tool_not_pinned")
RULE_IDS = {name: f"ALR02-R{i:02d}" for i, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR02-090"
RULE_SUMMARY = "ALR02-099"
POLICY_KEYS = ("suppressions", "pinned_tools")  # top-level operator policy keys this gate reads

MAX_TOOLS_PER_LIST = 512
MAX_REMEMBERED = 8192
# The parts of a definition that reach the model or constrain a call.
PARTS = ("description", "inputSchema", "annotations")

_lock = RLock()
_seen: OrderedDict[tuple[str, str], dict[str, str]] = OrderedDict()
_coverage_done: set[str] = set()


def reset_state() -> None:
    """Forget remembered definitions and emitted coverage records (tests, new runs)."""
    with _lock:
        _seen.clear()
        _coverage_done.clear()


def _digest(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _canonical(tool: Mapping[str, Any]) -> dict[str, Any]:
    """The pinned parts under one spelling: the proxy records ``input_schema``, MCP says
    ``inputSchema``. Both give the same digest, so a pin works with either source."""
    schema = tool["inputSchema"] if "inputSchema" in tool else tool.get("input_schema")
    return {"description": tool.get("description"), "inputSchema": schema,
            "annotations": tool.get("annotations")}


def definition_parts(tool: Mapping[str, Any]) -> dict[str, str]:
    """SHA-256 of each pinned part of a tool definition, plus ``all`` for the whole."""
    canonical = _canonical(tool)
    parts = {part: _digest(canonical[part]) for part in PARTS}
    parts["all"] = _digest({"name": tool.get("name"), **canonical})
    return parts


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _suppression(policy: Mapping[str, Any] | None, rule_id: str) -> str | None:
    suppressions = (policy or {}).get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    return reason.strip() if isinstance(reason, str) and reason.strip() else None


def _result(*, category: str, tool: str, server: str, event: Mapping[str, Any], outcome: str,
            severity: str, message: str, evidence: list[dict[str, Any]],
            policy: Mapping[str, Any] | None) -> dict[str, Any]:
    rule_id = RULE_IDS[category]
    reason = _suppression(policy, rule_id)
    suppressed = reason is not None
    return {
        "gate_id": GATE_ID, "rule_id": rule_id, "family": category,
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "outcome": outcome,
        "is_finding": outcome != "PASS" and not suppressed,
        "suppressed": suppressed, "suppression_reason": safe(reason, 160) if reason else None,
        "severity": severity, "owasp": OWASP,
        "evidence": evidence, "evidence_count": len(evidence), "message": message,
    }


def _coverage_record(event: Mapping[str, Any], reason: str, server: str = "") -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": RULE_COVERAGE, "family": "coverage",
        "entity": {"server": safe(server), "tool": ""}, "record_id": _pointer(event),
        "outcome": "INCONCLUSIVE", "is_finding": True, "suppressed": False,
        "severity": "medium", "decision_reason": reason, "coverage_notes": [reason],
        "owasp": OWASP, "evidence": [], "evidence_count": 0,
        "message": "Tool definitions were not compared, so changes cannot be detected.",
    }


def _once(event: Mapping[str, Any], reason: str, server: str) -> list[dict[str, Any]]:
    with _lock:
        if reason in _coverage_done:
            return []
        _coverage_done.add(reason)
    return [_coverage_record(event, reason, server)]


def _pins(policy: Mapping[str, Any] | None) -> tuple[dict[tuple[str, str], str], bool]:
    """(pins by (server, tool), valid). Anything malformed makes the policy invalid, not empty."""
    raw = (policy or {}).get("pinned_tools")
    if raw is None:
        return {}, True
    if not isinstance(raw, list):
        return {}, False
    pins: dict[tuple[str, str], str] = {}
    valid = True
    for item in raw:
        if (isinstance(item, Mapping) and isinstance(item.get("server"), str)
                and isinstance(item.get("tool"), str) and isinstance(item.get("sha256"), str)
                and len(item["sha256"].strip()) == 64):
            pins[(item["server"], item["tool"])] = item["sha256"].strip().lower()
        else:
            valid = False
    return pins, valid


def _remember(key: tuple[str, str], parts: dict[str, str]) -> dict[str, str] | None:
    """Store ``parts`` and return what was stored before for ``key`` (bounded)."""
    with _lock:
        before = _seen.get(key)
        _seen[key] = parts
        _seen.move_to_end(key)
        while len(_seen) > MAX_REMEMBERED:
            _seen.popitem(last=False)
        return before


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Findings for one importer event. ``policy`` must be trusted operator configuration."""
    if not isinstance(event, Mapping):
        return {"findings": _once({}, "malformed_event", "")}
    if event.get("method") != "tools/list" or event.get("stage") != "response":
        return {"findings": []}  # not an ALR02 input; not a PASS either

    server = str(event.get("server") or "")
    payload = event.get("payload")
    tools = payload.get("tools") if isinstance(payload, Mapping) else None
    if not isinstance(tools, list):
        return {"findings": _once(event, "payloads_not_recorded", server)}

    records: list[dict[str, Any]] = []
    pins, pins_valid = _pins(policy)
    if not pins_valid:
        records.extend(_once(event, "pinned_tools_invalid", server))
    server_pinned = any(pinned_server == server for pinned_server, _ in pins)

    counts = {"tools": 0, "pinned": 0, "changed": 0}
    for tool in tools[:MAX_TOOLS_PER_LIST]:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
            continue
        name = tool["name"]
        parts = definition_parts(tool)
        counts["tools"] += 1

        before = _remember((server, name), parts)
        if before is not None and before["all"] != parts["all"]:
            counts["changed"] += 1
            changed = [part for part in PARTS if before[part] != parts[part]]
            records.append(_result(
                category="definition_changed", tool=name, server=server, event=event,
                outcome="FAIL", severity="high", policy=policy,
                evidence=[{"signal": f"{part}_changed", "field": f"$/tools/{safe(name, 60)}/{part}",
                           "sha256_before": before[part], "sha256_after": parts[part]}
                          for part in changed] or [
                    {"signal": "name_or_structure_changed", "field": "$/tools",
                     "sha256_before": before["all"], "sha256_after": parts["all"]}],
                message="A tool definition changed after it was first listed in this run. A server "
                        "can behave until it is trusted and then change what the tool tells the "
                        "model. Review the new definition before relying on it.",
            ))

        pin = pins.get((server, name))
        if pin is not None:
            counts["pinned"] += 1
            if pin != parts["all"]:
                records.append(_result(
                    category="pin_mismatch", tool=name, server=server, event=event,
                    outcome="FAIL", severity="high", policy=policy,
                    evidence=[{"signal": "digest_differs_from_pin", "field": "$/tools",
                               "sha256_pinned": pin, "sha256_listed": parts["all"]}],
                    message="The listed definition does not match the digest the operator "
                            "pinned for this tool. Review it, then re-pin if the change is "
                            "expected.",
                ))
        elif server_pinned:
            records.append(_result(
                category="tool_not_pinned", tool=name, server=server, event=event,
                outcome="INCONCLUSIVE", severity="medium", policy=policy,
                evidence=[{"signal": "tool_missing_from_pins", "field": "$/tools",
                           "sha256_listed": parts["all"]}],
                message="The operator pinned other tools of this server but not this one, so "
                        "nobody reviewed its definition. Pin it after review.",
            ))

    records.append({
        "gate_id": GATE_ID, "rule_id": RULE_SUMMARY, "family": "scan_summary",
        "entity": {"server": safe(server), "tool": ""}, "record_id": _pointer(event),
        "outcome": "FAIL" if counts["changed"] else "PASS", "is_finding": False,
        "suppressed": False, "severity": "info", "owasp": OWASP, "evidence": [],
        "evidence_count": 0, "counts": counts,
        "message": "Tool definition integrity summary for this tool list.",
    })
    return {"findings": records}


def main(argv: list[str] | None = None) -> int:
    """Print the digest of every tool in the ``tools/list`` events of a normalized.jsonl."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m agent_latch.gates.alr02 NORMALIZED_JSONL", file=sys.stderr)
        return 2
    try:
        lines = Path(args[0]).read_text(encoding="utf-8").splitlines()
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        payload = item.get("payload") if isinstance(item, dict) else None
        if (isinstance(item, dict) and item.get("method") == "tools/list"
                and item.get("stage") == "response" and isinstance(payload, dict)
                and isinstance(payload.get("tools"), list)):
            for tool in payload["tools"]:
                if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                    print(f"{safe(item.get('server'))}\t{safe(tool['name'])}\t"
                          f"{definition_parts(tool)['all']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
