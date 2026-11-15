"""ALR04 Tool Schema Injection: instruction-like or hidden content inside MCP tool definitions.

Reads ``tools/list`` responses (and, as a fallback, the cached ``tool_definition`` carried by a
``tools/call`` request) and checks every string of every tool definition: name, title,
description, parameter descriptions, defaults, enums, examples, annotation text, ``_meta`` text and
even schema keys. Findings are per tool and per rule family; only checks that need attention are
reported, plus one small summary per scan.

Scope. This gate looks at what a tool definition *says*. It deliberately does not:

- detect that a definition *changed*, or pin / approve definitions (tool integrity, ALR02)
- judge tool names, duplicates, server identity or trust (ALR02 / ALR03)
- compare annotations with behaviour, or inspect call arguments or results
  (permission, execution and exfiltration gates)
- observe what the agent did after discovery (needs cross-event correlation)
- write reports; findings go to the importer's CSV and a separate exporter flattens them

A finding is recorded when evidence meets a rule threshold or needs review. Scores are
heuristic and never prove that an agent was compromised. The gate does not clear a tool.

Known blind spots: paraphrases that avoid every phrase family, languages beyond the few override
phrases listed, encodings beyond two layers of Base64/hex/percent, text cut by the payload file's
per-string limit (reported as INCONCLUSIVE coverage), and tool definitions this gate never sees.
Findings hold pointers and hashes, never the matched text.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from collections.abc import Mapping
from threading import RLock
from typing import Any

from agent_latch.catalog import gate
from agent_latch.gates._text import (
    BIDI,
    CODE_FENCE,
    CORRELATIONS,
    HTML_COMMENT,
    LIMIT_NOTES,
    MIN_COVERAGE,
    NON_OPERATIVE,
    READ_VERB,
    REDACTED,
    SENSITIVE_PATH,
    SUSPICIOUS_KEYS,
    TRUNCATION,
    UNKNOWN_EXTENT_NOTES,
    ZERO_WIDTH,
    Evidence,
    Field,
    decode_layers,
    digest,
    extract,
    field_role,
    normalise,
    normalise_variants,
    rx,
    safe,
    spans,
    walk,
)
from agent_latch.gates._text import verdict as _text_verdict

GATE_ID = "ALR04"
# Every ALR04 check cites its gate's OWASP categories (agent_latch.catalog).
OWASP = list(gate(GATE_ID).owasp)

MAX_TOOLS = 256
MAX_FIELD_CHARS = 16_000
MAX_EVIDENCE_PER_CATEGORY = 64
MAX_EVIDENCE_REPORTED = 8
MAX_OUTPUT_RECORDS = 400
MAX_SIBLINGS = 256
MAX_REMEMBERED = 2048

CATEGORIES = (
    "instruction_override", "authority_spoofing", "concealment", "sensitive_access",
    "data_exfiltration", "cross_tool_manipulation", "hidden_or_encoded_instruction",
    "tool_selection_hijack", "malicious_prerequisite",
)
RULE_IDS = {name: f"ALR04-{i:03d}" for i, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR04-090"
RULE_SUMMARY = "ALR04-099"
# category -> (fail_at, review_at): the score needed for FAIL via corroboration, and for review.
# Hard evidence fails on its own. A soft weight below review_at is informational: it only matters
# through corroboration. Each category has at least one signal that reaches review (tested).
RULE_THRESHOLDS = {
    "instruction_override": (.90, .55),
    "authority_spoofing": (.85, .55),
    "concealment": (.85, .55),
    "sensitive_access": (.90, .60),
    "data_exfiltration": (.90, .60),
    "cross_tool_manipulation": (.90, .60),
    "hidden_or_encoded_instruction": (.85, .50),
    "tool_selection_hijack": (.90, .55),
    "malicious_prerequisite": (.90, .60),
}

# The phrase families, text preparation, bounded walk, decode layers, clause splitting, the
# Evidence type and the corroboration verdict live in agent_latch.gates._text, shared with the
# other runtime gates. This module keeps only tool-definition logic.


def gather_signals(field: Field, siblings: list[str], own_name: str, notes: set[str],
                   policy: Mapping[str, Any] | None = None) -> list[Evidence]:
    """Correlate actionable wording inside clauses; one weak word is never enough for FAIL."""
    path, raw = field.path, field.raw
    role = field_role(path, field.kind)
    evidence: list[Evidence] = []
    seen: set[tuple[str, str, str]] = set()
    counts: dict[str, int] = {}
    policy = policy or {}
    allowed = {tuple(x) for x in policy.get("allowed_tool_dependencies", ())
               if isinstance(x, list | tuple) and len(x) == 2}
    if len(raw) > MAX_FIELD_CHARS:
        notes.add("field_exceeded_scanner_limit")
    text = raw[:MAX_FIELD_CHARS]
    own = own_name[:120]
    lowered_siblings = [(s, s.casefold()) for s in siblings[:MAX_SIBLINGS]
                        if s != own_name and len(s) >= 3]

    def add(category: str, cls: str, hard: bool, weight: float, signal: str,
            source: str = "visible", quoted: bool = False) -> None:
        key = (category, signal, source)
        if key in seen or counts.get(category, 0) >= MAX_EVIDENCE_PER_CATEGORY:
            return
        seen.add(key)
        counts[category] = counts.get(category, 0) + 1
        evidence.append(Evidence(category, cls, hard and not quoted,
                                 weight * (0.65 if quoted else 1.0), signal, path, source,
                                 digest(raw), role, quoted))

    def classify(chunk: str, source: str) -> None:
        clauses, overflow = spans(chunk)
        if overflow:
            notes.add("span_limit")
        fences = [(m.start(), m.end()) for m in CODE_FENCE.finditer(chunk)]
        for start, part in clauses:
            flags = extract(part)
            quoted = bool(NON_OPERATIVE.search(part)) or any(lo <= start < hi for lo, hi in fences)
            if CORRELATIONS["override"].search(part) or CORRELATIONS["override_i18n"].search(part):
                add("instruction_override", "content", True, .94,
                    "action_targets_protected_instruction", source, quoted)
            elif "override" in flags and "protected" in flags:
                add("instruction_override", "content", False, .57,
                    "possible_policy_override", source, quoted)
            elif "override" in flags and "directive" in flags:
                add("instruction_override", "content", False, .38,
                    "unresolved_override_intent", source, quoted)

            if CORRELATIONS["authority"].search(part):
                add("authority_spoofing", "structure", True, .90,
                    "forged_role_with_directive", source, quoted)
            elif "authority" in flags:
                add("authority_spoofing", "structure", False, .55,
                    "authority_marker", source, quoted)

            selection = bool(CORRELATIONS["selection"].search(part))
            if not selection and own:
                selection = bool(rx(r"\b(?:always|must|only)?\s*(?:use|call|select|choose)\s+(?:"
                                    + re.escape(own) + r")\s+(?:for\s+all|regardless|instead)\b")
                                 .search(part))
            if selection:
                add("tool_selection_hijack", "content", True, .85,
                    "mandatory_tool_selection", source, quoted)
            elif "selection" in flags:
                add("tool_selection_hijack", "content", False, .50,
                    "tool_preference_claim", source, quoted)

            if CORRELATIONS["exfil"].search(part):
                add("data_exfiltration", "content", True, .95,
                    "transfer_of_secret_to_destination", source, quoted)
            elif {"transfer", "destination", "sensitive"} <= flags:
                add("data_exfiltration", "content", False, .72,
                    "possible_sensitive_transfer", source, quoted)
            if CORRELATIONS["access_path"].search(part):
                add("sensitive_access", "content", True, .86,
                    "access_verb_targets_secret_path", source, quoted)
            elif "sensitive" in flags and "read" in flags:
                # Generic secret words are common in honest tools ("retrieve the API key").
                weight = .66 if flags & {"directive", "prerequisite"} else .45
                add("sensitive_access", "content", False, weight,
                    "possible_sensitive_access", source, quoted)

            if "prerequisite" in flags and CORRELATIONS["access_path"].search(part):
                add("malicious_prerequisite", "content", True, .90,
                    "sensitive_access_prerequisite", source, quoted)
            elif {"prerequisite", "sensitive", "read"} <= flags:
                add("malicious_prerequisite", "content", False, .66,
                    "possible_sensitive_prerequisite", source, quoted)

            if "secrecy" in flags:
                add("concealment", "content", True, .86,
                    "instruction_to_conceal_from_user", source, quoted)

            if "tool_bypass" in flags and "tool_action" in flags:
                part_folded = part.casefold()
                for sibling, folded in lowered_siblings:
                    if (own_name, sibling) in allowed or folded not in part_folded:
                        continue
                    if rx(r"(?<!\w)" + re.escape(sibling[:120]) + r"(?!\w)").search(part):
                        add("cross_tool_manipulation", "content", False, .70,
                            "sibling_tool_bypass", source, quoted)
                        break

    for variant in normalise_variants(text):
        classify(variant, "visible")
    visible = normalise(text)
    for match in HTML_COMMENT.finditer(visible):
        classify(match.group(1), "html_comment")
        add("hidden_or_encoded_instruction", "structure", False, .25, "html_comment",
            "html_comment")
    tags = "".join(chr(ord(c) - 0xE0000) for c in raw if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        add("hidden_or_encoded_instruction", "structure", False, .70, "unicode_tag_content",
            "unicode")
        classify(tags, "unicode_tags")
    if any(c in BIDI for c in raw):
        add("hidden_or_encoded_instruction", "structure", False, .55, "bidi_control", "unicode")
    if sum(c in ZERO_WIDTH and c not in "‌‍" for c in raw) >= 1:
        add("hidden_or_encoded_instruction", "structure", False, .35, "zero_width_characters",
            "unicode")
    for source, decoded in decode_layers(visible, notes):
        before = len(evidence)
        for variant in normalise_variants(decoded):
            classify(variant, source)
        if len(evidence) > before:
            add("hidden_or_encoded_instruction", "structure", False, .65,
                "encoded_instruction", source)
    if field.kind == "key" and visible.casefold() in SUSPICIOUS_KEYS:
        add("hidden_or_encoded_instruction", "structure", False, .55,
            "suspicious_schema_key", "key")
    return evidence


def cross_field_evidence(parts: list[tuple[str, str]]) -> list[Evidence]:
    """Instructions split across two fields of one tool (fragmentation); concrete targets only."""
    out: list[Evidence] = []
    visible = [(path, normalise(text[:MAX_FIELD_CHARS])) for path, text in parts if text]
    for index, (path_a, text_a) in enumerate(visible):
        if not SENSITIVE_PATH.search(text_a):
            continue
        for path_b, text_b in visible[index + 1:] + visible[:index]:
            if path_b == path_a:
                continue
            if READ_VERB.search(text_b) and not SENSITIVE_PATH.search(text_b):
                out.append(Evidence("sensitive_access", "cross_field", False, .63,
                                    "access_split_across_fields", path_a, "visible",
                                    digest(path_a + path_b)))
                break
    return out


def verdict(items: list[Evidence], coverage: float, ambiguous: bool, category: str
        ) -> tuple[str, float, str]:
    """(outcome, score, reason). Hard evidence fails alone; soft evidence needs corroboration."""
    fail_at, review_at = RULE_THRESHOLDS[category]
    return _text_verdict(items, coverage, ambiguous, fail_at=fail_at, review_at=review_at)


def _suppression(policy: Mapping[str, Any] | None, rule_id: str) -> str | None:
    suppressions = (policy or {}).get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    return reason.strip() if isinstance(reason, str) and reason.strip() else None


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def result(*, category: str, tool: str, server: str, event: Mapping[str, Any],
           evidence: list[Evidence], coverage: float, definition_hash: str,
           outcome: str, score: float, reason: str, notes: set[str],
           policy: Mapping[str, Any] | None) -> dict[str, Any]:
    rule_id = RULE_IDS[category]
    suppressed_reason = _suppression(policy, rule_id)
    suppressed = suppressed_reason is not None
    return {
        "gate_id": GATE_ID, "rule_id": rule_id, "family": category,
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "outcome": outcome,
        "is_finding": outcome != "PASS" and not suppressed,
        "suppressed": suppressed, "suppression_reason": safe(suppressed_reason, 160)
        if suppressed else None,
        "severity": {"FAIL": "high", "INCONCLUSIVE": "medium"}.get(outcome, "info"),
        "score": score, "coverage": round(coverage, 3), "decision_reason": reason,
        "inspection_complete": coverage >= MIN_COVERAGE and not (notes & LIMIT_NOTES),
        "coverage_notes": sorted(notes),
        "evidence": [{"class": e.evidence_class, "strength": "hard" if e.hard else "soft",
                      "signal": e.signal, "source": e.source, "role": e.role,
                      "field": safe(e.path, 220), "sha256": e.digest, "quoted": e.quoted}
                     for e in evidence[:MAX_EVIDENCE_REPORTED]],
        "evidence_count": len(evidence), "definition_sha256": definition_hash,
        "owasp": OWASP,
        "message": {
            "FAIL": "Tool definition contains above-threshold injection indicators; "
                    "no exploit confirmed.",
            "INCONCLUSIVE": "Suspicious or incomplete tool-definition evidence needs review.",
            "PASS": "Weak indicators below threshold; recorded for reference only.",
        }[outcome],
    }


def _coverage_record(event: Mapping[str, Any], reason: str, *, tool: str = "", server: str = "",
                     notes: set[str] | None = None, coverage: float = 0.0, not_cleared: int = 0,
                     skipped: int = 0, definition_hash: str = "") -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": RULE_COVERAGE, "family": "coverage",
        "entity": {"server": safe(server), "tool": safe(tool)}, "record_id": _pointer(event),
        "outcome": "INCONCLUSIVE", "is_finding": True, "suppressed": False,
        "severity": "medium", "score": 0.0, "coverage": round(coverage, 3),
        "decision_reason": reason, "coverage_notes": sorted(notes or {reason}),
        "categories_not_cleared": not_cleared, "skipped_tools": skipped,
        "definition_sha256": definition_hash, "owasp": OWASP, "evidence": [], "evidence_count": 0,
        "message": "Part of the tool-definition input was not evaluated, so it cannot be cleared.",
    }


def definition_hash(tool: Mapping[str, Any]) -> str:
    return digest(json.dumps(tool, sort_keys=True, ensure_ascii=False, default=str))


def scan_tool(tool: Mapping[str, Any], server: str, siblings: list[str],
              event: Mapping[str, Any], policy: Mapping[str, Any] | None = None,
              global_partial: bool = False) -> tuple[list[dict[str, Any]], str]:
    """Verdict records for one tool, and its worst outcome."""
    name = str(tool.get("name"))
    sha = definition_hash(tool)
    evidence: dict[str, list[Evidence]] = {category: [] for category in CATEGORIES}
    notes: set[str] = {"partial_tool_list"} if global_partial else set()
    observed = declared = 0
    parts: list[tuple[str, str]] = []
    for field in walk(tool):
        if field.kind == "coverage":
            notes.add(field.raw)
            break
        raw = field.raw
        if not raw:
            continue
        lost = 0
        cut = TRUNCATION.search(raw)
        if cut:
            lost = int(cut.group(1))
            raw = raw[:cut.start()]
            notes.add("payload_file_truncation")
        if REDACTED in raw:
            notes.add("redacted_field")
        declared += len(raw) + lost
        observed += min(len(raw), MAX_FIELD_CHARS)
        if field.kind == "value":
            parts.append((field.path, raw))
        for item in gather_signals(Field(field.path, field.kind, raw), siblings, name, notes,
                                   policy):
            evidence[item.category].append(item)
    for item in cross_field_evidence(parts):
        evidence[item.category].append(item)
    coverage = observed / declared if declared else 1.0
    if notes & UNKNOWN_EXTENT_NOTES:
        coverage = 0.0
    ambiguous = bool(notes & (LIMIT_NOTES | {"payload_file_truncation", "redacted_field",
                                              "partial_tool_list"}))
    records: list[dict[str, Any]] = []
    worst = "PASS"
    not_cleared = 0
    for category in CATEGORIES:
        items = evidence[category]
        outcome, score, reason = verdict(items, coverage, ambiguous, category)
        if outcome == "INCONCLUSIVE" and reason == "incomplete_input" and not items:
            not_cleared += 1  # reported once, in the tool's coverage record
            continue
        if outcome == "PASS" and not items:
            continue
        records.append(result(category=category, tool=name, server=server, event=event,
                              evidence=items, coverage=coverage, definition_hash=sha,
                              outcome=outcome, score=score, reason=reason, notes=notes,
                              policy=policy))
        if outcome == "FAIL" or (outcome == "INCONCLUSIVE" and worst == "PASS"):
            worst = outcome
    if not_cleared or ambiguous or coverage < MIN_COVERAGE:
        records.append(_coverage_record(event, "incomplete_input", tool=name, server=server,
                                        notes=notes, coverage=coverage, not_cleared=not_cleared,
                                        definition_hash=sha))
        worst = "FAIL" if worst == "FAIL" else "INCONCLUSIVE"
    return records, worst


# --- one-time scanning --------------------------------------------------------------------------

_lock = RLock()
_scanned: OrderedDict[tuple[str, str, str], bool] = OrderedDict()
_tools_seen: OrderedDict[tuple[str, str], bool] = OrderedDict()


def reset_state() -> None:
    """Forget which definitions were scanned (tests, or a new importer run)."""
    with _lock:
        _scanned.clear()
        _tools_seen.clear()


def _remember(store: OrderedDict[Any, bool], key: Any) -> bool:
    """True if ``key`` was already stored; otherwise store it (bounded) and return False."""
    with _lock:
        if key in store:
            store.move_to_end(key)
            return True
        store[key] = True
        while len(store) > MAX_REMEMBERED:
            store.popitem(last=False)
        return False


def startup_capabilities() -> list[dict[str, str]]:
    """What this gate cannot check, for a dispatcher to report up front instead of a silent PASS."""
    return [
        {"check": "tool_definition_content", "outcome": "SUPPORTED"},
        {"check": "prompt_and_resource_descriptions", "outcome": "UNSUPPORTED",
         "reason": "Prompt and resource descriptions are not captured as payload records."},
        {"check": "definition_change_or_pinning", "outcome": "UNSUPPORTED",
         "reason": "Tool integrity and baselines belong to ALR02."},
        {"check": "agent_consequence", "outcome": "UNSUPPORTED",
         "reason": "Agent behaviour after discovery needs cross-event correlation."},
        {"check": "semantic_paraphrase", "outcome": "UNSUPPORTED",
         "reason": "No semantic scorer is installed; reworded intent can evade the phrase families."},
    ]


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Findings for one importer event. ``policy`` must be trusted operator configuration."""
    if not isinstance(event, Mapping):
        return {"findings": [_coverage_record({}, "malformed_event")]}
    method, stage = event.get("method"), event.get("stage")
    relevant = (method == "tools/list" and stage == "response") or (
        method == "tools/call" and stage == "request")
    if not relevant:
        return {"findings": []}  # not an ALR04 input; not a PASS either
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        return {"findings": [_coverage_record(event, "payload_unavailable")]}

    invalid = extra = 0
    definitions: list[Mapping[str, Any]] = []
    if method == "tools/list":
        tools = payload.get("tools")
        if not isinstance(tools, list):
            return {"findings": [_coverage_record(event, "missing_or_invalid_tools_list")]}
        for tool in tools[:MAX_TOOLS]:
            if isinstance(tool, Mapping) and isinstance(tool.get("name"), str):
                definitions.append(tool)
            else:
                invalid += 1
        extra = max(0, len(tools) - MAX_TOOLS)
    else:
        cached, name = payload.get("tool_definition"), payload.get("tool")
        if cached is None:
            return {"findings": []}  # ordinary calls are not schema evidence
        if not isinstance(cached, Mapping) or not isinstance(name, str):
            return {"findings": [_coverage_record(event, "invalid_cached_tool_definition")]}
        definitions.append({**cached, "name": name})

    server = str(event.get("server") or "")
    siblings = [str(d["name"]) for d in definitions]
    partial = bool(invalid or extra)
    out: list[dict[str, Any]] = []
    scanned = skipped = 0
    outcomes = {"FAIL": 0, "INCONCLUSIVE": 0, "PASS": 0}
    for definition in definitions:
        if len(out) >= MAX_OUTPUT_RECORDS:
            out.append(_coverage_record(event, "output_record_limit"))
            break
        name = str(definition["name"])
        if method == "tools/call" and (server, name) in _tools_seen:
            skipped += 1  # already scanned from a tools/list; do not report it twice
            continue
        if _remember(_scanned, (server, name, definition_hash(definition))):
            skipped += 1
            continue
        _remember(_tools_seen, (server, name))
        records, worst = scan_tool(definition, server, siblings, event, policy, partial)
        out.extend(records)
        outcomes[worst] += 1
        scanned += 1
    if invalid:
        out.append(_coverage_record(event, "invalid_tool_definition", skipped=invalid))
    if extra:
        out.append(_coverage_record(event, "tool_count_limit", skipped=extra))
    if scanned:
        out.append({
            "gate_id": GATE_ID, "rule_id": RULE_SUMMARY, "family": "scan_summary",
            "entity": {"server": safe(server), "tool": ""}, "record_id": _pointer(event),
            "outcome": "FAIL" if outcomes["FAIL"] else
            "INCONCLUSIVE" if outcomes["INCONCLUSIVE"] else "PASS",
            "is_finding": False, "suppressed": False, "severity": "info", "score": 0.0,
            "coverage": 1.0, "tools_scanned": scanned, "tools_failed": outcomes["FAIL"],
            "tools_inconclusive": outcomes["INCONCLUSIVE"], "tools_clear": outcomes["PASS"],
            "tools_already_scanned": skipped, "owasp": OWASP, "evidence": [], "evidence_count": 0,
            "message": "Scan summary for this event.",
        })
    return {"findings": out}
