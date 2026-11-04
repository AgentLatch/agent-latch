"""ALR05 Untrusted Content Isolation: instruction-like content in MCP tool output.

Reads ``tools/call`` responses (and tool error messages) — the data an MCP server returns to the
agent — and flags content that appears to direct or override the agent's behaviour: override
phrases, forged authority or conversation turns, requests to hide actions from the user,
secret-access or exfiltration instructions, hidden or encoded payloads, and steering toward a
sibling tool seen earlier in the same run. When the payloads file is absent, the trace's short
secret-masked excerpt is scanned instead and the finding says so.

Scope. This gate looks at what a tool *returned*. It deliberately does not:

- inspect what a tool definition *says* (tool schema injection is ALR04)
- check whether the host fenced the output as data before it reached a model. The proxy sits
  between the app and the MCP server, so it can never observe that; the static rule AG003 checks
  the code side. Findings here are review signals about suspicious untrusted output, never claims
  that the content reached a model or that a prompt injection succeeded.
- judge server identity (ALR03), transport security (ALR12), or memory writes (ALR13)
- observe what the agent did with the output (needs cross-event correlation)

Monitor only. A finding records that untrusted output crossed a review threshold; it never blocks
the call, and a clean run is not proof that outputs are safe. Ordinary instructions in benign data
(a recipe's steps, a setup guide) are not enough for a finding: generic imperative wording never
raises evidence on its own, and a single soft signal cannot reach FAIL.

Known blind spots: paraphrases that avoid every signal family, languages beyond the few override
phrases listed, encodings beyond two layers of Base64/hex/percent, output cut by the payload
file's per-string limit or the trace's excerpt length (reported in coverage), prompt templates
(``prompts/get`` responses are not scanned), and output from tools this gate never sees. Findings
hold pointers and hashes, never the matched text.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Mapping
from threading import RLock
from typing import Any

from agent_latch.catalog import gate
from agent_latch.gates.alr04 import (
    BIDI,
    CODE_FENCE,
    CORRELATIONS,
    HTML_COMMENT,
    LIMIT_NOTES,
    NON_OPERATIVE,
    REDACTED,
    TRUNCATION,
    UNKNOWN_EXTENT_NOTES,
    ZERO_WIDTH,
    Evidence,
    Field,
    decode_layers,
    digest,
    extract,
    normalise,
    normalise_variants,
    rx,
    safe,
    spans,
    walk,
)

GATE_ID = "ALR05"
# Every ALR05 check cites its gate's OWASP categories (agent_latch.catalog).
OWASP = list(gate(GATE_ID).owasp)

RULE_ID = "ALR05-R01"
RULE_COVERAGE = "ALR05-090"
FAMILY = "instruction_like_output"

MIN_COVERAGE = 0.90
FAIL_AT = 0.90
REVIEW_AT = 0.60
INDEPENDENT_BOOST = 0.22
MAX_FIELD_CHARS = 16_000
MAX_EVIDENCE = 64
MAX_EVIDENCE_REPORTED = 8
MAX_REMEMBERED = 2048
MAX_SERVERS = 1024
MAX_TOOL_NAMES = 512

# Chat-template turn markers: a fake conversation boundary inside tool output is never data.
CHAT_TURN = re.compile(
    r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|"
    r"\[/?INST\]|<</?SYS>>|"
    r"^\s{0,4}#{1,3}\s*(?:system|instructions?)\b",
    re.IGNORECASE | re.MULTILINE,
)

_OUTCOME_SEVERITY = {"FAIL": "high", "INCONCLUSIVE": "medium"}
_MESSAGES = {
    "FAIL": "Tool output contains instruction-like content aimed at the agent. Review signal "
            "only: the proxy cannot show whether this output reached a model or was fenced.",
    "INCONCLUSIVE": "Tool output may contain instruction-like content; review. The proxy cannot "
                    "show whether it reached a model.",
    "PASS": "Weak indicators below threshold; recorded for reference only.",
}


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _remember_text(seen: set[str], text: str) -> bool:
    """False the first time an identical string is seen within one event."""
    key = digest(text)
    if key in seen:
        return True
    seen.add(key)
    return False


def _role(path: str, kind: str) -> str:
    if kind == "key":
        return "key"
    top = path.split("/", 2)[1] if "/" in path else ""
    return {"content": "content", "structured": "structured", "error_message": "error"}.get(
        top, "value")


def gather(field: Field, siblings: list[str], notes: set[str]) -> list[Evidence]:
    """Evidence that one output string tries to direct the agent; one weak word is never enough."""
    path, raw = field.path, field.raw
    role = _role(path, field.kind)
    evidence: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    if len(raw) > MAX_FIELD_CHARS:
        notes.add("field_exceeded_scanner_limit")
    text = raw[:MAX_FIELD_CHARS]
    lowered_siblings = [(s, s.casefold()) for s in siblings if len(s) >= 3]

    def add(cls: str, hard: bool, weight: float, signal: str, source: str = "visible",
            quoted: bool = False) -> None:
        key = (signal, source)
        if key in seen or len(evidence) >= MAX_EVIDENCE:
            return
        seen.add(key)
        evidence.append(Evidence(FAMILY, cls, hard and not quoted,
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
                add("content", True, .94, "action_targets_protected_instruction", source, quoted)
            elif "override" in flags and "protected" in flags:
                add("content", False, .57, "possible_policy_override", source, quoted)

            if CORRELATIONS["authority"].search(part):
                add("structure", True, .90, "forged_role_with_directive", source, quoted)
            elif "authority" in flags:
                add("structure", False, .55, "authority_marker", source, quoted)

            if CHAT_TURN.search(part):
                if flags & {"directive", "override"}:
                    add("structure", True, .90, "forged_conversation_turn", source, quoted)
                else:
                    add("structure", False, .55, "conversation_turn_marker", source, quoted)

            if CORRELATIONS["exfil"].search(part):
                add("content", True, .95, "transfer_of_secret_to_destination", source, quoted)
            elif {"transfer", "destination", "sensitive"} <= flags:
                add("content", False, .72, "possible_sensitive_transfer", source, quoted)

            if CORRELATIONS["access_path"].search(part):
                add("content", True, .86, "access_verb_targets_secret_path", source, quoted)
            elif "sensitive" in flags and "read" in flags:
                # Generic secret words are common in honest output ("retrieve the API key").
                weight = .66 if flags & {"directive", "prerequisite"} else .45
                add("content", False, weight, "possible_sensitive_access", source, quoted)

            if "secrecy" in flags:
                add("content", True, .86, "instruction_to_conceal_from_user", source, quoted)

            if "tool_action" in flags:
                folded_part = part.casefold()
                for sibling, folded in lowered_siblings:
                    if folded not in folded_part:
                        continue
                    if rx(r"(?<!\w)" + re.escape(sibling[:120]) + r"(?!\w)").search(part):
                        add("context", False, .70, "sibling_tool_reference", source, quoted)
                        break

    for variant in normalise_variants(text):
        classify(variant, "visible")
    visible = normalise(text)
    for match in HTML_COMMENT.finditer(visible):
        classify(match.group(1), "html_comment")
        add("structure", False, .25, "html_comment", "html_comment")
    tags = "".join(chr(ord(c) - 0xE0000) for c in raw if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        add("structure", False, .70, "unicode_tag_content", "unicode")
        classify(tags, "unicode_tags")
    if any(c in BIDI for c in raw):
        add("structure", False, .55, "bidi_control", "unicode")
    if sum(c in ZERO_WIDTH and c not in "‌‍" for c in raw) >= 1:
        add("structure", False, .35, "zero_width_characters", "unicode")
    for source, decoded in decode_layers(visible, notes):
        before = len(evidence)
        for variant in normalise_variants(decoded):
            classify(variant, source)
        if len(evidence) > before:
            add("structure", False, .65, "encoded_instruction", source)
    return evidence


def verdict(items: list[Evidence], coverage: float, ambiguous: bool
        ) -> tuple[str, float, str]:
    """(outcome, score, reason). Hard evidence fails alone; soft evidence needs corroboration."""
    strongest: dict[str, float] = {}
    for item in items:
        strongest[item.evidence_class] = max(strongest.get(item.evidence_class, 0), item.weight)
    score = max(strongest.values(), default=0.0)
    hard = any(item.hard for item in items)
    # Corroboration needs a different evidence class, a different field and a different string.
    independent = any(
        a.evidence_class != b.evidence_class and a.path != b.path and a.digest != b.digest
        for i, a in enumerate(items) for b in items[i + 1:i + 65]
    )
    if independent:
        score = min(1.0, score + INDEPENDENT_BOOST)
    score = round(min(1.0, score), 3)
    if hard:
        return "FAIL", max(score, .85), "hard_evidence"
    if independent and score >= FAIL_AT:
        return "FAIL", score, "independent_corroboration"
    if score >= REVIEW_AT:
        return "INCONCLUSIVE", score, "score_needs_review"
    if items and (coverage < MIN_COVERAGE or ambiguous):
        return "INCONCLUSIVE", score, "incomplete_input"
    return "PASS", score, "clear"


def _suppression(policy: Mapping[str, Any] | None, rule_id: str) -> str | None:
    suppressions = (policy or {}).get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    return reason.strip() if isinstance(reason, str) and reason.strip() else None


def _result(*, tool: str, server: str, event: Mapping[str, Any], evidence: list[Evidence],
            coverage: float, outcome: str, score: float, reason: str, notes: set[str],
            policy: Mapping[str, Any] | None) -> dict[str, Any]:
    suppressed_reason = _suppression(policy, RULE_ID)
    suppressed = suppressed_reason is not None
    return {
        "gate_id": GATE_ID, "rule_id": RULE_ID, "family": FAMILY,
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "outcome": outcome,
        "is_finding": outcome != "PASS" and not suppressed,
        "suppressed": suppressed, "suppression_reason": safe(suppressed_reason, 160)
        if suppressed else None,
        "severity": _OUTCOME_SEVERITY.get(outcome, "info"),
        "score": score, "coverage": round(coverage, 3), "decision_reason": reason,
        "inspection_complete": coverage >= MIN_COVERAGE and not (notes & LIMIT_NOTES),
        "coverage_notes": sorted(notes),
        "evidence": [{"class": e.evidence_class, "strength": "hard" if e.hard else "soft",
                      "signal": e.signal, "source": e.source, "role": e.role,
                      "field": safe(e.path, 220), "sha256": e.digest, "quoted": e.quoted}
                     for e in evidence[:MAX_EVIDENCE_REPORTED]],
        "evidence_count": len(evidence),
        "owasp": OWASP,
        "message": _MESSAGES[outcome],
    }


def _coverage_record(event: Mapping[str, Any], reason: str, *, tool: str = "", server: str = "",
                     notes: set[str] | None = None, coverage: float = 0.0) -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": RULE_COVERAGE, "family": "coverage",
        "entity": {"server": safe(server), "tool": safe(tool)}, "record_id": _pointer(event),
        "outcome": "INCONCLUSIVE", "is_finding": True, "suppressed": False,
        "severity": "medium", "score": 0.0, "coverage": round(coverage, 3),
        "decision_reason": reason, "coverage_notes": sorted(notes or {reason}),
        "owasp": OWASP, "evidence": [], "evidence_count": 0,
        "message": "Part of the tool output was not evaluated, so it cannot be cleared.",
    }


# --- per-run state ------------------------------------------------------------------------------

_lock = RLock()
_reported: OrderedDict[tuple[str, str, str], bool] = OrderedDict()
_tools_by_server: OrderedDict[str, OrderedDict[str, bool]] = OrderedDict()


def reset_state() -> None:
    """Forget reported outputs and learned tool names (tests, or a new importer run)."""
    with _lock:
        _reported.clear()
        _tools_by_server.clear()


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


def _learn_tools(event: Mapping[str, Any]) -> None:
    """Remember a server's tool names, so output steering toward a sibling tool can be seen."""
    payload = event.get("payload")
    tools = payload.get("tools") if isinstance(payload, Mapping) else None
    if not isinstance(tools, list):
        return
    names = [tool["name"] for tool in tools[:MAX_TOOL_NAMES]
             if isinstance(tool, Mapping) and isinstance(tool.get("name"), str)]
    if not names:
        return
    server = str(event.get("server") or "")
    with _lock:
        known = _tools_by_server.setdefault(server, OrderedDict())
        _tools_by_server.move_to_end(server)
        while len(_tools_by_server) > MAX_SERVERS:
            _tools_by_server.popitem(last=False)
        for name in names:
            known[name] = True
            known.move_to_end(name)
        while len(known) > MAX_TOOL_NAMES:
            known.popitem(last=False)


def _fields(event: Mapping[str, Any], stage: str, notes: set[str]) -> tuple[list[Field], str, int]:
    """Scannable output strings, the tool name, and how many bytes the trace said were output."""
    payload = event.get("payload")
    metadata = event.get("metadata")
    output_bytes = 0
    if isinstance(metadata, Mapping) and isinstance(metadata.get("output_bytes"), int):
        output_bytes = metadata["output_bytes"]
    name = event.get("name")
    if not isinstance(payload, Mapping):
        excerpt = metadata.get("excerpt") if isinstance(metadata, Mapping) else None
        if isinstance(excerpt, str) and excerpt:
            notes.add("trace_excerpt_only")
            return [Field("$/trace_excerpt", "value", excerpt)], str(name or ""), output_bytes
        return [], str(name or ""), output_bytes
    tool = str(payload.get("tool") or name or "")
    if stage == "error":
        message = payload.get("error_message")
        if isinstance(message, str) and message:
            return [Field("$/error_message", "value", message)], tool, output_bytes
        return [], tool, output_bytes
    root: dict[str, Any] = {}
    if payload.get("content") is not None:
        root["content"] = payload.get("content")
    if payload.get("structured") is not None:
        root["structured"] = payload.get("structured")
    fields: list[Field] = []
    for field in walk(root):
        if field.kind == "coverage":
            notes.add(field.raw)
        elif field.raw:
            fields.append(field)
    return fields, tool, output_bytes


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Findings for one importer event. ``policy`` must be trusted operator configuration."""
    if not isinstance(event, Mapping):
        return {"findings": [_coverage_record({}, "malformed_event")]}
    method, stage = event.get("method"), event.get("stage")
    if method == "tools/list" and stage == "response":
        _learn_tools(event)
        return {"findings": []}  # a definition list is ALR04's input, not ALR05's
    if not (method == "tools/call" and stage in {"response", "error"}):
        return {"findings": []}  # not an ALR05 input; not a PASS either

    notes: set[str] = set()
    fields, tool, output_bytes = _fields(event, stage, notes)
    server = str(event.get("server") or "")
    if not fields:
        if output_bytes > 0:
            # There was output, but neither a payload nor an excerpt of it is available.
            return {"findings": [_coverage_record(event, "output_unavailable",
                                                  tool=tool, server=server)]}
        return {"findings": []}  # empty output; nothing to inspect, not a PASS either

    declared = observed = 0
    texts: list[Field] = []
    for field in fields:
        raw = field.raw
        lost = 0
        cut = TRUNCATION.search(raw)
        if cut:
            lost = int(cut.group(1))
            raw = raw[:cut.start()]
            notes.add("payload_file_truncation")
        if REDACTED in raw:
            # The proxy's own masking hid part of the output; noted, but not treated as
            # suspicious — secret-shaped values in tool output are common and operator-masked.
            notes.add("redacted_field")
        declared += len(raw) + lost
        observed += min(len(raw), MAX_FIELD_CHARS)
        texts.append(Field(field.path, field.kind, raw))
    if "trace_excerpt_only" in notes and output_bytes > declared:
        declared = output_bytes
    coverage = observed / declared if declared else 1.0
    if notes & UNKNOWN_EXTENT_NOTES:
        coverage = 0.0
    ambiguous = bool(notes & (LIMIT_NOTES | {"payload_file_truncation"}))

    key = (server, tool, digest("\x00".join(field.raw for field in texts)))
    if _remember(_reported, key):
        return {"findings": []}  # identical output from this tool was already evaluated

    siblings = [name for name in _tools_by_server.get(server, ()) if name != tool]
    evidence: list[Evidence] = []
    scanned: set[str] = set()
    for field in texts:
        # Frameworks often mirror text content into structured output; identical strings are
        # scanned once (they could never count as independent corroboration anyway).
        if not _remember_text(scanned, field.raw):
            evidence.extend(gather(field, siblings, notes))
    outcome, score, reason = verdict(evidence, coverage, ambiguous)

    findings: list[dict[str, Any]] = []
    if outcome != "PASS" or evidence:
        findings.append(_result(tool=tool, server=server, event=event, evidence=evidence,
                                coverage=coverage, outcome=outcome, score=score, reason=reason,
                                notes=notes, policy=policy))
    elif ambiguous:
        findings.append(_coverage_record(event, "incomplete_input", tool=tool, server=server,
                                         notes=notes, coverage=coverage))
    return {"findings": findings}
