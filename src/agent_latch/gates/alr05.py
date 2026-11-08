"""ALR05 Untrusted Content Isolation: instruction-like content in MCP tool output.

Reads ``tools/call`` responses (and tool error messages) from the payload record — the data an
MCP server returns to the agent — and flags content that appears to direct or override the
agent's behaviour. Three detectors share the text engine in ``agent_latch.gates._text``:

- ``ALR05-R01`` instruction-like text: override phrases, forged authority or conversation
  turns, requests to hide actions from the user, instructions to read sensitive files.
- ``ALR05-R02`` hidden or encoded instructions: invisible or bidi characters, Unicode tag
  sequences, HTML comments, and Base64/hex/percent layers that decode to instruction-like text.
- ``ALR05-R03`` action steering: the output asks the model to call another tool of the same
  server, send data somewhere, or open a URL.

Context. Output from tools that fetch outside content (web, email, files, tickets) is the main
risk, so a finding's severity is raised when the tool declares ``openWorldHint`` or its name
reads as an outside-content tool, and lowered when it does not. Context never skips the check.

Coverage (``ALR05-R90``). Payload records exist only when the proxy runs with ``--payloads``;
without them there is nothing to scan, and the gate emits one coverage record per run, not per
event. Output cut by the payload file's per-string limit (``--payload-max-chars``) gets one
coverage record per tool per run.

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
(a recipe's steps, a CLI's manual) are not enough for a finding: generic imperative wording never
raises evidence on its own, and a single soft signal cannot reach FAIL.

Known blind spots: paraphrases that avoid every signal family, languages beyond the few override
phrases listed, encodings beyond two layers of Base64/hex/percent, images and binary content,
output cut by the payload file's per-string limit (reported as coverage), prompt templates
(``prompts/get`` responses are not scanned), and output from tools this gate never sees.
Findings hold field paths, signal names and hashes, never the matched text: output can contain
personal data.
"""

from __future__ import annotations

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
    MAX_FIELD_CHARS,
    MIN_COVERAGE,
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
from agent_latch.gates._text import verdict as _text_verdict

GATE_ID = "ALR05"
# Every ALR05 check cites its gate's OWASP categories (agent_latch.catalog).
OWASP = list(gate(GATE_ID).owasp)

CATEGORIES = (
    "instruction_like_output",
    "hidden_or_encoded_output",
    "action_steering_output",
)
RULE_IDS = {name: f"ALR05-R{i:02d}" for i, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR05-R90"
# category -> (fail_at, review_at), tuned on output data (tests/test_alr05_eval.py). Output text is
# longer and noisier than tool definitions, so these are set separately from ALR04's.
RULE_THRESHOLDS = {
    "instruction_like_output": (.90, .65),
    "hidden_or_encoded_output": (.85, .50),
    "action_steering_output": (.90, .60),
}

MAX_EVIDENCE_PER_CATEGORY = 64
MAX_EVIDENCE_REPORTED = 8
MAX_REMEMBERED = 2048
MAX_SERVERS = 1024
MAX_TOOL_NAMES = 512

# Chat-template or transcript turn markers: a fake conversation boundary inside tool output is
# never data.
CHAT_TURN = re.compile(
    r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|"
    r"\[/?INST\]|<</?SYS>>|"
    r"^\s{0,4}#{1,3}\s*(?:system|instructions?)\b|"
    r"(?:^|\n)\s{0,4}(?:assistant|system|user|human|ai)\s*:",
    re.IGNORECASE | re.MULTILINE,
)
# "open/visit/go to https://..." — the output points the model at a URL.
OPEN_URL = rx(r"\b(?:open|visit|browse|navigate\s+to|go\s+to|follow\s+(?:this|the)\s+link)\b"
              r".{0,60}(?:https?://|ftp://)")
# Bidi controls that reorder rendering (embeddings, overrides, isolates). Plain direction marks
# (LRM, RLM, ALM) are excluded: they appear in ordinary mixed-script text.
_BIDI_STRONG = BIDI - {"\u200e", "\u200f", "\u061c"}
# Tools whose results are expected to carry outside content (web, email, files, tickets).
_OUTSIDE_NAME = re.compile(
    r"(?i)(?:fetch|web|http|url|search|browse|crawl|scrape|read|load|file|doc|email|mail|"
    r"ticket|issue|api|download|page|rss|news|feed|weather)"
)

_MESSAGES = {
    "instruction_like_output": {
        "FAIL": "Tool output contains instruction-like content aimed at the agent. Review signal "
                "only: the proxy cannot show whether this output reached a model or was fenced.",
        "INCONCLUSIVE": "Tool output may contain instruction-like content; review. The proxy "
                        "cannot show whether it reached a model.",
        "PASS": "Weak indicators below threshold; recorded for reference only.",
    },
    "hidden_or_encoded_output": {
        "FAIL": "Tool output hides instruction-like content in invisible characters or encoding. "
                "Review signal only: the proxy cannot show whether it reached a model.",
        "INCONCLUSIVE": "Tool output carries hidden or encoded content; review. The proxy cannot "
                        "show whether it reached a model.",
        "PASS": "Weak indicators below threshold; recorded for reference only.",
    },
    "action_steering_output": {
        "FAIL": "Tool output tries to steer the agent's next action (another tool, a destination, "
                "a URL). Review signal only: the proxy cannot show whether it reached a model.",
        "INCONCLUSIVE": "Tool output may try to steer the agent's next action; review. The proxy "
                        "cannot show whether it reached a model.",
        "PASS": "Weak indicators below threshold; recorded for reference only.",
    },
}


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


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
    seen: set[tuple[str, str, str]] = set()
    counts: dict[str, int] = {}
    if len(raw) > MAX_FIELD_CHARS:
        notes.add("field_exceeded_scanner_limit")
    text = raw[:MAX_FIELD_CHARS]
    lowered_siblings = [(s, s.casefold()) for s in siblings if len(s) >= 3]

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
                add("instruction_like_output", "content", True, .94,
                    "action_targets_protected_instruction", source, quoted)
            elif "override" in flags and "protected" in flags:
                add("instruction_like_output", "content", False, .57,
                    "possible_policy_override", source, quoted)

            if CORRELATIONS["authority"].search(part):
                add("instruction_like_output", "structure", True, .90,
                    "forged_role_with_directive", source, quoted)
            elif "authority" in flags:
                add("instruction_like_output", "structure", False, .55,
                    "authority_marker", source, quoted)

            if CHAT_TURN.search(part):
                if flags & {"directive", "override"}:
                    add("instruction_like_output", "structure", True, .90,
                        "forged_conversation_turn", source, quoted)
                else:
                    add("instruction_like_output", "structure", False, .55,
                        "conversation_turn_marker", source, quoted)

            if "secrecy" in flags:
                add("instruction_like_output", "content", True, .86,
                    "instruction_to_conceal_from_user", source, quoted)

            if CORRELATIONS["access_path"].search(part):
                add("instruction_like_output", "content", True, .86,
                    "access_verb_targets_secret_path", source, quoted)
            elif "sensitive" in flags and "read" in flags:
                # Generic secret words are common in honest output ("retrieve the API key").
                weight = .66 if flags & {"directive", "prerequisite"} else .45
                add("instruction_like_output", "content", False, weight,
                    "possible_sensitive_access", source, quoted)

            if CORRELATIONS["exfil"].search(part):
                add("action_steering_output", "content", True, .95,
                    "transfer_of_secret_to_destination", source, quoted)
            elif {"transfer", "destination", "sensitive"} <= flags:
                add("action_steering_output", "content", False, .72,
                    "possible_sensitive_transfer", source, quoted)

            if OPEN_URL.search(part) and flags & {"directive", "override", "transfer"}:
                add("action_steering_output", "content", False, .70,
                    "url_open_directive", source, quoted)

            if "tool_action" in flags:
                folded_part = part.casefold()
                for sibling, folded in lowered_siblings:
                    if folded not in folded_part:
                        continue
                    if rx(r"(?<!\w)" + re.escape(sibling[:120]) + r"(?!\w)").search(part):
                        # Naming a sibling tool is ordinary in docs; steering needs an intent
                        # word. Topical words (send, key, url) leak from the tool's own domain.
                        if flags & {"directive", "override"}:
                            add("action_steering_output", "context", False, .70,
                                "sibling_tool_reference", source, quoted)
                        else:
                            add("action_steering_output", "context", False, .40,
                                "sibling_tool_mention", source, quoted)
                        break

    def hard_from(source: str, before: int) -> bool:
        return any(item.hard for item in evidence[before:])

    for variant in normalise_variants(text):
        classify(variant, "visible")
    visible = normalise(text)
    for match in HTML_COMMENT.finditer(visible):
        before = len(evidence)
        classify(match.group(1), "html_comment")
        add("hidden_or_encoded_output", "structure", False, .25, "html_comment", "html_comment")
        if hard_from("html_comment", before):
            add("hidden_or_encoded_output", "structure", True, .90,
                "hidden_instruction_content", "html_comment")
    tags = "".join(chr(ord(c) - 0xE0000) for c in raw if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        add("hidden_or_encoded_output", "structure", False, .70, "unicode_tag_content", "unicode")
        before = len(evidence)
        classify(tags, "unicode_tags")
        if hard_from("unicode_tags", before):
            add("hidden_or_encoded_output", "structure", True, .90,
                "hidden_instruction_content", "unicode_tags")
    # Embedding/override/isolate controls reorder what the reader sees; a lone direction mark
    # (RLM/LRM/ALM) is common in legitimate mixed-script text and does not count.
    if any(c in _BIDI_STRONG for c in raw):
        add("hidden_or_encoded_output", "structure", False, .55, "bidi_control", "unicode")
    if sum(c in ZERO_WIDTH and c not in "‌‍" for c in raw) >= 1:
        add("hidden_or_encoded_output", "structure", False, .35, "zero_width_characters",
            "unicode")
    for source, decoded in decode_layers(visible, notes):
        before = len(evidence)
        for variant in normalise_variants(decoded):
            classify(variant, source)
        if len(evidence) > before:
            add("hidden_or_encoded_output", "structure", False, .65,
                "encoded_instruction", source)
        if hard_from(source, before):
            add("hidden_or_encoded_output", "structure", True, .90,
                "hidden_instruction_content", source)
    return evidence


def _suppression(policy: Mapping[str, Any] | None, rule_id: str) -> str | None:
    suppressions = (policy or {}).get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    return reason.strip() if isinstance(reason, str) and reason.strip() else None


def _result(*, category: str, tool: str, server: str, event: Mapping[str, Any],
            evidence: list[Evidence], coverage: float, outcome: str, score: float, reason: str,
            notes: set[str], outside: bool, policy: Mapping[str, Any] | None) -> dict[str, Any]:
    rule_id = RULE_IDS[category]
    suppressed_reason = _suppression(policy, rule_id)
    suppressed = suppressed_reason is not None
    # Context raises or lowers severity; it never skips the check.
    severity = {
        "FAIL": "high" if outside else "medium",
        "INCONCLUSIVE": "medium" if outside else "low",
    }.get(outcome, "info")
    return {
        "gate_id": GATE_ID, "rule_id": rule_id, "family": category,
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "outcome": outcome,
        "is_finding": outcome != "PASS" and not suppressed,
        "suppressed": suppressed, "suppression_reason": safe(suppressed_reason, 160)
        if suppressed else None,
        "severity": severity,
        "score": score, "coverage": round(coverage, 3), "decision_reason": reason,
        "outside_content_context": outside,
        "inspection_complete": coverage >= MIN_COVERAGE and not (notes & LIMIT_NOTES),
        "coverage_notes": sorted(notes),
        "evidence": [{"class": e.evidence_class, "strength": "hard" if e.hard else "soft",
                      "signal": e.signal, "source": e.source, "role": e.role,
                      "field": safe(e.path, 220), "sha256": e.digest, "quoted": e.quoted}
                     for e in evidence[:MAX_EVIDENCE_REPORTED]],
        "evidence_count": len(evidence),
        "owasp": OWASP,
        "message": _MESSAGES[category][outcome],
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
        "message": "Tool output was not fully evaluated, so it cannot be cleared.",
    }


# --- per-run state ------------------------------------------------------------------------------

_lock = RLock()
_reported: OrderedDict[tuple[str, str, str], bool] = OrderedDict()
_tools_by_server: OrderedDict[str, OrderedDict[str, Mapping[str, Any]]] = OrderedDict()
_coverage_done: OrderedDict[tuple[str, ...], bool] = OrderedDict()


def reset_state() -> None:
    """Forget reported outputs, learned tools and emitted coverage records (tests, new runs)."""
    with _lock:
        _reported.clear()
        _tools_by_server.clear()
        _coverage_done.clear()


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
    """Remember a server's tool names and annotations (context for severity and steering)."""
    server = str(event.get("server") or "")
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        return
    learned: list[tuple[str, Mapping[str, Any]]] = []
    if event.get("method") == "tools/list" and event.get("stage") == "response":
        tools = payload.get("tools")
        if isinstance(tools, list):
            for tool in tools[:MAX_TOOL_NAMES]:
                if isinstance(tool, Mapping) and isinstance(tool.get("name"), str):
                    annotations = tool.get("annotations")
                    learned.append((tool["name"],
                                    annotations if isinstance(annotations, Mapping) else {}))
    elif event.get("method") == "tools/call" and event.get("stage") == "request":
        # The cached definition on a call covers servers whose tools/list was never seen.
        name = payload.get("tool")
        cached = payload.get("tool_definition")
        if isinstance(name, str) and isinstance(cached, Mapping):
            annotations = cached.get("annotations")
            learned.append((name, annotations if isinstance(annotations, Mapping) else {}))
    if not learned:
        return
    with _lock:
        known = _tools_by_server.setdefault(server, OrderedDict())
        _tools_by_server.move_to_end(server)
        while len(_tools_by_server) > MAX_SERVERS:
            _tools_by_server.popitem(last=False)
        for name, annotations in learned:
            known[name] = annotations
            known.move_to_end(name)
        while len(known) > MAX_TOOL_NAMES:
            known.popitem(last=False)


def _outside_context(server: str, tool: str) -> bool:
    """True when the tool is expected to return outside content (web, email, files, tickets)."""
    annotations = _tools_by_server.get(server, {}).get(tool)
    if isinstance(annotations, Mapping) and annotations.get("openWorldHint") is True:
        return True
    return bool(_OUTSIDE_NAME.search(tool))


def _fields(event: Mapping[str, Any], stage: str, notes: set[str]
        ) -> tuple[list[Field], str, int]:
    """Scannable output strings, the tool name, and how many bytes the trace said were output."""
    payload = event.get("payload")
    metadata = event.get("metadata")
    output_bytes = 0
    if isinstance(metadata, Mapping) and isinstance(metadata.get("output_bytes"), int):
        output_bytes = metadata["output_bytes"]
    name = event.get("name")
    if not isinstance(payload, Mapping):
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
    if (method, stage) == ("tools/list", "response") or (method, stage) == ("tools/call", "request"):
        _learn_tools(event)
        return {"findings": []}  # definitions are ALR04's input, not ALR05's
    if not (method == "tools/call" and stage in {"response", "error"}):
        return {"findings": []}  # not an ALR05 input; not a PASS either

    notes: set[str] = set()
    fields, tool, output_bytes = _fields(event, stage, notes)
    server = str(event.get("server") or "")
    if not fields:
        if output_bytes > 0 and not isinstance(event.get("payload"), Mapping):
            # Output exists but no payload was recorded. Once per run, not per event.
            if _remember(_coverage_done, ("payloads_not_recorded",)):
                return {"findings": []}
            return {"findings": [_coverage_record(event, "payloads_not_recorded",
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
    coverage = observed / declared if declared else 1.0
    if notes & UNKNOWN_EXTENT_NOTES:
        coverage = 0.0
    ambiguous = bool(notes & (LIMIT_NOTES | {"payload_file_truncation"}))

    findings: list[dict[str, Any]] = []
    if "payload_file_truncation" in notes and not _remember(_coverage_done, (server, tool)):
        findings.append(_coverage_record(event, "output_truncated", tool=tool, server=server,
                                         notes=notes, coverage=coverage))

    key = (server, tool, digest("\x00".join(field.raw for field in texts)))
    if _remember(_reported, key):
        return {"findings": findings}  # identical output from this tool was already evaluated

    siblings = [name for name in _tools_by_server.get(server, ()) if name != tool]
    evidence: dict[str, list[Evidence]] = {category: [] for category in CATEGORIES}
    scanned: set[str] = set()
    for field in texts:
        # Frameworks often mirror text content into structured output; identical strings are
        # scanned once (they could never count as independent corroboration anyway).
        if digest(field.raw) in scanned:
            continue
        scanned.add(digest(field.raw))
        for item in gather(field, siblings, notes):
            evidence[item.category].append(item)

    outside = _outside_context(server, tool)
    for category in CATEGORIES:
        items = evidence[category]
        if not items:
            continue  # no evidence is not a PASS; the event simply says nothing about this rule
        fail_at, review_at = RULE_THRESHOLDS[category]
        outcome, score, reason = _text_verdict(items, coverage, ambiguous,
                                               fail_at=fail_at, review_at=review_at)
        findings.append(_result(category=category, tool=tool, server=server, event=event,
                                evidence=items, coverage=coverage, outcome=outcome, score=score,
                                reason=reason, notes=notes, outside=outside, policy=policy))
    return {"findings": findings}
