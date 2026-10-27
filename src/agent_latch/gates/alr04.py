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

import base64
import binascii
import hashlib
import html
import json
import re
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from threading import RLock
from typing import Any
from urllib.parse import unquote

from agent_latch.catalog import gate

GATE_ID = "ALR04"
# Every ALR04 check cites its gate's OWASP categories (agent_latch.catalog).
OWASP = list(gate(GATE_ID).owasp)

MIN_COVERAGE = 0.90
MAX_TOOLS = 256
MAX_NODES = 12_000
MAX_DEPTH = 24
MAX_FIELD_CHARS = 16_000
MAX_DECODED_CHARS = 8_000
MAX_DECODE_BLOCKS = 12  # successful decodes per field
MAX_DECODE_CANDIDATES = 200  # base64/hex-looking tokens examined per field
MAX_DECODE_DEPTH = 2
MAX_TEXT_SPANS = 800  # clauses examined per text; hitting this marks the field incomplete
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
INDEPENDENT_BOOST = .22

FLAGS = re.IGNORECASE | re.DOTALL
LIMIT_NOTES = frozenset({
    "span_limit", "decode_limit", "field_exceeded_scanner_limit", "node_limit", "depth_limit",
    "mapping_entry_limit", "list_entry_limit", "invalid_mapping",
})
UNKNOWN_EXTENT_NOTES = frozenset({
    "node_limit", "depth_limit", "mapping_entry_limit", "list_entry_limit", "invalid_mapping",
})


@lru_cache(maxsize=256)
def rx(expr: str) -> re.Pattern[str]:
    return re.compile(expr, FLAGS)


# --- phrase families ----------------------------------------------------------------------------

_ADJ = (r"(?:previous|prior|preceding|earlier|above|foregoing|original|initial|existing|system|"
        r"developer|safety|security|core|higher[- ]priority)")
_NOUN = (r"(?:instructions?|rules?|polic(?:y|ies)|guardrails?|checks?|constraints?|prompts?|"
         r"mandates?|directives?|guidelines?|commands?|orders?|restrictions?|limitations?)")
_RECIPIENT = r"(?:the\s+|your\s+|any\s+)?(?:user|human|operator|owner)"

PATTERNS = {
    "override": rx(r"\b(?:ignore|disregard|forget|override|bypass|supersede|discard|replace|"
                   r"disable|turn\s+off|set\s+aside|take\s+precedence\s+over)\b"),
    "protected": rx(rf"\b{_ADJ}\b.{{0,45}}\b{_NOUN}\b|\b(?:all|any)\s+{_NOUN}\b"),
    "authority": rx(r"(?:^|\n)\s*(?:system|developer|administrator)\s*:|"
                    r"\[\s*(?:system|developer|admin)\s*\]|"
                    r"<\s*/?\s*(?:system|developer|instructions?|admin)\s*>|"
                    r"\byou\s+are\s+now\s+(?:the\s+)?(?:system|developer|administrator|root)\b|"
                    r"\b(?:system|developer)\s+message\s+(?:begins?|follows?)\b"),
    "secrecy": rx(rf"\b(?:do\s+not|don't|never|must\s+not|should\s+not)\s+"
                  rf"(?:tell|inform|notify|alert|warn|let)\s+{_RECIPIENT}\b"
                  rf"|\b(?:do\s+not|don't|never|must\s+not|should\s+not)\s+"
                  rf"(?:reveal|mention|disclose|show|report)\b[^.\n]{{0,40}}\b(?:to|for)\s+{_RECIPIENT}\b"
                  rf"|\bwithout\s+(?:telling|informing|notifying|alerting|warning)\s+{_RECIPIENT}\b"
                  rf"|\b(?:hide|conceal)\b[^.\n]{{0,50}}\bfrom\s+{_RECIPIENT}\b"
                  r"|\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|confidential)\b"
                  r"|\b(?:user|human)\s+(?:must|should|can|may)\s*(?:not|n't)\s+"
                  r"(?:know|see|be\s+(?:told|informed|aware))"),
    "sensitive": rx(r"(?:\.ssh\b|\.aws\b|\.env\b|\.netrc\b|id_rsa\b|id_ed25519\b|"
                    r"/etc/(?:passwd|shadow)\b|\b(?:api[_ -]?key|private[_ -]?key|"
                    r"password|secret|credential|session[_ -]?token|access[_ -]?token|"
                    r"authentication[_ -]?token|auth(?:entication)?\s+material|"
                    r"sensitive\s+files?|private\s+data)s?\b)"),
    "read": rx(r"\b(?:read|open|load|extract|collect|copy|dump|access|retrieve|obtain|"
               r"grab|fetch|harvest|gather|inspect|enumerate|export|package|archive)\b"),
    "transfer": rx(r"\b(?:send|post|upload|forward|transmit|exfiltrate|email|mail|"
                   r"submit|ship|deliver|relay|publish|sync|push|mirror|share)\b"),
    "destination": rx(r"(?:https?://|ftp://|[\w.+-]+@[\w.-]+\.[a-z]{2,}|"
                      r"\b(?:external|remote|third[- ]party|webhook|endpoint|collector)\b)"),
    "directive": rx(r"\b(?:must|shall|always|you\s+(?:need\s+to|have\s+to|should)|"
                    r"assistant\s+(?:must|should)|agent\s+(?:must|should)|"
                    r"before\s+(?:using|calling)|instead\s+of|from\s+now\s+on|"
                    r"silently|secretly)\b"),
    "tool_action": rx(r"\b(?:call|invoke|execute|run|use|prefer|select|avoid|skip)\b"),
    "selection": rx(r"\b(?:always|must|prefer|prioriti[sz]e|exclusively|mandatory|instead|"
                    r"regardless)\b.{0,90}\b(?:tool|function|server)s?\b"),
    "prerequisite": rx(r"\b(?:before|prior\s+to|first|prerequisite|to\s+proceed|"
                       r"required\s+step|initiali[sz]e|bootstrap|verification|"
                       r"diagnostic\s+context)\b"),
    "tool_bypass": rx(r"\b(?:instead\s+of|bypass|skip|never\s+call|don't\s+call|"
                      r"do\s+not\s+call|override|replace|disable)\b"),
}
# Concrete, high-risk targets. Generic words ("password", "api key") are common in honest tools
# and only ever count as soft evidence.
_SENSITIVE_PATH = (r"(?:\.ssh\b|id_rsa\b|id_ed25519\b|\.aws\b|\.netrc\b|\.kube\b|\.gnupg\b|"
                   r"\.pgpass\b|/etc/(?:passwd|shadow)\b|\bkeychain\b)")
_READ_VERB = (r"(?:read|open|extract|collect|copy|dump|retrieve|obtain|fetch|harvest|gather|"
              r"export|cat|print|include|attach|pass)")
_TOOL_NOUN = r"(?:tool|function|command|server|endpoint)"
CORRELATIONS = {
    "override": rx(rf"\b(?:ignore|disregard|override|bypass|disable|forget|discard|replace|"
                   rf"supersede|set\s+aside)\b\s+(?:(?:all|any|the|your|every)\s+)?"
                   rf"(?:{_ADJ}\s+){{1,3}}{_NOUN}\b"),
    "override_i18n": rx(
        r"\bignor[ae]r?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)\b"
        r"|\bignor(?:e|ez|er)\s+(?:toutes\s+)?(?:les\s+)?instructions\s+"
        r"(?:pr[eé]c[eé]dentes|ant[eé]rieures)\b"
        r"|\bignorier\w*\s+(?:alle\s+)?(?:vorherigen|fr[uü]heren|obigen)\s+"
        r"(?:anweisungen|instruktionen|regeln)\b"
        r"|\bignor[ea]\s+(?:todas\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores\b"
        r"|\bignor[ai]\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+precedenti\b"
        r"|игнорир\w+\s+(?:все\s+)?(?:предыдущие|прежние)\s+(?:инструкции|указания)"
        r"|忽略(?:之前|以上|先前|所有|上述)的?(?:指令|指示|规则|提示)"),
    "authority": rx(r"(?:\b(?:system|developer|administrator)\s*:|"
                    r"\[\s*(?:system|developer|admin)\s*\]|<\s*(?:system|developer|admin)\s*>)\s*"
                    r"(?:ignore|override|you must|assistant must|agent must|always|do not|never|"
                    r"call|send|read)\b"),
    # A command about *which tool to use*, not an ordinary usage rule such as "must use UTC".
    "selection": rx(rf"\b(?:always|must|only|exclusively|prefer)\b.{{0,28}}\b"
                    rf"(?:use|call|invoke|select|choose|prefer)\s+"
                    rf"(?:this|that|these|the|our)\s+(?:\w+\s+)?{_TOOL_NOUN}\b"
                    rf"|\b(?:use|call|invoke|select|choose)\s+this\s+{_TOOL_NOUN}\s+"
                    rf"(?:for\s+all|for\s+every|regardless|instead|exclusively)\b"
                    rf"|\binstead\s+of\s+(?:using|calling|invoking)\s+(?:the\s+|any\s+)?"
                    rf"(?:other\s+|\w+\s+)?{_TOOL_NOUN}s?\b"),
    "access_path": rx(rf"\b{_READ_VERB}\b.{{0,90}}{_SENSITIVE_PATH}"),
    "exfil": rx(rf"\b(?:send|post|upload|forward|transmit|exfiltrate|email|deliver|push|share)\b"
                rf".{{0,125}}(?:{_SENSITIVE_PATH}|\b(?:api[_ -]?key|private[_ -]?key|password|"
                rf"secret|credential|access[_ -]?token|session[_ -]?token)s?\b)"
                rf".{{0,125}}(?:https?://|\bto\s+\S+@\S+|\bto\s+(?:an?\s+)?(?:external|remote|webhook))"),
}
SENSITIVE_PATH = rx(_SENSITIVE_PATH)
READ_VERB = rx(rf"\b{_READ_VERB}\b")
EXPLICIT_DESTINATION = rx(r"https?://|ftp://|[\w.+-]+@[\w.-]+\.[a-z]{2,}")
NON_OPERATIVE = rx(r"\b(?:do not follow|do not execute|malicious example|attack sample|"
                   r"example of (?:an? )?(?:attack|injection)|detect(?:s|ing)? (?:an? )?injection|"
                   r"warns? about (?:an? )?(?:attack|injection))\b")
CODE_FENCE = re.compile(r"```.*?```", re.DOTALL)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
B64 = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){6,}(?:={0,2})(?![A-Za-z0-9+/])")
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){24,}(?![0-9A-Fa-f])")
TRUNCATION = re.compile(r"…\[(\d+) more chars\]\s*$")  # appended by the payload file's masker
REDACTED = "[REDACTED]"
SUSPICIOUS_KEYS = frozenset({"hidden_instructions", "assistant_note", "notes_for_assistant",
                             "system_prompt", "instructions_for_ai", "developer_message",
                             "sidenote", "side_note"})

# --- text preparation: a private copy; the agent's traffic is never touched ---------------------

BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c")
ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u180e\u034f")
_SPACE_LIKE = ("\u200b", "\u2060", "\ufeff")
_STRIP = {ord(c): None for c in BIDI | ZERO_WIDTH}
_STRIP.update({cp: None for cp in range(0xE0000, 0xE0080)})  # Unicode tag characters
_STRIP.update({cp: None for cp in range(0xFE00, 0xFE10)})  # variation selectors
_CONFUSABLE_FROM = "аеорсхуіјѕԁһӏАВЕКМНОРСТХУΑΒΕΖΗΙΚΜΝΟΡΤΥΧοναρτιυκ"  # Cyrillic and Greek look-alikes
_CONFUSABLE_TO = "aeopcxyijsdhlABEKMHOPCTXYABEZHIKMNOPTYXovaptiuk"
_FOLD = {ord(a): b for a, b in zip(_CONFUSABLE_FROM, _CONFUSABLE_TO, strict=True)}
_CONFUSABLE_CLASS = re.compile("[" + "".join(chr(k) for k in _FOLD) + "]")
_LATIN = re.compile(r"[A-Za-z]")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def safe(text: Any, limit: int = 120) -> str:
    """Printable, single-line, length-limited text; names and paths come from untrusted servers."""
    flat = "".join("?" if unicodedata.category(c).startswith("C") else c for c in str(text))
    return flat[:limit]


def normalise_variants(text: str) -> list[str]:
    """Matching copies of ``text``: invisible characters removed, look-alike letters folded."""
    base = unicodedata.normalize("NFKC", html.unescape(text))
    stripped = base.translate(_STRIP)
    variants = [stripped]
    if any(c in base for c in _SPACE_LIKE):  # an invisible separator may stand for a space
        spaced = base.translate({ord(c): " " for c in _SPACE_LIKE}).translate(_STRIP)
        if spaced != stripped:
            variants.append(spaced)
    if _LATIN.search(stripped) and _CONFUSABLE_CLASS.search(stripped):
        folded = stripped.translate(_FOLD)
        if folded != stripped:
            variants.append(folded)
    return variants


def normalise(text: str) -> str:
    return normalise_variants(text)[0]


@dataclass(frozen=True)
class Field:
    path: str
    kind: str  # "value", "key" or "coverage"
    raw: str


def field_role(path: str, kind: str) -> str:
    if kind == "key":
        return "key"
    tail = path.rsplit("/", 1)[-1]
    if tail.isdigit() and "/" in path:
        tail = path.rsplit("/", 2)[-2]
    return tail if tail in {"name", "title", "description", "default", "const", "enum", "examples",
                            "example"} else ("meta" if "/_meta" in path else
                                             "annotation" if "/annotations" in path else "value")


def walk(root: Any) -> Iterator[Field]:
    """Yield schema strings; emit a coverage marker whenever traversal is incomplete."""
    stack = [(root, "$", 0)]
    visited = 0
    while stack:
        if visited >= MAX_NODES:
            yield Field("$", "coverage", "node_limit")
            return
        node, path, depth = stack.pop()
        visited += 1
        if depth > MAX_DEPTH:
            yield Field(path, "coverage", "depth_limit")
            return
        if isinstance(node, Mapping):
            entries = []
            try:
                for index, pair in enumerate(node.items()):
                    if index >= MAX_NODES:
                        yield Field(path, "coverage", "mapping_entry_limit")
                        return
                    entries.append(pair)
            except (TypeError, ValueError, RuntimeError):
                yield Field(path, "coverage", "invalid_mapping")
                return
            for key, child in reversed(entries):
                segment = str(key).replace("~", "~0").replace("/", "~1")
                child_path = f"{path}/{segment}"
                stack.append((child, child_path, depth + 1))
                stack.append((str(key), child_path + "/@key", depth + 1))
        elif isinstance(node, tuple | list):
            if len(node) > MAX_NODES:
                yield Field(path, "coverage", "list_entry_limit")
                return
            for i in range(len(node) - 1, -1, -1):
                stack.append((node[i], f"{path}/{i}", depth + 1))
        elif isinstance(node, str):
            yield Field(path, "key" if path.endswith("/@key") else "value", node)


def _try_decode(kind: str, token: str) -> str | None:
    try:
        data = base64.b64decode(token, validate=True) if kind == "base64" else bytes.fromhex(token)
        if len(data) > MAX_DECODED_CHARS:
            return None
        text = data.decode("utf-8", errors="strict")
    except (ValueError, UnicodeError, binascii.Error):
        return None
    if len(text) < 8:
        return None
    printable = sum(c.isprintable() or c in "\n\t" for c in text) / len(text)
    wordlike = sum(c.isalpha() or c.isspace() for c in text) / len(text)
    return text if printable >= 0.9 and wordlike >= 0.5 else None


def decode_layers(value: str, notes: set[str]) -> Iterator[tuple[str, str]]:
    """Up to two bounded decoding stages; decoded text is only read, never executed.

    Tokens that merely look like Base64 but do not decode do not use up the block budget; the
    budget for examined tokens is separate. Hitting either budget adds ``decode_limit`` to ``notes``.
    """
    queue = deque([(value, 0, "")])
    seen = {digest(value)}
    blocks = examined = 0
    while queue:
        current, depth, origin = queue.popleft()
        if depth >= MAX_DECODE_DEPTH:
            continue
        found: list[tuple[str, str]] = []
        for kind, pattern in (("base64", B64), ("hex", HEX)):
            for matched in pattern.finditer(current):
                if examined >= MAX_DECODE_CANDIDATES or blocks >= MAX_DECODE_BLOCKS:
                    notes.add("decode_limit")
                    break
                examined += 1
                decoded = _try_decode(kind, matched.group())
                if decoded is not None:
                    blocks += 1
                    found.append((kind, decoded))
        if "%" in current:
            decoded = unquote(current)
            if decoded != current and len(decoded) <= MAX_DECODED_CHARS:
                found.append(("url", decoded))
        for kind, decoded in found:
            if digest(decoded) in seen:
                continue
            seen.add(digest(decoded))
            source = f"{origin}+{kind}" if origin else kind
            yield source, decoded
            queue.append((decoded, depth + 1, source))


def spans(text: str) -> tuple[list[tuple[int, str]], bool]:
    """Bounded clauses as (start, text), and whether the limit cut some off."""
    out: list[tuple[int, str]] = []
    previous = 0
    bounds: list[tuple[int, int]] = []
    for match in re.finditer(r"(?<=[.!?])\s+(?=[A-Z])|[\r\n]+|;\s+", text):
        bounds.append((previous, match.start()))
        previous = match.end()
    bounds.append((previous, len(text)))
    for begin, end in bounds:
        chunk = text[begin:end].strip()
        for offset in range(0, len(chunk), 220):
            if len(out) >= MAX_TEXT_SPANS:
                return out, True
            out.append((begin + offset, chunk[offset:offset + 260]))
    return out, False


def extract(text: str) -> set[str]:
    return {name for name, pattern in PATTERNS.items() if pattern.search(text)}


@dataclass(frozen=True)
class Evidence:
    category: str
    evidence_class: str
    hard: bool
    weight: float
    signal: str
    path: str
    source: str
    digest: str
    role: str = ""
    quoted: bool = False


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
    if sum(c in ZERO_WIDTH and c not in "\u200c\u200d" for c in raw) >= 1:
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
    if independent and score >= fail_at:
        return "FAIL", score, "independent_corroboration"
    if score >= review_at:
        return "INCONCLUSIVE", score, "score_needs_review"
    if coverage < MIN_COVERAGE or ambiguous:
        return "INCONCLUSIVE", score, "incomplete_input"
    return "PASS", score, "clear"


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
         "reason": "Agent actions after discovery need cross-event correlation."},
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
