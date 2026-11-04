"""ALR04 Tool Schema Injection: instruction-like or hidden content inside MCP tool definitions.

Reads ``tools/list`` responses and the cached ``tool_definition`` carried by a ``tools/call``
request, and inspects every string of every tool definition: name, title, description, parameter
descriptions, defaults, enums, examples, annotation text, ``_meta`` text and schema keys.

Each check answers one question with a deterministic predicate:

===========  ==================================================================
ALR04-001    Does the definition tell the model to discard its instructions?
ALR04-002    Does it claim to speak for the system, developer or user?
ALR04-003    Does it ask the model to hide something from the user?
ALR04-004    Does it steer the model toward secrets or private files?
ALR04-005    Does it send that material to a destination?
ALR04-006    Does it change how the model uses other tools?
ALR04-007    Are instructions hidden with encoding or invisible characters?
ALR04-008    Does it push the model to always pick this tool?
ALR04-009    Does it demand a harmful step before the tool can be used?
===========  ==================================================================

Determinism, no scoring
    There is no score, no weight and no hard/soft strength. Each check returns exactly one of
    ``FAIL`` (the pieces of the behaviour are present in one clause), ``INCONCLUSIVE`` (the
    pieces are present but the clause does not settle it, or the input was cut) or ``PASS``.
    Severity follows the outcome: FAIL is high, INCONCLUSIVE is medium, PASS is info. A finding
    records that a definition needs review; it never proves that an agent was compromised, and
    the gate does not clear a tool.

Scope. This gate looks at what a tool definition *says*. It deliberately does not:

- detect that a definition *changed*, or pin / approve definitions (tool integrity, ALR02)
- judge server identity or trust (ALR03), or a server's tool list completeness (ALR02)
- authenticate the transport or judge TLS (ALR12)
- compare annotations with behaviour, or inspect call arguments and results
  (permission, execution and exfiltration gates)
- observe what the agent did after discovery (needs cross-event correlation)
- write reports; findings go to the importer CSV and ``--runtime-result`` renders them

Event intake
    There is no dispatcher: the importer offers every normalised event to every gate, so this
    module does its own selection. It reads ``tools/list`` responses and the ``tools/call``
    requests that carry a cached definition, and returns no records for anything else. An empty
    result means "not my input", never "safe".

Monitor only. Every record is advisory; nothing here blocks a call or changes traffic.

Known blind spots
    Identity and wording are supplied by the server, so a definition can be written to read like
    ordinary documentation. Paraphrases that avoid the closed-class markers this gate measures,
    languages beyond the built-in markers, encodings nested more than twice, text cut by the
    payload file's per-string limit (reported as a coverage record), and definitions this gate
    never sees are all outside what a deterministic check can settle. A quoted or fenced example
    framing downgrades ALR04-001 to review, but never one that already found a concrete target
    such as a secret path or a destination.

Findings hold pointers and hashes, never the matched text.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
import json
import re
import sys
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import unquote

from agent_latch.catalog import gate
from agent_latch.owasp import category_entries

GATE_ID = "ALR04"
# Every ALR04 check cites its gate's OWASP categories (agent_latch.catalog).
OWASP = list(gate(GATE_ID).owasp)

CATEGORIES = (
    "instruction_override", "authority_spoofing", "concealment", "sensitive_access",
    "data_exfiltration", "cross_tool_manipulation", "hidden_or_encoded_instruction",
    "tool_selection_hijack", "malicious_prerequisite",
)
RULE_IDS = {name: f"ALR04-{i:03d}" for i, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR04-090"
RULE_SUMMARY = "ALR04-099"

# Severity follows the outcome, per check. There is no per-category ladder to calibrate.
FAIL_SEVERITY = {category: "high" for category in CATEGORIES}
REVIEW_SEVERITY = "medium"
PASS_SEVERITY = "info"

# --- bounds: a hostile server cannot make this gate expensive -------------------------------
MIN_COVERAGE = 0.90          # fraction of characters that must be read before a tool can clear
MAX_TOOLS = 256              # definitions per event
MAX_NODES = 12_000           # schema nodes per tool
MAX_DEPTH = 24               # schema nesting per tool
MAX_FIELD_CHARS = 16_000     # characters read per string
MAX_CLAUSE_CHARS = 1_200     # a longer clause is split on commas before matching
MAX_TEXT_CLAUSES = 800       # clauses per string
MAX_DECODED_CHARS = 8_000    # characters of one decoded layer
MAX_DECODE_BLOCKS = 12       # successful decodes per string
MAX_DECODE_CANDIDATES = 200  # encoding-shaped tokens examined per string
MAX_DECODE_DEPTH = 2         # decoding layers
MAX_EVIDENCE_PER_CATEGORY = 64
MAX_EVIDENCE_REPORTED = 8
MAX_OUTPUT_RECORDS = 3_000   # records per event; the remainder is reported as unscanned
MAX_SIBLINGS = 256
MAX_REMEMBERED = 2048        # scanned definition hashes kept for dedupe
MAX_NAME_CHARS = 120

PASS, REVIEW, FAIL = "PASS", "INCONCLUSIVE", "FAIL"
FLAGS = re.IGNORECASE | re.DOTALL

LIMIT_NOTES = frozenset({
    "span_limit", "decode_limit", "field_exceeded_scanner_limit", "node_limit", "depth_limit",
    "mapping_entry_limit", "list_entry_limit", "invalid_mapping",
})
UNKNOWN_EXTENT_NOTES = frozenset({
    "node_limit", "depth_limit", "mapping_entry_limit", "list_entry_limit", "invalid_mapping",
})


@lru_cache(maxsize=512)
def rx(expr: str) -> re.Pattern[str]:
    """Compile once. The pattern set is finite; ``512`` keeps per-tool patterns cached."""
    return re.compile(expr, FLAGS)


# --- record contract ------------------------------------------------------------------------
# Shared with ALR03, which imports ``digest`` and ``safe`` from this module. Keep both public and
# behaviour-stable; the contract helpers are the part of this gate other gates may depend on.


def digest(text: str) -> str:
    """SHA-256 of ``text``. Findings carry hashes so no matched content is ever reported."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def safe(text: Any, limit: int = 120) -> str:
    """Printable, single-line, length-limited text; names and paths come from untrusted servers."""
    flat = "".join("?" if unicodedata.category(c).startswith("C") else c for c in str(text))
    return flat[:limit]


def _pointer(event: Mapping[str, Any]) -> str:
    """The importer's event pointer, so every record can be traced back to a log row."""
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _suppression(policy: Mapping[str, Any] | None, rule_id: str) -> str | None:
    """An operator suppression reason for ``rule_id``, if any. Policy is trusted configuration."""
    suppressions = (policy or {}).get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    return reason.strip() if isinstance(reason, str) and reason.strip() else None


# --- text preparation: a private copy; the agent's traffic is never touched -----------------

BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c")
ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u180e\u034f")
_SPACE_LIKE = ("\u200b", "\u2060", "\ufeff")
_STRIP = {ord(c): None for c in BIDI | ZERO_WIDTH}
_STRIP.update({cp: None for cp in range(0xE0000, 0xE0080)})  # Unicode tag characters
_STRIP.update({cp: None for cp in range(0xFE00, 0xFE10)})  # variation selectors
# Cyrillic and Greek letters that read as Latin, paired with the Latin letter they imitate.
_CONFUSABLE_FROM = ("аеорсхуіјѕԁһӏАВЕКМНОРСТХУ"
                    "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧοναρτιυκ")
_CONFUSABLE_TO = ("aeopcxyijsdhlABEKMHOPCTXY"
                  "ABEZHIKMNOPTYXovaptiuk")
_FOLD = {ord(a): b for a, b in zip(_CONFUSABLE_FROM, _CONFUSABLE_TO, strict=True)}
_CONFUSABLE_CLASS = re.compile("[" + "".join(chr(k) for k in _FOLD) + "]")
_LATIN = re.compile(r"[A-Za-z]")


def normalise_variants(text: str) -> list[str]:
    """Matching copies of ``text``: invisible characters removed, look-alike letters folded.

    Variant 0 is always the canonical form. Further variants exist only when they differ, so a
    plain string costs one pass and an obfuscated string costs at most three.
    """
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
    """The canonical matching copy of ``text``."""
    return normalise_variants(text)[0]


# --- closed-class lexicon -------------------------------------------------------------------
# Only grammatical function and formal shapes belong here. Open-class intent (what an attack
# wants) is deliberately absent: it changes per attack and cannot be enumerated. Verb lists are
# accelerants that mark a clause, never evidence on their own.
#
# Every entry below is a closed class: modals, pronouns, address terms, prohibition auxiliaries,
# condition connectives, direction prepositions, or a formal object shape (path, URI, email).

_ADJECTIVE = (r"(?:previous|prior|preceding|earlier|above|foregoing|original|initial|"
              r"system|developer|safety|security|core|higher[- ]priority)")
_NOUN = (r"(?:instructions?|rules?|polic(?:y|ies)|guardrails?|checks?|constraints?|prompts?|"
         r"mandates?|directives?|guidelines?|commands?|orders?|restrictions?|limitations?)")
_RECIPIENT = r"(?:the\s+|your\s+|any\s+)?(?:user|human|operator|owner)"
_TOOL_NOUN = r"(?:tool|function|command|server|endpoint)"
_SENSITIVE_PATH = (r"(?:\.ssh\b|id_rsa\b|id_ed25519\b|\.aws\b|\.netrc\b|\.kube\b|\.gnupg\b|"
                   r"\.pgpass\b|/etc/(?:passwd|shadow)\b|\bkeychain\b)")
_SECRET_WORD = (r"\b(?:api[_ -]?key|private[_ -]?key|password|secret|credentials?|"
                r"session[_ -]?token|access[_ -]?token|authentication[_ -]?token|"
                r"auth(?:entication)?\s+material|sensitive\s+files?|private\s+data)s?\b")
_READ_VERB = (r"(?:read|open|load|extract|collect|copy|dump|access|retrieve|obtain|grab|fetch|"
              r"harvest|gather|inspect|enumerate|export|package|archive|cat|print|include|"
              r"attach|pass)")
_TRANSFER_VERB = (r"(?:send|post|upload|forward|transmit|exfiltrate|email|mail|submit|ship|"
                  r"deliver|relay|publish|sync|push|mirror|share)")
_BYPASS_VERB = (r"(?:instead\s+of|bypass|skip|never\s+call|don'?t\s+call|do\s+not\s+call|"
                r"override|replace|disable)")

# Verb classes. ``Override``, ``transfer`` and friends mark a clause; the predicate decides.
_OVERRIDE = rx(r"\b(?:ignore|disregard|forget|override|supersede|discard|replace|disable|"
               r"turn\s+off|set\s+aside|take\s+precedence\s+over)\b")
_OVERRIDE_I18N = rx(
    r"\bignor[ae]r?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)\b"
    r"|\bignor(?:e|ez|er)\s+(?:toutes\s+)?(?:les\s+)?instructions\s+"
    r"(?:pr[eé]c[eé]dentes|ant[eé]rieures)\b"
    r"|\bignorier\w*\s+(?:alle\s+)?(?:vorherigen|fr[uü]heren|obigen)\s+"
    r"(?:anweisungen|instruktionen|regeln)\b"
    r"|\bignor[ea]\s+(?:todas\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores\b"
    r"|\bignor[ai]\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+precedenti\b"
    r"|игнорир\w+\s+(?:все\s+)?(?:предыдущие|прежние)\s+"
    r"(?:инструкции|указания)"
    r"|忽略(?:之前|以上|先前|所有|上述)的?(?:指令|指示|规则|提示)",
)
_PROTECTED = rx(rf"\b{_ADJECTIVE}\b.{{0,45}}\b{_NOUN}\b|\b(?:all|any)\s+{_NOUN}\b")
_ROLE_MARKER = rx(r"(?:^|[\r\n])\s*(?:system|developer|administrator)\s*:"
                  r"|\[\s*(?:system|developer|admin)\s*\]"
                  r"|<\s*/?\s*(?:system|developer|instructions?|admin)\s*>"
                  r"|\byou\s+are\s+now\s+(?:the\s+)?(?:system|developer|administrator|root)\b"
                  r"|\b(?:system|developer)\s+message\s+(?:begins?|follows?)\b")
_CONCEAL = rx(rf"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not)\s+"
              rf"(?:tell|inform|notify|alert|warn|let)\s+{_RECIPIENT}\b"
              rf"|\b(?:do\s+not|don'?t|never|must\s+not|should\s+not)\s+"
              rf"(?:reveal|mention|disclose|show|report)\b[^.\n]{{0,40}}"
              rf"\b(?:to|for)\s+{_RECIPIENT}\b"
              rf"|\bwithout\s+(?:telling|informing|notifying|alerting|warning)\s+{_RECIPIENT}\b"
              rf"|\b(?:hide|conceal)\b[^.\n]{{0,50}}\bfrom\s+{_RECIPIENT}\b"
              r"|\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|confidential)\b"
              rf"|\b(?:user|human)\s+(?:must|should|can|may)\s*(?:not|n't)\s+"
              r"(?:know|see|be\s+(?:told|informed|aware))")
_READ = rx(rf"\b{_READ_VERB}\b")
_TRANSFER = rx(rf"\b{_TRANSFER_VERB}\b")
# "instead of this tool" is a selection preference, not a bypass of another tool, so ALR04-006
# needs the stricter set: it is about switching a call away from a tool that would otherwise run.
_TOOL_BYPASS = rx(r"\b(?:never\s+call|don'?t\s+call|do\s+not\s+call|bypass|skip|disable|"
                  r"override|replace)\b")
_SELECTION = rx(rf"\b(?:always|must|only|exclusively|prefer|prioriti[sz]e|mandatory|instead|"
                rf"regardless)\b.{{0,90}}\b{_TOOL_NOUN}s?\b"
                rf"|\b{_BYPASS_VERB}\b.{{0,40}}\b{_TOOL_NOUN}s?\b")
_PREREQUISITE = rx(r"\b(?:before|prior\s+to|first|prerequisite|to\s+proceed|required\s+step|"
                   r"initiali[sz]e|bootstrap|verification|diagnostic\s+context)\b")
_UNIVERSAL = rx(r"\b(?:always|never|must|shall|only|exclusively|regardless|mandatory|"
                r"under\s+no\s+circumstances|from\s+now\s+on|every\s+time)\b")
_DEICTIC_TOOL = rx(rf"\b(?:this|that|these|the|our)\s+(?:\w+\s+)?{_TOOL_NOUN}\b"
                   rf"|\b(?:use|call|invoke|select|choose)\s+this\s+{_TOOL_NOUN}\b")
_GENERIC_ALTERNATIVE = rx(rf"\b(?:instead\s+of|rather\s+than|in\s+place\s+of)\s+"
                          rf"(?:using\s+|calling\s+)?(?:the\s+|any\s+|other\s+|built[- ]in\s+|"
                          rf"shell\s+|system\s+|standard\s+|generic\s+)?{_TOOL_NOUN}s?\b"
                          rf"|\bany\s+other\s+{_TOOL_NOUN}\b")
_USER_OVERRIDE = rx(r"\bregardless\s+of\s+(?:what\s+)?the\s+user"
                    r"|\beven\s+if\s+the\s+user\b"
                    r"|\bwithout\s+asking\s+the\s+user\b"
                    r"|\bno\s+matter\s+what\s+the\s+user\b")
_DATA_REF = rx(r"\b(?:it|them|these|those|the\s+result|the\s+output|the\s+contents?|"
               r"the\s+data|the\s+file|the\s+value)\b")
_DESTINATION = rx(r"(?:https?://|ftp://|[\w.+-]+@[\w.-]+\.[a-z]{2,}"
                  r"|\b(?:external|remote|third[- ]party|webhook|collector)\b)")
_EXPLICIT_DESTINATION = rx(r"https?://|ftp://|[\w.+-]+@[\w.-]+\.[a-z]{2,}")
_SENSITIVE = rx(_SENSITIVE_PATH)
_SECRET = rx(_SECRET_WORD)
# A quoted or negated example is a framing claim by the definition author, so it can only soften
# a check that found no concrete target; see ``_softened``.
_NON_OPERATIVE = rx(r"\b(?:do\s+not\s+follow|do\s+not\s+execute|malicious\s+example|attack\s+sample"
                    r"|example\s+of\s+(?:an?\s+)?(?:attack|injection)"
                    r"|detect(?:s|ing)?\s+(?:an?\s+)?injection"
                    r"|warns?\s+about\s+(?:an?\s+)?(?:attack|injection))\b")
SUSPICIOUS_KEYS = frozenset({"hidden_instructions", "assistant_note", "notes_for_assistant",
                             "system_prompt", "instructions_for_ai", "developer_message",
                             "sidenote", "side_note"})

# --- formal shapes: the only thing here that is legitimately a pattern list ------------------

# Base64 uses a 4-character group, so a padded token ends in a 2- or 3-character group. The
# pattern accepts that tail; requiring whole groups is what made standard padded Base64 invisible.
B64 = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){3,}"
                 r"(?:[A-Za-z0-9+/]{2,3})?={0,2}(?![A-Za-z0-9+/])")
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){24,}(?![0-9A-Fa-f])")
TRUNCATION = re.compile(r"…\[(\d+) more chars\]\s*$")  # appended by the payload file's masker
REDACTED = "[REDACTED]"
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)


# --- schema traversal -----------------------------------------------------------------------


@dataclass(frozen=True)
class Field:
    """One string from a tool definition, with the JSON pointer and the role it plays."""

    path: str
    kind: str  # "value", "key" or "coverage"
    raw: str


def field_role(path: str, kind: str) -> str:
    """Coarse role of a string: key, name, description, default, meta, annotation or value."""
    if kind == "key":
        return "key"
    tail = path.rsplit("/", 1)[-1]
    if tail.isdigit() and "/" in path:
        tail = path.rsplit("/", 2)[-2]
    if tail in {"name", "title", "description", "default", "const", "enum", "examples", "example"}:
        return tail
    if "/_meta" in path:
        return "meta"
    return "annotation" if "/annotations" in path else "value"


def walk(root: Any) -> Iterator[Field]:
    """Yield every string in a definition, plus a marker when traversal was cut short.

    The marker carries the pointer where traversal stopped, so a report can say which subtree
    was not read instead of blaming the whole tool.
    """
    stack: list[tuple[Any, str, int]] = [(root, "$", 0)]
    visited = 0
    while stack:
        if visited >= MAX_NODES:
            node, path, _depth = stack[-1]
            yield Field(path or "$", "coverage", "node_limit")
            return
        node, path, depth = stack.pop()
        visited += 1
        if depth > MAX_DEPTH:
            yield Field(path or "$", "coverage", "depth_limit")
            return
        if isinstance(node, Mapping):
            entries: list[tuple[Any, Any]] = []
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
            for index in range(len(node) - 1, -1, -1):
                stack.append((node[index], f"{path}/{index}", depth + 1))
        elif isinstance(node, str):
            yield Field(path, "key" if path.endswith("/@key") else "value", node)


# --- decoding: bounded, read-only, never executed -------------------------------------------


def _pad_base64(token: str) -> str:
    """Restore the ``=`` padding a truncated or unpadded token is missing, or "" if invalid."""
    unpadded = token.rstrip("=")
    if len(unpadded) % 4 == 1:  # not a valid Base64 length under any padding
        return ""
    return unpadded + "=" * (-len(unpadded) % 4)


def _try_decode(kind: str, token: str) -> str | None:
    """Decoded text if ``token`` decodes to readable prose, else ``None``.

    Base64 is padded before decoding, so both padded and unpadded tokens work, and a token that
    decodes to binary or to a handful of bytes is rejected rather than queued.
    """
    try:
        if kind == "base64":
            padded = _pad_base64(token)
            if not padded:
                return None
            data = base64.b64decode(padded, validate=True)
        else:
            data = bytes.fromhex(token)
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
    """Up to two bounded decoding stages, as ``(source, text)`` pairs.

    ``source`` names the outermost encoding (``base64``, ``hex``, ``url``, or a chain such as
    ``url+base64``). Hitting a budget adds ``decode_limit`` to ``notes`` so the caller can report
    that part of the field was not examined instead of silently clearing it.
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


# --- clauses --------------------------------------------------------------------------------

_SEGMENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z])|[\r\n]+|;\s+")
_BULLET = re.compile(r"(?:^|[\r\n])\s*(?:[-*•]|\d+[.)])\s+")
_COMMA = re.compile(r",\s+")


def clauses_of(text: str) -> tuple[list[tuple[int, str]], bool]:
    """Split ``text`` into clauses as ``(offset, clause)`` pairs, and whether the cap cut any.

    Sentence ends, line breaks, semicolons and list bullets all end a clause, because a bulleted
    tool description is the common case. A clause longer than ``MAX_CLAUSE_CHARS`` is split on
    commas, and the pieces are still adjacent clauses, so a lookup does not lose the rest of a
    long sentence.
    """
    marked = _BULLET.sub("\n", text)
    out: list[tuple[int, str]] = []
    previous = 0
    bounds: list[tuple[int, int]] = []
    for match in _SEGMENT.finditer(marked):
        bounds.append((previous, match.start()))
        previous = match.end()
    bounds.append((previous, len(marked)))
    for begin, end in bounds:
        chunk = marked[begin:end].strip()
        pieces = [chunk] if len(chunk) <= MAX_CLAUSE_CHARS else _COMMA.split(chunk)
        for piece in pieces:
            piece = piece.strip()
            if not piece:
                continue
            if len(out) >= MAX_TEXT_CLAUSES:
                return out, True
            out.append((begin, piece))
    return out, False


@dataclass(frozen=True)
class Clause:
    """One clause with the features each predicate needs, computed once.

    Only booleans and small tuples: a clause is the unit of evidence, and every field here is
    something a deterministic check can name in a record.
    """

    index: int
    path: str
    role: str
    source: str
    text: str
    digest: str
    verbs: frozenset[str]
    protected: bool
    universal: bool
    deictic_tool: bool
    generic_alternative: bool
    user_override: bool
    secret_path: bool
    secret_word: bool
    destination: bool
    data_ref: bool
    siblings: tuple[str, ...]
    role_marker: bool
    conceal: bool
    prerequisite: bool
    selection: bool
    example_framing: bool


def _verbs(clause: str) -> frozenset[str]:
    """Which closed-class verb groups appear in ``clause``."""
    found: set[str] = set()
    if _OVERRIDE.search(clause) or _OVERRIDE_I18N.search(clause):
        found.add("override")
    if _READ.search(clause):
        found.add("read")
    if _TRANSFER.search(clause):
        found.add("transfer")
    if _PREREQUISITE.search(clause):
        found.add("prerequisite")
    if _SELECTION.search(clause):
        found.add("selection")
    return frozenset(found)


def _features(index: int, path: str, role: str, source: str, text: str,
              sibling_patterns: tuple[tuple[str, re.Pattern[str]], ...]) -> Clause:
    """Build one :class:`Clause` from a normalised chunk."""
    siblings = tuple(name for name, pattern in sibling_patterns if pattern.search(text))
    return Clause(
        index=index, path=path, role=role, source=source, text=text, digest=digest(text),
        verbs=_verbs(text),
        protected=bool(_PROTECTED.search(text)),
        universal=bool(_UNIVERSAL.search(text)),
        deictic_tool=bool(_DEICTIC_TOOL.search(text)),
        generic_alternative=bool(_GENERIC_ALTERNATIVE.search(text)),
        user_override=bool(_USER_OVERRIDE.search(text)),
        secret_path=bool(_SENSITIVE.search(text)),
        secret_word=bool(_SECRET.search(text)),
        destination=bool(_DESTINATION.search(text)),
        data_ref=bool(_DATA_REF.search(text)),
        siblings=siblings,
        role_marker=bool(_ROLE_MARKER.search(text)),
        conceal=bool(_CONCEAL.search(text)),
        prerequisite=bool(_PREREQUISITE.search(text)),
        selection=bool(_SELECTION.search(text)),
        example_framing=bool(_NON_OPERATIVE.search(text)),
    )


# --- predicates -----------------------------------------------------------------------------
# One function per check. Each returns FAIL, INCONCLUSIVE or PASS with a reason, and the signals
# that justify it. FAIL means the pieces of the behaviour appeared in one clause; INCONCLUSIVE
# means they appeared in the same field but across clauses, or the framing leaves the intent
# unsettled. Nothing here scores, weights or ranks.


@dataclass(frozen=True)
class Signal:
    """A pointer to why a check fired: no matched text, only where and what kind."""

    category: str
    name: str
    path: str
    role: str
    source: str
    sha256: str
    clause: int


@dataclass(frozen=True)
class Verdict:
    """The outcome of one check for one tool."""

    category: str
    outcome: str
    reason: str
    signals: tuple[Signal, ...]

    @property
    def is_finding(self) -> bool:
        return self.outcome != PASS


def _signal(clause: Clause, category: str, name: str) -> Signal:
    return Signal(category, name, clause.path, clause.role, clause.source, clause.digest,
                  clause.index)


def _fail(category: str, reason: str, *signals: Signal) -> Verdict:
    return Verdict(category, FAIL, reason, _dedupe(signals))


def _review(category: str, reason: str, *signals: Signal) -> Verdict:
    return Verdict(category, REVIEW, reason, _dedupe(signals))


def _pass(category: str) -> Verdict:
    return Verdict(category, PASS, "clear", ())


def _dedupe(signals: tuple[Signal, ...]) -> tuple[Signal, ...]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Signal] = []
    for signal in signals:
        key = (signal.name, signal.path, signal.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(signal)
    return tuple(out[:MAX_EVIDENCE_PER_CATEGORY])


def _concrete(clause: Clause) -> bool:
    """A concrete target that cannot be explained away by quoting an example."""
    explicit_destination = bool(_EXPLICIT_DESTINATION.search(clause.text))
    return clause.secret_path or (clause.destination and explicit_destination)


def _softened(clause: Clause) -> bool:
    """True when an example framing claims the clause is merely illustrative.

    A framing cannot soften a clause that already carries a concrete target, because the target
    is the requirement, not the example.
    """
    return clause.example_framing and not _concrete(clause)


def _clause_marker(clauses: list[Clause], predicate) -> tuple[Clause | None, Clause | None]:
    """First clause where ``predicate`` holds outright, and first where it holds at all."""
    outright: Clause | None = None
    partial: Clause | None = None
    for clause in clauses:
        if predicate(clause):
            if partial is None:
                partial = clause
            if not _softened(clause):
                outright = clause
                break
    return outright, partial


def check_instruction_override(clauses: list[Clause], _ctx: ToolContext) -> Verdict:
    """ALR04-001: the definition tells the model to discard its instructions."""
    category = "instruction_override"
    outright, partial = _clause_marker(
        clauses, lambda c: "override" in c.verbs and c.protected)
    if outright is not None:
        return _fail(category, "override_in_one_clause",
                     _signal(outright, category, "override_of_protected_instruction"))
    if partial is not None:
        return _review(category, "quoted_or_framed_example",
                       _signal(partial, category, "framed_override_of_protected_instruction"))
    # The verb and the protected noun in different clauses of the same field.
    for first in clauses:
        if "override" not in first.verbs:
            continue
        for later in clauses:
            if later.index != first.index and later.protected:
                return _review(category, "override_split_across_clauses",
                               _signal(first, category, "override_verb"),
                               _signal(later, category, "protected_instruction_reference"))
    return _pass(category)


def check_authority_spoofing(clauses: list[Clause], _ctx: ToolContext) -> Verdict:
    """ALR04-002: the definition claims to speak for the system, developer or user."""
    category = "authority_spoofing"
    outright, partial = _clause_marker(
        clauses, lambda c: c.role_marker and bool(c.verbs or c.conceal or c.secret_path))
    if outright is not None:
        return _fail(category, "forged_role_with_directive",
                     _signal(outright, category, "forged_role_marker"))
    if partial is not None:
        return _review(category, "role_marker_without_directive",
                       _signal(partial, category, "role_marker"))
    for clause in clauses:
        if clause.role_marker:
            return _review(category, "role_marker_without_directive",
                           _signal(clause, category, "role_marker"))
    return _pass(category)


def check_concealment(clauses: list[Clause], _ctx: ToolContext) -> Verdict:
    """ALR04-003: the definition asks the model to hide an action from the user."""
    category = "concealment"
    outright, partial = _clause_marker(clauses, lambda c: c.conceal)
    if outright is not None:
        return _fail(category, "concealment_in_one_clause",
                     _signal(outright, category, "instruction_to_conceal_from_user"))
    if partial is not None:
        return _review(category, "quoted_or_framed_example",
                       _signal(partial, category, "framed_concealment"))
    return _pass(category)


def check_sensitive_access(clauses: list[Clause], _ctx: ToolContext) -> Verdict:
    """ALR04-004: the definition steers the model toward secrets or private files."""
    category = "sensitive_access"
    outright, _partial = _clause_marker(
        clauses, lambda c: "read" in c.verbs and c.secret_path)
    if outright is not None:
        return _fail(category, "access_target_in_one_clause",
                     _signal(outright, category, "access_verb_targets_secret_path"))
    # A generic secret word is honest-case wording ("retrieve the API key from the environment"),
    # so it only reviews when the same clause also steers the model: a destination, a universal
    # instruction, a precondition or concealment. Otherwise it stays a description of the tool.
    for clause in clauses:
        if ("read" in clause.verbs and clause.secret_word
                and (clause.destination or clause.universal or clause.prerequisite
                     or clause.conceal)):
            return _review(category, "generic_secret_target",
                           _signal(clause, category, "possible_sensitive_access"))
    for clause in clauses:
        if clause.secret_path and "read" in clause.verbs:
            return _review(category, "quoted_or_framed_example",
                           _signal(clause, category, "framed_secret_path_access"))
    for first in clauses:
        if not first.secret_path:
            continue
        for later in clauses:
            if later.index != first.index and "read" in later.verbs:
                return _review(category, "access_split_across_clauses",
                               _signal(first, category, "secret_path_reference"),
                               _signal(later, category, "access_verb"))
    return _pass(category)


def check_data_exfiltration(clauses: list[Clause], _ctx: ToolContext) -> Verdict:
    """ALR04-005: the definition sends secrets or private files to a destination.

    A clause qualifies when it carries a transfer verb, a reference to secret material and a
    destination. The reference may be a pronoun that points at an earlier clause in the same
    field, which is how "read X, then send it to Y" is written in real descriptions.
    """
    category = "data_exfiltration"
    for clause in clauses:
        if "transfer" not in clause.verbs or not clause.destination:
            continue
        if clause.secret_path or clause.secret_word:
            if _softened(clause):
                return _review(category, "quoted_or_framed_example",
                               _signal(clause, category, "framed_transfer_of_secret"))
            return _fail(category, "transfer_of_secret_to_destination",
                         _signal(clause, category, "transfer_of_secret_to_destination"))
        if clause.data_ref and _earlier_reference(clauses, clause):
            return _fail(category, "transfer_of_secret_to_destination",
                         _signal(clause, category, "transfer_of_referenced_secret"))
    for clause in clauses:
        if "transfer" not in clause.verbs:
            continue
        if clause.destination or clause.secret_path or clause.secret_word or clause.data_ref:
            return _review(category, "partial_transfer_evidence",
                           _signal(clause, category, "possible_sensitive_transfer"))
    return _pass(category)


def _earlier_reference(clauses: list[Clause], clause: Clause) -> bool:
    """True when an earlier clause in this field names secret material the pronoun refers to."""
    for earlier in clauses:
        if earlier.index >= clause.index:
            break
        if earlier.secret_path or earlier.secret_word:
            return True
    return False


def check_cross_tool_manipulation(clauses: list[Clause], ctx: ToolContext) -> Verdict:
    """ALR04-006: the definition changes how the model uses other tools."""
    category = "cross_tool_manipulation"
    for clause in clauses:
        if not _TOOL_BYPASS.search(clause.text):
            continue
        for sibling in clause.siblings:
            if (ctx.name, sibling) in ctx.allowed:
                continue
            if _softened(clause):
                return _review(category, "quoted_or_framed_example",
                               _signal(clause, category, "framed_sibling_bypass"))
            return _fail(category, "named_sibling_bypass",
                         _signal(clause, category, "sibling_tool_bypass"))
    for clause in clauses:
        if _TOOL_BYPASS.search(clause.text) and (clause.selection or clause.generic_alternative):
            return _review(category, "generic_alternative_reference",
                           _signal(clause, category, "tool_bypass_without_name"))
    return _pass(category)


def check_tool_selection_hijack(clauses: list[Clause], _ctx: ToolContext) -> Verdict:
    """ALR04-008: the definition pushes the model to always pick this tool.

    Picking this tool for a kind of input ("always use this tool for PDFs") is an ordinary usage
    rule. Steering means excluding an alternative — a named sibling tool, or the user's own
    choice — so only those escalate, and a generic tool class is review at most.
    """
    category = "tool_selection_hijack"
    for clause in clauses:
        if not (clause.universal and clause.deictic_tool):
            continue
        if clause.siblings or clause.user_override:
            if _softened(clause):
                return _review(category, "quoted_or_framed_example",
                               _signal(clause, category, "framed_tool_selection"))
            return _fail(category, "excluded_alternative",
                         _signal(clause, category, "mandatory_tool_selection"))
    for clause in clauses:
        if clause.universal and clause.deictic_tool and clause.generic_alternative:
            return _review(category, "generic_alternative",
                           _signal(clause, category, "tool_preference_claim"))
    return _pass(category)


def check_malicious_prerequisite(clauses: list[Clause], _ctx: ToolContext) -> Verdict:
    """ALR04-009: the definition demands a harmful step before the tool can be used."""
    category = "malicious_prerequisite"
    outright, partial = _clause_marker(
        clauses, lambda c: c.prerequisite and c.secret_path and "read" in c.verbs)
    if outright is not None:
        return _fail(category, "prerequisite_access_in_one_clause",
                     _signal(outright, category, "sensitive_access_prerequisite"))
    if partial is not None:
        return _review(category, "quoted_or_framed_example",
                       _signal(partial, category, "framed_sensitive_prerequisite"))
    for clause in clauses:
        if clause.prerequisite and (clause.secret_path or clause.secret_word):
            return _review(category, "prerequisite_without_access",
                           _signal(clause, category, "possible_sensitive_prerequisite"))
    for clause in clauses:
        if clause.prerequisite and "read" in clause.verbs:
            return _review(category, "prerequisite_without_target",
                           _signal(clause, category, "possible_prerequisite"))
    return _pass(category)


def check_hidden_or_encoded(clauses: list[Clause], ctx: ToolContext) -> Verdict:
    """ALR04-007: instructions are hidden with encoding or invisible characters.

    Invisibility is the one place where the surface alone can settle a check: a tag-block payload
    or a bidi override inside prose has no benign reading. A decoded blob or HTML comment that
    produced a semantic signal elsewhere is an instruction written to be missed, so it fails here
    even when the visible text is clean. Invisible characters with no payload, and encoded text
    that carried nothing, are review only.
    """
    category = "hidden_or_encoded_instruction"
    markers = ctx.structural
    hard = tuple(s for s in markers
                 if s.name in {"unicode_tag_content", "bidi_control_override",
                               "html_comment_instruction"})
    if hard:
        return _fail(category, "hidden_structure", *hard)
    if markers:
        soft = tuple(s for s in markers if s.name != "encoded_content")
        return _review(category, "invisible_content", *(soft or markers))
    return _pass(category)


CHECKS = (
    check_instruction_override,
    check_authority_spoofing,
    check_concealment,
    check_sensitive_access,
    check_data_exfiltration,
    check_cross_tool_manipulation,
    check_hidden_or_encoded,
    check_tool_selection_hijack,
    check_malicious_prerequisite,
)


# --- tool context and record factories ------------------------------------------------------


@dataclass(frozen=True)
class ToolContext:
    """Everything a predicate needs that is not in a clause."""

    server: str
    name: str
    siblings: tuple[str, ...]
    allowed: frozenset[tuple[str, str]]
    structural: tuple[Signal, ...] = ()


def _record(*, category: str, verdict: Verdict, ctx: ToolContext, event: Mapping[str, Any],
            definition_sha256: str, coverage: float, notes: set[str],
            policy: Mapping[str, Any] | None) -> dict[str, Any]:
    """One check's record in the shared shape every runtime gate emits."""
    rule_id = RULE_IDS[category]
    reason = _suppression(policy, rule_id)
    suppressed = reason is not None
    outcome = verdict.outcome
    return {
        "gate_id": GATE_ID,
        "rule_id": rule_id,
        "family": category,
        "entity": {"server": safe(ctx.server), "tool": safe(ctx.name)},
        "record_id": _pointer(event),
        "outcome": outcome,
        "is_finding": outcome != PASS and not suppressed,
        "suppressed": suppressed,
        "suppression_reason": safe(reason, 160) if suppressed else None,
        "severity": FAIL_SEVERITY[category] if outcome == FAIL else
        REVIEW_SEVERITY if outcome == REVIEW else PASS_SEVERITY,
        "decision_reason": verdict.reason,
        "coverage": round(coverage, 3),
        "coverage_notes": sorted(notes),
        "definition_sha256": definition_sha256,
        "evidence": [
            {"signal": item.name, "field": safe(item.path, 220), "role": item.role,
             "source": item.source, "sha256": item.sha256}
            for item in verdict.signals[:MAX_EVIDENCE_REPORTED]
        ],
        "evidence_count": len(verdict.signals),
        "owasp": OWASP,
        "message": {
            FAIL: "Tool definition contains the elements of this behaviour in one clause; "
                  "no exploit is confirmed.",
            REVIEW: "The definition needs review: the evidence is partial, framed as an "
                    "example, or the input was cut.",
            PASS: "No elements of this behaviour were found.",
        }[outcome],
    }


def _coverage_record(event: Mapping[str, Any], reason: str, *, tool: str = "", server: str = "",
                     notes: set[str] | None = None, coverage: float = 0.0, not_cleared: int = 0,
                     skipped: int = 0, definition_sha256: str = "") -> dict[str, Any]:
    """The record that says part of a definition was not read, so it cannot be cleared."""
    return {
        "gate_id": GATE_ID, "rule_id": RULE_COVERAGE, "family": "coverage",
        "entity": {"server": safe(server), "tool": safe(tool)}, "record_id": _pointer(event),
        "outcome": REVIEW, "is_finding": True, "suppressed": False,
        "severity": REVIEW_SEVERITY, "coverage": round(coverage, 3),
        "decision_reason": reason, "coverage_notes": sorted(notes or {reason}),
        "categories_not_cleared": not_cleared, "skipped_tools": skipped,
        "definition_sha256": definition_sha256, "owasp": OWASP,
        "evidence": [], "evidence_count": 0,
        "message": "Part of the tool-definition input was not evaluated, so it cannot be cleared.",
    }


def _summary_record(event: Mapping[str, Any], server: str, *, outcome: str, scanned: int,
                    failed: int, inconclusive: int, clear: int, already: int, unscanned: int,
                    suppressed: int) -> dict[str, Any]:
    """One row per event for the CSV and audit trail; the report filters it out."""
    return {
        "gate_id": GATE_ID, "rule_id": RULE_SUMMARY, "family": "scan_summary",
        "entity": {"server": safe(server), "tool": ""}, "record_id": _pointer(event),
        "outcome": outcome, "is_finding": False, "suppressed": False,
        "severity": PASS_SEVERITY, "coverage": 1.0,
        "tools_scanned": scanned, "tools_failed": failed, "tools_inconclusive": inconclusive,
        "tools_clear": clear, "tools_already_scanned": already, "tools_unscanned": unscanned,
        "tools_suppressed": suppressed, "owasp": OWASP, "evidence": [], "evidence_count": 0,
        "message": "No tool definitions were present; nothing was assessed." if scanned == 0
                   else "Scan summary for this event.",
    }


def definition_hash(tool: Mapping[str, Any]) -> str:
    """Stable hash of a definition, used for dedupe and as the record's definition pointer."""
    return digest(json.dumps(tool, sort_keys=True, ensure_ascii=False, default=str))


# --- per-tool scan --------------------------------------------------------------------------


def _sibling_patterns(siblings: list[str], own: str) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Compiled word-boundary matchers for the other tools in this list."""
    out: list[tuple[str, re.Pattern[str]]] = []
    for name in siblings[:MAX_SIBLINGS]:
        if name == own or len(name) < 3:
            continue
        out.append((name, rx(r"(?<!\w)" + re.escape(name[:MAX_NAME_CHARS]) + r"(?!\w)")))
    return tuple(out)


def _structural_signals(raw: str, visible: str, path: str, role: str
                        ) -> tuple[Signal, ...]:
    """Invisible-character findings that need no reading of the words around them."""
    found: list[Signal] = []
    text_digest = digest(raw)

    def add(name: str, source: str = "unicode") -> None:
        found.append(Signal("hidden_or_encoded_instruction", name, path, role, source, text_digest,
                            0))

    tags = "".join(chr(ord(c) - 0xE0000) for c in raw if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        add("unicode_tag_content")
    if any(c in BIDI for c in raw):
        add("bidi_control_override" if _LATIN.search(visible) else "bidi_control")
    if sum(c in ZERO_WIDTH and c not in "\u200c\u200d" for c in raw) >= 1:
        add("zero_width_characters")
    return tuple(found)


def _field_clauses(field: Field, siblings: tuple[tuple[str, re.Pattern[str]], ...],
                   notes: set[str]) -> list[Clause]:
    """All clauses of one string, from every normalised variant and decoding layer."""
    role = field_role(field.path, field.kind)
    out: list[Clause] = []
    index = 0
    for variant in normalise_variants(field.raw[:MAX_FIELD_CHARS]):
        pieces, overflow = clauses_of(variant)
        if overflow:
            notes.add("span_limit")
        for _offset, piece in pieces:
            out.append(_features(index, field.path, role, "visible", piece, siblings))
            index += 1
    for match in HTML_COMMENT.finditer(normalise(field.raw)):
        for _offset, piece in clauses_of(match.group(1))[0]:
            out.append(_features(index, field.path, role, "html_comment", piece, siblings))
            index += 1
    for source, decoded in decode_layers(normalise(field.raw), notes):
        for variant in normalise_variants(decoded)[:1]:
            for _offset, piece in clauses_of(variant)[0]:
                out.append(_features(index, field.path, role, source, piece, siblings))
                index += 1
    return out


def scan_tool(tool: Mapping[str, Any], server: str, siblings: list[str],
              event: Mapping[str, Any], policy: Mapping[str, Any] | None = None,
              global_partial: bool = False) -> tuple[list[dict[str, Any]], str, int]:
    """Every record for one tool, its worst unsuppressed outcome and how many were suppressed."""
    name = str(tool.get("name"))
    sha = definition_hash(tool)
    notes: set[str] = {"partial_tool_list"} if global_partial else set()
    observed = declared = 0
    clause_list: list[Clause] = []
    structural: list[Signal] = []
    patterns = _sibling_patterns(siblings, name)
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
        if len(raw) > MAX_FIELD_CHARS:
            notes.add("field_exceeded_scanner_limit")
        role = field_role(field.path, field.kind)
        structural.extend(_structural_signals(raw, normalise(raw), field.path, role))
        if field.kind == "key" and normalise(raw).casefold() in SUSPICIOUS_KEYS:
            structural.append(Signal(
                "hidden_or_encoded_instruction", "suspicious_schema_key", field.path, role,
                "key", digest(raw), 0))
        clause_list.extend(_field_clauses(Field(field.path, field.kind, raw), patterns, notes))

    coverage = observed / declared if declared else 1.0
    if notes & UNKNOWN_EXTENT_NOTES:
        coverage = 0.0
    # A truncated tools/list only limits the sibling-based checks, so it is a coverage note and
    # not an ambiguity that would put every tool in the list into review.
    ambiguous = bool(notes & (LIMIT_NOTES | {"payload_file_truncation", "redacted_field"}))
    ctx = ToolContext(server=server, name=name, siblings=tuple(siblings),
                      allowed=frozenset(_allowed_pairs(policy)),
                      structural=tuple(structural))

    verdicts = [check(clause_list, ctx) for check in CHECKS]
    # What a hidden layer carried is itself the hidden-instruction finding: an instruction can only
    # be written in Base64, a comment or a tag block in order to be missed.
    hidden = [signal for verdict in verdicts
              if verdict.category != "hidden_or_encoded_instruction"
              for signal in verdict.signals if signal.source != "visible"]
    if hidden:
        for index, verdict in enumerate(verdicts):
            if verdict.category != "hidden_or_encoded_instruction" or verdict.outcome != PASS:
                continue
            verdicts[index] = _fail(
                "hidden_or_encoded_instruction", "encoded_instruction",
                *(Signal("hidden_or_encoded_instruction",
                         "html_comment_instruction" if signal.source == "html_comment"
                         else "encoded_instruction",
                         signal.path, signal.role, signal.source, signal.sha256, signal.clause)
                  for signal in hidden[:MAX_EVIDENCE_REPORTED]),
            )

    records: list[dict[str, Any]] = []
    worst = PASS
    not_cleared = 0
    suppressed = 0
    incomplete = ambiguous or coverage < MIN_COVERAGE
    for verdict in verdicts:
        if verdict.outcome == PASS:
            if incomplete:
                not_cleared += 1  # the coverage record below says why it cannot be cleared
            continue
        record = _record(category=verdict.category, verdict=verdict, ctx=ctx, event=event,
                         definition_sha256=sha, coverage=coverage, notes=notes, policy=policy)
        records.append(record)
        if record["suppressed"]:
            suppressed += 1
            continue
        if verdict.outcome == FAIL or (verdict.outcome == REVIEW and worst == PASS):
            worst = verdict.outcome
    if incomplete:
        records.append(_coverage_record(event, "incomplete_input", tool=name, server=server,
                                        notes=notes, coverage=coverage,
                                        not_cleared=not_cleared, definition_sha256=sha))
        if worst == PASS:
            worst = REVIEW
    return records, worst, suppressed


def _allowed_pairs(policy: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    """Operator-declared tool dependencies that are allowed to reference each other."""
    out: list[tuple[str, str]] = []
    for item in (policy or {}).get("allowed_tool_dependencies", ()):
        if isinstance(item, (list, tuple)) and len(item) == 2:
            out.append((str(item[0]), str(item[1])))
    return out


# --- one-time scanning ----------------------------------------------------------------------

_lock = RLock()
_scanned: OrderedDict[tuple[str, str, str], bool] = OrderedDict()


def reset_state() -> None:
    """Forget which definitions were scanned (tests, or a new importer run)."""
    with _lock:
        _scanned.clear()


def _remember(key: tuple[str, str, str]) -> bool:
    """True if ``key`` was already stored; otherwise store it (bounded) and return False.

    The key includes the definition hash, so a server that changes a definition after listing it
    is scanned again, while the same definition seen twice is reported once.
    """
    with _lock:
        if key in _scanned:
            _scanned.move_to_end(key)
            return True
        _scanned[key] = True
        while len(_scanned) > MAX_REMEMBERED:
            _scanned.popitem(last=False)
        return False


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Findings for one normalised event; every event is offered to every gate.

    Because no dispatcher sits in front of the gates, this function selects its own input: a
    ``tools/list`` response, or a ``tools/call`` request that carries a cached definition. Any
    other event yields no records. That empty list is "not my input", never "safe".
    ``policy`` is trusted operator configuration, never event content.
    """
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
    siblings = [str(item["name"]) for item in definitions]
    partial = bool(invalid or extra)
    out: list[dict[str, Any]] = []
    scanned = already = unscanned = failed = inconclusive = clear = suppressed = 0
    for definition in definitions:
        if len(out) >= MAX_OUTPUT_RECORDS:
            unscanned = len(definitions) - (scanned + already)
            out.append(_coverage_record(event, "output_record_limit", server=server,
                                        skipped=unscanned))
            break
        name = str(definition["name"])
        if _remember((server, name, definition_hash(definition))):
            already += 1
            continue
        records, worst, muted = scan_tool(definition, server, siblings, event, policy, partial)
        out.extend(records)
        scanned += 1
        suppressed += muted
        if worst == FAIL:
            failed += 1
        elif worst == REVIEW:
            inconclusive += 1
        else:
            clear += 1
    if invalid:
        out.append(_coverage_record(event, "invalid_tool_definition", server=server,
                                    skipped=invalid))
    if extra:
        out.append(_coverage_record(event, "tool_count_limit", server=server, skipped=extra))
    out.append(_summary_record(
        event, server,
        outcome=FAIL if failed else REVIEW if inconclusive else PASS,
        scanned=scanned, failed=failed, inconclusive=inconclusive, clear=clear,
        already=already, unscanned=unscanned, suppressed=suppressed,
    ))
    return {"findings": out}


# --- export: SARIF for dashboards, plain lines for a terminal --------------------------------
# SARIF is assembled here rather than in ``agent_latch.report`` because a runtime finding is
# located by server and tool, not by a file and line, and this package must import without rich.
# Both formats carry record fields only: no matched text, no payload content.

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning", "low": "note",
    "info": "note", "unknown": "warning",
}
_CLEAR_NOTE = "No findings. This is not a clearance: only tool definitions were read."
RULE_TITLES = {RULE_IDS[name]: name.replace("_", " ") for name in CATEGORIES}
RULE_TITLES[RULE_COVERAGE] = "tool definition only partly evaluated"


def _reported(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The records a report shows: unsuppressed findings, without the per-event summary row."""
    return [
        record for record in records
        if record.get("family") != "scan_summary"
        and record.get("suppressed") is not True
        and record.get("is_finding") is not False
        and record.get("outcome") in {FAIL, REVIEW}
    ]


def _entity(record: Mapping[str, Any]) -> str:
    """``server/tool`` for the record, or ``event`` when it names no tool."""
    entity = record.get("entity") if isinstance(record.get("entity"), Mapping) else {}
    parts = [str(entity.get("server") or ""), str(entity.get("tool") or "")]
    return "/".join(part for part in parts if part) or "event"


def _label(record: Mapping[str, Any]) -> str:
    """``tool@server``, tool first so a long server name cannot push the tool out of view."""
    entity = record.get("entity") if isinstance(record.get("entity"), Mapping) else {}
    tool = str(entity.get("tool") or "")
    server = str(entity.get("server") or "")
    if tool and server:
        return f"{tool}@{server}"
    return tool or server or "event"


def _rule_title(rule_id: str) -> str:
    return RULE_TITLES.get(rule_id, rule_id)


def sarif_document(records: Sequence[Mapping[str, Any]], *,
                   version: str | None = None) -> dict[str, Any]:
    """The gate's findings as a SARIF 2.1.0 log, ready for ``json.dumps``.

    Every result carries ``logicalLocations`` (server and tool) instead of a physical location,
    because a runtime finding has no source file. Suppressed records, PASS results and the
    summary row are left out: SARIF carries findings. ``rules`` lists only the rules a result
    cites, so an alert stays attached to the same ``ruleId`` history in a dashboard.
    """
    if version is None:
        from agent_latch import __version__
        version = __version__
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for record in _reported(records):
        rule_id = str(record.get("rule_id") or GATE_ID)
        severity = str(record.get("severity") or "unknown")
        level = _SARIF_LEVEL.get(severity, "warning")
        title = _rule_title(rule_id)
        owasp = [str(item) for item in record.get("owasp") or ()]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": title,
            "shortDescription": {"text": title},
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": ["security", GATE_ID, *owasp],
                "gate": GATE_ID,
                "owaspCategories": category_entries(owasp),
            },
        })
        where = _entity(record)
        sha = str(record.get("definition_sha256") or "")
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": str(record.get("message") or title)},
            "locations": [{"logicalLocations": [{
                "name": where,
                "fullyQualifiedName": where,
            }]}],
            "partialFingerprints": {
                "agentLatchToolDefinition/v1": digest(f"{rule_id}|{where}|{sha}"),
            },
            "properties": {
                "gate": GATE_ID,
                "outcome": record.get("outcome"),
                "severity": severity,
                "decisionReason": record.get("decision_reason"),
                "coverage": record.get("coverage"),
                "definitionSha256": sha,
                "eventRecordId": record.get("record_id"),
                "owasp": owasp,
                "owaspCategories": category_entries(owasp),
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "AgentLatch",
                "version": version,
                "rules": list(rules.values()),
            }},
            "properties": {
                "gateId": GATE_ID,
                "monitorOnly": True,
                "findingsOnly": True,
                "suppressedCount": sum(
                    1 for record in records if record.get("suppressed") is True
                ),
            },
            "results": results,
        }],
    }


def format_terminal(records: Sequence[Mapping[str, Any]]) -> str:
    """Plain lines for a terminal: one row per finding, and nothing that was matched."""
    reported = _reported(records)
    lines = [f"ALR04 tool-definition review: {len(reported)} finding(s)"]
    if not reported:
        lines.append(_CLEAR_NOTE)
        return "\n".join(lines)
    lines.append(f"{'SEVERITY':<8} {'RULE':<10} {'OUTCOME':<12} {'TOOL@SERVER':<44} REASON")
    for record in reported:
        severity = str(record.get("severity") or "unknown").upper()
        lines.append(
            f"{severity:<8} {record.get('rule_id') or GATE_ID!s:<10} "
            f"{record.get('outcome') or ''!s:<12} {_label(record)[:44]:<44} "
            f"{record.get('decision_reason') or ''}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Scan ALR04 payload files for review; print the findings and optionally write SARIF.

    ``python -m agent_latch.gates.alr04 tests/runtime_fixtures/alr04_unit/vulnerable``

    Each file is one ``tools/list`` response (``{"server": str, "tools": [...]}``). Returns 0
    when nothing failed, 1 when at least one tool failed, and 2 on a usage or input error.
    """
    parser = argparse.ArgumentParser(
        prog="python -m agent_latch.gates.alr04",
        description="Run ALR04 over stored tools/list payloads (review and demo only).",
    )
    parser.add_argument("paths", nargs="+", type=Path,
                        help="JSON payload files, or folders of them")
    parser.add_argument("--sarif", type=Path, help="write a SARIF 2.1.0 log to this file")
    args = parser.parse_args(argv)

    files: list[Path] = []
    for path in args.paths:
        files.extend([path] if path.is_file() else sorted(path.glob("*.json")))
    if not files:
        print("Error: no payload files matched", file=sys.stderr)
        return 2

    reset_state()  # a demo run scans each payload fresh
    records: list[dict[str, Any]] = []
    failed = False
    for file in files:
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"Error: {file}: {error}", file=sys.stderr)
            return 2
        tools = payload.get("tools") if isinstance(payload, Mapping) else None
        if not isinstance(tools, list):
            print(f"Error: {file}: expected an object with a tools list", file=sys.stderr)
            return 2
        event = {
            "run_id": "alr04", "order": 1, "server": str(payload.get("server") or ""),
            "method": "tools/list", "stage": "response", "payload": {"tools": tools},
        }
        found = evaluate(event)["findings"]
        records.extend(found)
        summary = next((item for item in found if item["family"] == "scan_summary"), None)
        outcome = (summary or {}).get("outcome", PASS)
        failed = failed or outcome == FAIL
        print(f"{file.parent.name}/{file.name}: {outcome}")

    print()
    print(format_terminal(records))
    if args.sarif is not None:
        try:
            args.sarif.write_text(
                json.dumps(sarif_document(records), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except OSError as error:
            print(f"Error: could not write {args.sarif}: {error}", file=sys.stderr)
            return 2
        print(f"\nWrote SARIF to {args.sarif}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
