"""Shared text-scanning engine for the runtime gates.

Everything here is gate-neutral machinery for finding instruction-like or hidden content in
untrusted text: normalisation (invisible characters removed, look-alike letters folded), bounded
decoding layers, phrase families and correlations, the bounded JSON walk, clause splitting, the
Evidence type, and the corroboration verdict. Gates import from here and add their own input
selection, thresholds, and result records.

The module name starts with an underscore so the importer's gate discovery skips it: it is not a
gate, and it must never become one.

Stability contract: ALR04's recorded 111-case baseline pins this engine's behaviour. A change
here changes both gates at once, so run the ALR04 baseline test before and after any edit.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import re
import unicodedata
from collections import deque
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

MIN_COVERAGE = 0.90
MAX_NODES = 12_000
MAX_DEPTH = 24
MAX_FIELD_CHARS = 16_000
MAX_DECODED_CHARS = 8_000
MAX_DECODE_BLOCKS = 12  # successful decodes per field
MAX_DECODE_CANDIDATES = 200  # base64/hex-looking tokens examined per field
MAX_DECODE_DEPTH = 2
MAX_TEXT_SPANS = 800  # clauses examined per text; hitting this marks the field incomplete

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
B64 = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){6,}"
                 r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])")
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


INDEPENDENT_BOOST = .22


def verdict(items: list[Evidence], coverage: float, ambiguous: bool, *,
            fail_at: float, review_at: float) -> tuple[str, float, str]:
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
    if independent and score >= fail_at:
        return "FAIL", score, "independent_corroboration"
    if score >= review_at:
        return "INCONCLUSIVE", score, "score_needs_review"
    if coverage < MIN_COVERAGE or ambiguous:
        return "INCONCLUSIVE", score, "incomplete_input"
    return "PASS", score, "clear"
