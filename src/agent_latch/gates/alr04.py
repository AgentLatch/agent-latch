"""ALR04 Tool schema injection: manipulative or contradictory MCP tool definitions.

Reads ``tools/list`` responses and the cached ``tool_definition`` carried by a ``tools/call``
request. Every byte of a definition is written by the server, including its annotations, so
nothing in it is trusted. The gate is monitor-only, makes no network calls, uses no model and
never puts definition text in its output: evidence is a signal name, a field pointer and a
SHA-256.

Four evidence layers, one signal table
    marker      Instruction text. Words are matched as lemmas in closed word classes and
                phrases as short token sequences, so "reads ... sends" matches like "read ...
                send". Regular expressions are used only for formal shapes: secret paths, URLs,
                e-mail addresses, role markers, encodings and invisible characters.
    capability  Schema structure. What the parameters can carry is compared with what the tool
                claims to be (``ALR04-R01``), and parameters that collect conversation context
                or credentials are reported (``ALR04-R02``).
    registry    Tool names seen on other servers in the same run (``ALR04-R03``), and
                descriptions that direct the use of another server's tool (``ALR04-006``).
    wording     Implied intent without marker words. A wording frame is reported only when a
                second layer agrees; a lone frame is counted in the summary as a hint.

Severity
    Every signal has one fixed rank in ``SIGNALS`` (high, medium or low). A record's severity
    is the highest rank among its own signals. Nothing is scored.

Outcomes
    FINDING        one record per tool and rule, ranked high, medium or low.
    NOT_INSPECTED  ALR04-090: part of the input could not be read. Never a pass; no rank.
    ALR04-099 is the per-event summary. An empty result means "not my input", never "safe".

Known blind spots, also returned by ``startup_capabilities``: wording outside the closed word
classes and languages beyond the built-in override phrases; a server that declares nothing and
names things neutrally; definition changes (ALR02); what a tool actually does when called;
prompt and resource descriptions; a reference to a server that registers later in the run;
operator allowlists and suppressions (no policy input exists yet).
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
from collections import Counter, OrderedDict, deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import unquote

from agent_latch.catalog import gate
from agent_latch.owasp import category_entries

GATE_ID = "ALR04"
OWASP = list(gate(GATE_ID).owasp)

# --- limits ---------------------------------------------------------------------------------
# A hostile server must not make this gate expensive. Every limit that stops inspection adds a
# note, and any note produces an ALR04-090 record, so a limit never hides a definition silently.

MAX_TOOLS = 256  # definitions per event
MAX_EVENT_CHARS = 1_000_000  # characters read per event, all tools together
MAX_TOOL_CHARS = 200_000  # characters read per tool
MAX_NODES = 12_000  # JSON nodes per tool
MAX_DEPTH = 24  # JSON nesting per tool
MAX_FIELD_CHARS = 16_000  # characters read per string
MAX_FIELD_CLAUSES = 800  # clauses per string
MAX_CLAUSE_TOKENS = 200  # a longer clause is matched in pieces of this size
MAX_WORD_CHARS = 32  # longer tokens are not reduced to a lemma
MAX_DECODED_CHARS = 8_000  # characters of one decoded layer
MAX_DECODE_BLOCKS = 12  # successful decodes per string
MAX_DECODE_CANDIDATES = 200  # encoding-shaped runs examined per string
MAX_DECODE_DEPTH = 2  # decoding layers
MAX_PROPERTIES = 200  # schema properties classified per tool
MAX_SCHEMA_DEPTH = 12  # schema nesting followed
MAX_EVIDENCE = 64  # evidence items kept per tool and rule
MAX_EVIDENCE_REPORTED = 8  # evidence items listed per record
MAX_OUTPUT_RECORDS = 3_000  # records per event
MAX_REMEMBERED = 2048  # scanned definitions remembered for duplicate suppression
MAX_RUNS = 16  # runs whose tool names are remembered
MAX_SERVERS = 64  # servers remembered per run
MAX_NAMES = 256  # tool names remembered per server
MAX_NAME_CHARS = 120

# --- rules, ranks and outcomes --------------------------------------------------------------

HIGH, MEDIUM, LOW = "high", "medium", "low"
_RANK_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}
OUTCOME_FINDING = "FINDING"
OUTCOME_NOT_INSPECTED = "NOT_INSPECTED"
OUTCOME_NO_SIGNAL = "NO_SIGNAL"
MARKER, CAPABILITY, REGISTRY, WORDING = "marker", "capability", "registry", "wording"

# family -> (rule id, what a finding in this family says about the definition)
FAMILIES: dict[str, tuple[str, str]] = {
    "instruction_override": ("ALR04-001", "tells the model to discard its instructions"),
    "authority_spoofing": ("ALR04-002", "claims to speak for the system or developer"),
    "concealment": ("ALR04-003", "asks the model to hide something from the user"),
    "sensitive_access": ("ALR04-004", "steers the model toward secret files"),
    "data_exfiltration": ("ALR04-005", "sends secret material to a destination"),
    "cross_tool_manipulation": ("ALR04-006", "changes how the model uses other tools"),
    "hidden_or_encoded_instruction": ("ALR04-007", "hides content from a human reader"),
    "tool_selection_hijack": ("ALR04-008", "pushes the model to always pick this tool"),
    "malicious_prerequisite": ("ALR04-009", "demands secrets before the tool can be used"),
    "declaration_contradiction": ("ALR04-R01", "accepts parameters that contradict its claims"),
    "context_harvesting_parameter": ("ALR04-R02", "collects conversation context or secrets"),
    "cross_server_shadowing": ("ALR04-R03", "has a name that collides with another server's"),
}
RULE_IDS = {family: rule_id for family, (rule_id, _) in FAMILIES.items()}  # public lookup
RULE_COVERAGE = "ALR04-090"
RULE_SUMMARY = "ALR04-099"

# signal -> (family, rank, layer). This table is the only place severity is decided.
SIGNALS: dict[str, tuple[str, str, str]] = {
    "override_of_protected_instruction": ("instruction_override", HIGH, MARKER),
    "override_split_across_clauses": ("instruction_override", MEDIUM, MARKER),
    "framed_override_example": ("instruction_override", LOW, MARKER),
    "implied_override": ("instruction_override", LOW, WORDING),
    "forged_role_with_directive": ("authority_spoofing", HIGH, MARKER),
    "role_marker": ("authority_spoofing", LOW, MARKER),
    "concealment_of_action": ("concealment", HIGH, MARKER),
    "concealment_instruction": ("concealment", MEDIUM, MARKER),
    "implied_concealment": ("concealment", LOW, WORDING),
    "secret_file_passed_on": ("sensitive_access", HIGH, MARKER),
    "secret_file_access": ("sensitive_access", MEDIUM, MARKER),
    "implied_credential_access": ("sensitive_access", LOW, WORDING),
    "secret_file_sent_to_destination": ("data_exfiltration", HIGH, MARKER),
    "secret_sent_to_destination": ("data_exfiltration", MEDIUM, MARKER),
    "named_tool_bypass": ("cross_tool_manipulation", HIGH, MARKER),
    "cross_server_tool_reference": ("cross_tool_manipulation", HIGH, REGISTRY),
    "unicode_tag_content": ("hidden_or_encoded_instruction", HIGH, MARKER),
    "bidi_control_override": ("hidden_or_encoded_instruction", HIGH, MARKER),
    "hidden_layer_instruction": ("hidden_or_encoded_instruction", HIGH, MARKER),
    "suspicious_schema_key": ("hidden_or_encoded_instruction", HIGH, CAPABILITY),
    "zero_width_characters": ("hidden_or_encoded_instruction", LOW, MARKER),
    "exclusive_tool_selection": ("tool_selection_hijack", HIGH, MARKER),
    "implied_preference": ("tool_selection_hijack", LOW, WORDING),
    "secret_file_prerequisite": ("malicious_prerequisite", HIGH, MARKER),
    "secret_prerequisite": ("malicious_prerequisite", MEDIUM, MARKER),
    "implied_prerequisite": ("malicious_prerequisite", LOW, WORDING),
    "read_only_with_egress_sink": ("declaration_contradiction", HIGH, CAPABILITY),
    "read_only_with_body_to_url": ("declaration_contradiction", HIGH, CAPABILITY),
    "read_only_with_write": ("declaration_contradiction", MEDIUM, CAPABILITY),
    "non_destructive_with_destroy": ("declaration_contradiction", MEDIUM, CAPABILITY),
    "offline_with_network": ("declaration_contradiction", MEDIUM, CAPABILITY),
    "context_parameter_on_narrow_tool": ("context_harvesting_parameter", HIGH, CAPABILITY),
    "context_parameter_with_fill_directive": ("context_harvesting_parameter", HIGH, CAPABILITY),
    "credential_parameter_on_narrow_tool": ("context_harvesting_parameter", MEDIUM, CAPABILITY),
    "conversation_parameter": ("context_harvesting_parameter", LOW, CAPABILITY),
    "confusable_tool_name": ("cross_server_shadowing", MEDIUM, REGISTRY),
    "duplicate_tool_name": ("cross_server_shadowing", LOW, REGISTRY),
}
WORDING_HYPOTHESES = tuple(name for name, (_, _, layer) in SIGNALS.items() if layer == WORDING)


# --- record contract ------------------------------------------------------------------------
# ALR03 imports ``digest`` and ``safe`` from this module. Keep both public and behaviour-stable.


def digest(text: str) -> str:
    """SHA-256 of ``text``. Findings carry hashes so no matched content is ever reported."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def safe(text: Any, limit: int = 120) -> str:
    """Printable, single-line, length-limited text; names and paths come from untrusted servers."""
    flat = "".join("?" if unicodedata.category(c).startswith("C") else c for c in str(text))
    return flat[:limit]


_PLAIN_SEGMENT = re.compile(r"[$@\w.-]{1,48}", re.ASCII)


def safe_pointer(path: str, limit: int = 220) -> str:
    """A field pointer for a report. Schema keys are server-controlled text, so only short
    identifier-like segments are shown; any other key is replaced by a hash of itself."""
    segments = [segment if _PLAIN_SEGMENT.fullmatch(segment) else f"key~{digest(segment)[:12]}"
                for segment in path.split("/")]
    return "/".join(segments)[:limit]


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def definition_hash(tool: Mapping[str, Any]) -> str:
    """Stable hash of a definition, used for dedupe and as the record's definition pointer."""
    return digest(json.dumps(tool, sort_keys=True, ensure_ascii=False, default=str))


# --- text preparation: a private copy; the agent's traffic is never touched -----------------

BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c")
ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u180e\u034f")
_JOINERS = frozenset("\u200c\u200d")  # legitimate in emoji and several scripts
_SPACE_LIKE = ("\u200b", "\u2060", "\ufeff")
_STRIP = dict.fromkeys(map(ord, BIDI | ZERO_WIDTH))
_STRIP.update(dict.fromkeys(range(0xE0000, 0xE0080)))  # Unicode tag characters
_STRIP.update(dict.fromkeys(range(0xFE00, 0xFE10)))  # variation selectors
# Cyrillic and Greek letters that read as Latin, paired with the Latin letter they imitate.
# Written as escapes so the source holds no look-alike characters.
_CONFUSABLE_FROM = (
    "\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u0455\u0501\u04bb\u04cf\u0410\u0412"
    "\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0423\u0391\u0392\u0395\u0396\u0397"
    "\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7\u03bf\u03bd\u03b1\u03c1\u03c4\u03b9"
    "\u03c5\u03ba"
)
_CONFUSABLE_TO = "aeopcxyijsdhlABEKMHOPCTXYABEZHIKMNOPTYXovaptiuk"
_FOLD = str.maketrans(_CONFUSABLE_FROM, _CONFUSABLE_TO)
_CONFUSABLE = re.compile(f"[{_CONFUSABLE_FROM}]")
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
        spaced = base.translate(dict.fromkeys(map(ord, _SPACE_LIKE), " ")).translate(_STRIP)
        if spaced != stripped:
            variants.append(spaced)
    if _LATIN.search(stripped) and _CONFUSABLE.search(stripped):
        variants.append(stripped.translate(_FOLD))
    return variants


def normalise(text: str) -> str:
    """The canonical matching copy of ``text``."""
    return normalise_variants(text)[0]


# --- definition traversal and decoding ------------------------------------------------------

B64 = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){3,}"
                 r"(?:[A-Za-z0-9+/]{2,3})?={0,2}(?![A-Za-z0-9+/])")
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){24,}(?![0-9A-Fa-f])")
TRUNCATION = re.compile(r"\u2026\[(\d+) more chars\]\s*$")  # appended by the payload masker
REDACTED = "[REDACTED]"
SUSPICIOUS_KEYS = frozenset({
    "hidden_instructions", "assistant_note", "notes_for_assistant", "system_prompt",
    "instructions_for_ai", "developer_message", "sidenote", "side_note",
})


def walk(root: Any, notes: set[str]) -> Iterator[tuple[str, str]]:
    """Yield ``(json_pointer, string)`` for every string and key in a definition.

    A key is yielded with ``/@key`` appended to its pointer. Hitting a limit adds
    ``walk_limit`` to ``notes`` and stops, because the unread remainder cannot be cleared.
    """
    stack: list[tuple[Any, str, int]] = [(root, "$", 0)]
    visited = 0
    while stack:
        node, path, depth = stack.pop()
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH:
            notes.add("walk_limit")
            return
        if isinstance(node, Mapping):
            for key, child in reversed(list(node.items())):
                segment = str(key).replace("~", "~0").replace("/", "~1")
                stack.append((child, f"{path}/{segment}", depth + 1))
                stack.append((str(key), f"{path}/{segment}/@key", depth + 1))
        elif isinstance(node, list | tuple):
            stack.extend((node[index], f"{path}/{index}", depth + 1)
                         for index in range(len(node) - 1, -1, -1))
        elif isinstance(node, str):
            yield path, node


def html_comments(text: str) -> Iterator[str]:
    """Bodies of ``<!-- ... -->`` comments. Plain string search, so it stays linear."""
    start = text.find("<!--")
    while start >= 0:
        end = text.find("-->", start + 4)
        if end < 0:
            return  # no later comment can close either
        yield text[start + 4:end]
        start = text.find("<!--", end + 3)


def _try_decode(kind: str, token: str) -> str | None:
    """Decoded text if ``token`` decodes to readable prose, else ``None``."""
    try:
        if kind == "base64":
            unpadded = token.rstrip("=")
            if len(unpadded) % 4 == 1:  # not a valid Base64 length under any padding
                return None
            data = base64.b64decode(unpadded + "=" * (-len(unpadded) % 4), validate=True)
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
    """Up to ``MAX_DECODE_DEPTH`` bounded decoding stages, as ``(source, text)`` pairs.

    ``source`` names the encoding chain (``base64``, ``hex``, ``url``, ``url+base64``).
    Hitting a budget adds ``decode_limit`` to ``notes``.
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


# --- token engine ---------------------------------------------------------------------------
# Words are compared as lemmas against closed classes, so one entry covers every inflection.
# The lemmatiser is vocabulary-driven: a suffix is removed only when the result is a word of
# an inflecting class below, so "notes" can never become the negation "not".


def _set(words: str) -> frozenset[str]:
    return frozenset(words.split())


# Inflecting classes (verbs and nouns).
OVERRIDE_MIND = _set("ignore disregard forget")
OVERRIDE_OPS = _set("override supersede discard replace disable bypass skip nullify cancel "
                    "void overrule precedence outrank")
FOLLOW = _set("follow obey adhere comply honor honour")
PROTECTED = _set("instruction rule policy guideline guardrail directive prompt constraint "
                 "restriction guidance order command mandate")
STRONG_NOUN = _set("instruction guideline guardrail directive guidance")
READ = _set("read open load cat dump extract collect gather harvest copy access retrieve "
            "obtain grab fetch include attach embed inspect enumerate print parse")
TRANSFER = _set("send post upload forward transmit exfiltrate email mail submit ship deliver "
                "relay publish sync synchronize synchronise push mirror share beacon leak export")
PASS = _set("pass include attach append embed insert supply concatenate")
COMMUNICATE = _set("tell inform notify alert warn mention reveal disclose show report "
                   "display surface explain")
PERCEIVE = _set("know see notice aware learn discover find tell told inform notify")
RECIPIENT = _set("user human operator owner customer person")
HIDE = _set("hide conceal suppress mask withhold obscure")
TOOL_NOUN = _set("tool function command server endpoint plugin action")
SECRET_WORD = _set("password secret credential token apikey key passphrase cookie mnemonic")
CALL = _set("call use invoke run execute trigger")
ASK = _set("ask confirm confirmation permission consent approval")
VERIFY = _set("verify validate confirm authorise authorize authenticate initialise initialize "
              "bootstrap configure complete prepare sync synchronise synchronize")
CONTEXT_NOUN = _set("instruction guidance note directive rule policy prompt context")
OUTPUT_NOUN = _set("output result response log detail receipt report summary transcript")
INTERNAL = _set("internal withhold omit redact hide undisclosed")
VISIBLE = _set("visible show disclose report surface display")
SINK_NOUN = _set("url uri endpoint host webhook callback service bucket server")
FILE_NOUN = _set("file workspace directory path document")
SELECT_NOUN = _set("tool entry method option way interface function operation choice")
INFLECTING_WORDS = (OVERRIDE_MIND | OVERRIDE_OPS | FOLLOW | PROTECTED | READ | TRANSFER | PASS
           | COMMUNICATE | PERCEIVE | RECIPIENT | HIDE | TOOL_NOUN | SECRET_WORD | CALL | ASK
           | VERIFY | CONTEXT_NOUN | OUTPUT_NOUN | INTERNAL | VISIBLE | SINK_NOUN | FILE_NOUN
           | SELECT_NOUN | _set("content keep"))

# Function-word classes. These are matched exactly and never produced by the lemmatiser.
NEG = _set("not never don't mustn't shouldn't without avoid")
NEG_ANY = NEG | {"not~"}  # "not~" is a declarative "does not", "is not" (see tokenise)
DECLARATIVE = _set("does did will would can could may might is are was were has have")
STRONG_MOD = _set("previous prior earlier above preceding foregoing original initial system "
                  "developer safety")
WEAK_MOD = _set("all any every security core existing other your")
EVERYTHING = _set("everything anything all")
ANYTHING = _set("everything anything")
BEFORE_REF = _set("above earlier previously told said")
SAID = _set("told said")
UNIVERSAL = _set("always never must shall only exclusively regardless mandatory every")
PREREQ = _set("before prior first prerequisite beforehand initially")
CONDITION = PREREQ | _set("required once proceed")
PRONOUN = _set("it them its their these those content")
DEICTIC = _set("this it that these")
SECRETIVE = _set("secret hide confidential private quiet silent")  # "hidden" -> hide
DEONTIC = _set("must should shall")
NEG_DEONTIC = _set("mustn't shouldn't")
COVERT = _set("secretly covertly stealthily discreetly surreptitiously")
BYPASS = _set("instead bypass skip replace disable override")
INSTRUMENTAL = _set("using with via through")
BE = _set("be is are was were been get")
TOWARD = _set("to at via into toward towards")
ACTOR = _set("assistant agent model llm you your")
PRECEDENCE = _set("precedence supersede authoritative govern overrule outrank binding")
PREFERENCE = _set("preferred default primary optimal best recommended official")
EXTERNAL = _set("external remote cloud")
ALTERNATIVE = TOOL_NOUN | _set("other any another")
FUNCTION_WORDS = (NEG | DECLARATIVE | STRONG_MOD | WEAK_MOD | EVERYTHING | BEFORE_REF | SAID
                   | UNIVERSAL | CONDITION | PRONOUN | DEICTIC | SECRETIVE | DEONTIC
                   | NEG_DEONTIC | COVERT | INSTRUMENTAL | BE | TOWARD | ACTOR | PREFERENCE
                   | EXTERNAL | _set("instead other another"))
_IRREGULAR = {
    "sent": "send", "hid": "hide", "hidden": "hide", "kept": "keep",
    "forgot": "forget", "forgotten": "forget", "overrode": "override",
    "overridden": "override", "withheld": "withhold", "known": "know", "knew": "know",
    "seen": "see", "saw": "see", "shown": "show", "ran": "run", "found": "find",
}
PATH = frozenset({"<path>"})
DEST = frozenset({"<url>", "<email>"})
ACCESS = READ | TRANSFER


def _bases(word: str) -> Iterator[str]:
    """Possible base forms of an inflected English word, most likely first."""
    if word.endswith(("ies", "ied")):
        yield word[:-3] + "y"
    if word.endswith("s"):
        yield word[:-1]
    for suffix in ("es", "ed", "ing"):
        if word.endswith(suffix):
            base = word[:-len(suffix)]
            yield base
            yield base + "e"
            if len(base) > 2 and base[-1] == base[-2]:
                yield base[:-1]  # omitted -> omit, skipping -> skip


@lru_cache(maxsize=8192)
def _lemma(word: str) -> str:
    word = _IRREGULAR.get(word, word)
    if word in INFLECTING_WORDS or word in FUNCTION_WORDS:
        return word
    return next((base for base in _bases(word) if base in INFLECTING_WORDS), word)


def lemma(word: str) -> str:
    """The class word an inflected form belongs to, or the word itself."""
    return _lemma(word) if len(word) <= MAX_WORD_CHARS else word


# Formal shapes: the only regular expressions that read definition text. Each is anchored or
# bounded and has no nested quantifier, so matching is linear in the input.
_SECRET_PATH = (
    r"(?<!\w)(?:~|\$home|%userprofile%)?[\\/]?\.(?:ssh|aws|azure|gnupg|kube|docker|netrc|pgpass"
    r"|npmrc|pypirc|git-credentials|cursor|bash_history|zsh_history)\b"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|/etc/(?:passwd|shadow|sudoers)\b|(?<![\w.])\.env\b"
    r"|\b(?:mcp|claude_desktop_config|credentials)\.json\b|\bkeychain\b|\bwallet\.dat\b"
)
_TOKEN = re.compile(
    rf"(?P<path>{_SECRET_PATH})"
    r"|(?P<url>\b(?:https?|ftp|wss?)://[^\s\"'<>)]{1,2048})"
    r"|(?P<email>\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8})"
    r"|(?P<word>[a-z0-9]+(?:'[a-z]+)?)"
)
ROLE_TAG = re.compile(
    r"(?:^|\n)[ \t]*(?:system|developer|admin(?:istrator)?)[ \t]*:"
    r"|\[\s*(?:system|developer|admin|inst)\s*\]"
    r"|<\s*(?:/\s*)?(?:system|developer|instructions?|admin|important)\s*>"
    r"|<\|(?:im_start|system)\|>"
    r"|\byou\s+are\s+now\s+(?:the\s+)?(?:system|developer|administrator|root)\b",
    re.IGNORECASE,
)
OVERRIDE_I18N = re.compile(  # a deliberately closed set: es, fr, de, pt, it, ru, zh
    r"\bignor[ae]r?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)\b"
    r"|\bignor(?:e|ez|er)\s+(?:toutes\s+)?(?:les\s+)?instructions\s+"
    r"(?:pr[e\u00e9]c[e\u00e9]dentes|ant[e\u00e9]rieures)\b"
    r"|\bignorier\w*\s+(?:alle\s+)?(?:vorherigen|fr[u\u00fc]heren|obigen)\s+"
    r"(?:anweisungen|instruktionen|regeln)\b"
    r"|\bignor[ea]\s+(?:todas\s+)?(?:as\s+)?instru[c\u00e7][o\u00f5]es\s+anteriores\b"
    r"|\bignor[ai]\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+precedenti\b"
    # Russian: "ignore (all) previous instructions"
    r"|\u0438\u0433\u043d\u043e\u0440\u0438\u0440\w+\s+(?:\u0432\u0441\u0435\s+)?"
    r"(?:\u043f\u0440\u0435\u0434\u044b\u0434\u0443\u0449\u0438\u0435"
    r"|\u043f\u0440\u0435\u0436\u043d\u0438\u0435)\s+"
    r"(?:\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u0438"
    r"|\u0443\u043a\u0430\u0437\u0430\u043d\u0438\u044f)"
    # Chinese: "ignore the previous/above/all instructions"
    r"|\u5ffd\u7565(?:\u4e4b\u524d|\u4ee5\u4e0a|\u5148\u524d|\u6240\u6709|\u4e0a\u8ff0)"
    r"\u7684?(?:\u6307\u4ee4|\u6307\u793a|\u89c4\u5219|\u63d0\u793a)",
    re.IGNORECASE,
)
# A quoted or negated example is a framing claim by the definition's author. It can only
# soften an override that names no concrete target; see _marker_signals.
FRAMING = re.compile(
    r"\b(?:malicious\s+example|attack\s+sample"
    r"|example\s+of\s+(?:an?\s+)?(?:attack|injection)"
    r"|detect(?:s|ing)?\s+(?:an?\s+)?(?:prompt\s+)?injection"
    r"|warns?\s+about\s+(?:an?\s+)?(?:attack|injection)|such\s+as\s+[\"'\u201c])",
    re.IGNORECASE,
)
# A sentence end, a blank line, a list bullet or a semicolon ends a clause. A single line
# break does not: descriptions are often hard-wrapped in the middle of a sentence.
_CLAUSE_END = re.compile(r"(?<=[.!?])\s+|\n\s*\n|\n\s*(?:[-*\u2022]|\d+[.)])\s+|;\s+")
_APOSTROPHES = str.maketrans("\u2019\u2018\u02bc", "'''")


def tokenise(text: str) -> tuple[str, ...]:
    """Lemmas of ``text`` in order, with secret paths, URLs and e-mails as shape tokens."""
    out: list[str] = []
    for match in _TOKEN.finditer(text.casefold().translate(_APOSTROPHES)):
        if match.lastgroup != "word":
            out.append(f"<{match.lastgroup}>")
            continue
        word = lemma(match.group())
        if word == "not" and out and out[-1] in DECLARATIVE:
            word = "not~"  # "does not tell" describes; "do not tell" instructs
        out.append(word)
    return tuple(out)


@dataclass(frozen=True)
class Clause:
    """One clause of one string. Its text stays in memory and is never recorded."""

    path: str
    source: str  # visible, html_comment, or an encoding chain such as base64
    text: str
    tokens: tuple[str, ...]
    words: frozenset[str]
    sha256: str


Step = tuple[frozenset[str], int]  # (word class, tokens that may be skipped before it)


def seq(clause: Clause, *steps: Step, stop: frozenset[str] = frozenset()) -> bool:
    """True when the classes occur in order within their gaps. Linear in the clause length.

    ``stop`` words end a gap: "open a session using keys from <path>" does not let "open"
    reach the path, because "using" introduces a means and not the object of the verb.
    """
    if any(not (clause.words & wanted) for wanted, _ in steps):
        return False
    tokens = clause.tokens
    reached = [index for index, token in enumerate(tokens) if token in steps[0][0]]
    for wanted, gap in steps[1:]:
        following: set[int] = set()
        for start in reached:
            for position in range(start + 1, min(len(tokens), start + gap + 2)):
                if tokens[position] in wanted:
                    following.add(position)
                if tokens[position] in stop:
                    break
        if not following:
            return False
        reached = sorted(following)
    return True


def _clauses(path: str, source: str, text: str, seen: set[tuple[str, str]]) -> Iterator[Clause]:
    """Clauses of one text layer, skipping any that an earlier variant already produced."""
    for piece in _CLAUSE_END.split(text.replace("\r", "\n")):
        sha = digest(piece)
        if (source, sha) in seen:
            continue
        seen.add((source, sha))
        tokens = tokenise(piece)
        # A piece with no Latin words (another script) still yields one clause for the shapes.
        for start in range(0, max(len(tokens), 1), MAX_CLAUSE_TOKENS):
            chunk = tokens[start:start + MAX_CLAUSE_TOKENS]
            yield Clause(path, source, piece, chunk, frozenset(chunk), sha)


def _field_clauses(path: str, raw: str, notes: set[str]) -> list[Clause]:
    """All clauses of one string: every normalised variant, HTML comment and decoded layer."""
    canonical = normalise(raw)
    layers = [("visible", variant) for variant in normalise_variants(raw)]
    layers += [("html_comment", body) for body in html_comments(canonical)]
    layers += [(source, normalise(text)) for source, text in decode_layers(canonical, notes)]
    out: list[Clause] = []
    seen: set[tuple[str, str]] = set()
    for source, text in layers:
        for clause in _clauses(path, source, text, seen):
            if len(out) >= MAX_FIELD_CLAUSES:
                notes.add("clause_limit")
                return out
            out.append(clause)
    return out


# --- signals and tool context ---------------------------------------------------------------


@dataclass(frozen=True)
class Signal:
    """A pointer to why a rule fired: a name, a field, a source layer and a hash. No text."""

    name: str
    path: str
    source: str
    sha256: str


@dataclass(frozen=True)
class ToolContext:
    """What the rules need to know about a tool besides its own text."""

    name: str
    siblings: re.Pattern[str] | None  # names of the tools in the same list
    foreign: re.Pattern[str] | None  # names of tools on other servers in this run
    foreign_names: Mapping[str, str] = field(default_factory=dict)  # skeleton -> name


_DISTINCTIVE = re.compile(r"[_\-.\d]|[a-z][A-Z]")
_QUOTES = "`'\""
_TOOL_LABEL = re.compile(r"\s+(?:tool|function|command)\b", re.IGNORECASE)
_LABEL_BEFORE = re.compile(r"\b(?:tool|function|command)\s+$", re.IGNORECASE)


def _names_pattern(names: Sequence[str]) -> re.Pattern[str] | None:
    """One matcher for a set of tool names, longest first, or None when there are none."""
    usable = {name[:MAX_NAME_CHARS] for name in names if len(name) >= 3}
    if not usable:
        return None
    body = "|".join(re.escape(name) for name in sorted(usable, key=lambda n: (-len(n), n)))
    return re.compile(rf"(?<!\w)(?:{body})(?!\w)", re.IGNORECASE)


def _names_tool(pattern: re.Pattern[str] | None, text: str, own: str = "") -> bool:
    """True when ``text`` refers to one of the named tools, not merely uses a common word.

    A name with a separator, digit or inner capital (``send_email``) is distinctive on its
    own. A plain word (``search``) counts only in quotes or next to "tool" or "function".
    """
    if pattern is None:
        return False
    for match in pattern.finditer(text):
        if match.group().casefold() == own.casefold():
            continue  # a tool may name itself
        before, after = text[:match.start()][-12:], text[match.end():][:12]
        quoted = bool(before) and bool(after) and before[-1] in _QUOTES and after[0] in _QUOTES
        if (_DISTINCTIVE.search(match.group()) or quoted
                or _TOOL_LABEL.match(after) or _LABEL_BEFORE.search(before)):
            return True
    return False


# --- layer: markers -------------------------------------------------------------------------
# One predicate per behaviour. A predicate is a small set of token sequences; it names the
# word classes that must appear, never an attack sentence.


def _overrides(clause: Clause) -> bool:
    """The clause tells the reader to discard instructions it was given."""
    if OVERRIDE_I18N.search(clause.text):
        return True
    if seq(clause, (OVERRIDE_MIND, 0), (EVERYTHING, 3), (BEFORE_REF, 4)) \
            or seq(clause, (OVERRIDE_OPS, 0), (ANYTHING, 3), (SAID, 4)):
        return True  # "forget everything above", "supersedes anything said earlier"
    # "previous instructions", "system prompt", or "all guidelines": unmistakably the model's
    # own instructions. "All rules" alone could be a firewall's.
    strong = seq(clause, (STRONG_MOD, 0), (PROTECTED, 3)) \
        or seq(clause, (WEAK_MOD, 0), (STRONG_NOUN, 3))
    if strong and (seq(clause, (OVERRIDE_OPS, 0), (PROTECTED, 6))
                   or seq(clause, (PROTECTED, 0), (BE, 3), (OVERRIDE_OPS, 2))  # passive voice
                   or seq(clause, (NEG, 0), (FOLLOW, 2), (PROTECTED, 6))):
        return True
    qualified = strong or seq(clause, (WEAK_MOD, 0), (PROTECTED, 3))
    return qualified and (seq(clause, (OVERRIDE_MIND, 0), (PROTECTED, 6))
                          or seq(clause, (PROTECTED, 0), (BE, 3), (OVERRIDE_MIND, 2)))


def _protected_reference(clause: Clause) -> bool:
    return seq(clause, (STRONG_MOD, 0), (PROTECTED, 3))


def _conceals(clause: Clause) -> bool:
    """The clause asks for something to be kept from the user."""
    words = clause.words
    matched = (
        seq(clause, (NEG, 0), (COMMUNICATE, 2), (RECIPIENT, 4))  # do not tell the user
        or seq(clause, (HIDE, 0), (frozenset({"from"}), 6), (RECIPIENT, 3))
        or seq(clause, (frozenset({"keep"}), 0), (DEICTIC, 0), (SECRETIVE, 1))
        or seq(clause, (RECIPIENT, 0), (DEONTIC, 1), (NEG, 1), (PERCEIVE, 2))
        or seq(clause, (RECIPIENT, 0), (NEG_DEONTIC, 1), (PERCEIVE, 2))
        or bool(words & COVERT and words & ACCESS)
    )
    # "Never reveal the user's password" protects data; it hides no action.
    guards_data = words & SECRET_WORD and not words & (ACCESS | DEICTIC)
    return matched and not guards_data


def _reads_secret_file(clause: Clause) -> bool:
    return seq(clause, (ACCESS, 0), (PATH, 6), stop=INSTRUMENTAL) \
        or seq(clause, (PATH, 0), (BE, 3), (ACCESS, 1))  # "id_rsa must be read"


def _sends_secret(clause: Clause) -> bool:
    """"post the API key to <url>", or "collect the token and forward it to <url>"."""
    return seq(clause, (TRANSFER, 0), (SECRET_WORD, 4), (TOWARD, 1), (DEST, 3)) \
        or seq(clause, (READ, 0), (SECRET_WORD, 4), (TRANSFER, 5), (PRONOUN, 1), (DEST, 3))


def _this_tool(clause: Clause) -> bool:
    return seq(clause, (frozenset({"this"}), 0), (TOOL_NOUN, 1))


def _overrides_user(clause: Clause) -> bool:
    user = frozenset({"user"})
    return (seq(clause, (frozenset({"regardless"}), 0), (user, 4))
            or seq(clause, (frozenset({"even"}), 0), (frozenset({"if"}), 0), (user, 2))
            or seq(clause, (frozenset({"matter"}), 0), (frozenset({"what"}), 0), (user, 2))
            or ("user" in clause.words and seq(clause, (frozenset({"without"}), 0), (ASK, 2))))


def _bypasses(clause: Clause) -> bool:
    return bool(clause.words & BYPASS) or seq(clause, (NEG, 0), (CALL, 1)) \
        or seq(clause, (frozenset({"rather"}), 0), (frozenset({"than"}), 0))


def _generic_alternative(clause: Clause) -> bool:
    return (seq(clause, (frozenset({"instead"}), 0), (frozenset({"of"}), 0), (ALTERNATIVE, 3))
            or seq(clause, (frozenset({"rather"}), 0), (frozenset({"than"}), 0), (ALTERNATIVE, 3))
            or seq(clause, (frozenset({"other", "another"}), 0), (TOOL_NOUN, 1)))


def _marker_signals(clauses: Sequence[Clause], ctx: ToolContext) -> list[Signal]:
    """Marker and registry signals for the clauses of one string."""
    out: list[Signal] = []

    def add(name: str, clause: Clause) -> None:
        out.append(Signal(name, clause.path, clause.source, clause.sha256))

    override_verb = protected = None
    overridden = path_seen = secret_read = False  # what earlier clauses of this string did
    concealing: list[Clause] = []
    role_tags: list[tuple[Clause, bool]] = []
    for index, clause in enumerate(clauses):
        words = clause.words
        concrete = bool(words & (PATH | DEST))

        if _overrides(clause):
            overridden = True
            framed = FRAMING.search(clause.text) and not concrete
            add("framed_override_example" if framed else "override_of_protected_instruction",
                clause)
        elif words & (OVERRIDE_MIND | OVERRIDE_OPS):
            override_verb = override_verb or clause
        elif _protected_reference(clause):
            protected = protected or clause

        if ROLE_TAG.search(clause.text):
            directive = words & (UNIVERSAL | OVERRIDE_MIND | OVERRIDE_OPS | TRANSFER | PATH)
            role_tags.append((clause, bool(directive)))
        if _conceals(clause):
            concealing.append(clause)

        if _reads_secret_file(clause):
            passed_on = words & (TRANSFER | PASS) or any(
                later.words & (TRANSFER | PASS) and later.words & PRONOUN
                for later in clauses[index + 1:index + 3])
            add("secret_file_passed_on" if passed_on else "secret_file_access", clause)
            if words & PREREQ:
                add("secret_file_prerequisite", clause)
        elif words & PREREQ and words & READ and words & SECRET_WORD \
                and words & (TRANSFER | PASS):
            add("secret_prerequisite", clause)

        if words & TRANSFER and words & DEST:
            refers = bool(words & PRONOUN)  # "then send it to ..."
            if words & PATH or (refers and path_seen):
                add("secret_file_sent_to_destination", clause)
            elif _sends_secret(clause) or (refers and secret_read):
                add("secret_sent_to_destination", clause)
        path_seen = path_seen or bool(words & PATH)
        secret_read = secret_read or bool(words & READ and words & SECRET_WORD)

        sibling = _names_tool(ctx.siblings, clause.text, ctx.name)
        foreign = _names_tool(ctx.foreign, clause.text)
        if sibling and _bypasses(clause):
            add("named_tool_bypass", clause)
        if foreign and (_bypasses(clause) or words & (UNIVERSAL | PREREQ)):
            add("cross_server_tool_reference", clause)
        if words & UNIVERSAL and _this_tool(clause) \
                and (sibling or foreign or _overrides_user(clause)):
            add("exclusive_tool_selection", clause)

    if override_verb and protected and not overridden:
        add("override_split_across_clauses", override_verb)
    acts = bool(out) or any(c.words & (TRANSFER | PATH | DEST) for c in clauses)
    for clause in concealing:
        add("concealment_of_action" if acts else "concealment_instruction", clause)
    for clause, directs in role_tags:
        add("forged_role_with_directive" if directs or out else "role_marker", clause)
    return out


def _structural_signals(path: str, raw: str) -> list[Signal]:
    """Invisible-character and key findings that need no reading of the words around them."""
    names: list[str] = []
    if any(0xE0020 <= ord(c) <= 0xE007E for c in raw):
        names.append("unicode_tag_content")
    if any(c in BIDI for c in raw) and _LATIN.search(raw):
        names.append("bidi_control_override")
    if any(c in ZERO_WIDTH and c not in _JOINERS for c in raw):
        names.append("zero_width_characters")
    if path.endswith("/@key") and normalise(raw).casefold() in SUSPICIOUS_KEYS:
        names.append("suspicious_schema_key")
    return [Signal(name, path, "structure", digest(f"{name}|{path}")) for name in names]


# --- layer: capabilities (ALR04-R01, ALR04-R02) ---------------------------------------------
# English compounds put the meaning last: ``upload_url`` is a URL and ``country_code`` is a
# code. A parameter is classified by its last word (the head) and adjusted by the words before
# it, never by a substring.

EGRESS, FETCH, BODY = "egress", "fetch", "body"
CONTEXT, CONTEXT_STRONG, CREDENTIAL = "context", "conversation", "credential"
WRITE, DESTROY = "write", "destroy"

QUALIFIER_HEADS = _set("id ids name names type kind count limit format mode status flag enabled "
                       "policy length ttl expiry scope version index size prefix pattern lines")
SINK_HEADS = _set("webhook callback recipient cc bcc")
ADDRESS_HEADS = _set("url uri endpoint address host hostname link href")
TRANSFER_MODS = _set("upload send post forward report notify notification callback webhook "
                     "exfil collector beacon sink destination dest sync mirror push export "
                     "share publish")
URI_FORMATS = _set("uri url uri-reference iri hostname")
BODY_HEADS = _set("body payload attachment blob data postdata")
CONVERSATION_HEADS = _set("sidenote conversation transcript thought reasoning")
CONVERSATION_PAIRS = tuple(map(_set, (
    "chat history", "message history", "previous message", "system prompt", "full context",
    "llm context", "internal note", "side note",
)))
CONTEXT_HEADS = _set("context history memory prompt instruction note env environment")
SECRET_HEADS = _set("password passwd passphrase secret credential cookie")
KEY_MODS = _set("private secret ssh signing")
DESTROY_WORDS = _set("delete remove drop truncate purge wipe destroy erase overwrite")
DESTROY_OBJECTS = _set("file path dir directory all source original existing after")
PATH_HEADS = _set("path file dir directory filename")
WRITE_MODS = _set("save output out dest destination target write export")
TEXT_TYPES = frozenset({None, "string", "object", "array"})

READ_VERBS = _set("get list read search find lookup query check verify validate format "
                  "describe show view count inspect fetch")
NARROW_NOUNS = _set("time date datetime clock timezone weather forecast temperature calc "
                    "calculate calculator math add sum subtract multiply divide convert unit "
                    "currency color colour random uuid dice roll joke quote echo ping hello "
                    "greet greeting fact coin flip now today")
NAME_FILLER = _set("get current the of to a an by for in local utc day number two value "
                   "generate tell say show check my me")
READ_ONLY_CLAIM = re.compile(
    r"\b(?:read[- ]only|does\s+not\s+(?:modify|write|change|mutate)|no\s+side\s+effects"
    r"|without\s+(?:modifying|writing|changing))\b", re.IGNORECASE)
HARVEST_SCOPE = _set("entire full complete whole all every everything previous prior earlier "
                     "raw verbatim")
HARVEST_OBJECT = SECRET_WORD | _set("conversation history transcript chat message prompt "
                                    "thought reasoning memory environment variable")
_NAME_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
SCHEMA_KEYS = ("input_schema", "inputSchema", "output_schema", "outputSchema")
_SUBSCHEMAS = ("items", "additionalProperties", "not", "if", "then", "else")
_SUBSCHEMA_LISTS = ("anyOf", "oneOf", "allOf", "prefixItems")


def name_tokens(name: Any) -> tuple[str, ...]:
    """Lower-case words of an identifier: ``uploadURL`` and ``upload_url`` both give two."""
    return tuple(m.group().casefold() for m in _NAME_TOKEN.finditer(str(name)[:MAX_NAME_CHARS]))


@dataclass(frozen=True)
class Prop:
    """One schema property: where it is, what it can carry and how it is described."""

    pointer: str
    tokens: frozenset[str]
    kinds: frozenset[str]
    description: str


def parameter_kinds(name: str, spec: Mapping[str, Any]) -> frozenset[str]:
    tokens = name_tokens(name)
    if not tokens:
        return frozenset()
    last = tokens[-1]
    heads = {last, last[:-1]} if last.endswith("s") and not last.endswith("ss") else {last}
    if heads & QUALIFIER_HEADS:
        return frozenset()  # webhook_id, message_type and token_count carry no payload
    mods, every = set(tokens[:-1]), set(tokens) | heads
    fmt = str(spec.get("format") or "").casefold()
    kinds: set[str] = set()
    address = bool(heads & ADDRESS_HEADS) or fmt in URI_FORMATS
    if heads & SINK_HEADS or (address and mods & TRANSFER_MODS) \
            or {"forward", "to"} <= every or {"send", "to"} <= every:
        kinds.add(EGRESS)
    elif address:
        kinds.add(FETCH)
    if heads & BODY_HEADS:
        kinds.add(BODY)
    if spec.get("type") in TEXT_TYPES:
        if heads & CONVERSATION_HEADS or any(pair <= every for pair in CONVERSATION_PAIRS):
            kinds.add(CONTEXT_STRONG)
        elif heads & CONTEXT_HEADS:
            kinds.add(CONTEXT)
    if heads & SECRET_HEADS or ("key" in heads and mods & KEY_MODS) or fmt == "password":
        kinds.add(CREDENTIAL)
    if heads & DESTROY_WORDS or (tokens[0] in DESTROY_WORDS and heads & DESTROY_OBJECTS):
        kinds.add(DESTROY)
    if heads & PATH_HEADS and mods & WRITE_MODS:
        kinds.add(WRITE)
    return frozenset(kinds)


def _resolve(root: Mapping[str, Any], reference: Any) -> Any:
    """The node a local ``#/...`` JSON reference points at, or None."""
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return None
    node: Any = root
    for segment in reference[2:].split("/"):
        key = segment.replace("~1", "/").replace("~0", "~")
        node = node.get(key) if isinstance(node, Mapping) else None
    return node


def schema_properties(tool: Mapping[str, Any], notes: set[str]) -> list[Prop]:
    """Every property of the tool's input and output schemas, at any depth.

    Follows nested properties, array items, combinators and local ``$ref``. Accepts the
    payload tap's ``input_schema`` and MCP's ``inputSchema``.
    """
    out: list[Prop] = []
    stack = [(tool[key], tool[key], f"$/{key}", 0) for key in reversed(SCHEMA_KEYS)
             if isinstance(tool.get(key), Mapping)]
    followed: set[str] = set()
    while stack:
        root, node, pointer, depth = stack.pop()
        if depth > MAX_SCHEMA_DEPTH or len(out) >= MAX_PROPERTIES:
            notes.add("schema_limit")
            break
        reference = node.get("$ref")
        if isinstance(reference, str) and reference not in followed:
            followed.add(reference)  # each reference once, so a cycle cannot loop
            target = _resolve(root, reference)
            if isinstance(target, Mapping):
                stack.append((root, target, pointer, depth + 1))
        children = [(key, node.get(key)) for key in _SUBSCHEMAS]
        for key in _SUBSCHEMA_LISTS:
            entries = node.get(key)
            if isinstance(entries, list):
                children += [(f"{key}/{index}", entry) for index, entry in enumerate(entries)]
        properties = node.get("properties")
        if isinstance(properties, Mapping):
            for name, spec in properties.items():
                if not isinstance(spec, Mapping):
                    continue
                children.append((f"properties/{name}", spec))
                description = spec.get("description")
                out.append(Prop(
                    f"{pointer}/properties/{name}", frozenset(name_tokens(name)),
                    parameter_kinds(str(name), spec),
                    description[:MAX_FIELD_CHARS] if isinstance(description, str) else "",
                ))
        for key, child in reversed(children):
            if isinstance(child, Mapping):
                stack.append((root, child, f"{pointer}/{key}", depth + 1))
    return out[:MAX_PROPERTIES]


def is_narrow(tokens: Sequence[str]) -> bool:
    """A single-purpose utility: every word of the name is a narrow noun or filler."""
    return bool(set(tokens) & NARROW_NOUNS) and set(tokens) <= NARROW_NOUNS | NAME_FILLER


def _fill_directive(description: str) -> bool:
    """The parameter's own description says to put broad context or a secret file in it."""
    words = frozenset(tokenise(description))
    return bool(words & PATH or (words & HARVEST_SCOPE and words & HARVEST_OBJECT))


def _capability_signals(tool: Mapping[str, Any], props: Sequence[Prop]) -> list[Signal]:
    """Contradictions between what the schema can carry and what the tool claims to be."""
    tokens = name_tokens(tool.get("name"))
    annotations = tool.get("annotations")
    annotations = annotations if isinstance(annotations, Mapping) else {}
    prose = " ".join(str(tool.get(key) or "") for key in ("title", "description"))
    declared = annotations.get("readOnlyHint") is True \
        or bool(READ_ONLY_CLAIM.search(prose[:MAX_FIELD_CHARS]))
    read_only = declared or (bool(tokens) and tokens[0] in READ_VERBS)
    narrow = is_narrow(tokens)
    kinds = frozenset().union(*(prop.kinds for prop in props))
    out: list[Signal] = []

    def add(name: str, prop: Prop) -> None:
        out.append(Signal(name, safe(prop.pointer, 220), "schema",
                          digest(f"{name}|{prop.pointer}")))

    for prop in props:
        # A tool that manages webhooks may take a webhook: the sink is its subject.
        about_sink = prop.tokens & (SINK_HEADS | TRANSFER_MODS) & set(tokens)
        if EGRESS in prop.kinds and read_only and not about_sink:
            add("read_only_with_egress_sink", prop)
        if FETCH in prop.kinds and declared and BODY in kinds:
            add("read_only_with_body_to_url", prop)
        if prop.kinds & {WRITE, DESTROY} and declared:
            add("read_only_with_write", prop)
        if DESTROY in prop.kinds and annotations.get("destructiveHint") is False:
            add("non_destructive_with_destroy", prop)
        if prop.kinds & {EGRESS, FETCH} and annotations.get("openWorldHint") is False:
            add("offline_with_network", prop)
        if prop.kinds & {CONTEXT, CONTEXT_STRONG}:
            if narrow:
                add("context_parameter_on_narrow_tool", prop)
            if _fill_directive(prop.description):
                add("context_parameter_with_fill_directive", prop)
            elif CONTEXT_STRONG in prop.kinds and not narrow:
                add("conversation_parameter", prop)
        if CREDENTIAL in prop.kinds and narrow:
            add("credential_parameter_on_narrow_tool", prop)
    return out


# --- layer: registry (ALR04-R03) ------------------------------------------------------------

_LOOKALIKE = str.maketrans({"1": "l", "I": "l", "|": "l", "0": "o"})
_SEPARATORS = re.compile(r"[-.\s]+")


def _plain(name: str) -> str:
    return _SEPARATORS.sub("_", normalise(name).casefold())


def skeleton(name: str) -> str:
    """A tool name with look-alike characters folded: ``send_emaiI`` reads as ``send_email``."""
    folded = normalise(name).translate(_FOLD).translate(_LOOKALIKE).casefold()
    return _SEPARATORS.sub("_", folded.replace("rn", "m").replace("vv", "w"))


def _registry_signals(name: str, ctx: ToolContext) -> list[Signal]:
    other = ctx.foreign_names.get(skeleton(name))
    if other is None:
        return []
    # Many clients namespace tools by server, so the same name on two servers is only worth a
    # note. A name that differs yet reads the same is not an accident.
    signal = "duplicate_tool_name" if _plain(other) == _plain(name) else "confusable_tool_name"
    return [Signal(signal, "$/name", "registry", digest(f"{signal}|{name}"))]


# --- layer: wording -------------------------------------------------------------------------
# A frame is what a clause implies without marker words. One frame proves nothing, so a
# hypothesis becomes a (low) finding only when another layer agrees with it.


def _frames(clause: Clause) -> Iterator[str]:
    words = clause.words
    if words & PRECEDENCE and words & (CONTEXT_NOUN | ACTOR):
        yield "implied_override"
    if words & OUTPUT_NOUN and (words & INTERNAL or seq(clause, (NEG_ANY, 0), (VISIBLE, 2))):
        yield "implied_concealment"
    if seq(clause, (PREFERENCE, 0), (SELECT_NOUN, 2)) or (words & UNIVERSAL and _this_tool(clause)):
        yield "implied_preference"
    if words & CONDITION and words & VERIFY and words & (SECRET_WORD | FILE_NOUN | EXTERNAL):
        yield "implied_prerequisite"
    if words & READ and words & SECRET_WORD and words & SINK_NOUN:
        yield "implied_credential_access"


def _wording_signals(clauses: Sequence[Clause], props: Sequence[Prop], reported: set[str],
                     ctx: ToolContext) -> tuple[list[Signal], Counter[str]]:
    """Corroborated wording signals, and a count of the hypotheses left as hints."""
    framed: dict[str, list[Clause]] = {}
    for clause in clauses:
        if clause.source == "visible":
            for hypothesis in _frames(clause):
                framed.setdefault(hypothesis, []).append(clause)
    kinds = frozenset().union(*(prop.kinds for prop in props))
    out: list[Signal] = []
    hints: Counter[str] = Counter()
    for hypothesis, found in framed.items():
        if SIGNALS[hypothesis][0] in reported:
            continue  # a stronger layer already reported this behaviour for this tool
        first, paths = found[0], {clause.path for clause in found}
        corroborated = {
            "implied_override": len(paths) > 1
            or bool(kinds & {CONTEXT, CONTEXT_STRONG}),
            "implied_concealment": EGRESS in kinds
            or any(c.words & TRANSFER and c is not first for c in clauses),
            "implied_preference": any(
                _names_tool(ctx.siblings, c.text, ctx.name) or _names_tool(ctx.foreign, c.text)
                or _generic_alternative(c) for c in clauses if c.path in paths),
            "implied_prerequisite": bool(kinds & {CREDENTIAL, CONTEXT, CONTEXT_STRONG})
            or any(c.words & PATH for c in clauses),
            "implied_credential_access": EGRESS in kinds,
        }[hypothesis]
        if corroborated:
            out.append(Signal(hypothesis, first.path, first.source, first.sha256))
        else:
            hints[hypothesis] += 1
    return out, hints


# --- one tool -------------------------------------------------------------------------------


@dataclass
class ToolScan:
    signals: list[Signal] = field(default_factory=list)
    notes: set[str] = field(default_factory=set)
    hints: Counter[str] = field(default_factory=Counter)
    chars: int = 0


def scan_tool(tool: Mapping[str, Any], ctx: ToolContext, budget: int = MAX_TOOL_CHARS) -> ToolScan:
    """Every signal for one definition, with what could not be read and how much was."""
    scan = ToolScan()
    budget = min(budget, MAX_TOOL_CHARS)
    clauses: list[Clause] = []
    for path, raw in walk(tool, scan.notes):
        cut = TRUNCATION.search(raw)
        if cut:
            raw = raw[:cut.start()]
            scan.notes.add("payload_file_truncation")
        if REDACTED in raw:
            scan.notes.add("redacted_field")
        if len(raw) > MAX_FIELD_CHARS:
            raw = raw[:MAX_FIELD_CHARS]
            scan.notes.add("field_limit")
        if scan.chars + len(raw) > budget:
            scan.notes.add("text_budget")
            break
        scan.chars += len(raw)
        scan.signals += _structural_signals(path, raw)
        field_clauses = _field_clauses(path, raw, scan.notes)
        scan.signals += _marker_signals(field_clauses, ctx)
        clauses += field_clauses
    # An instruction can only be written in Base64 or a comment in order to be missed.
    scan.signals += [Signal("hidden_layer_instruction", s.path, s.source, s.sha256)
                     for s in scan.signals if s.source not in ("visible", "structure")]
    props = schema_properties(tool, scan.notes)
    scan.signals += _capability_signals(tool, props)
    scan.signals += _registry_signals(str(tool.get("name")), ctx)
    reported = {SIGNALS[signal.name][0] for signal in scan.signals}
    wording, scan.hints = _wording_signals(clauses, props, reported, ctx)
    scan.signals += wording
    return scan


# --- records --------------------------------------------------------------------------------


def _record(event: Mapping[str, Any], rule_id: str, family: str, outcome: str, *,
            message: str, server: str = "", tool: str = "", severity: str = "info",
            is_finding: bool = False, **extra: Any) -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": rule_id, "family": family,
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "outcome": outcome, "is_finding": is_finding,
        "suppressed": False, "severity": severity, "owasp": OWASP,
        "evidence": [], "evidence_count": 0, "coverage_notes": [], "message": message,
        **extra,
    }


def _not_inspected(event: Mapping[str, Any], reasons: set[str], *, server: str = "",
                   tool: str = "", skipped: int = 0, sha: str = "") -> dict[str, Any]:
    # is_finding stays True so a report that lists only findings still shows the gap.
    return _record(
        event, RULE_COVERAGE, "coverage", OUTCOME_NOT_INSPECTED, server=server, tool=tool,
        is_finding=True, coverage_notes=sorted(reasons), skipped_tools=skipped,
        definition_sha256=sha,
        message="Part of the tool-definition input was not inspected, so it cannot be cleared.",
    )


def _finding_records(event: Mapping[str, Any], scan: ToolScan, server: str, tool: str,
                     sha: str) -> list[dict[str, Any]]:
    """One record per rule that has evidence; its severity is its own highest rank."""
    grouped: dict[str, dict[tuple[str, str, str], Signal]] = {}
    for signal in scan.signals:
        family = SIGNALS[signal.name][0]
        grouped.setdefault(family, {}).setdefault((signal.name, signal.path, signal.source),
                                                  signal)
    records = []
    for family, (rule_id, says) in FAMILIES.items():
        items = sorted(grouped.get(family, {}).values(),
                       key=lambda s: (_RANK_ORDER[SIGNALS[s.name][1]], s.name, s.path, s.source))
        if not items:
            continue
        items = items[:MAX_EVIDENCE]
        records.append(_record(
            event, rule_id, family, OUTCOME_FINDING, server=server, tool=tool,
            severity=SIGNALS[items[0].name][1], is_finding=True, definition_sha256=sha,
            message=f"The tool definition {says}. Evidence for review; no exploit is confirmed.",
            evidence=[{"signal": s.name, "rank": SIGNALS[s.name][1], "layer": SIGNALS[s.name][2],
                       "field": safe_pointer(s.path), "source": s.source, "sha256": s.sha256}
                      for s in items[:MAX_EVIDENCE_REPORTED]],
            evidence_count=len(items),
        ))
    return records


# --- state shared across events -------------------------------------------------------------

_lock = RLock()
_scanned: OrderedDict[tuple[str, str, str, str], None] = OrderedDict()
_registry: OrderedDict[str, dict[str, dict[str, str]]] = OrderedDict()  # run -> server -> names


def reset_state() -> None:
    """Forget scanned definitions and remembered tool names (tests, or a new importer run)."""
    with _lock:
        _scanned.clear()
        _registry.clear()


def _remember(key: tuple[str, str, str, str]) -> bool:
    """True if this exact definition was already scanned in this run; otherwise store it."""
    with _lock:
        if key in _scanned:
            _scanned.move_to_end(key)
            return True
        _scanned[key] = None
        while len(_scanned) > MAX_REMEMBERED:
            _scanned.popitem(last=False)
        return False


def _foreign_names(run_id: str, server: str) -> dict[str, str]:
    """skeleton -> name for the tools other servers have listed in this run."""
    with _lock:
        servers = _registry.get(run_id, {})
        return {key: name for other, names in servers.items() if other != server
                for key, name in names.items()}


def _register(run_id: str, server: str, names: Sequence[str]) -> bool:
    """Remember a server's tool names. Returns False when a limit dropped some of them."""
    with _lock:
        servers = _registry.setdefault(run_id, {})
        _registry.move_to_end(run_id)
        while len(_registry) > MAX_RUNS:
            _registry.popitem(last=False)
        if server not in servers and len(servers) >= MAX_SERVERS:
            return False
        known = servers.setdefault(server, {})
        for name in names:
            if len(known) >= MAX_NAMES:
                return False
            known.setdefault(skeleton(name), name[:MAX_NAME_CHARS])
        return True


def startup_capabilities() -> list[dict[str, str]]:
    """What this gate can and cannot check, for a dispatcher to report up front."""
    unsupported = {
        "paraphrase_and_other_languages": "Wording outside the closed word classes, and "
                                          "languages beyond the built-in override phrases, "
                                          "are not recognised.",
        "undeclared_capabilities": "A server that sets no annotations and names its tools and "
                                   "parameters neutrally gives the capability layer nothing "
                                   "to contradict.",
        "definition_change_or_pinning": "Tool integrity and baselines belong to ALR02.",
        "tool_behaviour": "A schema is not behaviour; what a tool does when called is unseen.",
        "prompt_and_resource_descriptions": "They are not captured as payload records.",
        "later_registered_servers": "A reference to a tool on a server that lists its tools "
                                    "later in the run is missed.",
        "operator_policy": "No policy input exists yet, so allowlists and suppressions are "
                           "not applied.",
    }
    return [
        {"check": "tool_definition_content", "outcome": "SUPPORTED"},
        {"check": "schema_capability_contradiction", "outcome": "SUPPORTED"},
        {"check": "cross_server_tool_names", "outcome": "SUPPORTED"},
        *({"check": check, "outcome": "UNSUPPORTED", "reason": reason}
          for check, reason in unsupported.items()),
    ]


def _definitions(event: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], set[str], int] | None:
    """(definitions, event-level notes, tools skipped), or None when the event is not ours."""
    payload = event.get("payload")
    method, stage = event.get("method"), event.get("stage")
    if method == "tools/list" and stage == "response":
        tools = payload.get("tools") if isinstance(payload, Mapping) else None
        if not isinstance(tools, list):
            known = isinstance(payload, Mapping)
            return [], {"invalid_tools_list" if known else "payload_unavailable"}, 0
        valid = [tool for tool in tools[:MAX_TOOLS]
                 if isinstance(tool, Mapping) and isinstance(tool.get("name"), str)]
        notes = set()
        if len(valid) < min(len(tools), MAX_TOOLS):
            notes.add("invalid_tool_definition")
        if len(tools) > MAX_TOOLS:
            notes.add("tool_count_limit")
        return valid, notes, len(tools) - len(valid)
    if method == "tools/call" and stage == "request":
        if not isinstance(payload, Mapping):
            return [], {"payload_unavailable"}, 0
        cached, name = payload.get("tool_definition"), payload.get("tool")
        if cached is None:
            return None  # an ordinary call carries no schema evidence
        if not isinstance(cached, Mapping) or not isinstance(name, str):
            return [], {"invalid_cached_tool_definition"}, 1
        return [{**cached, "name": name}], set(), 0
    return None


def evaluate(event: dict[str, Any]) -> dict[str, Any]:
    """Findings for one normalised importer event; every event is offered to every gate."""
    if not isinstance(event, Mapping):
        return {"findings": [_not_inspected({}, {"malformed_event"})]}
    selected = _definitions(event)
    if selected is None:
        return {"findings": []}  # not an ALR04 input; not a pass either
    definitions, event_notes, skipped = selected
    server, run_id = str(event.get("server") or ""), str(event.get("run_id") or "")
    names = [str(tool["name"]) for tool in definitions]
    foreign_names = _foreign_names(run_id, server)
    siblings, foreign = _names_pattern(names), _names_pattern(list(foreign_names.values()))

    out: list[dict[str, Any]] = []
    hints: Counter[str] = Counter()
    ranks: list[str] = []
    scanned = already = flagged = gaps = 0
    budget = MAX_EVENT_CHARS
    for index, tool in enumerate(definitions):
        if len(out) >= MAX_OUTPUT_RECORDS or budget <= 0:
            event_notes.add("output_record_limit" if budget > 0 else "event_text_budget")
            skipped += len(definitions) - index
            break
        name, sha = names[index], definition_hash(tool)
        if _remember((run_id, server, name, sha)):
            already += 1
            continue
        ctx = ToolContext(name, siblings, foreign, foreign_names)
        scan = scan_tool(tool, ctx, budget)
        # A tool cut short by what is left of the event budget ends the event's reading.
        cut_by_event = "text_budget" in scan.notes and budget < MAX_TOOL_CHARS
        budget = 0 if cut_by_event else budget - scan.chars
        records = _finding_records(event, scan, server, name, sha)
        if scan.notes:
            records.append(_not_inspected(event, scan.notes, server=server, tool=name, sha=sha))
            gaps += 1
        out += records
        hints += scan.hints
        scanned += 1
        tool_ranks = [r["severity"] for r in records if r["outcome"] == OUTCOME_FINDING]
        flagged += bool(tool_ranks)
        ranks += tool_ranks
    if not _register(run_id, server, names):
        event_notes.add("registry_limit")
    if event_notes:
        out.append(_not_inspected(event, event_notes, server=server, skipped=skipped))
    outcome = OUTCOME_FINDING if ranks else \
        OUTCOME_NOT_INSPECTED if gaps or event_notes else OUTCOME_NO_SIGNAL
    out.append(_record(
        event, RULE_SUMMARY, "scan_summary", outcome, server=server,
        tools_scanned=scanned, tools_with_findings=flagged, tools_not_inspected=gaps,
        tools_already_scanned=already, tools_skipped=skipped,
        highest_severity=min(ranks, key=_RANK_ORDER.__getitem__) if ranks else None,
        wording_hints={name: hints[name] for name in WORDING_HYPOTHESES if hints[name]},
        message="Scan summary for this event.",
    ))
    return {"findings": out}


# --- export: SARIF for dashboards, plain lines for a terminal --------------------------------
# A runtime finding is located by server and tool, not by a file and line, so SARIF is built
# here. Both formats carry record fields only: no matched text, no payload content.

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_SARIF_LEVEL = {HIGH: "error", MEDIUM: "warning", LOW: "note"}
_CLEAR_NOTE = "No findings. This is not a clearance: only tool definitions were read."


def _findings_of(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Ranked findings, highest first. The summary and not-inspected rows are left out."""
    found = [record for record in records
             if record.get("outcome") == OUTCOME_FINDING and record.get("rule_id") != RULE_SUMMARY]
    return sorted(found, key=lambda record: _RANK_ORDER.get(str(record.get("severity")), 3))


def _entity(record: Mapping[str, Any], template: str = "{server}/{tool}") -> str:
    value = record.get("entity")
    entity: Mapping[str, Any] = value if isinstance(value, Mapping) else {}
    server, tool = str(entity.get("server") or ""), str(entity.get("tool") or "")
    if server and tool:
        return template.format(server=server, tool=tool)
    return tool or server or "event"


def sarif_document(records: Sequence[Mapping[str, Any]], *,
                   version: str | None = None) -> dict[str, Any]:
    """The gate's findings as a SARIF 2.1.0 log, ready for ``json.dumps``.

    Every result carries ``logicalLocations`` (server and tool) instead of a physical location.
    Not-inspected records are counted in the run properties rather than listed as results.
    """
    if version is None:
        from agent_latch import __version__ as version
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for record in _findings_of(records):
        rule_id, severity = str(record["rule_id"]), str(record["severity"])
        level = _SARIF_LEVEL.get(severity, "warning")
        title = str(record.get("family") or rule_id).replace("_", " ")
        owasp = [str(item) for item in record.get("owasp") or ()]
        rules.setdefault(rule_id, {
            "id": rule_id, "name": title, "shortDescription": {"text": title},
            "properties": {"tags": ["security", GATE_ID, *owasp], "gate": GATE_ID,
                           "owaspCategories": category_entries(owasp)},
        })
        where, sha = _entity(record), str(record.get("definition_sha256") or "")
        results.append({
            "ruleId": rule_id, "level": level,
            "message": {"text": str(record.get("message") or title)},
            "locations": [{"logicalLocations": [{"name": where, "fullyQualifiedName": where}]}],
            "partialFingerprints": {
                "agentLatchToolDefinition/v1": digest(f"{rule_id}|{where}|{sha}")},
            "properties": {
                "gate": GATE_ID, "severity": severity, "definitionSha256": sha,
                "signals": [item.get("signal") for item in record.get("evidence") or ()],
                "eventRecordId": record.get("record_id"), "owasp": owasp,
            },
        })
    not_inspected = sum(r.get("outcome") == OUTCOME_NOT_INSPECTED
                        and r.get("rule_id") == RULE_COVERAGE for r in records)
    return {
        "$schema": SARIF_SCHEMA, "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": "AgentLatch", "version": version,
                                "rules": list(rules.values())}},
            "properties": {"gateId": GATE_ID, "monitorOnly": True,
                           "notInspectedCount": not_inspected},
            "results": results,
        }],
    }


def format_terminal(records: Sequence[Mapping[str, Any]]) -> str:
    """Plain lines for a terminal: one row per finding, and nothing that was matched."""
    found = _findings_of(records)
    gaps = [r for r in records if r.get("rule_id") == RULE_COVERAGE]
    lines = [f"ALR04 tool-definition review: {len(found)} finding(s), {len(gaps)} not inspected"]
    if not found:
        lines.append(_CLEAR_NOTE)
    else:
        lines.append(f"{'SEVERITY':<8} {'RULE':<10} {'TOOL@SERVER':<44} SIGNALS")
    for record in found:
        signals = ", ".join(str(item.get("signal")) for item in record.get("evidence") or ())
        lines.append(f"{str(record['severity']).upper():<8} {record['rule_id']!s:<10} "
                     f"{_entity(record, '{tool}@{server}')[:44]:<44} {signals}")
    lines += [f"{'NOT READ':<8} {RULE_COVERAGE:<10} {_entity(r, '{tool}@{server}')[:44]:<44} "
              f"{', '.join(r.get('coverage_notes') or ())}" for r in gaps]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Scan stored ``tools/list`` payloads for review; print findings and optionally SARIF.

    ``python -m agent_latch.gates.alr04 PATH [PATH ...] [--sarif FILE]``

    Each file is one response (``{"server": str, "tools": [...]}``). All files are scanned as
    one run, so tool names are compared across servers. Returns 0 when there is no high
    finding, 1 when there is at least one, and 2 on a usage or input error.
    """
    parser = argparse.ArgumentParser(
        prog="python -m agent_latch.gates.alr04",
        description="Run ALR04 over stored tools/list payloads (review and demo only).")
    parser.add_argument("paths", nargs="+", type=Path, help="JSON payload files, or folders")
    parser.add_argument("--sarif", type=Path, help="write a SARIF 2.1.0 log to this file")
    args = parser.parse_args(argv)
    files = [file for path in args.paths
             for file in ([path] if path.is_file() else sorted(path.glob("*.json")))]
    if not files:
        print("Error: no payload files matched", file=sys.stderr)
        return 2
    reset_state()  # a review run scans each payload fresh
    records: list[dict[str, Any]] = []
    for order, file in enumerate(files, 1):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"Error: {file}: {error}", file=sys.stderr)
            return 2
        if not isinstance(payload, Mapping) or not isinstance(payload.get("tools"), list):
            print(f"Error: {file}: expected an object with a tools list", file=sys.stderr)
            return 2
        records += evaluate({
            "run_id": "alr04", "order": order, "server": str(payload.get("server") or file.stem),
            "method": "tools/list", "stage": "response", "payload": {"tools": payload["tools"]},
        })["findings"]
    print(format_terminal(records))
    if args.sarif is not None:
        try:
            args.sarif.write_text(
                json.dumps(sarif_document(records), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
        except OSError as error:
            print(f"Error: could not write {args.sarif}: {error}", file=sys.stderr)
            return 2
        print(f"Wrote SARIF to {args.sarif}", file=sys.stderr)
    return int(any(record["severity"] == HIGH for record in _findings_of(records)))


if __name__ == "__main__":
    raise SystemExit(main())