"""ALR16 Package installation integrity: package installs invoked through MCP tool calls.

Reads ``tools/call`` request arguments (exec/shell/file tools) and, when present, a startup
command record. It classifies install invocations along four risk dimensions -- source trust,
integrity bypass, execution shape and pin/integrity -- and reports findings per rule. The gate
is monitor-only: it never blocks, fetches nothing from the network, and records pointers and
hashes, never commands, URLs or file contents.

Outcome policy: FAIL needs an intrinsic integrity bypass (TLS/verification disabled), an
off-policy package or source (policy applied), or signals in two or more distinct dimensions.
One dimension is INCONCLUSIVE. A pinned install from the default source with no other signal
is a recorded non-finding (info). Missing policy, startup record or parse is a coverage fact
in the summary, never a PASS and never evidence toward FAIL.

Known blind spots: the registry actually contacted, the installed digest, installs inside a
fetched script that is never written through a tool, response text cut by the payload limit,
and any startup command the proxy does not record (no initialize hook exists yet).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from threading import RLock
from typing import Any

GATE_ID = "ALR16"
# ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution. The gate is not in catalog.GATES
# yet, so the IDs are listed here; names always resolve through agent_latch.owasp.
OWASP = ("ASI04", "ASI05")

MIN_COVERAGE = 0.90
MAX_VALUE_CHARS = 16_000
MAX_SEGMENTS = 32
MAX_PACKAGES = 64
MAX_DECODED_CHARS = 8_000
MAX_DECODE_CANDIDATES = 64
MAX_SHELL_DEPTH = 3
MAX_ARGUMENT_DEPTH = 5
MAX_EVIDENCE_REPORTED = 8
MAX_OUTPUT_RECORDS = 400
MAX_REMEMBERED = 2048
MAX_WRITE_HISTORY = 512

CATEGORIES = ("install_intent", "source_class", "pinning_integrity", "sequence_execution")
RULE_IDS = {name: f"ALR16-{i:03d}" for i, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR16-090"
RULE_SUMMARY = "ALR16-099"

FLAGS = re.IGNORECASE | re.DOTALL


@lru_cache(maxsize=256)
def rx(expr: str) -> re.Pattern[str]:
    return re.compile(expr, FLAGS)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def safe(text: Any, limit: int = 120) -> str:
    """Printable, single-line, length-limited text; tool input is untrusted."""
    flat = "".join("?" if unicodedata.category(c).startswith("C") else c for c in str(text))
    return flat[:limit]


# --- install grammar ----------------------------------------------------------------------------

# (manager label, pattern). Kept as data, not per-ecosystem functions.
INSTALL_RES = (
    ("pip", rx(r"\bpip3?\s+install\b")),
    ("pip", rx(r"\bpython\w*\s+-m\s+pip\s+install\b")),
    ("pipx", rx(r"\bpipx\s+(install|run)\b")),
    ("uv", rx(r"\buv\s+(add|pip\s+install|tool\s+install)\b")),
    ("uv", rx(r"\buv\s+run\s+--with\b")),
    ("uvx", rx(r"\buvx?\s+[a-z]")),
    ("poetry", rx(r"\bpoetry\s+add\b")),
    ("pipenv", rx(r"\bpipenv\s+install\b")),
    ("npm", rx(r"\bnpm\s+(install|i|add|ci|exec)\b")),
    ("npx", rx(r"\bnpx\s+(-y\s+)?[a-z@]")),
    ("yarn", rx(r"\byarn\s+(add|dlx)\b")),
    ("pnpm", rx(r"\bpnpm\s+(add|dlx)\b")),
    ("bun", rx(r"\bbun\s+(add|x)\b")),
    ("cargo", rx(r"\bcargo\s+(install|add)\b")),
    ("go", rx(r"\bgo\s+install\b")),
    ("gem", rx(r"\bgem\s+install\b")),
    ("apt", rx(r"\bapt(?:-get)?\s+install\b")),
    ("dnf", rx(r"\bdnf\s+install\b")),
    ("brew", rx(r"\bbrew\s+install\b")),
    ("conda", rx(r"\b(?:conda|mamba)\s+install\b")),
    ("apk", rx(r"\bapk\s+add\b")),
    ("winget", rx(r"\bwinget\s+install\b")),
    ("choco", rx(r"\bchoco\s+install\b")),
    ("powershell", rx(r"\bInstall-Module\b")),
)

PIPE_SHELL = rx(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sh|bash)\b")
PROCESS_SUBST = rx(r"\bsh\s+<\(\s*(?:curl|wget)\b")
SOURCE_PIPE = rx(r"\bsource\s+<\(\s*(?:curl|wget)\b")
OBFUSCATED_PIPE = rx(r"base64\s+-d[^|]*\|\s*(?:sh|bash)\b")
INSTALL_THROUGH_CODE = rx(
    r"\bpython\w*\s+-c\s+[\"'].*?(?:pip\s+install|os\.system|subprocess)"
    r"|\bos\.system\s*\(.*?pip\s+install|\beval\s*\(.*?(?:pip|npm|curl)"
    r"|\$\(\s*(?:curl|wget|pip|npm)|`(?:curl|wget|pip|npm)"
)
VCS_RE = rx(r"(?:git\+|hg\+|svn\+|bzr\+|github:|bitbucket:|gitlab:|git@|git://)\S+")
URL_ARCHIVE_RE = rx(r"https?://\S+\.(?:whl|tar\.gz|tgz|zip)\b")
INDEX_FLAGS = rx(r"(?:--index-url|--extra-index-url|--registry)\s*=\s*\S+"
                 r"|(?:--index-url|--extra-index-url|--registry|-i)\s+\S+")
TRUSTED_HOST = rx(r"--trusted-host\s+\S+|PIP_TRUSTED_HOST\s*=\s*\S+")
INSECURE = rx(r"(?:curl\s+[^|]*?-[a-z]*k|--insecure)\b|--allow-unverified|--allow-external")
HTTP_INDEX = rx(r"(?:--index-url|--extra-index-url|--registry)\s*=?\s*http://")
VALUE_FLAGS = frozenset({"-i", "--index-url", "--extra-index-url", "--registry",
                         "--find-links", "--trusted-host", "-r", "--requirement",
                         "-c", "--constraint", "--hash", "--cert", "--client-cert",
                         "--proxy", "--no-index"})
LOCKED_POSITIVE = rx(r"\bnpm\s+ci\b|--frozen-lockfile\b|uv\s+sync\s+--locked\b")
REQUIRE_HASHES = rx(r"--require-hashes\b|--hash\s*=\s*\S+")
FETCH_AND_RUN = rx(
    r"(?:curl|wget)\b[^|\n]*(?:\|\s*(?:bash|sh|zsh|dash|powershell|pwsh|cmd)\b|"
    r"\s+-o\s+-\s*\|\s*(?:bash|sh|zsh|dash|powershell|pwsh|cmd)\b)"
)
NO_INDEX = rx(r"(?:^|\s)--no-index\b|\bPIP_NO_INDEX\s*=\s*1\b")
PACKAGE_URL_SPEC = rx(r"\b[A-Za-z0-9_.-]+\s*@\s*(?:https?://|git\+|git@|github:|gitlab:|bitbucket:|ssh://)\S+")

ENV_SOURCE_RES = (
    ("env_index", rx(r"\b(?:PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|"
                     r"NPM_CONFIG_REGISTRY)\s*=\s*\S+")),
    ("env_trusted_host", rx(r"\bPIP_TRUSTED_HOST\s*=\s*\S+")),
    ("env_proxy_config", rx(r"\b(?:GOPROXY|GONOSUMDB|GOINSECURE|CURL_CA_BUNDLE)\s*=\s*\S+")),
)
SOURCE_CONFIG_CHANGE = rx(
    r"\bpip\s+config\s+set\s+global\.(?:index-url|extra-index-url|trusted-host)"
    r"|\bnpm\s+config\s+set\s+registry\b"
    r"|(?:pip\.conf|\.npmrc|uv\.toml)\b"
    r"|\badd-apt-repository\b|\bapt-key\b"
    r"|\bcargo\s+.*source\s+replacement"
)

# Kept small and explicit: shell, python and JS runners plus Windows managers.
EXEC_NAME_HINTS = ("bash", "sh", "shell", "terminal", "command", "exec", "run",
                   "python", "repl", "powershell", "pwsh", "cmd", "winget", "choco")
EXEC_DESC_HINTS = ("shell command", "run a command", "execute", "terminal",
                   "command line", "powershell", "command prompt")
EXEC_SCHEMA_KEYS = ("command", "cmd", "script", "code", "command_line", "commands",
                    "path", "file", "args", "argv")
FILE_HINTS = ("write", "file", "save", "create", "script")
SCRIPT_MARKERS = (".sh", ".ps1", ".bat", "Dockerfile", "setup.py", "package.json")

B64 = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){6,}(?:={0,2})(?![A-Za-z0-9+/])")
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){24,}(?![0-9A-Fa-f])")

LIMIT_NOTES = frozenset({"value_limit", "segment_limit", "decode_limit", "package_limit",
                         "unparsed", "history_limit"})
UNKNOWN_EXTENT_NOTES = frozenset({"unparsed"})


@dataclass(frozen=True)
class Evidence:
    category: str
    dimension: str  # source | integrity_bypass | execution | pin
    hard: bool
    signal: str
    path: str
    source: str  # channel: arguments | pipeline | env | decoded | sequence | policy
    digest: str


def _lev1(a: str, b: str) -> bool:
    """True when two names differ by one insertion, deletion, substitution or swap."""
    if a == b:
        return False
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1 \
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]:
            return True
    if abs(len(a) - len(b)) > 1:
        return False
    short, long = (a, b) if len(a) <= len(b) else (b, a)
    for i in range(len(long)):
        if short[:i] + short[i + (len(long) - len(short)):] == long[:i] + long[i + 1:]:
            return True
    return False


# --- command parsing (quote-aware, backslash-preserving) ----------------------------------------


def _split_segments(text: str) -> tuple[list[str], bool]:
    """Split on newline, carriage return, &&, ||, ; and |, respecting quotes. Pipes are split
    here only after the pipeline shape was already detected on the raw text."""
    out: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        char = text[i]
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
            current.append(char)
        elif char in ("\r", "\n"):
            out.append("".join(current))
            current = []
        elif text.startswith("&&", i) or text.startswith("||", i):
            out.append("".join(current))
            current = []
            i += 1
        elif char in (";", "|", "&"):
            out.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    out.append("".join(current))
    segments = [s.strip().strip("'\" ") for s in out if s.strip().strip("'\" ")]
    return segments[:MAX_SEGMENTS], len(segments) > MAX_SEGMENTS


def _split_args(segment: str) -> list[str]:
    """Quote-aware whitespace split that never interprets backslashes (Windows paths)."""
    out: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in segment:
        if quote is not None:
            if char == quote:
                quote = None
            else:
                current.append(char)
        elif char in ("'", '"'):
            quote = char
        elif char.isspace():
            if current:
                out.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        out.append("".join(current))
    return out


def _unwrap_shell(text: str) -> str:
    """Peel one `sh -c "..."` / `powershell -Command "..."` / `cmd /c "..."` layer."""
    match = re.match(r"\s*(?:sudo\s+)?(?:sh|bash|dash|zsh)\s+-c\s+[\"']?(.*)[\"']?\s*$",
                     text, FLAGS)
    if match:
        return match.group(1)
    match = re.match(r"\s*(?:powershell|pwsh)(?:\.exe)?\s+-(?:Command|c)\s+[\"']?(.*)[\"']?\s*$",
                     text, FLAGS)
    if match:
        return match.group(1)
    match = re.match(r"\s*cmd(?:\.exe)?\s+/[ck]\s+[\"']?(.*)[\"']?\s*$", text, FLAGS)
    if match:
        return match.group(1)
    return text


def _try_decoded(token: str) -> str | None:
    for decoder in (base64.b64decode, lambda value: binascii.unhexlify(value.encode("ascii"))):
        try:
            data = decoder(token)
        except (ValueError, TypeError, binascii.Error):
            continue
        if len(data) > MAX_DECODED_CHARS:
            continue
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeError:
            continue
        if len(text) < 8:
            continue
        printable = sum(c.isprintable() or c in "\n\t" for c in text) / len(text)
        wordlike = sum(c.isalpha() or c.isspace() for c in text) / len(text)
        if printable >= 0.9 and wordlike >= 0.5:
            return text
    return None


# --- policy ---


def _gate_policy(policy: Mapping[str, Any] | None) -> tuple[dict[str, Any] | None, str]:
    """(parsed policy or None, policy_state). Invalid input is a coverage fact, never silent."""
    if not isinstance(policy, Mapping):
        return None, "absent"
    candidate: Any = policy
    gates = policy.get("gates")
    if isinstance(gates, Mapping):
        namespaced = gates.get("alr16", gates.get("ALR16"))
        if namespaced is not None:
            candidate = namespaced
    if not isinstance(candidate, Mapping):
        return None, "invalid"
    if candidate is policy and not any(
            key in candidate for key in ("packages", "indexes", "mode", "suppressions")):
        return None, "absent"
    mode = str(candidate.get("mode", "auto")).lower()
    if mode == "off":
        return None, "ignored"
    if mode not in ("auto", "require"):
        return None, "invalid"

    def _names(value: Any) -> set[str] | None:
        if not isinstance(value, list):
            return None
        names = {str(item).casefold() for item in value if isinstance(item, str) and item}
        if value and not names:
            return None
        return names

    packages = candidate.get("packages", {})
    allow: set[str] | None = None
    dev_allow: set[str] | None = None
    deny: set[str] | None = None
    require_hashes = False
    if isinstance(packages, Mapping):
        allow = _names(packages.get("allow", []))
        dev_allow = _names(packages.get("dev_allow", []))
        deny = _names(packages.get("deny", []))
        require_hashes = bool(packages.get("require_hashes", False))
    else:
        allow = _names(packages)
        dev_allow, deny = set(), set()
    indexes = candidate.get("indexes", [])
    if not isinstance(indexes, list) or any(not isinstance(i, str) for i in indexes):
        return None, "invalid"
    if allow is None or dev_allow is None or deny is None:
        return None, "invalid"
    enforce_allow = (isinstance(packages, Mapping) and "allow" in packages) or mode == "require"
    return {"mode": mode, "allow": allow, "dev_allow": dev_allow, "deny": deny,
            "indexes": [str(i) for i in indexes], "enforce_allow": enforce_allow,
            "require_hashes": require_hashes}, "applied"


def _suppression(policy: Mapping[str, Any] | None, rule_id: str) -> str | None:
    parsed, _ = _gate_policy(policy)
    _ = parsed
    container = policy if isinstance(policy, Mapping) else {}
    gates = container.get("gates")
    if isinstance(gates, Mapping):
        inner = gates.get("alr16", gates.get("ALR16"))
        if isinstance(inner, Mapping):
            container = inner
    suppressions = container.get("suppressions", {})
    reason = suppressions.get(rule_id) if isinstance(suppressions, Mapping) else None
    return reason.strip() if isinstance(reason, str) and reason.strip() else None


# --- per-segment classification ---


@dataclass
class Scan:
    evidence: list[Evidence]
    dimensions: set[str]
    packages: list[str]
    install_seen: bool
    notes: set[str]

    def add(self, category: str, dimension: str, hard: bool, signal: str,
            path: str, source: str, text: str) -> None:
        if len(self.evidence) >= MAX_EVIDENCE_REPORTED * 4:
            return
        self.evidence.append(Evidence(category, dimension, hard, signal, path, source,
                                      digest(signal + "|" + text[:200])))
        if dimension != "none":
            self.dimensions.add(dimension)


def _package_name(token: str) -> str:
    name = re.split(r"[=<>!~\s\[;@]", token.strip("'\""), maxsplit=1)[0]
    return name.strip("'\"")


def _classify_segment(segment: str, path: str, scan: Scan,
                      parsed: dict[str, Any] | None) -> None:
    for manager, pattern in INSTALL_RES:
        if not pattern.search(segment):
            continue
        scan.install_seen = True  # invocation itself is not evidence; signals below decide
        tokens = _split_args(segment)
        try:
            verb_at = next(i for i, tok in enumerate(tokens)
                           if tok.lower() in ("install", "add", "i", "ci"))
        except StopIteration:
            verb_at = 0
        rest = tokens[verb_at + 1:verb_at + 1 + MAX_PACKAGES]
        if len(tokens) - (verb_at + 1) > MAX_PACKAGES:
            scan.notes.add("package_limit")
        hashed = bool(REQUIRE_HASHES.search(segment))
        index_hard = False
        skip_next = False
        for pos, token in enumerate(rest):
            if skip_next:
                skip_next = False
                continue
            low = token.lower()
            index_flag = None
            index_value = ""
            consume_next = False
            if low in ("-i", "--index-url", "--extra-index-url", "--registry"):
                index_flag = low
                index_value = rest[pos + 1] if pos + 1 < len(rest) else ""
                consume_next = True
            else:
                for flag in ("--index-url", "--extra-index-url", "--registry"):
                    if low.startswith(f"{flag}="):
                        index_flag = flag
                        index_value = token[len(flag) + 1:]
                        break
                if index_flag is None and low.startswith("-i") and low != "-i":
                    index_flag = "-i"
                    index_value = token[2:].lstrip("=")
            if index_flag is not None:
                scan.add("source_class", "source", False, "custom_index",
                         path, "arguments", index_flag)
                if index_flag == "--extra-index-url":
                    scan.add("source_class", "source", False,
                             "extra_index_merge_shape", path, "arguments", index_flag)
                if parsed is not None and parsed["indexes"] \
                        and index_value not in parsed["indexes"]:
                    index_hard = True
                if consume_next:
                    skip_next = True
                continue
            if low in VALUE_FLAGS:
                if low == "-r":
                    scan.add("pinning_integrity", "pin", False,
                             "requirements_unresolved", path, "arguments",
                             "requirements_file")
                if low == "--trusted-host":
                    scan.add("source_class", "integrity_bypass", True,
                             "trusted_host_disables_tls", path, "arguments", token)
                if low == "--no-index":
                    scan.add("source_class", "integrity_bypass", True,
                             "no_index_disables_registry_policy", path, "arguments", token)
                skip_next = True
                continue
            if low.startswith("-"):
                if low in ("--insecure", "-k", "--allow-unverified", "--allow-external",
                           "--break-system-packages"):
                    scan.add("source_class", "integrity_bypass", True,
                             f"verification_disabled_{low.lstrip('-').replace('-', '_')}",
                             path, "arguments", token)
                if low == "--no-index":
                    scan.add("source_class", "integrity_bypass", True,
                             "no_index_disables_registry_policy", path, "arguments", token)
                continue
            if PACKAGE_URL_SPEC.search(segment):
                scan.add("source_class", "source", False, "direct_url_source",
                         path, "arguments", "direct_url_source")
            if VCS_RE.search(token):
                scan.add("source_class", "source", False, "vcs_source",
                         path, "arguments", "vcs_source")
                continue
            if URL_ARCHIVE_RE.search(token) or (
                    token.startswith("http") and manager in ("pip", "npm", "cargo")):
                scan.add("source_class", "source", False, "url_source",
                         path, "arguments", "url_source")
                continue
            if token in (".", "-e") or token.startswith(("./", "../", "/", "file:", "~")) \
                    or re.match(r"[A-Za-z]:\\", token):
                scan.add("source_class", "source", False, "local_path_source",
                         path, "arguments", "local_path")
                continue
            name = _package_name(token)
            if not name or len(scan.packages) >= MAX_PACKAGES:
                continue
            scan.packages.append(name)
            if parsed is not None:
                folded = name.casefold()
                if folded in parsed["deny"]:
                    scan.add("source_class", "source", True, "explicitly_denied_package",
                             path, "policy", name[:80])
                elif parsed["enforce_allow"] and folded not in parsed["allow"] \
                        and folded not in parsed["dev_allow"]:
                    lookalike = any(_lev1(folded, allowed)
                                    for allowed in parsed["allow"] if len(allowed) >= 5)
                    if lookalike:
                        scan.add("pinning_integrity", "pin", False, "possible_typosquat",
                                 path, "policy", name[:80])
                    else:
                        scan.add("source_class", "source", True, "off_allowlist_package",
                                 path, "policy", name[:80])
            if re.search(r"==[^=]|@[0-9]", token):
                continue  # pinned: integrity-positive, no signal
            if re.search(r">=|~=|\*|\^|>|<|latest", token):
                scan.add("pinning_integrity", "pin", False, "version_range_not_pinned",
                         path, "arguments", name[:80])
            elif token.startswith("-r") or token.endswith((".txt", ".in")):
                scan.add("pinning_integrity", "pin", False, "requirements_unresolved",
                         path, "arguments", name[:80])
            else:
                scan.add("pinning_integrity", "pin", False, "unpinned_package",
                         path, "arguments", name[:80])
        if index_hard:
            scan.add("source_class", "source", True, "off_policy_index",
                     path, "policy", "custom_index")
        if NO_INDEX.search(segment):
            scan.add("source_class", "integrity_bypass", True,
                     "no_index_disables_registry_policy", path, "arguments",
                     safe(NO_INDEX.search(segment).group(0), 80))
        if parsed is not None and parsed["require_hashes"] and not hashed:
            scan.add("pinning_integrity", "pin", False, "hashless_install", path,
                     "policy", "hash_policy")
        if LOCKED_POSITIVE.search(segment):
            scan.notes.add("locked_install_mode")
        break


def _classify_text(text: str, path: str, scan: Scan,
                   parsed: dict[str, Any] | None, depth: int = 0) -> None:
    """Pipeline shapes and env first (they vanish after unwrapping/splitting), then segments."""
    if (PIPE_SHELL.search(text) or PROCESS_SUBST.search(text) or SOURCE_PIPE.search(text)
            or OBFUSCATED_PIPE.search(text) or FETCH_AND_RUN.search(text)):
        scan.install_seen = True
        scan.add("sequence_execution", "execution", False, "pipe_to_shell",
                 path, "pipeline", "pipe_to_shell")
    if INSTALL_THROUGH_CODE.search(text):
        scan.install_seen = True
        scan.add("sequence_execution", "execution", False, "install_through_code",
                 path, "arguments", "install_through_code")
    if SOURCE_CONFIG_CHANGE.search(text):
        scan.install_seen = True
        scan.add("source_class", "source", False, "persistent_source_config_change",
                 path, "arguments", "source_config_change")
    for label, pattern in ENV_SOURCE_RES:
        if pattern.search(text):
            scan.install_seen = True
            dimension = "integrity_bypass" if label == "env_trusted_host" else "source"
            hard = label == "env_trusted_host"
            scan.add("source_class", dimension, hard, f"env_{label}", path, "env", label)
    if TRUSTED_HOST.search(text):
        scan.add("source_class", "integrity_bypass", True, "trusted_host_disables_tls",
                 path, "arguments", "trusted_host")
    if NO_INDEX.search(text):
        scan.add("source_class", "integrity_bypass", True, "no_index_disables_registry_policy",
                 path, "arguments", "no_index")
    if INSECURE.search(text):
        scan.add("source_class", "integrity_bypass", True, "insecure_download_flag",
                 path, "arguments", "insecure_flag")
    if HTTP_INDEX.search(text):
        scan.add("source_class", "integrity_bypass", True, "plaintext_http_index",
                 path, "arguments", "http_index")
    unwrapped = _unwrap_shell(text)
    if unwrapped != text:
        if depth >= MAX_SHELL_DEPTH:
            scan.notes.add("unparsed")
            return
        _classify_text(unwrapped, path, scan, parsed, depth + 1)
        return
    segments, cut = _split_segments(text)
    if cut:
        scan.notes.add("segment_limit")
    for segment in segments:
        _classify_segment(segment, path, scan, parsed)


def _classify_decoded(text: str, path: str, scan: Scan) -> None:
    """Inspect a small number of decode rounds so obfuscated install commands are not missed."""
    examined = 0
    queue = deque([text])
    seen: set[str] = set()
    while queue and examined < MAX_DECODE_CANDIDATES:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        for pattern in (B64, HEX):
            for match in pattern.finditer(current):
                if examined >= MAX_DECODE_CANDIDATES:
                    scan.notes.add("decode_limit")
                    return
                examined += 1
                decoded = _try_decoded(match.group())
                if decoded is None:
                    continue
                if any(pattern.search(decoded) for _, pattern in INSTALL_RES) or PIPE_SHELL.search(decoded):
                    scan.install_seen = True
                    scan.add("sequence_execution", "execution", False, "obfuscated_install",
                             path, "decoded", "obfuscated")
                    return
                queue.append(decoded)


# --- tool role and two-step sequence ---


def _tool_role(name: str, definition: Mapping[str, Any] | None) -> str:
    folded = name.casefold()
    if any(hint in folded for hint in EXEC_NAME_HINTS):
        return "exec"
    if any(hint in folded for hint in FILE_HINTS):
        return "file"
    if not isinstance(definition, Mapping):
        return "other"
    text = f"{definition.get('description', '')} {definition.get('title', '')}".casefold()
    schema = definition.get("inputSchema")
    keys = " ".join(str(k).casefold() for k in schema.get("properties", {})) \
        if isinstance(schema, Mapping) and isinstance(schema.get("properties"), Mapping) \
        else ""
    if any(hint in text or hint in keys for hint in EXEC_DESC_HINTS) \
            or any(key in keys.split() for key in EXEC_SCHEMA_KEYS):
        return "exec"
    if any(hint in text for hint in FILE_HINTS):
        return "file"
    return "other"


def _basenames(text: str) -> list[str]:
    return [match.group(1).casefold()
            for match in re.finditer(r"([A-Za-z0-9_][\w.\-]*\.(?:sh|ps1|bat|py))\b", text)]


_lock = RLock()
_seen: OrderedDict[tuple[str, ...], bool] = OrderedDict()
_writes: deque[tuple[str, str, str]] = deque()  # (run_id, server, basename)


def reset_state() -> None:
    """Forget scanned calls and written-script history (tests, or a new importer run)."""
    with _lock:
        _seen.clear()
        _writes.clear()


def _remember(key: tuple[str, ...]) -> bool:
    with _lock:
        if key in _seen:
            _seen.move_to_end(key)
            return True
        _seen[key] = True
        while len(_seen) > MAX_REMEMBERED:
            _seen.popitem(last=False)
        return False


def _note_writes(run_id: str, server: str, values: list[str]) -> None:
    with _lock:
        for value in values:
            for base in _basenames(value):
                _writes.append((run_id, server, base))
        while len(_writes) > MAX_WRITE_HISTORY:
            _writes.popleft()


def _write_history_state(run_id: str, server: str) -> str:
    with _lock:
        relevant = [base for run, host, base in _writes if run == run_id and host == server]
    return digest("\n".join(relevant))


def _matches_prior_write(run_id: str, server: str, segment: str) -> str | None:
    for base in _basenames(segment) + [tok.casefold().split("/")[-1].split("\\")[-1]
                                       for tok in _split_args(segment)
                                       if "." in tok and len(tok) < 80]:
        with _lock:
            history = list(_writes)
        if any(r == run_id and s == server and b == base for r, s, b in history):
            return base
    return None


# --- records ---


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _result(*, category: str, tool: str, server: str, event: Mapping[str, Any],
            evidence: list[Evidence], coverage: float, args_hash: str, outcome: str,
            score: float, reason: str, notes: set[str],
            policy: Mapping[str, Any] | None) -> dict[str, Any]:
    rule_id = RULE_IDS[category]
    suppressions = policy if isinstance(policy, Mapping) else {}
    gates = suppressions.get("gates")
    if isinstance(gates, Mapping):
        inner = gates.get("alr16", gates.get("ALR16"))
        if isinstance(inner, Mapping):
            suppressions = inner
    raw = suppressions.get("suppressions", {})
    found = raw.get(rule_id) if isinstance(raw, Mapping) else None
    suppressed_reason = found.strip() if isinstance(found, str) and found.strip() else None
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
        "evidence": [{"class": e.dimension, "strength": "hard" if e.hard else "soft",
                      "signal": e.signal, "source": e.source, "role": "",
                      "field": safe(e.path, 220), "sha256": e.digest, "quoted": False}
                     for e in evidence[:MAX_EVIDENCE_REPORTED]],
        "evidence_count": len(evidence), "definition_sha256": args_hash,
        "owasp": list(OWASP),
        "message": {
            "FAIL": "Tool arguments invoke a package install that bypasses verification, "
                    "leaves the allowlisted source, or stacks two risk dimensions; "
                    "no exploit confirmed.",
            "INCONCLUSIVE": "A package install signal needs review or the input "
                            "could not be fully inspected.",
            "PASS": "A pinned install from the default source; recorded for reference only.",
        }[outcome],
    }


def _coverage_record(event: Mapping[str, Any], reason: str, *, tool: str = "",
                     server: str = "", notes: set[str] | None = None,
                     args_hash: str = "") -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": RULE_COVERAGE, "family": "coverage",
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "outcome": "INCONCLUSIVE", "is_finding": True,
        "suppressed": False, "severity": "medium", "score": 0.0, "coverage": 0.0,
        "decision_reason": reason, "coverage_notes": sorted(notes or {reason}),
        "definition_sha256": args_hash, "owasp": list(OWASP), "evidence": [],
        "evidence_count": 0,
        "message": "Part of the package-install input was not evaluated, so it cannot be cleared.",
    }


def startup_capabilities() -> list[dict[str, str]]:
    """What this gate cannot check, for a dispatcher to report up front instead of a silent PASS."""
    return [
        {"check": "tool_call_install_arguments", "outcome": "SUPPORTED"},
        {"check": "startup_command", "outcome": "UNSUPPORTED",
         "reason": "The proxy records no initialize/startup command yet; absence is reported."},
        {"check": "response_corroboration", "outcome": "UNSUPPORTED",
         "reason": "tools/call responses are not inspected; request intent only."},
        {"check": "registry_contact_or_digest", "outcome": "UNSUPPORTED",
         "reason": "No network or digest verification; the contacted index is unknown."},
        {"check": "fetched_script_contents", "outcome": "UNSUPPORTED",
         "reason": "Installs inside a remotely fetched script are invisible until written."},
    ]


# --- evaluation ---


def _verdict(scan: Scan, parsed: dict[str, Any] | None, policy_state: str,
             coverage: float, ambiguous: bool) -> tuple[str, float, str]:
    hard = [e for e in scan.evidence if e.hard]
    if hard:
        if parsed is None and all(e.source != "policy" for e in hard):
            pass  # intrinsic bypasses fail policy-free; off-policy needs a policy (below)
        intrinsic = [e for e in hard if e.source != "policy"]
        if intrinsic:
            return "FAIL", 0.95, "integrity_bypass"
        if parsed is not None:
            return "FAIL", 0.9, "off_policy_source_or_package"
        return "INCONCLUSIVE", 0.6, "source_needs_policy"
    dims = set(scan.dimensions)
    if len(dims) >= 2:
        return "FAIL", 0.85, "two_risk_dimensions"
    if dims:
        return "INCONCLUSIVE", 0.6, "single_risk_dimension"
    if policy_state == "require" and parsed is None and scan.install_seen:
        return "INCONCLUSIVE", 0.5, "policy_required_but_absent"
    if coverage < MIN_COVERAGE or ambiguous:
        return "INCONCLUSIVE", 0.5, "incomplete_input"
    if scan.install_seen:
        return "PASS", 0.1, "pinned_default_source"
    return "PASS", 0.0, "no_install_invocation"


def _scan_arguments(arguments: Mapping[str, Any], role: str, run_id: str, server: str,
                    parsed: dict[str, Any] | None) -> Scan:
    scan = Scan([], set(), [], False, set())
    strings: list[tuple[str, str]] = []

    def collect(value: Any, path: str, depth: int) -> None:
        if isinstance(value, str):
            if not value:
                return
            if len(value) > MAX_VALUE_CHARS:
                scan.notes.add("value_limit")
                value = value[:MAX_VALUE_CHARS]
            strings.append((path, value))
        elif isinstance(value, Mapping):
            if depth >= MAX_ARGUMENT_DEPTH:
                scan.notes.add("unparsed")
                return
            for key, child in value.items():
                collect(child, f"{path}.{safe(key, 60)}", depth + 1)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            collect(" ".join(value), path, depth)
        else:
            scan.notes.add("unparsed")

    for key, value in arguments.items():
        collect(value, f"arguments.{safe(key, 60)}", 0)
    for path, value in strings:
        _classify_text(value, path, scan, parsed)
        _classify_decoded(value, path, scan)
        if role == "file" or value.lstrip().startswith("#!") \
                or any(marker in value for marker in SCRIPT_MARKERS):
            inner = Scan([], set(), [], False, set())
            _classify_text(value, path, inner, parsed)
            if inner.install_seen and not scan.install_seen:
                scan.install_seen = True
                scan.add("sequence_execution", "execution", False,
                         "embedded_install_script", path, "arguments", "embedded")
    if role == "file":
        _note_writes(run_id, server, [value for _, value in strings])
    elif role == "exec":
        for path, value in strings:
            for segment in _split_segments(_unwrap_shell(value))[0]:
                matched = _matches_prior_write(run_id, server, segment)
                if matched:
                    scan.install_seen = True
                    scan.add("sequence_execution", "execution", False,
                             "write_then_execute_sequence", path, "sequence", matched)
                    break
    return scan


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Findings for one importer event. ``policy`` must be trusted operator configuration."""
    if not isinstance(event, Mapping):
        return {"findings": [_coverage_record({}, "malformed_event")]}
    method, stage = event.get("method"), event.get("stage")
    is_call = method == "tools/call" and stage == "request"
    is_startup = method == "initialize" and stage == "startup"
    if not (is_call or is_startup):
        return {"findings": []}  # not an ALR16 input; not a PASS either
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        return {"findings": [_coverage_record(event, "payload_unavailable")]}
    server = str(event.get("server") or "")
    run_id = str(event.get("run_id") or "")

    parsed, policy_state = _gate_policy(policy)
    notes: set[str] = set()
    if policy_state in ("absent", "invalid"):
        notes.add(f"policy_{policy_state}")
    elif policy_state == "ignored":
        notes.add("policy_ignored")

    if is_startup:
        command = payload.get("command", payload.get("argv", ""))
        text = " ".join(str(c) for c in command) if isinstance(command, list) else str(command)
        if not text.strip():
            return {"findings": [_coverage_record(
                event, "startup_command_unavailable", server=server, notes=notes)]}
        scan = Scan([], set(), [], False, set(notes))
        _classify_text(text[:MAX_VALUE_CHARS], "startup.command", scan, parsed)
        args_hash = digest(text[:MAX_VALUE_CHARS])
        outcome, score, reason = _verdict(scan, parsed, policy_state, 1.0, False)
        records = _emit(scan, "startup", server, event, args_hash, outcome, score,
                        reason, notes, policy)
        records.append(_summary(event, server, 1, outcome, policy_state,
                                "recorded", notes))
        return {"findings": records}

    tool = payload.get("tool")
    arguments = payload.get("arguments")
    if not isinstance(tool, str) or not isinstance(arguments, Mapping):
        return {"findings": [_coverage_record(event, "call_arguments_unavailable",
                                              server=server, notes=notes)]}
    definition = payload.get("tool_definition")
    role = _tool_role(tool, definition if isinstance(definition, Mapping) else None)
    if role == "other":
        out = [_summary(event, server, 0, "PASS", policy_state, "unavailable",
                        notes | {"non_exec_tool"})]
        return {"findings": out}
    args_hash = digest(json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str))
    history_state = _write_history_state(run_id, server) if role == "exec" else ""
    scan = _scan_arguments(arguments, role, run_id, server, parsed)
    if _remember((run_id, server, tool, args_hash, history_state)):
        return {"findings": []}  # exact duplicate call already reported
    scan.notes |= notes
    coverage = 1.0
    if scan.notes & UNKNOWN_EXTENT_NOTES:
        coverage = 0.0
    ambiguous = bool(scan.notes & LIMIT_NOTES)
    outcome, score, reason = _verdict(scan, parsed, policy_state, coverage, ambiguous)
    if outcome == "PASS" and reason == "no_install_invocation":
        return {"findings": [_summary(event, server, 0, "PASS", policy_state,
                                      "unavailable", scan.notes)]}
    records = _emit(scan, tool, server, event, args_hash, outcome, score, reason,
                    scan.notes, policy)
    records.append(_summary(event, server, 1, outcome, policy_state, "unavailable",
                            scan.notes))
    if len(records) > MAX_OUTPUT_RECORDS:
        records = records[:MAX_OUTPUT_RECORDS] + [_coverage_record(
            event, "output_record_limit", tool=tool, server=server, args_hash=args_hash)]
    return {"findings": records}


def _emit(scan: Scan, tool: str, server: str, event: Mapping[str, Any], args_hash: str,
          outcome: str, score: float, reason: str, notes: set[str],
          policy: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    by_category: dict[str, list[Evidence]] = {name: [] for name in CATEGORIES}
    for item in scan.evidence:
        by_category.setdefault(item.category, []).append(item)
    records: list[dict[str, Any]] = []
    worst = "PASS"
    for category in CATEGORIES:
        items = by_category.get(category, [])
        if not items:
            continue
        item_outcome = outcome
        if outcome == "PASS":
            item_outcome = "PASS"
        records.append(_result(category=category, tool=tool, server=server, event=event,
                               evidence=items, coverage=1.0, args_hash=args_hash,
                               outcome=item_outcome, score=score, reason=reason,
                               notes=notes, policy=policy))
        if item_outcome == "FAIL" or (item_outcome == "INCONCLUSIVE" and worst == "PASS"):
            worst = item_outcome
    if outcome == "PASS" and not records and scan.install_seen:
        records.append(_result(category="install_intent", tool=tool, server=server,
                               event=event, evidence=[], coverage=1.0, args_hash=args_hash,
                               outcome="PASS", score=score, reason=reason, notes=notes,
                               policy=policy))
    _ = worst
    return records


def _summary(event: Mapping[str, Any], server: str, scanned: int, worst: str,
             policy_state: str, startup_state: str, notes: set[str]) -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": RULE_SUMMARY, "family": "scan_summary",
        "entity": {"server": safe(server), "tool": ""}, "record_id": _pointer(event),
        "outcome": worst, "is_finding": False, "suppressed": False, "severity": "info",
        "score": 0.0, "coverage": 1.0, "tools_scanned": scanned,
        "policy_state": policy_state, "startup_state": startup_state,
        "decision_reason": "scan_summary", "coverage_notes": sorted(notes),
        "definition_sha256": "", "owasp": list(OWASP), "evidence": [], "evidence_count": 0,
        "message": "Scan summary for this event; policy and startup availability included.",
    }
