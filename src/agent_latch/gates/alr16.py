"""ALR16 Package installation integrity: package installs requested through MCP tool calls.

Scope
    Reads the arguments of ``tools/call`` requests. For a tool that runs commands, each
    command is parsed the way a shell hands it to a program: the program first, then its
    subcommand, then its arguments. An install phrase inside a quoted argument, a commit
    message or an ``echo`` is therefore not an install. For a tool that writes files, the gate
    only remembers a script whose content contains an install or a fetch, so that running
    that script later can be reported.

Severity
    Every signal has one fixed rank in ``SIGNALS`` (high, medium or low). A record's severity
    is the highest rank among its own signals. Nothing is scored and no record inherits the
    severity of another.

Outcomes
    FINDING        ALR16-002/003/004, ranked high, medium or low.
    OBSERVED       ALR16-001, an install was seen; informational, not a finding.
    NOT_INSPECTED  ALR16-090, part of the input could not be read (missing payload, a limit).
                   It is never a pass and carries no rank.
    ALR16-099 is the per-event summary.

The gate is monitor-only and makes no network calls. Output never contains commands, URLs,
package names or file contents: evidence is a signal name, a field pointer and a SHA-256.

Layout: the package-manager tables are in ``_alr16_grammar``, the command lexer is in
``_commandline``, and this module holds the detection logic and the record format.

Known blind spots, also returned by ``startup_capabilities``: shell indirection (variables,
aliases, ``eval`` of built strings); commands handed to another launcher (docker, ssh, xargs,
make); installs inside a script that is fetched or already on disk; the contents of
requirements and lock files; the registry actually contacted and what was resolved; operator
allowlists and typosquat checks (no policy input exists yet); the MCP server's own launch
command; text removed by payload masking or truncation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from agent_latch import catalog
from agent_latch.gates import _alr16_grammar as grammar
from agent_latch.gates import _commandline as shell
from agent_latch.gates._alr16_grammar import Action, Manager
from agent_latch.gates._commandline import Command

GATE_ID = "ALR16"
OWASP = tuple(catalog.gate(GATE_ID).owasp)

# --- limits ---------------------------------------------------------------------------------
# Tool arguments are untrusted. Every limit that stops inspection adds a note, and any note
# produces an ALR16-090 record, so a limit can never hide an install silently.

MAX_STRINGS = 256  # argument strings read per call
MAX_TOTAL_CHARS = 32_000  # characters read per call, all strings together
MAX_ARGUMENT_DEPTH = 5  # nesting of objects and arrays in the arguments
MAX_NESTING = 3  # layers followed through sh -c, $(...), eval and decoded text
MAX_PACKAGES = 64  # package specs classified per install command
MAX_SPEC_CHARS = 200  # characters of one package spec that are classified
MAX_DECODE_CANDIDATES = 64  # Base64/hex runs tried per string
MAX_DECODED_CHARS = 8_000  # size of one decoded run
MAX_DECODED_TOTAL = 16_000  # decoded characters analysed per string
MAX_EVIDENCE = 64  # evidence items kept per call
MAX_EVIDENCE_REPORTED = 8  # evidence items listed per record
MAX_REMEMBERED = 2048  # calls remembered for duplicate suppression
MAX_WRITE_HISTORY = 512  # written scripts remembered for the write-then-execute check

# --- rules, ranks and outcomes --------------------------------------------------------------

HIGH, MEDIUM, LOW = "high", "medium", "low"
_RANK_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

INTENT, SOURCE, PINNING, SEQUENCE = (
    "install_intent", "source_class", "pinning_integrity", "sequence_execution",
)
CATEGORIES = (INTENT, SOURCE, PINNING, SEQUENCE)
RULE_IDS = {name: f"ALR16-{number:03d}" for number, name in enumerate(CATEGORIES, 1)}
RULE_COVERAGE = "ALR16-090"
RULE_SUMMARY = "ALR16-099"

OUTCOME_FINDING = "FINDING"
OUTCOME_OBSERVED = "OBSERVED"
OUTCOME_NOT_INSPECTED = "NOT_INSPECTED"
OUTCOME_NO_SIGNAL = "NO_SIGNAL"
OUTCOME_OUT_OF_SCOPE = "OUT_OF_SCOPE"

# signal -> (rule family, rank). This table is the only place severity is decided.
SIGNALS: dict[str, tuple[str, str]] = {
    # Content the gate cannot see is fetched or decoded, then executed without review.
    "fetch_pipe_to_shell": (SEQUENCE, HIGH),
    "obfuscated_install": (SEQUENCE, HIGH),
    "install_through_code": (SEQUENCE, MEDIUM),
    "write_then_execute_install": (SEQUENCE, MEDIUM),
    "ephemeral_execute_unpinned": (SEQUENCE, MEDIUM),
    # A check that proves "the right file from the right server" is switched off.
    "tls_verification_disabled": (SOURCE, HIGH),
    "plaintext_http_source": (SOURCE, HIGH),
    "integrity_check_disabled": (SOURCE, HIGH),
    # The install leaves the default registry.
    "extra_index_url": (SOURCE, MEDIUM),
    "custom_index": (SOURCE, MEDIUM),
    "vcs_source": (SOURCE, MEDIUM),
    "direct_url_source": (SOURCE, MEDIUM),
    "registry_bypassed": (SOURCE, MEDIUM),
    "persistent_source_config_change": (SOURCE, MEDIUM),
    "local_archive_or_path": (SOURCE, LOW),
    "system_env_modified": (SOURCE, LOW),
    # The version that will be installed is not fixed by the command.
    "unpinned_package": (PINNING, LOW),
    "version_range": (PINNING, LOW),
    "requirements_file_unhashed": (PINNING, LOW),
}

_MESSAGES = {
    SOURCE: "A package install leaves the default registry or switches off a verification "
            "check. No exploit is confirmed.",
    PINNING: "A package install does not fix the exact version that will be installed.",
    SEQUENCE: "Fetched, decoded or generated content is executed, or a package is installed "
              "through code or a previously written script. No exploit is confirmed.",
}


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def safe(text: Any, limit: int = 120) -> str:
    """Printable, single-line, length-limited text; tool input is untrusted."""
    flat = "".join("?" if unicodedata.category(c).startswith("C") else c for c in str(text))
    return flat[:limit]


# --- source and verification settings -------------------------------------------------------

_EFFECT_SIGNAL = {
    "tls_off": "tls_verification_disabled",
    "integrity_off": "integrity_check_disabled",
    "no_index": "registry_bypassed",
    "system_env": "system_env_modified",
    "vcs": "vcs_source",
    "path": "local_archive_or_path",
}
_WHEN = {
    "any": lambda value: True,
    "true": lambda value: value.strip().lower() in ("1", "true", "yes", "on"),
    "false": lambda value: value.strip().lower() in ("0", "false", "no", "off"),
    "off": lambda value: value.strip().lower() == "off",
}
_LIST_SEPARATOR = re.compile(r"[,|\s]+")


def _url_parts(value: str) -> tuple[str, str]:
    """(scheme, host) in lower case; empty strings when the value is not a URL."""
    try:
        parts = urlsplit(value.strip())
        return parts.scheme.lower(), (parts.hostname or "").lower()
    except ValueError:
        return "", ""


def _is_plaintext(value: str) -> bool:
    scheme, host = _url_parts(value)
    return scheme == "http" and host not in grammar.LOOPBACK_HOSTS


def _is_default_index(entry: str) -> bool:
    # Hosts are compared exactly, so pypi.org.example.net is not treated as pypi.org.
    host = _url_parts(entry)[1]
    if host:
        return host in grammar.DEFAULT_INDEX_HOSTS
    return entry.lower() in grammar.DEFAULT_INDEX_NAMES


def _index_signals(value: str, *, extra: bool) -> list[str]:
    """Signals for a package index setting. ``value`` may list several indexes."""
    signals: list[str] = []
    entries = [entry for entry in _LIST_SEPARATOR.split(value.strip()) if entry]
    if any(_is_plaintext(entry) for entry in entries):
        signals.append("plaintext_http_source")
    if extra:
        signals.append("extra_index_url")  # a second index is the dependency-confusion shape
    elif not entries or not all(_is_default_index(entry) for entry in entries):
        signals.append("custom_index")
    return signals


def _effect_signals(action: Action, value: str) -> list[str]:
    """Signals for one source or verification setting, whatever syntax supplied it."""
    if not _WHEN[action.when](value):
        return []
    if action.effect in ("index", "extra_index"):
        return _index_signals(value, extra=action.effect == "extra_index")
    signal = _EFFECT_SIGNAL.get(action.effect)
    return [signal] if signal else []


# --- package specs --------------------------------------------------------------------------

PINNED, RANGE, UNPINNED = "pinned", "range", "unpinned"
_PIN_SIGNAL: dict[str, list[str]] = {
    PINNED: [], RANGE: ["version_range"], UNPINNED: ["unpinned_package"],
}

VCS_PREFIXES = (
    "git+", "hg+", "svn+", "bzr+", "git://", "git@", "ssh://", "github:", "gitlab:",
    "bitbucket:",
)
PLAINTEXT_VCS_PREFIXES = ("git://", "git+http://", "hg+http://", "svn+http://", "bzr+http://")
ARCHIVE_SUFFIXES = (
    ".whl", ".tar.gz", ".tgz", ".tar.bz2", ".zip", ".gem", ".deb", ".rpm", ".nupkg",
)
LOCAL_PREFIXES = ("./", "../", ".\\", "..\\", "/", "~", "file:")

# Each pattern is a fixed alternation, one character class or dot-separated digits, so
# matching is linear in the input. Specs are also cut to MAX_SPEC_CHARS first.
_EXACT_VERSION = re.compile(r"v?\d[0-9A-Za-z.+_!-]*")  # 2.31.0, 1.0rc1, v1.2.3
_FULL_SEMVER = re.compile(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?")
_COMMIT = re.compile(r"[0-9a-f]{7,40}")
_PEP440_CLAUSE = re.compile(r"(===|==|~=|!=|<=|>=|<|>)\s*([^,\s]*)")
_CONDA_CLAUSE = re.compile(r"([=<>!~]+)([^=<>!~,\s]*)")
_DIRECT_REFERENCE = re.compile(  # PEP 508 "name @ url"
    r"@\s*((?:git\+|hg\+|svn\+|bzr\+|https?://|file:|ssh://|git@).*)",
    re.IGNORECASE | re.DOTALL,
)
_GIT_SHORTHAND = re.compile(r"[A-Za-z0-9][\w.-]*/[\w.-]+(?:#[\w./-]*)?")  # npm: user/repo
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:[\\/]")


def _pin_state(spec: str, style: str) -> str:
    """Whether a named package spec fixes one exact version, in the manager's own syntax."""
    spec = spec.split(";", 1)[0].strip()  # drop a PEP 508 environment marker
    if style == "pep440":
        clauses = _PEP440_CLAUSE.findall(spec)
        if clauses:
            exact = any(operator in ("==", "===") and _EXACT_VERSION.fullmatch(version)
                        for operator, version in clauses)
            return PINNED if exact else RANGE
        style = "at"  # uvx and pipx also accept name@version
    if style in ("at", "npm", "go"):
        at = spec.rfind("@")
        if at <= 0:  # no version, or only an npm scope such as @scope/name
            return PINNED if style == "go" else UNPINNED  # go: go.mod and go.sum decide
        version = spec[at + 1:]
        exact = _FULL_SEMVER.fullmatch(version) or _COMMIT.fullmatch(version)
        return PINNED if exact else RANGE
    if style == "conda":
        clause = _CONDA_CLAUSE.search(spec)
        if clause is None:
            return UNPINNED
        operator, version = clause.groups()
        exact = operator in ("=", "==") and _EXACT_VERSION.fullmatch(version)
        return PINNED if exact else RANGE
    if style == "gem":
        _, colon, version = spec.partition(":")
        return PINNED if colon and _EXACT_VERSION.fullmatch(version) else UNPINNED
    return UNPINNED  # "flag": only a PIN option fixes the version


def _spec_signals(spec: str, manager: Manager) -> list[str]:
    """Signals for one package spec: where it comes from, then whether it is pinned."""
    target = spec[:MAX_SPEC_CHARS].strip()
    reference = _DIRECT_REFERENCE.search(target)
    if reference and reference.start() > 0:
        target = reference.group(1)
    lowered = target.lower()
    if lowered.startswith(VCS_PREFIXES):
        plaintext = lowered.startswith(PLAINTEXT_VCS_PREFIXES)
        return ["vcs_source", "plaintext_http_source"] if plaintext else ["vcs_source"]
    if lowered.startswith(("http://", "https://")):
        if _is_plaintext(target):
            return ["direct_url_source", "plaintext_http_source"]
        return ["direct_url_source"]
    if target in (".", "./", ".\\") or (target.startswith(".[") and target.endswith("]")):
        return []  # the current project, as in `pip install -e .`
    if lowered.startswith(LOCAL_PREFIXES) or lowered.endswith(ARCHIVE_SUFFIXES) \
            or target == ".." or _WINDOWS_DRIVE.match(target):
        return ["local_archive_or_path"]
    if manager.pin_style == "npm" and _GIT_SHORTHAND.fullmatch(target):
        return ["vcs_source"]
    if not manager.pin_style:
        return []
    return _PIN_SIGNAL[_pin_state(target, manager.pin_style)]


def _match_verb(manager: Manager,
                args: Sequence[str]) -> tuple[str, list[str], list[str]] | None:
    """Find the install verb where the CLI expects it: (mode, words before, words after).

    Global options may come before the verb. Any other word before it must be the value of
    the option just before, so ``npm run install`` and ``pip help install`` do not match.
    """
    paths = sorted(manager.verbs, key=len, reverse=True)
    for start in range(len(args) + 1):
        for path in paths:
            window = tuple(word.lower() for word in args[start:start + len(path)])
            if window == path:
                return manager.verbs[path], list(args[:start]), list(args[start + len(path):])
        if start == len(args):
            break
        follows_option = start > 0 and args[start - 1].startswith("-") \
            and "=" not in args[start - 1]
        if not args[start].startswith(("-", "+")) and not follows_option:
            break
    return None


def _options(manager: Manager, args: Sequence[str]) -> Iterator[tuple[Action | None, str]]:
    """Yield (action, value) for each known option and (None, word) for each positional.

    An option that is not in the manager's table is skipped as a switch. If it actually takes
    a value, that value is read as a positional; this is a declared limit of the tables.
    """
    index, options_open = 0, True
    while index < len(args):
        word = args[index]
        index += 1
        if options_open and word == "--":
            options_open = False
        elif options_open and len(word) > 1 and word.startswith("-"):
            name, equals, value = word.partition("=") if word.startswith("--") \
                else (word, "", "")
            action = manager.flags.get(name.lower() if manager.fold_flags else name)
            if action is None and not word.startswith("--"):
                attached = manager.flags.get(word[:2])  # -ihttps://... and -rreqs.txt
                if attached is not None and attached.takes_value and len(word) > 2:
                    yield attached, word[2:]
            elif action is not None:
                if action.takes_value and not equals:
                    value = args[index] if index < len(args) else ""
                    index += 1
                yield action, value
        else:
            yield None, word


# --- decoding -------------------------------------------------------------------------------

_B64 = "[A-Za-z0-9+/]"
_B64_RUN = re.compile(
    rf"(?<!{_B64})(?:{_B64}{{4}}){{5,}}(?:{_B64}{{4}}|{_B64}{{3}}=|{_B64}{{2}}==)(?![A-Za-z0-9+/=])"
)
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){24,}(?![0-9A-Fa-f])")


def _decode(run: str) -> str | None:
    """Readable text hidden in a Base64 or hex run, or None."""
    for decoder in (bytes.fromhex, lambda value: base64.b64decode(value, validate=True)):
        try:
            data = decoder(run)
        except (ValueError, binascii.Error):
            continue
        if not data or len(data) > MAX_DECODED_CHARS:
            continue
        # PowerShell -EncodedCommand is UTF-16LE: every second byte of ASCII text is zero.
        utf16 = len(data) % 2 == 0 and data[1::2].count(0) == len(data) // 2
        try:
            text = data.decode("utf-16-le" if utf16 else "utf-8")
        except UnicodeError:
            continue
        if len(text) < 8:
            continue
        printable = sum(c.isprintable() or c in "\n\t" for c in text) / len(text)
        wordlike = sum(c.isalpha() or c.isspace() for c in text) / len(text)
        if printable >= 0.9 and wordlike >= 0.5:
            return text
    return None


# --- state shared across events -------------------------------------------------------------


@dataclass(frozen=True)
class Origin:
    """Where a call came from. Written scripts are only matched within the same origin."""

    run_id: str
    session_id: str
    server: str


_lock = Lock()
_seen: OrderedDict[tuple[str, ...], None] = OrderedDict()
_writes: deque[tuple[Origin, str]] = deque()


def reset_state() -> None:
    """Forget reported calls and written-script history (tests, or a new importer run)."""
    with _lock:
        _seen.clear()
        _writes.clear()


def _already_reported(key: tuple[str, ...]) -> bool:
    with _lock:
        if key in _seen:
            _seen.move_to_end(key)
            return True
        _seen[key] = None
        while len(_seen) > MAX_REMEMBERED:
            _seen.popitem(last=False)
        return False


def _remember_scripts(origin: Origin, names: Iterable[str]) -> bool:
    """Record written script names. Returns True when older history had to be dropped."""
    dropped = False
    with _lock:
        for name in names:
            if (origin, name) not in _writes:
                _writes.append((origin, name))
        while len(_writes) > MAX_WRITE_HISTORY:
            _writes.popleft()
            dropped = True
    return dropped


def _written_scripts(origin: Origin) -> frozenset[str]:
    with _lock:
        return frozenset(name for owner, name in _writes if owner == origin)


# --- analysis of command text ---------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    signal: str
    path: str
    sha256: str


@dataclass
class Scan:
    """What one tool call produced: evidence, coverage notes and observed installs."""

    evidence: dict[Evidence, None] = field(default_factory=dict)  # used as an ordered set
    notes: set[str] = field(default_factory=set)
    installs: int = 0
    modes: set[str] = field(default_factory=set)

    @property
    def found(self) -> bool:
        return bool(self.installs or self.evidence)

    def add(self, signal: str, path: str, detail: str = "") -> None:
        # The detail (an option, a package name) is hashed, never stored.
        item = Evidence(signal, safe(path, 220), digest(f"{signal}|{detail[:MAX_SPEC_CHARS]}"))
        if item in self.evidence:
            return
        if len(self.evidence) >= MAX_EVIDENCE:
            self.notes.add("evidence_limit")
            return
        self.evidence[item] = None


_SHELL_COMMAND_FLAG = re.compile(r"-[A-Za-z]*c[A-Za-z]*")  # -c, -lc, -ec
_CURL_INSECURE = re.compile(r"-[A-Za-z]*k[A-Za-z]*")  # -k, -sk, -fsSLk
_FETCH_TLS_OFF = frozenset({"--insecure", "--no-check-certificate", "-skipcertificatecheck"})
_POWERSHELL_VALUE_PARAMETERS = (
    "executionpolicy", "windowstyle", "workingdirectory", "configurationname",
    "custompipename", "settingsfile", "inputformat", "outputformat",
)
_SOURCE_CONFIG_TEXT = re.compile(
    r"registry|index-url|index_url|trusted-host|strict-ssl|channels|\[\[index|^\s*deb\s",
    re.IGNORECASE | re.MULTILINE,
)
# Program text installs a package only if it both names an install and can start a process.
# The gap between the two words is bounded, so the search is linear.
_CODE_INSTALL = re.compile(
    r"\b(?:pip3?|npm|pnpm|yarn|uv|conda|gem|cargo)\b.{0,48}?\binstall\b",
    re.IGNORECASE | re.DOTALL,
)
_CODE_EXEC = re.compile(
    r"os\.system|subprocess|popen|pip\.main|pip\._internal|child_process|execSync|spawn"
    r"|\bsystem\s*\(|\bexec\s*\(|`",
    re.IGNORECASE,
)


def _code_installs(code: str) -> bool:
    code = code[:MAX_TOTAL_CHARS]
    return bool(_CODE_INSTALL.search(code) and _CODE_EXEC.search(code))


def _fetches(script: str) -> bool:
    """True when the script is nothing but ``$(curl ...)`` or the backtick form of it."""
    script = script.strip()
    if script.startswith("$(") and script.endswith(")"):
        return shell.first_program(script[2:-1]) in grammar.FETCHERS
    if len(script) > 1 and script[0] == script[-1] == "`":
        return shell.first_program(script[1:-1]) in grammar.FETCHERS
    return False


def _runs_stdin(program: str, args: Sequence[str]) -> bool:
    """True when the program executes whatever is piped into it."""
    if program in grammar.SHELLS:
        for arg in args:
            if arg in ("-", "-s", "--"):
                return True
            if _SHELL_COMMAND_FLAG.fullmatch(arg) or not arg.startswith("-"):
                return False  # the script comes from -c or a file, not from the pipe
        return True
    if program in grammar.POWERSHELLS:
        return not args or args[-1] == "-"
    if program in grammar.CODE_FLAGS:
        return all(arg == "-" for arg in args)  # `curl ... | python -m json.tool` is fine
    return program in grammar.POWERSHELL_EVAL


def _emits_unseen_content(program: str, args: Sequence[str]) -> bool:
    """True when the program's output is content the gate cannot read: fetched or decoded."""
    decode_flags = grammar.DECODERS.get(program, frozenset())
    return program in grammar.FETCHERS or any(arg in decode_flags for arg in args)


def _fetch_signals(program: str, args: Sequence[str]) -> list[str]:
    signals = []
    for arg in args:
        if arg.lower() in _FETCH_TLS_OFF or (program == "curl" and _CURL_INSECURE.fullmatch(arg)):
            signals.append("tls_verification_disabled")
        elif _is_plaintext(arg):
            signals.append("plaintext_http_source")
    return signals


def _exported(word: str, program: str, args: Sequence[str]) -> dict[str, str]:
    """Assignments made by export, set, setx or PowerShell's ``$env:NAME = value``."""
    if word.lower().startswith("$env:"):
        name, equals, value = word[5:].partition("=")
        if not equals and len(args) >= 2 and args[0] == "=":
            value = args[1]
        return {name: value}
    if program == "setx":
        return {args[0]: args[1]} if len(args) >= 2 else {}
    if program in grammar.ENV_SETTERS:
        return dict(pair for pair in map(shell.assignment, args) if pair)
    return {}


class Analyser:
    """Interprets command text from one argument field and records signals on ``scan``."""

    def __init__(self, scan: Scan, origin: Origin, path: str) -> None:
        self.scan = scan
        self.origin = origin
        self.path = path
        self._written = _written_scripts(origin)

    def text(self, text: str, depth: int = 0) -> None:
        if depth > MAX_NESTING:
            self.scan.notes.add("nesting_limit")
            return
        commands, cut = shell.lex(text)
        if cut:
            self.scan.notes.add("command_limit")
        self.commands(commands, depth)

    def commands(self, commands: Sequence[Command], depth: int = 0) -> None:
        # Stages of the current pipeline whose output has not been consumed by an interpreter.
        # Each stage is looked at once, so a long pipeline costs linear time.
        upstream: list[tuple[str, list[str]]] = []
        for command in commands:
            words, redirect_targets = shell.split_redirections(command.tokens)
            argv, assignments = shell.strip_prefixes(words)
            self.environment(assignments)
            program = shell.program_name(argv[0]) if argv else ""
            args = argv[1:]
            if upstream and _runs_stdin(program, args):
                self._piped_into_interpreter(upstream, depth)
                upstream.clear()
            if argv:
                self._writes_source_config(program, argv, redirect_targets)
                self._command(program, argv, command, depth)
            for _, body in command.substitutions:
                self.text(body, depth + 1)
            if command.operator == "|":
                upstream.append((program, args))
            else:
                upstream.clear()

    def environment(self, assignments: Mapping[str, str]) -> None:
        for name, value in assignments.items():
            action = grammar.ENV_SETTINGS.get(name.upper())
            if action is not None:
                self._signal(_effect_signals(action, value), name)

    def hidden(self, text: str, depth: int) -> bool:
        """Analyse decoded text. Anything found inside it is reported as obfuscated."""
        nested = Analyser(Scan(), self.origin, self.path)
        nested.text(text, depth + 1)
        self.scan.notes |= nested.scan.notes
        if nested.scan.found:
            self.scan.add("obfuscated_install", self.path, "decoded")
        return nested.scan.found

    # -- one command ------------------------------------------------------------------------

    def _command(self, program: str, argv: Sequence[str], command: Command, depth: int) -> None:
        args = argv[1:]
        self._runs_written_script(program, argv)
        self.environment(_exported(argv[0], program, args))
        if program in grammar.MANAGERS:
            self._manager(program, args)
        elif program in grammar.SHELLS:
            self._shell(args, command, depth)
        elif program in grammar.POWERSHELLS:
            self._powershell(args, depth)
        elif program == "cmd":
            self._cmd(args, depth)
        elif program == "eval":
            script = " ".join(args)
            if _fetches(script):
                self.scan.add("fetch_pipe_to_shell", self.path, program)
            self.text(script, depth + 1)
        elif program in ("source", "."):
            self._process_substitution(command)
        elif program in grammar.POWERSHELL_EVAL:
            self._powershell_eval(args, command)
        elif program in grammar.CODE_FLAGS:
            self._interpreter(program, args)
        elif program in grammar.SOURCE_CONFIG_PROGRAMS:
            self.scan.add("persistent_source_config_change", self.path, program)

    def _signal(self, signals: Iterable[str], detail: str) -> None:
        for signal in signals:
            self.scan.add(signal, self.path, detail)

    def _piped_into_interpreter(self, upstream: Sequence[tuple[str, list[str]]],
                                depth: int) -> None:
        for program, args in upstream:
            if _emits_unseen_content(program, args):
                self.scan.add("fetch_pipe_to_shell", self.path, program)
                self._signal(_fetch_signals(program, args), program)
            elif program in grammar.ECHOERS:
                self.text(" ".join(args), depth + 1)  # echo "pip install x" | sh

    def _runs_written_script(self, program: str, argv: Sequence[str]) -> None:
        if not self._written:
            return
        candidates = argv[1:] if program in grammar.SCRIPT_RUNNERS else argv[:1]
        for word in candidates:
            if shell.basename(word) in self._written:
                self.scan.add("write_then_execute_install", self.path, shell.basename(word))
                return

    def _writes_source_config(self, program: str, argv: Sequence[str],
                              redirect_targets: Sequence[str]) -> None:
        targets = [*redirect_targets]
        if program == "tee":
            targets += [arg for arg in argv[1:] if not arg.startswith("-")]
        names = {shell.basename(target) for target in targets} & grammar.SOURCE_CONFIG_FILES
        if names and _SOURCE_CONFIG_TEXT.search(" ".join(argv)):
            self.scan.add("persistent_source_config_change", self.path, min(names))

    # -- shells and interpreters ------------------------------------------------------------

    def _shell(self, args: Sequence[str], command: Command, depth: int) -> None:
        for index, word in enumerate(args):
            if _SHELL_COMMAND_FLAG.fullmatch(word) or word == "<<<":
                script = args[index + 1] if index + 1 < len(args) else ""
                if _fetches(script):
                    self.scan.add("fetch_pipe_to_shell", self.path, "shell")
                self.text(script, depth + 1)
                return
            if not word.startswith("-"):
                break  # a script file; _runs_written_script has looked at it
        self._process_substitution(command)

    def _process_substitution(self, command: Command) -> None:
        for kind, body in command.substitutions:  # bash <(curl ...), source <(curl ...)
            if kind == "proc" and shell.first_program(body) in grammar.FETCHERS:
                self.scan.add("fetch_pipe_to_shell", self.path, "process_substitution")

    def _powershell(self, args: Sequence[str], depth: int) -> None:
        index = 0
        while index < len(args):
            word = args[index]
            is_parameter = word[:1] in ("-", "/") and word[1:].isalpha()
            name = word[1:].lower() if is_parameter else ""
            index += 1
            if not name or "command".startswith(name):
                script = args[index:] if name else args[index - 1:]
                self.text(" ".join(script), depth + 1)
                return
            if name == "ec" or "encodedcommand".startswith(name):
                decoded = _decode(args[index]) if index < len(args) else None
                if decoded is None:
                    self.scan.notes.add("encoded_command_unreadable")
                else:
                    self.hidden(decoded, depth)
                return
            if "file".startswith(name):
                return  # a script file; _runs_written_script has looked at it
            if name in ("ep", "wd") or any(
                    parameter.startswith(name) for parameter in _POWERSHELL_VALUE_PARAMETERS):
                index += 1

    def _powershell_eval(self, args: Sequence[str], command: Command) -> None:
        fetched = any(shell.first_program(body) in grammar.FETCHERS
                      for _, body in command.substitutions)
        for word in args:  # iex (irm URL), iex (New-Object Net.WebClient).DownloadString(URL)
            lowered = word.lower().lstrip("($")
            fetched = fetched or shell.program_name(lowered) in grammar.FETCHERS \
                or "downloadstring" in lowered
        if fetched:
            self.scan.add("fetch_pipe_to_shell", self.path, "iex")

    def _cmd(self, args: Sequence[str], depth: int) -> None:
        for index, word in enumerate(args):
            if word.lower() in ("/c", "/k"):
                self.text(" ".join(args[index + 1:]), depth + 1)
                return

    def _interpreter(self, program: str, args: Sequence[str]) -> None:
        for index, word in enumerate(args):
            value = args[index + 1] if index + 1 < len(args) else ""
            if word in grammar.CODE_FLAGS[program]:
                if _code_installs(value):
                    self.scan.add("install_through_code", self.path, program)
                return
            if word == "-m" and program in ("python", "py"):
                if value.lower() in grammar.MANAGERS:  # python -m pip install ...
                    self._manager(value.lower(), args[index + 2:])
                return
            if not word.startswith("-"):
                return  # a script file; _runs_written_script has looked at it

    # -- package managers -------------------------------------------------------------------

    def _manager(self, name: str, args: Sequence[str]) -> None:
        if name in grammar.CONFIG_MANAGERS and self._config_change(args):
            return
        manager = grammar.MANAGERS[name]
        matched = _match_verb(manager, args)
        if matched is not None:
            self._install(manager, *matched)

    def _config_change(self, args: Sequence[str]) -> bool:
        """``pip config set global.index-url URL`` and the npm, yarn and pnpm forms."""
        words = [arg for arg in args if not arg.startswith("-")]
        lowered = [word.lower() for word in words[:2]]
        if lowered == ["config", "set"]:
            words = words[2:]
        elif lowered[:1] == ["set"]:
            words = words[1:]
        else:
            return False
        key, equals, value = words[0].partition("=") if words else ("", "", "")
        if not equals:
            value = " ".join(words[1:])
        action = grammar.CONFIG_KEYS.get(key.lower().rsplit(".", 1)[-1])
        signals = _effect_signals(action, value) if action else []
        if signals:  # setting the default registry again is not a change worth reporting
            self._signal([*signals, "persistent_source_config_change"], key)
        return True

    def _install(self, manager: Manager, mode: str, before: Sequence[str],
                 after: Sequence[str]) -> None:
        positionals: list[str] = []
        option_specs: list[str] = []
        requirements: list[str] = []
        directives: set[str] = set()
        # Options given before the verb count; positionals there are option values.
        global_options = [item for item in _options(manager, before) if item[0] is not None]
        for action, value in (*global_options, *_options(manager, after)):
            if action is None:
                positionals.append(value)
                if mode != grammar.INSTALL:
                    break  # the rest are the arguments of the program being run
            elif action.effect == "spec":
                option_specs.append(value)
            elif action.effect == "requirements":
                requirements.append(value)
            elif action.effect in ("hashed", "locked", "pin", "yes"):
                directives.add(action.effect)
            else:
                self._signal(_effect_signals(action, value), action.effect)

        runs_package = mode in (grammar.RUN, grammar.RUN_LOCAL)
        if runs_package:
            # With --from or -p the positional is a command name, not a package.
            specs = option_specs or positionals[:1]
        elif mode == grammar.INSTALL:
            specs = option_specs + positionals
        else:
            specs = option_specs
        if mode == grammar.RUN_LOCAL and not (option_specs or "yes" in directives):
            return  # `npx jest` may run a local binary; a download cannot be told from text
        if mode == grammar.WITH_ONLY and not specs:
            return  # `uv run script.py` installs nothing named on the line

        self.scan.installs += 1
        if "hashed" in directives:
            self.scan.modes.add("hashed")
        if mode == grammar.LOCKFILE or "locked" in directives:
            self.scan.modes.add("locked")
        if len(specs) > MAX_PACKAGES:
            self.scan.notes.add("package_limit")
        version_fixed = bool(directives & {"hashed", "pin"})
        for spec in specs[:MAX_PACKAGES]:
            for signal in _spec_signals(spec, manager):
                if SIGNALS[signal][0] == PINNING:
                    if version_fixed:
                        continue
                    if runs_package:
                        signal = "ephemeral_execute_unpinned"
                self.scan.add(signal, self.path, spec)
        if "hashed" not in directives:
            for name in requirements:  # any pins are inside a file the gate cannot read
                self.scan.add("requirements_file_unhashed", self.path, name)


# --- one tool call --------------------------------------------------------------------------

# Whole words in a tool name. Substrings are not used: "publish" is not a shell.
EXEC_WORDS = frozenset({
    "bash", "sh", "zsh", "shell", "terminal", "console", "command", "commands", "cmd",
    "exec", "execute", "run", "powershell", "pwsh", "python", "repl", "subprocess",
})
WRITE_WORDS = frozenset({"write", "save", "append", "edit"})
WRITE_OBJECT_VERBS = frozenset({"create", "put", "update", "upload"})
WRITE_OBJECTS = frozenset({"file", "files", "script"})
EXEC_DESCRIPTION_HINTS = (
    "shell command", "run a command", "execute", "terminal", "command line", "powershell",
    "command prompt",
)
# Argument names that hold command text, file paths and environment variables.
COMMAND_KEYS = frozenset({
    "command", "cmd", "commands", "command_line", "commandline", "script", "code", "argv",
})
CODE_KEYS = frozenset({"code", "script"})
LINE_LIST_KEYS = frozenset({"commands"})  # an array of command lines, not one argv
PATH_KEYS = frozenset({
    "path", "file_path", "filepath", "filename", "file_name", "file", "target", "target_file",
    "destination", "dest",
})
ENV_KEYS = frozenset({"env", "environment"})

_NAME_WORDS = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def _tool_role(name: str, definition: Mapping[str, Any] | None,
               arguments: Mapping[str, Any]) -> str:
    """exec (runs commands), write (writes files) or other (not inspected)."""
    words = {word.lower() for word in _NAME_WORDS.split(name) if word}
    if words & EXEC_WORDS:
        return "exec"
    if words & WRITE_WORDS or (words & WRITE_OBJECT_VERBS and words & WRITE_OBJECTS):
        return "write"
    keys = {str(key).lower() for key in arguments}
    if isinstance(definition, Mapping):
        description = f"{definition.get('description', '')} {definition.get('title', '')}"
        if any(hint in description.casefold() for hint in EXEC_DESCRIPTION_HINTS):
            return "exec"
        # The payload tap writes input_schema; MCP itself calls the field inputSchema.
        schema = definition.get("input_schema", definition.get("inputSchema"))
        properties = schema.get("properties") if isinstance(schema, Mapping) else None
        if isinstance(properties, Mapping):
            keys |= {str(key).lower() for key in properties}
    return "exec" if keys & COMMAND_KEYS else "other"


@dataclass(frozen=True)
class Field:
    """One argument value: its pointer, its top-level argument name and its content."""

    path: str
    key: str
    text: str
    argv: tuple[str, ...] | None = None  # set when the value was a complete array of words


def _collect(arguments: Mapping[str, Any], scan: Scan) -> list[Field]:
    """Flatten the arguments into fields, within the per-call budgets."""
    fields: list[Field] = []
    budget = MAX_TOTAL_CHARS

    def take(text: str) -> str:
        nonlocal budget
        if len(fields) >= MAX_STRINGS:
            scan.notes.add("string_limit")
            return ""
        if len(text) > budget:
            scan.notes.add("character_budget")
            text = text[:budget]
        budget -= len(text)
        return text

    def walk(value: Any, path: str, key: str, depth: int) -> None:
        if isinstance(value, str):
            text = take(value)
            if text:
                fields.append(Field(path, key, text))
        elif isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            lines = key in LINE_LIST_KEYS
            joined = "\n".join(value) if lines else " ".join(value)
            text = take(joined)
            if text:
                whole = not lines and len(text) == len(joined)
                fields.append(Field(path, key, text, tuple(value) if whole else None))
        elif isinstance(value, (Mapping, list)):
            if depth >= MAX_ARGUMENT_DEPTH:
                scan.notes.add("depth_limit")
                return
            items = value.items() if isinstance(value, Mapping) else enumerate(value)
            for name, child in items:
                walk(child, f"{path}.{safe(name, 60)}", key, depth + 1)
        # Numbers, booleans and null carry no command text.

    for name, value in arguments.items():
        walk(value, f"arguments.{safe(name, 60)}", str(name).lower(), 0)
    return fields


def _scan_encoded(text: str, analyser: Analyser) -> None:
    """Look inside Base64 and hex runs, breadth-first, within the decode budgets."""
    queue, seen = deque([text]), {text}
    examined = decoded_chars = 0
    while queue:
        current = queue.popleft()
        for pattern in (_B64_RUN, _HEX_RUN):
            for match in pattern.finditer(current):
                if examined >= MAX_DECODE_CANDIDATES or decoded_chars >= MAX_DECODED_TOTAL:
                    analyser.scan.notes.add("decode_limit")
                    return
                examined += 1
                decoded = _decode(match.group())
                if decoded is None or decoded in seen:
                    continue
                seen.add(decoded)
                decoded_chars += len(decoded)
                if analyser.hidden(decoded, 0):
                    return
                queue.append(decoded)


def _scan_commands(fields: Sequence[Field], scan: Scan, origin: Origin) -> None:
    for item in fields:
        analyser = Analyser(scan, origin, item.path)
        installs_before = scan.installs
        if item.argv is not None:
            analyser.commands([Command(item.argv)])
        else:
            analyser.text(item.text)
        if item.key in CODE_KEYS and scan.installs == installs_before \
                and _code_installs(item.text):
            scan.add("install_through_code", item.path, item.key)
        _scan_encoded(item.text, analyser)


def _scan_write(fields: Sequence[Field], scan: Scan, origin: Origin) -> None:
    """A file write is not an install. Remember the file if its content contains one."""
    names = [shell.basename(item.text) for item in fields if item.key in PATH_KEYS]
    contents = [item for item in fields if item.key not in PATH_KEYS]
    suspicious = False
    for item in contents:
        nested = Analyser(Scan(), origin, item.path)
        nested.text(item.text)
        scan.notes |= nested.scan.notes
        suspicious = suspicious or nested.scan.found or _code_installs(item.text)
    for name in names:
        if name in grammar.SOURCE_CONFIG_FILES and any(
                _SOURCE_CONFIG_TEXT.search(item.text) for item in contents):
            scan.add("persistent_source_config_change", "arguments", name)
    if suspicious and _remember_scripts(origin, [name for name in names if name]):
        scan.notes.add("write_history_limit")


def _scan_call(arguments: Mapping[str, Any], role: str, origin: Origin) -> Scan:
    scan = Scan()
    fields = _collect(arguments, scan)
    if role == "write":
        _scan_write(fields, scan, origin)
        return scan
    for name, value in arguments.items():  # an env argument applies to the command it runs
        if str(name).lower() in ENV_KEYS and isinstance(value, Mapping):
            pairs = {str(key): item for key, item in value.items() if isinstance(item, str)}
            Analyser(scan, origin, f"arguments.{safe(name, 60)}").environment(pairs)
    # When the call names its command field, only that field is command text; a free-text
    # field such as "description" is not. Otherwise every string is inspected.
    command_fields = [item for item in fields if item.key in COMMAND_KEYS]
    _scan_commands(command_fields or [item for item in fields if item.key not in ENV_KEYS],
                   scan, origin)
    return scan


# --- records --------------------------------------------------------------------------------


def _pointer(event: Mapping[str, Any]) -> str:
    record = event.get("record_id")
    if isinstance(record, str) and record:
        return safe(record)
    return safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _record(event: Mapping[str, Any], rule_id: str, family: str, outcome: str, *,
            message: str, tool: str = "", server: str = "", severity: str = "info",
            is_finding: bool = False, **extra: Any) -> dict[str, Any]:
    return {
        "gate_id": GATE_ID, "rule_id": rule_id, "family": family,
        "entity": {"server": safe(server), "tool": safe(tool)},
        "record_id": _pointer(event), "outcome": outcome, "is_finding": is_finding,
        "suppressed": False, "severity": severity, "owasp": list(OWASP),
        "evidence": [], "evidence_count": 0, "coverage_notes": [], "message": message,
        **extra,
    }


def _not_inspected(event: Mapping[str, Any], reasons: Iterable[str], *, tool: str = "",
                   server: str = "", arguments_sha256: str = "") -> dict[str, Any]:
    # is_finding stays True so a report that lists only findings still shows the gap.
    return _record(
        event, RULE_COVERAGE, "coverage", OUTCOME_NOT_INSPECTED, tool=tool, server=server,
        is_finding=True, coverage_notes=sorted(reasons), arguments_sha256=arguments_sha256,
        message="Part of the tool-call input was not inspected, so it cannot be cleared.",
    )


def _findings(scan: Scan, event: Mapping[str, Any], tool: str, server: str,
              arguments_sha256: str) -> list[dict[str, Any]]:
    """One record per rule that has evidence; its severity is its own highest rank."""
    records = []
    for family in (SOURCE, PINNING, SEQUENCE):
        items = sorted(
            (item for item in scan.evidence if SIGNALS[item.signal][0] == family),
            key=lambda item: (_RANK_ORDER[SIGNALS[item.signal][1]], item.signal, item.path,
                              item.sha256),
        )
        if not items:
            continue
        records.append(_record(
            event, RULE_IDS[family], family, OUTCOME_FINDING, tool=tool, server=server,
            severity=SIGNALS[items[0].signal][1], is_finding=True, message=_MESSAGES[family],
            evidence=[{"signal": item.signal, "rank": SIGNALS[item.signal][1],
                       "field": item.path, "sha256": item.sha256}
                      for item in items[:MAX_EVIDENCE_REPORTED]],
            evidence_count=len(items), arguments_sha256=arguments_sha256,
        ))
    return records


def _summary(event: Mapping[str, Any], server: str, role: str, outcome: str,
             records: Sequence[Mapping[str, Any]], scan: Scan | None) -> dict[str, Any]:
    ranks = [record["severity"] for record in records if record["outcome"] == OUTCOME_FINDING]
    return _record(
        event, RULE_SUMMARY, "scan_summary", outcome, server=server, tool_role=role,
        installs_observed=scan.installs if scan else 0,
        highest_severity=min(ranks, key=_RANK_ORDER.__getitem__) if ranks else None,
        coverage_notes=sorted(scan.notes) if scan else [],
        message="Scan summary for this event.",
    )


def startup_capabilities() -> list[dict[str, str]]:
    """What this gate can and cannot check, for a dispatcher to report up front."""
    unsupported = {
        "operator_policy": "No policy input exists yet, so allowlists, denylists, approved "
                           "indexes and typosquat checks are not applied.",
        "startup_command": "The proxy does not record the MCP server's launch command.",
        "response_corroboration": "tools/call responses are not inspected; request intent only.",
        "registry_contact_or_digest": "No network or digest verification; the registry "
                                      "contacted and the versions resolved are unknown.",
        "fetched_or_existing_scripts": "Installs inside a script that is fetched or already "
                                       "on disk are not visible in tool arguments.",
        "shell_indirection": "Variables, aliases and eval of built strings are not expanded; "
                             "commands handed to docker, ssh, xargs or make are not followed.",
        "payload_truncation": "Text removed or shortened by payload masking is not detected.",
    }
    return [
        {"check": "tool_call_install_arguments", "outcome": "SUPPORTED"},
        *({"check": check, "outcome": "UNSUPPORTED", "reason": reason}
          for check, reason in unsupported.items()),
    ]


def evaluate(event: dict[str, Any]) -> dict[str, Any]:
    """Findings for one normalized importer event."""
    if not isinstance(event, Mapping):
        return {"findings": [_not_inspected({}, {"malformed_event"})]}
    if event.get("method") != "tools/call" or event.get("stage") != "request":
        return {"findings": []}  # not an ALR16 input; not a pass either
    server = str(event.get("server") or "")
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        return {"findings": [_not_inspected(event, {"payload_unavailable"}, server=server)]}
    tool, arguments = payload.get("tool"), payload.get("arguments")
    if not isinstance(tool, str) or not isinstance(arguments, Mapping):
        return {"findings": [
            _not_inspected(event, {"call_arguments_unavailable"}, server=server)]}

    definition = payload.get("tool_definition")
    role = _tool_role(tool, definition if isinstance(definition, Mapping) else None, arguments)
    if role == "other":
        return {"findings": [_summary(event, server, role, OUTCOME_OUT_OF_SCOPE, (), None)]}

    origin = Origin(str(event.get("run_id") or ""), str(event.get("session_id") or ""), server)
    arguments_sha256 = digest(
        json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str))
    # The same command means something new once a script has been written, so the write
    # history is part of the duplicate key.
    history = digest("\n".join(sorted(_written_scripts(origin))))
    scan = _scan_call(arguments, role, origin)
    if _already_reported((origin.run_id, origin.session_id, origin.server, tool,
                          arguments_sha256, history)):
        return {"findings": []}

    records = _findings(scan, event, tool, server, arguments_sha256)
    outcome = OUTCOME_FINDING if records else OUTCOME_NO_SIGNAL
    if scan.installs:
        records.append(_record(
            event, RULE_IDS[INTENT], INTENT, OUTCOME_OBSERVED, tool=tool, server=server,
            installs_observed=scan.installs, install_modes=sorted(scan.modes),
            arguments_sha256=arguments_sha256,
            message="A package install was requested through this tool call.",
        ))
        if outcome == OUTCOME_NO_SIGNAL:
            outcome = OUTCOME_OBSERVED
    if scan.notes:
        records.append(_not_inspected(event, scan.notes, tool=tool, server=server,
                                      arguments_sha256=arguments_sha256))
        if outcome != OUTCOME_FINDING:
            outcome = OUTCOME_NOT_INSPECTED
    records.append(_summary(event, server, role, outcome, records, scan))
    return {"findings": records}