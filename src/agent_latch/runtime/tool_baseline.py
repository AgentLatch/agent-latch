"""Tool-surface fingerprints and the operator-approved baseline behind ALR02.

Everything here is standard library only and never touches the network.

Fingerprint
    One tool definition is reduced to the fields a provider advertises and keeps stable: the
    server label, the tool reference (name), title, description, input and output schema,
    annotations and ``_meta``. They are written as canonical JSON (sorted keys, no whitespace, see
    ``ledger.canonical``) and hashed with SHA-256. Key order in the source therefore never changes
    a fingerprint, while any change to a value does. Fields a server does not advertise are left
    out, so ``null`` and a missing key are the same thing.

Baseline
    A baseline is a JSON file the operator approved, keyed by the server label and the tool
    reference. Its status must be ``approved``. A capture from live traffic is written with status
    ``candidate``, which ``load_baseline`` refuses, so nothing observed on the wire can become
    trusted by itself. ``approve_candidate`` is the one explicit step that turns a candidate into a
    baseline, and it refuses a destination inside the folders the monitored process can write.

A baseline holds names and hashes only, never definition text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from agent_latch.runtime.events import utc_now
from agent_latch.runtime.ledger.canonical import dumps

BASELINE_SCHEMA = "agentlatch.alr02.baseline/1"
STATUS_APPROVED = "approved"
STATUS_CANDIDATE = "candidate"

MAX_TOOLS = 512
MAX_BASELINE_BYTES = 4 * 1024 * 1024
MAX_NAME_CHARS = 200

# Source key (payload or MCP wire name) -> canonical field. First match wins per field.
_FIELD_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("title", ("title",)),
    ("description", ("description",)),
    ("input_schema", ("input_schema", "inputSchema")),
    ("output_schema", ("output_schema", "outputSchema")),
    ("annotations", ("annotations",)),
    ("meta", ("meta", "_meta")),
)
# The payload file cuts long strings and appends this marker.
_TRUNCATION = re.compile(r"…\[\d+ more chars\]$")


class BaselineError(ValueError):
    """The baseline could not be used. ``code`` is a short reason for coverage records."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Snapshot:
    """The fingerprints of one ``tools/list`` response, plus what could not be read."""

    server: str
    tools: dict[str, str]
    malformed: int = 0
    duplicates: tuple[str, ...] = ()
    truncated: bool = False
    too_large: bool = False
    next_cursor: bool = False

    @property
    def problems(self) -> list[str]:
        """Reasons the snapshot cannot be compared; empty means it is complete and readable."""
        found = []
        if self.next_cursor:
            found.append("snapshot_incomplete_pagination")
        if self.truncated:
            found.append("snapshot_truncated")
        if self.too_large:
            found.append("snapshot_too_large")
        if self.malformed:
            found.append("malformed_definition")
        if self.duplicates:
            found.append("ambiguous_tool_reference")
        return found

    @property
    def digest(self) -> str:
        return snapshot_digest(self.server, self.tools)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_definition(server: str, name: str, definition: Mapping[str, Any]) -> dict[str, Any]:
    """The stable fields of one definition, under canonical names. Absent and null are dropped."""
    out: dict[str, Any] = {"server": server, "name": name}
    for canonical, aliases in _FIELD_ALIASES:
        for alias in aliases:
            value = definition.get(alias)
            if value is not None:
                out[canonical] = value
                break
    return out


def tool_fingerprint(server: str, name: str, definition: Mapping[str, Any]) -> str:
    return sha256(dumps(canonical_definition(server, name, definition)))


def snapshot_digest(server: str, tools: Mapping[str, str]) -> str:
    return sha256(dumps({"server": server, "tools": dict(sorted(tools.items()))}))


def _has_truncation(value: Any, budget: list[int]) -> bool:
    """True when a string ends with the payload file's cut marker. Bounded walk."""
    budget[0] -= 1
    if budget[0] < 0:
        return True  # too big to read in full: treat as not fully read
    if isinstance(value, str):
        return bool(_TRUNCATION.search(value))
    if isinstance(value, Mapping):
        return any(_has_truncation(item, budget) for item in value.values())
    if isinstance(value, list):
        return any(_has_truncation(item, budget) for item in value)
    return False


def _shape_ok(tool: Mapping[str, Any]) -> bool:
    """Advertised fields have the types MCP gives them; null and absent are the same."""
    for canonical, aliases in _FIELD_ALIASES:
        expected = str if canonical in ("title", "description") else Mapping
        for alias in aliases:
            value = tool.get(alias)
            if value is not None and not isinstance(value, expected):
                return False
    return True


def snapshot_from_tools(server: str, tools: Sequence[Any], *, next_cursor: bool = False) -> Snapshot:
    """Fingerprint a ``tools/list`` payload. Nothing is raised: problems are recorded.

    A definition that is malformed, cannot be encoded, or was cut or is too big to read in full is
    left out and recorded, never fingerprinted: its hash would not describe what the server sent.
    """
    fingerprints: dict[str, str] = {}
    seen: set[str] = set()
    duplicates: list[str] = []
    malformed = 0
    truncated = False
    for tool in tools[:MAX_TOOLS]:
        name = tool.get("name") if isinstance(tool, Mapping) else None
        if (not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME_CHARS
                or not _shape_ok(tool)):
            malformed += 1
            continue
        if name in seen:
            duplicates.append(name)
            continue
        seen.add(name)
        try:
            if _has_truncation(tool, [200_000]):
                truncated = True
                continue
            fingerprints[name] = tool_fingerprint(server, name, tool)
        except RecursionError:
            truncated = True
        except (UnicodeEncodeError, ValueError, TypeError):
            malformed += 1
    return Snapshot(
        server, fingerprints, malformed, tuple(duplicates), truncated,
        too_large=len(tools) > MAX_TOOLS, next_cursor=next_cursor,
    )


# --- baseline documents --------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerBaseline:
    tools: dict[str, str]
    digest: str


@dataclass(frozen=True)
class Baseline:
    path: Path
    servers: dict[str, ServerBaseline] = field(default_factory=dict)


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _parse_servers(document: Mapping[str, Any]) -> dict[str, ServerBaseline]:
    servers = document.get("servers")
    if not isinstance(servers, Mapping):
        raise BaselineError("baseline_invalid", "baseline has no 'servers' mapping")
    parsed: dict[str, ServerBaseline] = {}
    for label, entry in servers.items():
        tools = entry.get("tools") if isinstance(entry, Mapping) else None
        if not isinstance(label, str) or not label or not isinstance(tools, Mapping):
            raise BaselineError("baseline_invalid", "a server entry is malformed")
        if not all(isinstance(n, str) and n and _is_sha(h) for n, h in tools.items()):
            raise BaselineError("baseline_invalid", f"a tool entry for {label!r} is malformed")
        try:
            digest = snapshot_digest(label, tools)
        except UnicodeEncodeError as error:
            raise BaselineError("baseline_invalid", "a name cannot be encoded") from error
        if entry.get("snapshot_sha256") != digest:
            raise BaselineError("baseline_invalid", f"snapshot hash of {label!r} does not match")
        parsed[label] = ServerBaseline(dict(tools), digest)
    return parsed


Stamp = tuple[int, int, int, int, int]


def file_stamp(info: os.stat_result) -> Stamp:
    """Identity of one file instance: replacing it changes the stamp even if size and mtime match."""
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)


def read_document(path: Path, *, stream: BinaryIO | None = None) -> dict[str, Any]:
    return read_document_stamped(path, stream=stream)[0]


def read_document_stamped(path: Path, *, stream: BinaryIO | None = None) -> tuple[dict[str, Any], Stamp]:
    """The parsed document and the stamp of the very file those bytes came from."""
    try:
        if stream is None:
            with path.open("rb") as opened:
                stamp = file_stamp(os.fstat(opened.fileno()))
                raw = opened.read(MAX_BASELINE_BYTES + 1)
        else:
            stamp = file_stamp(os.fstat(stream.fileno()))
            raw = stream.read(MAX_BASELINE_BYTES + 1)
    except OSError as error:
        raise BaselineError("baseline_unreadable", f"cannot read {path.name}") from error
    if len(raw) > MAX_BASELINE_BYTES:
        raise BaselineError("baseline_invalid", f"{path.name} is too large")
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise BaselineError("baseline_invalid", f"{path.name} is not valid JSON") from error
    if not isinstance(document, dict) or document.get("schema") != BASELINE_SCHEMA:
        raise BaselineError("baseline_invalid", f"{path.name} is not an ALR02 baseline")
    return document, stamp


def load_baseline(path: Path, *, stream: BinaryIO | None = None) -> Baseline:
    """Read an approved baseline. A candidate, or any other status, is refused."""
    return load_baseline_stamped(path, stream=stream)[0]


def load_baseline_stamped(path: Path, *, stream: BinaryIO | None = None) -> tuple[Baseline, Stamp]:
    document, stamp = read_document_stamped(path, stream=stream)
    if document.get("status") != STATUS_APPROVED:
        raise BaselineError(
            "baseline_not_approved",
            f"{path.name} has status {str(document.get('status'))[:20]!r}, not 'approved'",
        )
    return Baseline(path, _parse_servers(document)), stamp


# --- where a baseline may live -------------------------------------------------------------------


def _inside(path: Path, folder: Path) -> bool:
    return path == folder or folder in path.parents


def location_problem(
    baseline: Path, protected: Iterable[Path | None], *, extra_roots: Iterable[str] = (),
    protected_directories: Iterable[Path] = (),
) -> str | None:
    """Why ``baseline`` may not be trusted, or None. ``protected`` are folders (or files whose
    folder counts) that the monitored process writes: logs, payloads, stores, outputs.
    """
    target = baseline.resolve()
    for item in protected:
        if item is None:
            continue
        folder = item.resolve()
        if folder.is_file() or (not folder.exists() and folder.suffix):
            folder = folder.parent
        if _inside(target, folder):
            return f"{baseline} is inside {folder}, which the monitored process can write"
    for folder in protected_directories:
        if _inside(target, folder.resolve()):
            return f"{baseline} is inside {folder}, which the monitored process can write"
    for root in extra_roots:
        if root and _inside(target, Path(root).resolve()):
            return f"{baseline} is inside the monitored project {root}"
    return None


# --- candidate and approval ----------------------------------------------------------------------


def _document(status: str, servers: Mapping[str, Mapping[str, str]], **stamp: str) -> dict[str, Any]:
    return {
        "schema": BASELINE_SCHEMA,
        "status": status,
        **stamp,
        "servers": {
            label: {
                "tool_count": len(tools),
                "snapshot_sha256": snapshot_digest(label, tools),
                "tools": dict(sorted(tools.items())),
            }
            for label, tools in sorted(servers.items())
        },
    }


def capture_candidate(payloads: Path, *, server: str | None = None) -> dict[str, Any]:
    """Candidate document from the last ``tools/list`` of each server in a payloads file.

    Raises ``BaselineError`` when a server's newest list is not complete and readable: a baseline
    built from a partial list would report the missing tools as removed for good.
    """
    latest: dict[str, Snapshot] = {}
    try:
        stream = payloads.open(encoding="utf-8")
    except OSError as error:
        raise BaselineError("payloads_unreadable", f"cannot read {payloads.name}") from error
    with stream:
        for line in stream:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not (isinstance(record, dict) and record.get("method") == "tools/list"
                    and record.get("stage") == "response"):
                continue
            label, body = record.get("server"), record.get("payload")
            if not isinstance(label, str) or not label.strip():
                continue
            if server is not None and label != server:
                continue
            tools = body.get("tools") if isinstance(body, dict) else None
            if not isinstance(tools, list):
                # The newest response is unreadable: it replaces an older good one, so the
                # candidate is refused instead of describing a list the server no longer sends.
                latest[label] = Snapshot(label, {}, malformed=1)
                continue
            cursor = bool(body.get("next_cursor") or body.get("nextCursor"))
            latest[label] = snapshot_from_tools(label, tools, next_cursor=cursor)
    if not latest:
        raise BaselineError("no_snapshot", "no tools/list response found for the server")
    for label, snap in latest.items():
        if snap.problems:
            raise BaselineError(
                "snapshot_incomplete", f"newest tool list of {label!r}: {', '.join(snap.problems)}"
            )
    return _document(
        STATUS_CANDIDATE, {label: snap.tools for label, snap in latest.items()},
        captured_at=utc_now(),
    )


def write_private(path: Path, document: Mapping[str, Any], *, replace: bool = False) -> None:
    """Write JSON atomically with mode 0600; refuses an existing file unless ``replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not replace:
        raise BaselineError("exists", f"{path} already exists; use --force to replace it")
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".alr02-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temp, 0o600)
        if replace:
            os.replace(temp, path)
        else:
            _publish_new(Path(temp), path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def _publish_new(temp: Path, path: Path) -> None:
    """Put ``temp`` at ``path`` only if nothing is there, atomically, so two approvals cannot
    overwrite each other."""
    try:
        os.link(temp, path)
    except FileExistsError as error:
        raise BaselineError("exists", f"{path} already exists; use --force to replace it") from error
    except OSError:
        # No hard links here: create exclusively and copy.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise BaselineError(
                "exists", f"{path} already exists; use --force to replace it"
            ) from error
        with os.fdopen(fd, "wb") as out:
            out.write(temp.read_bytes())
    finally:
        temp.unlink(missing_ok=True)


def check_candidate(document: Mapping[str, Any]) -> dict[str, ServerBaseline]:
    """The servers of a candidate document, or ``BaselineError`` if it is not a valid candidate."""
    if document.get("status") != STATUS_CANDIDATE:
        raise BaselineError("not_a_candidate", "this file is not a candidate")
    return _parse_servers(document)


def approve_candidate(
    candidate: Path, destination: Path, protected: Iterable[Path | None] = (), *,
    replace: bool = False,
) -> dict[str, Any]:
    """Turn a reviewed candidate file into an approved baseline at ``destination``."""
    return approve_document(
        read_document(candidate), candidate.parent, destination, protected, replace=replace
    )


def approve_document(
    document: Mapping[str, Any], candidate_dir: Path, destination: Path,
    protected: Iterable[Path | None] = (), *, replace: bool = False,
) -> dict[str, Any]:
    """Approve one candidate document, the same in-memory one the operator was shown.

    The destination must be outside ``protected`` and the candidate's own folder. Returns the
    approved document.
    """
    servers = check_candidate(document)
    problem = location_problem(destination, [candidate_dir, *protected])
    if problem:
        raise BaselineError("unsafe_location", problem)
    approved = _document(
        STATUS_APPROVED, {label: entry.tools for label, entry in servers.items()},
        approved_at=utc_now(),
    )
    write_private(destination, approved, replace=replace)
    return approved
