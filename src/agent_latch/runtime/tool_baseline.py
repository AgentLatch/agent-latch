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
from typing import Any

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


def snapshot_from_tools(server: str, tools: Sequence[Any], *, next_cursor: bool = False) -> Snapshot:
    """Fingerprint a ``tools/list`` payload. Nothing is raised: problems are recorded."""
    fingerprints: dict[str, str] = {}
    duplicates: list[str] = []
    malformed = 0
    truncated = False
    for tool in tools[:MAX_TOOLS]:
        name = tool.get("name") if isinstance(tool, Mapping) else None
        if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME_CHARS:
            malformed += 1
            continue
        if name in fingerprints:
            duplicates.append(name)
            continue
        if _has_truncation(tool, [200_000]):
            truncated = True
        fingerprints[name] = tool_fingerprint(server, name, tool)
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
        digest = snapshot_digest(label, tools)
        if entry.get("snapshot_sha256") != digest:
            raise BaselineError("baseline_invalid", f"snapshot hash of {label!r} does not match")
        parsed[label] = ServerBaseline(dict(tools), digest)
    return parsed


def read_document(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
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
    return document


def load_baseline(path: Path) -> Baseline:
    """Read an approved baseline. A candidate, or any other status, is refused."""
    document = read_document(path)
    if document.get("status") != STATUS_APPROVED:
        raise BaselineError(
            "baseline_not_approved",
            f"{path.name} has status {str(document.get('status'))[:20]!r}, not 'approved'",
        )
    return Baseline(path, _parse_servers(document))


# --- where a baseline may live -------------------------------------------------------------------


def _inside(path: Path, folder: Path) -> bool:
    return path == folder or folder in path.parents


def location_problem(
    baseline: Path, protected: Iterable[Path | None], *, extra_roots: Iterable[str] = ()
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
            if not isinstance(label, str) or not label.strip() or not isinstance(body, dict):
                continue
            if server is not None and label != server:
                continue
            tools = body.get("tools")
            if not isinstance(tools, list):
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
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def approve_candidate(
    candidate: Path, destination: Path, protected: Iterable[Path | None] = (), *,
    replace: bool = False,
) -> dict[str, Any]:
    """Turn a reviewed candidate into an approved baseline at ``destination``.

    The destination must be outside ``protected`` and the candidate's own folder. Returns the
    approved document.
    """
    document = read_document(candidate)
    if document.get("status") != STATUS_CANDIDATE:
        raise BaselineError("not_a_candidate", f"{candidate.name} is not a candidate")
    servers = _parse_servers(document)
    problem = location_problem(destination, [candidate.parent, *protected])
    if problem:
        raise BaselineError("unsafe_location", problem)
    approved = _document(
        STATUS_APPROVED, {label: entry.tools for label, entry in servers.items()},
        approved_at=utc_now(),
    )
    write_private(destination, approved, replace=replace)
    return approved
