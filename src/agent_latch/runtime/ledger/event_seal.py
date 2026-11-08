"""Seal every stored event, and check a store against its seals and the published anchor.

The trace ledger (``chain.py``) seals trace *lines*. This module seals the *events* an event store
keeps, so a changed, deleted, reordered or rebuilt row is found whatever database holds it. Each
event is hashed (SHA-256 over its canonical JSON plus the time it was imported) and chained to the
event before it. A row carries three plain values, ``seal_seq``, ``seal_prev`` and ``seal_digest``,
so any store that can hold a number and some text can hold a seal. The seal is computed here, in
AgentLatch's own code, never by the database.

It uses the same canonical JSON, genesis value, anchor points and six verdicts as the trace ledger,
under its own domain tag so a store seal can never be mistaken for a ledger block.

Checking never writes to the store, never repairs it, and never uses the network.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agent_latch.runtime.ledger.anchor import AnchorError, AnchorPoint, FileAnchor
from agent_latch.runtime.ledger.canonical import dumps
from agent_latch.runtime.ledger.chain import GENESIS
from agent_latch.runtime.ledger.verify import (
    STATUS_DELETED,
    STATUS_MISSING,
    STATUS_TAMPERED,
    Issue,
    Verification,
    _nothing_to_verify,
    anchor_point_issues,
    status_for,
)

STORE_SEAL = "agentlatch.runtime.store-seal/1"
DOMAIN = STORE_SEAL.encode("ascii") + b"\x00"
# What an anchor point says about the chain it belongs to (a trace ledger point says nothing).
SOURCE = "event-store"

CHANGED_MESSAGE = (
    "the event store changed after it was sealed; keep this file as evidence"
    " and use a new --database file"
)


class StoreIntegrityError(RuntimeError):
    """The store cannot be trusted, or cannot be extended safely. Nothing newer is published."""


class StoreTampered(StoreIntegrityError):
    """The store no longer matches its seals, its schema, its anchor or the trace."""


class StoreRefused(StoreIntegrityError):
    """The store looks fine, but extending it could hide a problem (for example no anchor)."""


@dataclass(frozen=True)
class Seal:
    """One event's place in the chain."""

    seq: int
    prev: str
    digest: str


@dataclass(frozen=True)
class StoredRow:
    """A row read back from a store: its seal (None when missing or unreadable), event and time."""

    seal: Seal | None
    event: dict[str, Any]
    imported_at: str


@runtime_checkable
class SealedSource(Protocol):
    """What a store gives the checker. The SQLite writer and reader both provide it."""

    def sealed_rows(self) -> Iterator[StoredRow]: ...

    def schema_sha256(self) -> str: ...

    def expected_schema_sha256(self) -> str: ...

    def schema_version(self) -> int: ...


def event_sha256(event: Mapping[str, Any], imported_at: str) -> str:
    """SHA-256 of the event's canonical JSON together with the time it was imported."""
    return hashlib.sha256(dumps({"event": event, "imported_at": imported_at})).hexdigest()


def seal_digest(*, prev: str, seq: int, event_sha256: str) -> str:
    """The seal's own digest: the event's hash, its number, and the seal before it."""
    body = {"prev": prev, "seq": seq, "event_sha256": event_sha256}
    return hashlib.sha256(DOMAIN + dumps(body)).hexdigest()


def next_seal(head: Seal | None, event: Mapping[str, Any], imported_at: str) -> Seal:
    """The seal for ``event`` when it follows ``head`` (``None`` starts a new chain)."""
    prev = GENESIS if head is None else head.digest
    seq = 1 if head is None else head.seq + 1
    digest = seal_digest(prev=prev, seq=seq, event_sha256=event_sha256(event, imported_at))
    return Seal(seq=seq, prev=prev, digest=digest)


@dataclass(frozen=True)
class Chain:
    """What walking the stored seals found."""

    issues: tuple[Issue, ...]
    head: Seal | None
    rows: int  # every row, sealed or not
    sealed: int  # rows that carry a readable seal
    digests: dict[int, str]  # the stored digest at each requested seq that exists


def walk_chain(rows: Iterable[StoredRow], *, track_seqs: Iterable[int] = ()) -> Chain:
    """Recompute every seal in order. Collects problems instead of stopping at the first.

    ``track_seqs`` are the numbers whose stored digests are wanted (the anchored ones), so the
    caller can compare them without holding every digest in memory.
    """
    issues: list[Issue] = []
    prev = GENESIS
    expected = 1
    head: Seal | None = None
    wanted = set(track_seqs)
    found: dict[int, str] = {}
    total = sealed = 0
    for row in rows:
        total += 1
        seal = row.seal
        if seal is None:
            issues.append(
                Issue("added", 0, "a row has no valid seal: it was added outside AgentLatch")
            )
            continue
        sealed += 1
        if seal.seq != expected:
            if seal.seq > expected:
                missing = seal.seq - expected
                detail = "a record is missing here" if missing == 1 else (
                    f"{missing} records are missing here"
                )
                issues.append(Issue("deleted", expected, detail))
            else:
                issues.append(Issue("reordered", seal.seq, "this seal number repeats or is out of order"))
        if seal.prev != prev:
            issues.append(
                Issue("reordered", seal.seq, "this row does not follow the row before it")
            )
        recomputed = seal_digest(
            prev=seal.prev, seq=seal.seq, event_sha256=event_sha256(row.event, row.imported_at)
        )
        if recomputed != seal.digest:
            issues.append(Issue("edited", seal.seq, "the row no longer matches its seal"))
        prev = seal.digest
        expected = seal.seq + 1
        head = seal
        if seal.seq in wanted:
            found[seal.seq] = seal.digest
    return Chain(
        issues=tuple(issues), head=head, rows=total, sealed=sealed, digests=found
    )


def anchor_history_issues(points: Sequence[AnchorPoint], chain: Chain) -> list[Issue]:
    """Every point ever published must still hold, not only the newest.

    The anchor file is append-only history the agent cannot edit. If a chain was rewritten and
    resealed and a later point was then published over the rewrite, the newest point alone would
    match the forgery, but every older point at or after the first changed row would not.
    """
    head_seq = chain.head.seq if chain.head else 0
    issues: list[Issue] = []
    for point in points:
        issues += anchor_point_issues(
            point.seq, point.digest, head_seq=head_seq, digest_at_seq=chain.digests.get(point.seq)
        )
    return issues


def schema_issues(source: SealedSource, point: AnchorPoint | None = None) -> list[Issue]:
    """Compare the table layout, view and triggers with what AgentLatch creates.

    This catches what the seal cannot: an added column that hides data, an edited ``event_log``
    view, a dropped trigger. When the anchor recorded a layout for this same schema version, the
    stored layout must match it too.
    """
    actual = source.schema_sha256()
    if actual != source.expected_schema_sha256():
        return [
            Issue(
                "schema",
                0,
                "the table layout, view or triggers differ from what AgentLatch creates"
                " (a column, view or trigger was added, changed or dropped)",
            )
        ]
    if (
        point is not None
        and point.schema_sha256 is not None
        and point.schema_version == source.schema_version()
        and point.schema_sha256 != actual
    ):
        return [Issue("schema", 0, "the table layout differs from the layout that was anchored")]
    return []


def downgrade_issues(stored_version: int | None, point: AnchorPoint | None) -> list[Issue]:
    """A file that reports an older schema version than its anchor recorded was tampered with.

    ``PRAGMA user_version`` is just a number in the file. Lowering it would make a sealed store
    look like an old unsealed one (which the reader refuses and the writer would re-seal), so a
    point that recorded a higher version is the evidence that it was lowered.
    """
    if (
        stored_version is None
        or point is None
        or point.source != SOURCE
        or point.schema_version is None
        or stored_version >= point.schema_version
    ):
        return []
    return [
        Issue(
            "schema",
            0,
            f"the store reports schema version {stored_version}, but the anchor recorded"
            f" version {point.schema_version}: the version was lowered",
        )
    ]


def downgrade_verdict(name: str, point: AnchorPoint, issues: list[Issue]) -> Verification:
    """The ``tampered`` verdict for a store whose schema version was lowered below its anchor's."""
    return Verification(
        status=STATUS_TAMPERED,
        blocks=0,
        head_seq=0,
        head_digest="",
        issues=tuple(issues),
        anchored=True,
        anchor_seq=point.seq,
        anchor_digest=point.digest,
        anchor_time=point.timestamp,
        ledger=Path(name).name,
        trace_checked=False,
    )


def verify_store(
    source: SealedSource, *, name: str, anchor_path: Path | None = None
) -> Verification:
    """Verify a store: every seal, its schema, and (optionally) every published anchor point."""
    point: AnchorPoint | None = None
    points: list[AnchorPoint] = []
    anchor_issues: list[Issue] = []
    if anchor_path is not None:
        try:
            points = FileAnchor(Path(anchor_path)).points()
        except (AnchorError, OSError) as error:
            anchor_issues.append(Issue("malformed", 0, f"the anchor file cannot be read: {error}"))
        point = points[-1] if points else None
        if point is None:
            anchor_issues.append(Issue("unanchored", 0, f"no anchor point at {anchor_path}"))
        elif any(each.source != SOURCE for each in points):
            anchor_issues.append(
                Issue("malformed", 0, "the anchor point belongs to a trace ledger, not a store")
            )
            point, points = None, []

    chain = walk_chain(source.sealed_rows(), track_seqs=[each.seq for each in points])
    layout = schema_issues(source, point)

    if chain.rows == 0:
        # Nothing stored: an anchor point proves rows existed once, and then they were removed.
        result = _nothing_to_verify(
            Path(name),
            f"the event store {name} holds no rows",
            trace_path=None,
            anchor_path=anchor_path,
        )
        if layout:
            status = STATUS_DELETED if result.status == STATUS_DELETED else STATUS_TAMPERED
            result = replace(result, status=status, issues=(*result.issues, *layout))
        return result

    issues = [*chain.issues, *layout]
    head_seq = chain.head.seq if chain.head else 0
    if point is not None:
        issues += anchor_history_issues(points, chain)
        if head_seq > point.seq:
            issues.append(
                Issue(
                    "unanchored",
                    point.seq + 1,
                    f"{head_seq - point.seq} row(s) after the newest anchor (#{point.seq})"
                    " are not covered by it yet",
                )
            )
    issues += anchor_issues
    status = status_for({issue.kind for issue in issues}, anchored=point is not None)
    return Verification(
        status=status,
        blocks=chain.sealed,
        head_seq=head_seq,
        head_digest=chain.head.digest if chain.head else "",
        issues=tuple(issues),
        anchored=point is not None,
        anchor_seq=point.seq if point else None,
        anchor_digest=point.digest if point else None,
        anchor_time=point.timestamp if point else None,
        ledger=Path(name).name,
        trace_checked=False,
    )


def changed_message(issues: Iterable[Issue], *, limit: int = 3) -> str:
    """The one-line refusal for a store that fails its check, naming the first problems."""
    found = list(issues)
    parts = [
        f"#{issue.seq}: {issue.detail}" if issue.seq else issue.detail for issue in found[:limit]
    ]
    if len(found) > limit:
        parts.append(f"and {len(found) - limit} more")
    return f"{CHANGED_MESSAGE} ({'; '.join(parts)})" if parts else CHANGED_MESSAGE


def is_sqlite_file(path: Path) -> bool:
    """True when the file starts with the SQLite header, so it is never read as a ledger."""
    try:
        with Path(path).open("rb") as stream:
            return stream.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


__all__ = [
    "CHANGED_MESSAGE",
    "SOURCE",
    "STATUS_MISSING",
    "Chain",
    "Seal",
    "SealedSource",
    "StoreIntegrityError",
    "StoreRefused",
    "StoreTampered",
    "StoredRow",
    "anchor_history_issues",
    "changed_message",
    "downgrade_issues",
    "downgrade_verdict",
    "event_sha256",
    "is_sqlite_file",
    "next_seal",
    "schema_issues",
    "seal_digest",
    "verify_store",
    "walk_chain",
]
