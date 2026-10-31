"""Check a ledger against itself, against the trace, and against the last published anchor.

Six outcomes, and the difference between them matters:

- ``intact``     every block chains and the head matches the anchor
- ``unanchored`` the file verifies locally but nothing outside proves it was not rewritten
- ``tampered``   a block's content no longer matches its digest, or two blocks disagree
- ``deleted``    records are missing, or the log is shorter than the anchored head
- ``rewritten``  the chain is consistent but its head is not the digest that was published
- ``missing``    there is no ledger to check

Nothing here writes to the ledger, and nothing here uses the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agent_latch.runtime.ledger.anchor import AnchorError, FileAnchor
from agent_latch.runtime.ledger.chain import (
    GENESIS,
    Block,
    LedgerError,
    block_digest,
    iter_blocks,
    record_hash,
)

STATUS_INTACT = "intact"
STATUS_UNANCHORED = "unanchored"
STATUS_TAMPERED = "tampered"
STATUS_DELETED = "deleted"
STATUS_REWRITTEN = "rewritten"
STATUS_MISSING = "missing"

FAILED_STATUSES = frozenset({STATUS_TAMPERED, STATUS_DELETED, STATUS_REWRITTEN})


@dataclass(frozen=True)
class Issue:
    """One problem found, tied to the block it affects."""

    kind: str
    seq: int
    detail: str


@dataclass(frozen=True)
class Verification:
    status: str
    blocks: int
    head_seq: int
    head_digest: str
    issues: tuple[Issue, ...]
    anchored: bool
    anchor_seq: int | None
    anchor_digest: str | None
    anchor_time: str | None
    ledger: str
    trace_checked: bool

    @property
    def ok(self) -> bool:
        """True when nothing in the log was altered. An unanchored log counts as ok, but weak."""
        return self.status not in FAILED_STATUSES and self.status != STATUS_MISSING

    @property
    def failed(self) -> bool:
        """True when the trail cannot be trusted."""
        return self.status in FAILED_STATUSES

    @property
    def deleted(self) -> bool:
        return any(issue.kind == "deleted" for issue in self.issues)

    @property
    def edited(self) -> bool:
        """A block's content no longer matches what was sealed."""
        return any(issue.kind in {"edited", "malformed"} for issue in self.issues)

    @property
    def reordered(self) -> bool:
        return any(issue.kind == "reordered" for issue in self.issues)

    def headline(self) -> str:
        """One sentence for a report banner."""
        if self.status == STATUS_MISSING:
            return "NO AUDIT TRAIL — nothing to verify."
        if self.status == STATUS_INTACT:
            return (
                f"AUDIT TRAIL INTACT — {self.blocks:,} record(s) verify and match the anchor "
                f"of {self.anchor_time}."
            )
        if self.status == STATUS_UNANCHORED:
            return (
                f"AUDIT TRAIL UNANCHORED — {self.blocks:,} record(s) verify locally, but nothing "
                "outside the machine proves the file was not rebuilt."
            )
        if self.status == STATUS_REWRITTEN:
            return (
                "AUDIT TRAIL REWRITTEN — the chain is consistent, but its head is not the digest "
                f"published at {self.anchor_time}. The whole file was rebuilt."
            )

        if self.status == STATUS_DELETED:
            return "AUDIT TRAIL DELETED — records are missing; the log cannot be trusted."
        if self.edited:
            return "AUDIT TRAIL TAMPERED — a record was altered; the log cannot be trusted."
        if self.reordered:
            return "AUDIT TRAIL TAMPERED — records are out of order; the log cannot be trusted."
        return "AUDIT TRAIL DAMAGED — the log cannot be trusted."


LEDGER_SUFFIX = ".ledger.jsonl"


def trace_for(ledger: Path) -> Path | None:
    """The trace a ledger sits beside: ``x.ledger.jsonl`` seals ``x.jsonl``.

    The path is returned even when the file is gone, so a deleted trace is reported as deleted
    and not skipped. A ledger with any other name has no known trace.
    """
    if not ledger.name.endswith(LEDGER_SUFFIX):
        return None
    return ledger.with_name(ledger.name[: -len(LEDGER_SUFFIX)] + ".jsonl")


def find_ledgers(root: Path, *, recursive: bool) -> list[Path]:
    """Every ``*.ledger.jsonl`` in a folder, or below it. Symlinks are not followed."""
    pattern = "*" + LEDGER_SUFFIX
    found = root.rglob(pattern) if recursive else root.glob(pattern)
    return sorted(path for path in found if path.is_file() and not path.is_symlink())


def _block_digest(block: Block) -> str:
    return block_digest(
        prev=block.prev,
        seq=block.seq,
        timestamp=block.timestamp,
        method=block.method,
        stage=block.stage,
        record_sha256=block.record_sha256,
    )


def _nothing_to_verify(
    ledger: Path,
    detail: str,
    *,
    trace_path: Path | None,
    anchor_path: Path | None,
) -> Verification:
    """A ledger that is gone or empty: ``missing``, unless something proves records existed.

    The proxy creates an empty ledger when it starts, so empty alone is a fresh start. But an
    anchor point, or lines in the trace, mean records were sealed once, and a ledger without them
    was deleted or emptied.
    """
    evidence: Issue | None = None
    anchor_seq: int | None = None
    anchor_digest: str | None = None
    anchor_time: str | None = None
    if anchor_path is not None:
        try:
            point = FileAnchor(Path(anchor_path)).latest()
        except (AnchorError, OSError):
            point = None
        if point is not None:
            anchor_seq, anchor_digest, anchor_time = point.seq, point.digest, point.timestamp
            evidence = Issue(
                "deleted", point.seq, f"{detail}, but #{point.seq} was anchored at {point.timestamp}"
            )
    trace_lines = 0
    if trace_path is not None and Path(trace_path).is_file():
        try:
            text = Path(trace_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            text = ""
        trace_lines = sum(1 for line in text.splitlines() if line.strip())
    if evidence is None and trace_lines:
        evidence = Issue("deleted", 1, f"{detail}, but the trace holds {trace_lines} line(s)")
    if evidence is None:
        return _missing(ledger, detail)
    return Verification(
        status=STATUS_DELETED,
        blocks=0,
        head_seq=0,
        head_digest="",
        issues=(evidence,),
        anchored=anchor_seq is not None,
        anchor_seq=anchor_seq,
        anchor_digest=anchor_digest,
        anchor_time=anchor_time,
        ledger=Path(ledger).name,
        trace_checked=trace_path is not None and Path(trace_path).is_file(),
    )


def _missing(ledger: Path, detail: str) -> Verification:
    return Verification(
        status=STATUS_MISSING,
        blocks=0,
        head_seq=0,
        head_digest="",
        issues=(Issue("missing", 0, detail),),
        anchored=False,
        anchor_seq=None,
        anchor_digest=None,
        anchor_time=None,
        ledger=Path(ledger).name,
        trace_checked=False,
    )


def verify_ledger(
    ledger_path: Path,
    *,
    trace_path: Path | None = None,
    anchor_path: Path | None = None,
) -> Verification:
    """Verify the chain, optionally against the trace file and the last anchor point."""
    ledger_path = Path(ledger_path)
    if not ledger_path.is_file():
        return _nothing_to_verify(
            ledger_path, f"no ledger at {ledger_path}", trace_path=trace_path, anchor_path=anchor_path
        )

    try:
        blocks = list(iter_blocks(ledger_path))
    except (LedgerError, OSError) as error:
        return Verification(
            status=STATUS_TAMPERED,
            blocks=0,
            head_seq=0,
            head_digest="",
            issues=(Issue("malformed", 0, str(error)),),
            anchored=False,
            anchor_seq=None,
            anchor_digest=None,
            anchor_time=None,
            ledger=ledger_path.name,
            trace_checked=False,
        )
    if not blocks:
        return _nothing_to_verify(
            ledger_path,
            f"the ledger at {ledger_path} is empty",
            trace_path=trace_path,
            anchor_path=anchor_path,
        )

    issues: list[Issue] = []
    prev = GENESIS
    expected = 1
    for block in blocks:
        if block.seq != expected:
            first = expected
            last = block.seq - 1
            missing = last - first + 1
            detail = "a record is missing here" if missing == 1 else f"{missing} records are missing here"
            issues.append(Issue("deleted", first, detail))
        if block.prev != prev:
            issues.append(
                Issue("reordered", block.seq, "this block does not follow the block before it")
            )
        if _block_digest(block) != block.digest:
            issues.append(
                Issue("edited", block.seq, "the block's digest does not match its content")
            )
        prev = block.digest
        expected = block.seq + 1

    # The anchor is read first so the trace walk can tell a lost ledger tail from added lines.
    anchor_issues: list[Issue] = []
    point = None
    if anchor_path is not None:
        try:
            point = FileAnchor(Path(anchor_path)).latest()
        except (AnchorError, OSError) as error:
            anchor_issues.append(Issue("malformed", 0, f"the anchor file cannot be read: {error}"))
        if point is None:
            anchor_issues.append(
                Issue("unanchored", 0, f"no anchor point at {anchor_path}")
            )

    trace_checked = trace_path is not None
    if trace_path is not None:
        tail_lost = point is not None and point.seq > blocks[-1].seq
        issues.extend(_trace_issues(Path(trace_path), blocks, tail_lost=tail_lost))

    anchored = False
    anchor_seq: int | None = None
    anchor_digest: str | None = None
    anchor_time: str | None = None
    issues.extend(anchor_issues)
    if point is not None:
        anchored = True
        anchor_seq, anchor_digest, anchor_time = point.seq, point.digest, point.timestamp
        issues.extend(_anchor_issues(point.seq, point.digest, blocks))

    kinds = {issue.kind for issue in issues}
    if kinds & {"edited", "malformed"}:
        status = STATUS_TAMPERED
    elif "deleted" in kinds:
        # A gap also breaks the next link, so a deletion must not be read as an edit.
        status = STATUS_DELETED
    elif "reordered" in kinds:
        status = STATUS_TAMPERED
    elif "rewritten" in kinds:
        status = STATUS_REWRITTEN
    elif not anchored:
        status = STATUS_UNANCHORED
    else:
        status = STATUS_INTACT

    head = blocks[-1]
    return Verification(
        status=status,
        blocks=len(blocks),
        head_seq=head.seq,
        head_digest=head.digest,
        issues=tuple(issues),
        anchored=anchored,
        anchor_seq=anchor_seq,
        anchor_digest=anchor_digest,
        anchor_time=anchor_time,
        ledger=ledger_path.name,
        trace_checked=trace_checked,
    )


def _trace_issues(
    trace_path: Path, blocks: list[Block], *, tail_lost: bool = False
) -> list[Issue]:
    """Walk blocks and trace lines together, so a removed line is named as removed.

    Position alone is not enough: a deleted line shifts every later comparison, which would
    read as an edit on every record after it. When a line does not match its block, it is looked
    up among the later blocks: a match means every block in between lost its line. A line that
    matches no later block is an edit. (Someone could overwrite a line with a copy of a later
    one, which then reads as a deletion; both fail verification.)

    ``tail_lost`` says the anchor is ahead of the ledger, so lines past the last block are
    records whose blocks were cut off, not lines added to the trace.
    """
    if not trace_path.is_file():
        return [Issue("deleted", 1, f"the trace file {trace_path} is gone")]
    try:
        lines = [line for line in trace_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as error:
        return [Issue("malformed", 0, f"the trace file cannot be read: {error}")]

    # A sequence gap already shifts every later position, so only the run before it is comparable.
    expected = 1
    comparable: list[Block] = []
    for block in blocks:
        if block.seq != expected:
            break
        comparable.append(block)
        expected = block.seq + 1

    later: dict[str, list[int]] = {}
    for at, item in enumerate(comparable):
        later.setdefault(item.record_sha256, []).append(at)

    issues: list[Issue] = []
    index = position = 0
    while index < len(comparable) and position < len(lines):
        block = comparable[index]
        digest = record_hash(lines[position])
        if digest == block.record_sha256:
            index += 1
            position += 1
            continue
        ahead = next((at for at in later.get(digest, ()) if at > index), None)
        if ahead is not None:
            for skipped in comparable[index:ahead]:
                issues.append(
                    Issue("deleted", skipped.seq, "the trace line this block sealed is gone")
                )
            index = ahead
            continue
        issues.append(
            Issue("edited", block.seq, "the trace line is not the record this block sealed")
        )
        index += 1
        position += 1

    for block in comparable[index:]:
        issues.append(Issue("deleted", block.seq, "the trace line this block sealed is gone"))
    # After a gap the rest of the trace has no matching block, so its tail proves nothing.
    unsealed = len(lines) - position
    if unsealed > 0 and len(comparable) == len(blocks):
        tail = comparable[-1].seq if comparable else 0
        if tail_lost:
            detail = (
                f"the ledger lost its tail: the trace holds {unsealed} line(s) past #{tail} "
                "that the ledger no longer seals"
            )
        else:
            detail = f"the trace holds {unsealed} line(s) that no block sealed"
        issues.append(Issue("edited", tail, detail))
    return issues


def _anchor_issues(seq: int, digest: str, blocks: list[Block]) -> list[Issue]:
    """Compare the published point with the chain as it stands now."""
    head = blocks[-1]
    if seq > head.seq:
        return [
            Issue(
                "deleted",
                head.seq + 1,
                f"the log ends at #{head.seq}, but #{seq} was anchored",
            )
        ]
    target = next((block for block in blocks if block.seq == seq), None)
    if target is None:
        return [Issue("deleted", seq, f"record #{seq} was anchored and is now missing")]
    if target.digest != digest:
        return [
            Issue(
                "rewritten",
                seq,
                f"record #{seq} now hashes to {target.digest[:12]}…, the anchor says {digest[:12]}…",
            )
        ]
    return []


def describe(verification: Verification, *, limit: int = 5) -> list[str]:
    """Plain lines for a terminal, an issue list, or a log file."""
    lines = [verification.headline()]
    if verification.status == STATUS_MISSING:
        return lines
    shown = verification.issues[:limit]
    for issue in shown:
        where = f"#{issue.seq}" if issue.seq else "log"
        lines.append(f"  {where}: {issue.detail}")
    hidden = len(verification.issues) - len(shown)
    if hidden > 0:
        lines.append(f"  … and {hidden} more problem(s)")
    if verification.status == STATUS_INTACT:
        lines.append(
            f"  head #{verification.head_seq} · anchor #{verification.anchor_seq}"
            f" · {verification.blocks:,} record(s)"
        )
    return lines
