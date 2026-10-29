"""Tamper-evident audit trail for the runtime log (ALR15).

The log stays where it is. Every trace record is sealed into a local hash chain, and one short
digest per batch is published somewhere the agent cannot write. Editing, deleting or rebuilding
the log then shows up when you verify, and `agent-latch --runtime-result --ledger FILE` says so
at the top of the report.

Standard library only, no network, and never in the request path: a failed append is reported on
stderr and the tool call carries on. See docs/ledger.md for the model and docs/ledger-setup.md
for the commands.
"""

from __future__ import annotations

from agent_latch.runtime.ledger.anchor import (
    ANCHOR_SCHEMA,
    Anchor,
    AnchorError,
    AnchorPoint,
    FileAnchor,
    make_anchor,
    point_for,
)
from agent_latch.runtime.ledger.chain import (
    GENESIS,
    LEDGER_SCHEMA,
    Block,
    Ledger,
    LedgerError,
    block_digest,
    iter_blocks,
    record_hash,
    seal,
)
from agent_latch.runtime.ledger.verify import (
    FAILED_STATUSES,
    STATUS_DELETED,
    STATUS_INTACT,
    STATUS_MISSING,
    STATUS_REWRITTEN,
    STATUS_TAMPERED,
    STATUS_UNANCHORED,
    Issue,
    Verification,
    describe,
    verify_ledger,
)

__all__ = [
    "ANCHOR_SCHEMA",
    "FAILED_STATUSES",
    "GENESIS",
    "LEDGER_SCHEMA",
    "STATUS_DELETED",
    "STATUS_INTACT",
    "STATUS_MISSING",
    "STATUS_REWRITTEN",
    "STATUS_TAMPERED",
    "STATUS_UNANCHORED",
    "Anchor",
    "AnchorError",
    "AnchorPoint",
    "Block",
    "FileAnchor",
    "Issue",
    "Ledger",
    "LedgerError",
    "Verification",
    "block_digest",
    "describe",
    "iter_blocks",
    "make_anchor",
    "point_for",
    "record_hash",
    "seal",
    "verify_ledger",
]
