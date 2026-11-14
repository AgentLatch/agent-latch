"""Check an event store once, for ``verify --database`` and the runtime report (ALR15).

``check_store`` opens the SQLite store read-only and returns one of three outcomes, so every
command reads the store the same way:

- a ``Verification`` with one of the six verdicts (``ALR15-R01``),
- ``unsealed``: the file is an older database whose rows carry no seals, so nothing in it can be
  checked (``ALR15-R02``),
- ``error``: the file cannot be read as an AgentLatch store at all.

``unsealed_finding`` is the ``ALR15-R02`` finding in the gate-results envelope, written by
``import-logs`` for a store that does not seal and shown by ``agent-latch --runtime-result``.
Standard library only; nothing here writes to the store.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_latch.runtime.ledger import make_anchor
from agent_latch.runtime.ledger.anchor import AnchorError
from agent_latch.runtime.ledger.event_seal import (
    downgrade_issues,
    downgrade_verdict,
    verify_store,
)
from agent_latch.runtime.ledger.verify import Verification, _nothing_to_verify
from agent_latch.runtime.sqlite_store import (
    MIGRATIONS,
    SQLiteEventReader,
    stored_schema_version,
)

UNSEALED_RULE_ID = "ALR15-R02"
UNSEALED_GATE_ID = "ALR15"
UNSEALED_TITLE = "Event store is not tamper-evident"
# The ``order`` of the gate-results row for a store-level finding: it is about no single event.
STORE_ORDER = "store"


@dataclass(frozen=True)
class StoreCheck:
    """What one look at an event store found. Exactly one field is set."""

    verification: Verification | None = None
    unsealed: str | None = None
    error: str | None = None


def unsealed_finding(
    store: str, reason: str, fix: str = "Use a store that seals its rows."
) -> dict[str, Any]:
    """The ``ALR15-R02`` finding for a store whose rows carry no seals."""
    return {
        "rule_id": UNSEALED_RULE_ID,
        "title": UNSEALED_TITLE,
        "severity": "high",
        "is_finding": True,
        "message": (
            f"{reason}. Its rows can be changed or deleted without a trace, so this record of what"
            f" the agent did cannot be checked. {fix}"
        ),
        "owasp": ["ASI10"],
        "location": store,
        "evidence": [{"signal": "unsealed event store", "field": store}],
    }


def unsealed_result(store: str, reason: str) -> dict[str, Any]:
    """``unsealed_finding`` wrapped in the gate-results envelope ``import-logs`` writes."""
    return {
        "gate_id": UNSEALED_GATE_ID,
        "status": "ok",
        "findings": [unsealed_finding(store, reason)],
        "error": None,
    }


def check_store(database: Path, anchor_path: Path | None = None) -> StoreCheck:
    """Verify the store at ``database`` (and its anchor, when given) without changing it."""
    if not database.is_file():
        return StoreCheck(verification=_nothing_to_verify(
            database, f"no event store at {database}", trace_path=None, anchor_path=anchor_path
        ))
    if anchor_path is not None:
        # A file whose schema version was lowered below its anchor's is tampering, not an old file.
        try:
            point = make_anchor(anchor_path).latest()
        except (AnchorError, OSError):
            point = None
        issues = downgrade_issues(stored_schema_version(database), point)
        if issues and point is not None:
            return StoreCheck(verification=downgrade_verdict(database.name, point, issues))
    reader = SQLiteEventReader(database)
    try:
        reader.open()
    except (ValueError, OSError) as error:
        version = stored_schema_version(database)
        if version is not None and 1 <= version < len(MIGRATIONS):  # an older AgentLatch store
            return StoreCheck(unsealed=str(error))
        return StoreCheck(error=str(error))
    try:
        return StoreCheck(
            verification=verify_store(reader, name=database.name, anchor_path=anchor_path)
        )
    finally:
        reader.close()
