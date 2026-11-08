"""Shared contract tests for any event store that seals its rows.

A new store (another database, a warehouse, plain files) proves it is append-only and tamper
evident by passing ``assert_store_is_append_only``. It needs only two things from the store's
test module: a way to make a fresh empty store, and a way to change that store's rows behind its
back. Nothing here mentions SQL.

    def make_store() -> SealedWriter:                  # a new, unopened store in a new place
    def tamper(store: SealedWriter, how: str) -> None:  # "edit", "delete" or "swap" two rows

The store must implement the writer contract (``open``, ``save``, ``close``, ``events``,
``head``, ``as_stored``) and ``event_seal.SealedSource`` (``sealed_rows`` and the schema methods).
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from agent_latch.runtime.ledger.event_seal import SOURCE, SealedSource, verify_store
from agent_latch.runtime.ledger.verify import (
    STATUS_DELETED,
    STATUS_TAMPERED,
    STATUS_UNANCHORED,
)


def sample_events(count: int = 5, *, run_id: str = "run-contract") -> list[dict[str, Any]]:
    """Normalized events, shaped like the importer's."""
    return [
        {
            "run_id": run_id,
            "order": order,
            "timestamp": f"2026-01-01T00:00:{order:02d}Z",
            "session_id": "s",
            "request_id": str(order),
            "client_id": "client",
            "server": "demo",
            "method": "tools/call",
            "stage": "request",
            "name": f"tool_{order}",
            "trace": {"path": "trace.jsonl", "line": order},
            "payloads": None,
            "metadata": {"is_error": False, "duration_ms": order},
            "payload": None,
        }
        for order in range(1, count + 1)
    ]


def assert_store_is_append_only(
    make_store: Callable[[], Any], tamper: Callable[[Any, str], None]
) -> None:
    events = sample_events()

    # 1. A key saved again keeps the first write, whatever the new content is.
    store = make_store()
    store.open()
    try:
        assert store.save(events) == len(events)
        assert store.save(events) == 0
        changed = copy.deepcopy(events)
        for event in changed:
            event["name"] = "changed"
            event["metadata"] = {"is_error": True}
        assert store.save(changed) == 0
        assert [event["name"] for event in store.events()] == [e["name"] for e in events]
        assert store.head() is not None and store.head().seq == len(events)

        # 2. A store that only ever went through save() verifies, and each new row extends it.
        assert isinstance(store, SealedSource)
        result = verify_store(store, name="contract")
        assert result.status == STATUS_UNANCHORED and result.blocks == len(events)
        assert not result.issues or all(issue.kind == "unanchored" for issue in result.issues)
        assert SOURCE == "event-store"
    finally:
        store.close()

    # 3. Changing, removing or swapping rows behind the store's back is named by verify.
    expected = {"edit": STATUS_TAMPERED, "delete": STATUS_DELETED, "swap": STATUS_TAMPERED}
    for how, status in expected.items():
        store = make_store()
        store.open()
        try:
            store.save(events)
            tamper(store, how)
            result = verify_store(store, name="contract")
            assert result.status == status, (how, result.status, result.issues)
            assert result.issues, how
        finally:
            store.close()
