"""Anchor points: the one short line that leaves the machine.

A point records the head of the ledger at a moment in time: sequence number, digest, record
count and a timestamp. Publishing it elsewhere is what turns a locally consistent log into
evidence, because a full rewrite of the log cannot reproduce a digest that already left.

Only the file anchor ships. It writes to a path you choose, so you decide where that path lives:
a mounted share, a write-once bucket that syncs, or a copy step to another host. Adding another
destination means implementing two methods; see docs/ledger-reference.md.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agent_latch.runtime.events import utc_now

ANCHOR_SCHEMA = "agentlatch.runtime.anchor/1"


class AnchorError(RuntimeError):
    """The anchor could not be read or written."""


@dataclass(frozen=True)
class AnchorPoint:
    """The published claim: 'the ledger reached this block at this time'."""

    seq: int
    digest: str
    records: int
    timestamp: str
    ledger: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": ANCHOR_SCHEMA,
            "seq": self.seq,
            "digest": self.digest,
            "records": self.records,
            "timestamp": self.timestamp,
            "ledger": self.ledger,
        }

    @classmethod
    def from_dict(cls, data: Any) -> AnchorPoint | None:
        if not isinstance(data, dict):
            return None
        seq = data.get("seq")
        records = data.get("records")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return None
        if not isinstance(records, int) or isinstance(records, bool) or records < 1:
            return None
        fields = {}
        for name in ("digest", "timestamp", "ledger"):
            value = data.get(name)
            if not isinstance(value, str) or not value:
                return None
            fields[name] = value
        return cls(seq=seq, records=records, **fields)


class Anchor(Protocol):
    """Where a point goes. Two methods is the whole contract."""

    path: Path

    def publish(self, point: AnchorPoint) -> AnchorPoint:
        """Record a point. Refuses to go backwards, so history stays monotonic."""

    def latest(self) -> AnchorPoint | None:
        """The newest point, or None when nothing has been published."""


class FileAnchor:
    """Append-only anchor file. Put it where the agent cannot write."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _points(self) -> list[AnchorPoint]:
        if not self.path.is_file():
            return []
        points: list[AnchorPoint] = []
        with self.path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                text = line.strip()
                if not text:
                    continue
                try:
                    point = AnchorPoint.from_dict(json.loads(text))
                except json.JSONDecodeError as error:
                    raise AnchorError(f"{self.path}: line {number} is not valid JSON") from error
                if point is None:
                    raise AnchorError(f"{self.path}: line {number} is not an anchor point")
                points.append(point)
        return points

    def latest(self) -> AnchorPoint | None:
        points = self._points()
        return points[-1] if points else None

    def publish(self, point: AnchorPoint) -> AnchorPoint:
        previous = self.latest()
        if previous is not None and point.seq < previous.seq:
            raise AnchorError(
                f"refusing to anchor #{point.seq}: #{previous.seq} is already anchored"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(point.to_dict(), ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return point

    def points(self) -> list[AnchorPoint]:
        """Every point, oldest first, for audit review."""
        return self._points()


def make_anchor(spec: str | Path) -> Anchor:
    """'file:/path/to/anchors.jsonl', or a bare path."""
    text = str(spec)
    if text.startswith("file:"):
        text = text.removeprefix("file:")
    return FileAnchor(Path(text).expanduser())


def point_for(ledger_path: Path, *, seq: int, digest: str, records: int) -> AnchorPoint:
    """Build a point for a ledger head."""
    return AnchorPoint(
        seq=seq,
        digest=digest,
        records=records,
        timestamp=utc_now(),
        ledger=Path(ledger_path).name,
    )
