"""The hash chain over trace records.

One block per trace record. A block holds the SHA-256 of the record it seals, the digest of the
block before it, and its own digest, so an edit, a deletion or a reorder breaks every block after
it. The chain is a plain JSONL file you own: standard library only, no network, never in the
request path.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Self

from agent_latch.runtime.events import utc_now
from agent_latch.runtime.ledger.canonical import dumps

LEDGER_SCHEMA = "agentlatch.runtime.ledger/1"
GENESIS = "0" * 64
DOMAIN = b"agentlatch.runtime.ledger/1\x00"
_TAIL_BYTES = 64 * 1024


class LedgerError(RuntimeError):
    """The ledger could not be read, appended or parsed."""


@dataclass(frozen=True)
class Block:
    """One sealed trace record."""

    seq: int
    timestamp: str
    method: str
    stage: str
    record_sha256: str
    prev: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": LEDGER_SCHEMA,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "method": self.method,
            "stage": self.stage,
            "record_sha256": self.record_sha256,
            "prev": self.prev,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, data: Any) -> Block | None:
        """A block, or None when the object is not a well-formed block."""
        if not isinstance(data, dict):
            return None
        seq = data.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return None
        fields = {}
        for name in ("timestamp", "method", "stage", "record_sha256", "prev", "digest"):
            value = data.get(name)
            if not isinstance(value, str) or not value:
                return None
            fields[name] = value
        return cls(seq=seq, **fields)


def record_hash(record: str | bytes) -> str:
    """SHA-256 of one trace line, without its newline."""
    data = record.encode("utf-8") if isinstance(record, str) else record
    return hashlib.sha256(data).hexdigest()


def block_digest(
    *,
    prev: str,
    seq: int,
    timestamp: str,
    method: str,
    stage: str,
    record_sha256: str,
) -> str:
    """The block's own digest: every field that defines it, plus the one before it."""
    body = {
        "prev": prev,
        "seq": seq,
        "timestamp": timestamp,
        "method": method,
        "stage": stage,
        "record_sha256": record_sha256,
    }
    return hashlib.sha256(DOMAIN + dumps(body)).hexdigest()


def seal(
    record: str | bytes,
    *,
    seq: int,
    prev: str,
    method: str,
    stage: str,
    timestamp: str,
) -> Block:
    """Build the block that seals `record` after a block whose digest is `prev`."""
    return Block(
        seq=seq,
        timestamp=timestamp,
        method=method,
        stage=stage,
        record_sha256=record_hash(record),
        prev=prev,
        digest=block_digest(
            prev=prev,
            seq=seq,
            timestamp=timestamp,
            method=method,
            stage=stage,
            record_sha256=record_hash(record),
        ),
    )


def iter_blocks(path: Path) -> Iterator[Block]:
    """Yield every block in order. A malformed line is an error, not something to skip."""
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            text = line.strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as error:
                raise LedgerError(f"{path}: line {number} is not valid JSON") from error
            block = Block.from_dict(data)
            if block is None:
                raise LedgerError(f"{path}: line {number} is not a ledger block")
            yield block


def _last_block(path: Path) -> Block | None:
    """The final block, read from the tail of the file instead of parsing all of it."""
    if not path.is_file() or path.stat().st_size == 0:
        return None
    with path.open("rb") as stream:
        size = path.stat().st_size
        stream.seek(max(0, size - _TAIL_BYTES))
        chunk = stream.read()
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    if size > _TAIL_BYTES:
        lines = lines[1:]  # first line is truncated mid-record
    for line in reversed(lines):
        text = line.strip()
        if not text:
            continue
        try:
            block = Block.from_dict(json.loads(text))
        except json.JSONDecodeError:
            # Only a crash mid-write leaves a partial last line; anything else is corruption.
            if line is lines[-1] and not chunk.endswith(b"\n"):
                continue
            raise LedgerError(f"{path}: the last complete line is not a ledger block") from None
        if block is not None:
            return block
        raise LedgerError(f"{path}: the last complete line is not a ledger block")
    return None


class Ledger:
    """Append blocks to a JSONL file, resuming after the last block already there."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        last = _last_block(self.path)
        self.seq = last.seq if last else 0
        self.digest = last.digest if last else GENESIS
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._handle = os.fdopen(fd, "a", encoding="utf-8")

    @property
    def head(self) -> tuple[int, str]:
        """The sequence number and digest of the newest block."""
        return self.seq, self.digest

    def append(
        self,
        record: str | bytes,
        *,
        method: str,
        stage: str,
        timestamp: str | None = None,
    ) -> Block:
        """Seal one record. Raises LedgerError; callers decide whether that is fatal."""
        if self._handle is None:
            raise LedgerError("ledger is closed")
        block = seal(
            record,
            seq=self.seq + 1,
            prev=self.digest,
            method=method,
            stage=stage,
            timestamp=timestamp or utc_now(),
        )
        try:
            self._handle.write(json.dumps(block.to_dict(), ensure_ascii=False) + "\n")
            self._handle.flush()
        except OSError as error:
            raise LedgerError(str(error)) from error
        self.seq, self.digest = block.seq, block.digest
        return block

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @classmethod
    def read_head(cls, path: Path) -> Block | None:
        """The newest block without opening the file for writing."""
        return _last_block(Path(path))


def rewrite(path: Path, blocks: list[Block]) -> None:
    """Replace a ledger file wholesale. Used by tests and by recovery tooling."""
    with Path(path).open("w", encoding="utf-8") as stream:
        stream.writelines(
            json.dumps(block.to_dict(), ensure_ascii=False) + "\n" for block in blocks
        )


def reseal(blocks: list[Block]) -> list[Block]:
    """Recompute a run of blocks so they are internally consistent again (tests, demos)."""
    out: list[Block] = []
    prev = GENESIS
    for seq, block in enumerate(blocks, 1):
        fresh = replace(
            block,
            seq=seq,
            prev=prev,
            digest=block_digest(
                prev=prev,
                seq=seq,
                timestamp=block.timestamp,
                method=block.method,
                stage=block.stage,
                record_sha256=block.record_sha256,
            ),
        )
        out.append(fresh)
        prev = fresh.digest
    return out
