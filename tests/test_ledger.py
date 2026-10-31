"""Tests for the tamper-evident ledger (ALR15).

Every test runs on tmp files, makes no network call, and touches nothing outside tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_latch.runtime.ledger import (
    GENESIS,
    STATUS_DELETED,
    STATUS_INTACT,
    STATUS_REWRITTEN,
    STATUS_TAMPERED,
    STATUS_UNANCHORED,
    AnchorError,
    FileAnchor,
    Ledger,
    LedgerError,
    block_digest,
    describe,
    point_for,
    verify_ledger,
)
from agent_latch.runtime.ledger.chain import Block, iter_blocks, reseal, rewrite
from agent_latch.runtime.trace import TraceLog


def _trace(path: Path, count: int = 4) -> list[str]:
    """Write a small trace and return its lines, the way the proxy would."""
    log = TraceLog(path, summary=None)
    for index in range(1, count + 1):
        log.write({
            "session_id": "s-1",
            "request_id": f"r-{index}",
            "server": "filesystem",
            "method": "tools/call",
            "stage": "request",
            "tool": "read_file",
        })
    log.close()
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


def _ledger(trace: Path, ledger: Path, count: int = 4) -> Ledger:
    chain = Ledger(ledger)
    for index in range(1, count + 1):
        chain.append(
            json.dumps({"request_id": f"r-{index}", "method": "tools/call"}),
            method="tools/call",
            stage="request",
            timestamp=f"2026-10-29T09:15:4{index}.000Z",
        )
    chain.close()
    return chain


@pytest.fixture()
def sealed(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A trace, a matching ledger, and an empty anchor path."""
    trace = tmp_path / "trace.jsonl"
    lines = _trace(trace)
    ledger = tmp_path / "trace.ledger.jsonl"
    chain = Ledger(ledger)
    for index, line in enumerate(lines, 1):
        chain.append(line, method="tools/call", stage="request",
                     timestamp=f"2026-10-29T09:15:4{index}.000Z")
    chain.close()
    return trace, ledger, tmp_path / "anchors.jsonl"


def _anchor(ledger: Path, anchor: Path) -> None:
    head = Ledger.read_head(ledger)
    assert head is not None
    FileAnchor(anchor).publish(
        point_for(ledger, seq=head.seq, digest=head.digest, records=head.seq)
    )


def _blocks(ledger: Path) -> list[Block]:
    return list(iter_blocks(ledger))


# --------------------------------------------------------------- the happy path
def test_unanchored_ledger_verifies_but_says_so(sealed) -> None:
    trace, ledger, _ = sealed
    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_UNANCHORED
    assert result.ok and not result.failed
    assert result.blocks == 4
    assert result.head_seq == 4
    assert "nothing outside the machine proves" in result.headline()


def test_anchored_ledger_is_intact(sealed) -> None:
    trace, ledger, anchor = sealed
    _anchor(ledger, anchor)
    result = verify_ledger(ledger, trace_path=trace, anchor_path=anchor)
    assert result.status == STATUS_INTACT
    assert result.anchored
    assert result.anchor_seq == 4
    assert "INTACT" in result.headline()


def test_missing_ledger_is_reported(tmp_path: Path) -> None:
    result = verify_ledger(tmp_path / "nope.jsonl")
    assert not result.ok
    assert "NO AUDIT TRAIL" in result.headline()


# --------------------------------------------------------------- tampering
def test_edited_block_is_detected(sealed) -> None:
    _, ledger, anchor = sealed
    _anchor(ledger, anchor)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[1])
    edited["method"] = "tools/list"
    lines[1] = json.dumps(edited)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_ledger(ledger, anchor_path=anchor)
    assert result.status == STATUS_TAMPERED
    assert result.failed
    assert any(issue.kind == "edited" and issue.seq == 2 for issue in result.issues)
    assert "cannot be trusted" in result.headline()


def test_deleted_block_is_detected(sealed) -> None:
    _, ledger, _ = sealed
    blocks = _blocks(ledger)
    rewrite(ledger, [blocks[0], blocks[2], blocks[3]])

    result = verify_ledger(ledger)
    assert result.status == STATUS_DELETED
    assert any(issue.kind == "deleted" for issue in result.issues)


def test_truncated_log_is_caught_by_the_anchor(sealed) -> None:
    _, ledger, anchor = sealed
    _anchor(ledger, anchor)
    blocks = _blocks(ledger)
    rewrite(ledger, blocks[:2])

    result = verify_ledger(ledger, anchor_path=anchor)
    assert result.status == STATUS_DELETED
    assert "the log ends at #2, but #4 was anchored" in " ".join(
        issue.detail for issue in result.issues
    )


def test_full_rewrite_is_caught_by_the_anchor(sealed) -> None:
    _, ledger, anchor = sealed
    _anchor(ledger, anchor)
    blocks = _blocks(ledger)
    forged = reseal([
        Block(seq=1, timestamp=b.timestamp, method="tools/list", stage=b.stage,
              record_sha256=b.record_sha256, prev=GENESIS, digest="")
        for b in blocks
    ])
    rewrite(ledger, forged)

    # Internally the forgery is perfect: the chain verifies on its own.
    assert verify_ledger(ledger).status == STATUS_UNANCHORED
    # Only the published digest disagrees.
    result = verify_ledger(ledger, anchor_path=anchor)
    assert result.status == STATUS_REWRITTEN
    assert "REWRITTEN" in result.headline()


def test_trace_edited_behind_the_ledger_is_detected(sealed) -> None:
    trace, ledger, _ = sealed
    lines = trace.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("read_file", "send_email")
    trace.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_TAMPERED
    assert any(issue.kind == "edited" and issue.seq == 1 for issue in result.issues)


def test_deleted_block_is_still_a_deletion_when_the_trace_is_checked(sealed) -> None:
    """One removed line shifts every later comparison; that must not read as editing."""
    trace, ledger, _ = sealed
    blocks = _blocks(ledger)
    rewrite(ledger, [blocks[0], blocks[2], blocks[3]])

    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_DELETED
    assert "DELETED" in result.headline()
    assert not any(issue.kind == "edited" for issue in result.issues)


def test_deleted_trace_line_is_named_as_a_deletion(sealed) -> None:
    trace, ledger, _ = sealed
    lines = trace.read_text(encoding="utf-8").splitlines()
    trace.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")

    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_DELETED
    assert [issue.kind for issue in result.issues].count("deleted") == 1
    assert any(issue.kind == "deleted" and issue.seq == 3 for issue in result.issues)


def _sealed_six(tmp_path: Path) -> tuple[Path, Path]:
    trace = tmp_path / "trace.jsonl"
    lines = _trace(trace, count=6)
    ledger = tmp_path / "trace.ledger.jsonl"
    chain = Ledger(ledger)
    for index, line in enumerate(lines, 1):
        chain.append(line, method="tools/call", stage="request",
                     timestamp=f"2026-10-29T09:15:4{index}.000Z")
    chain.close()
    return trace, ledger


def _write_lines(trace: Path, lines: list[str]) -> None:
    trace.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    ("keep", "gone"),
    [
        ([0, 1, 4, 5], [3, 4]),  # two adjacent lines from the middle
        ([2, 3, 4, 5], [1, 2]),  # the first lines, where the old one-block look-ahead failed
        ([0, 1, 2, 3], [5, 6]),  # the last lines
        ([0, 2, 3, 4, 5], [2]),  # a single line
    ],
)
def test_run_of_deleted_trace_lines_is_a_deletion_not_an_edit(tmp_path, keep, gone) -> None:
    trace, ledger = _sealed_six(tmp_path)
    lines = trace.read_text(encoding="utf-8").splitlines()
    _write_lines(trace, [lines[i] for i in keep])

    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_DELETED
    assert not any(issue.kind == "edited" for issue in result.issues)
    assert sorted(i.seq for i in result.issues if i.kind == "deleted") == gone


def test_edited_trace_line_is_still_an_edit(tmp_path: Path) -> None:
    trace, ledger = _sealed_six(tmp_path)
    lines = trace.read_text(encoding="utf-8").splitlines()
    lines[2] = lines[2].replace("read_file", "send_email")
    _write_lines(trace, lines)

    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_TAMPERED
    assert [(i.kind, i.seq) for i in result.issues] == [("edited", 3)]


def test_deletion_and_edit_together_stay_tampered(tmp_path: Path) -> None:
    trace, ledger = _sealed_six(tmp_path)
    lines = trace.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("read_file", "send_email")
    _write_lines(trace, [lines[0], lines[1], lines[4], lines[5]])

    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_TAMPERED
    kinds = {i.kind for i in result.issues}
    assert {"edited", "deleted"} <= kinds


def test_lost_ledger_tail_is_not_described_as_added_lines(sealed) -> None:
    trace, ledger, anchor = sealed
    _anchor(ledger, anchor)
    rewrite(ledger, _blocks(ledger)[:2])

    result = verify_ledger(ledger, trace_path=trace, anchor_path=anchor)
    assert result.status == STATUS_TAMPERED
    details = " ".join(issue.detail for issue in result.issues)
    assert "the ledger lost its tail" in details
    assert "no block sealed" not in details
    assert "the log ends at #2, but #4 was anchored" in details


def test_trace_line_no_block_sealed_is_reported(sealed) -> None:
    trace, ledger, _ = sealed
    with trace.open("a", encoding="utf-8") as stream:
        stream.write('{"schema": "agentlatch.runtime.trace/1", "method": "tools/call"}\n')

    result = verify_ledger(ledger, trace_path=trace)
    assert result.status == STATUS_TAMPERED
    assert any("no block sealed" in issue.detail for issue in result.issues)


# --------------------------------------------------------------- mechanics
def test_ledger_resumes_after_the_last_block(tmp_path: Path) -> None:
    ledger = tmp_path / "resume.jsonl"
    first = Ledger(ledger)
    for _ in range(3):
        first.append("{}", method="tools/call", stage="request")
    head = first.head
    first.close()

    second = Ledger(ledger)
    assert second.head == head
    block = second.append("{}", method="tools/call", stage="request")
    second.close()
    assert block.seq == 4
    assert block.prev == head[1]


def test_blocks_chain_and_recompute(sealed) -> None:
    _, ledger, _ = sealed
    blocks = _blocks(ledger)
    prev = GENESIS
    for block in blocks:
        assert block.prev == prev
        assert block.digest == block_digest(
            prev=block.prev, seq=block.seq, timestamp=block.timestamp,
            method=block.method, stage=block.stage, record_sha256=block.record_sha256,
        )
        prev = block.digest


def test_anchor_refuses_to_go_backwards(sealed) -> None:
    _, ledger, anchor = sealed
    _anchor(ledger, anchor)
    head = Ledger.read_head(ledger)
    assert head is not None
    with pytest.raises(AnchorError):
        FileAnchor(anchor).publish(
            point_for(ledger, seq=head.seq - 1, digest=head.digest, records=head.seq - 1)
        )


def test_malformed_line_is_an_error_not_a_skipped_line(sealed) -> None:
    _, ledger, _ = sealed
    with ledger.open("a", encoding="utf-8") as stream:
        stream.write("{not json}\n")
    with pytest.raises(LedgerError):
        list(iter_blocks(ledger))
    assert verify_ledger(ledger).status == STATUS_TAMPERED


def test_describe_lists_the_first_problems(sealed) -> None:
    _, ledger, _ = sealed
    blocks = _blocks(ledger)
    rewrite(ledger, blocks[:1] + blocks[2:])
    lines = describe(verify_ledger(ledger))
    assert lines[0].startswith("AUDIT TRAIL")
    assert any(line.strip().startswith("#") for line in lines[1:])


# --------------------------------------------------------------- verify PATH and --all
def _pair(folder: Path, name: str = "trace", count: int = 3) -> tuple[Path, Path]:
    """A trace and the ledger that seals it, named the way the proxy pairs them."""
    folder.mkdir(parents=True, exist_ok=True)
    trace = folder / f"{name}.jsonl"
    lines = _trace(trace, count=count)
    ledger = folder / f"{name}.ledger.jsonl"
    chain = Ledger(ledger)
    for index, line in enumerate(lines, 1):
        chain.append(line, method="tools/call", stage="request",
                     timestamp=f"2026-10-29T09:15:4{index}.000Z")
    chain.close()
    return trace, ledger


def _verify_cli(*argv: str) -> int:
    from agent_latch.runtime.cli import main

    return main(["verify", *argv])


def test_verify_a_path_finds_the_trace_beside_the_ledger(tmp_path: Path, capsys) -> None:
    trace, ledger = _pair(tmp_path)
    assert _verify_cli(str(ledger)) == 0
    assert "UNANCHORED" in capsys.readouterr().out

    lines = trace.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("read_file", "send_email")
    _write_lines(trace, lines)
    assert _verify_cli(str(ledger)) == 1
    assert "TAMPERED" in capsys.readouterr().out


def test_verify_a_path_reports_a_deleted_trace(tmp_path: Path, capsys) -> None:
    trace, ledger = _pair(tmp_path)
    trace.unlink()
    assert _verify_cli(str(ledger)) == 1
    assert "is gone" in capsys.readouterr().out


def test_verify_ledger_flag_still_works_and_does_not_guess_the_trace(tmp_path: Path) -> None:
    trace, ledger = _pair(tmp_path)
    trace.unlink()
    assert _verify_cli("--ledger", str(ledger)) == 0
    assert _verify_cli("--ledger", str(ledger), "--trace", str(trace)) == 1


def test_verify_a_folder_checks_each_ledger_and_all_goes_into_subfolders(
    tmp_path: Path, capsys
) -> None:
    _pair(tmp_path, "run-a")
    _pair(tmp_path, "run-b")
    bad_trace, _ = _pair(tmp_path / "archive" / "20261030-081346")
    lines = bad_trace.read_text(encoding="utf-8").splitlines()
    _write_lines(bad_trace, lines[:1] + lines[2:])

    assert _verify_cli(str(tmp_path)) == 0
    top = capsys.readouterr().out
    assert "2 ledger(s): 2 unanchored" in top
    assert "archive" not in top

    assert _verify_cli(str(tmp_path), "--all") == 1
    out = capsys.readouterr().out
    assert "3 ledger(s): 1 deleted, 2 unanchored" in out
    assert "archive/20261030-081346/trace.ledger.jsonl" in out
    assert "AUDIT TRAIL DELETED" in out


def test_verify_folder_and_path_usage_errors(tmp_path: Path, capsys) -> None:
    _, ledger = _pair(tmp_path / "one")
    empty = tmp_path / "empty"
    empty.mkdir()

    assert _verify_cli(str(empty)) == 2
    assert "add --all" in capsys.readouterr().err
    assert _verify_cli(str(tmp_path), "--all", "--anchor", str(tmp_path / "a.jsonl")) == 2
    assert "one ledger" in capsys.readouterr().err
    assert _verify_cli(str(ledger), "--all") == 2
    assert _verify_cli(str(ledger), "--ledger", str(ledger)) == 2
    assert _verify_cli() == 2
    assert _verify_cli(str(tmp_path / "nope.ledger.jsonl")) == 2
