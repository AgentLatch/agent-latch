"""The ledger as a table for a terminal, and the audit verdict as SARIF results (ALR15).

Presentation only: nothing here decides a verdict. ``verify_ledger`` does, and this module
shows its issues next to the blocks they belong to.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from agent_latch.catalog import gate_entry
from agent_latch.owasp import category_entries
from agent_latch.runtime.ledger.chain import LedgerError, iter_blocks
from agent_latch.runtime.ledger.verify import (
    STATUS_MISSING,
    STATUS_UNANCHORED,
    Verification,
)

RULE_ID = "ALR15-R01"
RULE_TITLE = "Audit log altered, deleted or rebuilt"
DEFAULT_ROWS = 20
STATE_OK = "ok"

# When one record has several problems, the first state in this list is the one shown.
_STATE_ORDER = ("edited", "malformed", "reordered", "deleted")
_STATE_LABEL = {
    "edited": "EDITED",
    "malformed": "MALFORMED",
    "reordered": "REORDERED",
    "deleted": "DELETED",
    STATE_OK: "ok",
}
_PLACEHOLDER = "-"


@dataclass(frozen=True)
class LedgerRow:
    seq: int
    timestamp: str
    method: str
    stage: str
    digest: str
    state: str

    @property
    def problem(self) -> bool:
        return self.state != STATE_OK


def _state_for(kinds: set[str]) -> str:
    for state in _STATE_ORDER:
        if state in kinds:
            return state
    return STATE_OK


def ledger_rows(ledger: Path, verification: Verification) -> list[LedgerRow]:
    """One row per sealed block, plus one per gap the verifier named, in sequence order."""
    try:
        blocks = list(iter_blocks(ledger))
    except (LedgerError, OSError):
        return []
    kinds_by_seq: dict[int, set[str]] = {}
    for issue in verification.issues:
        if issue.seq > 0:
            kinds_by_seq.setdefault(issue.seq, set()).add(issue.kind)

    rows: list[LedgerRow] = []
    present = {block.seq for block in blocks}
    for block in blocks:
        rows.append(LedgerRow(
            seq=block.seq,
            timestamp=block.timestamp,
            method=block.method,
            stage=block.stage,
            digest=block.digest[:12],
            state=_state_for(kinds_by_seq.get(block.seq, set())),
        ))
    for seq, kinds in kinds_by_seq.items():
        if seq not in present:
            rows.append(LedgerRow(
                seq=seq,
                timestamp=_PLACEHOLDER,
                method=_PLACEHOLDER,
                stage=_PLACEHOLDER,
                digest=_PLACEHOLDER,
                state=_state_for(kinds),
            ))
    rows.sort(key=lambda row: row.seq)
    return rows


def select_rows(rows: list[LedgerRow], limit: int) -> tuple[list[LedgerRow], int]:
    """Every problem row, then the newest intact ones up to ``limit``. 0 means all rows.

    Returns the rows to show and how many intact rows were left out.
    """
    if limit <= 0 or len(rows) <= limit:
        return rows, 0
    problems = [row for row in rows if row.problem]
    room = max(limit - len(problems), 0)
    intact = [row for row in rows if not row.problem]
    keep = {row.seq for row in problems} | {row.seq for row in intact[len(intact) - room:]}
    shown = [row for row in rows if row.seq in keep]
    return shown, len(rows) - len(shown)


def _caption(verification: Verification, hidden: int) -> str:
    text = f"{verification.blocks:,} record(s), head #{verification.head_seq}"
    if hidden:
        text += f", {hidden:,} intact record(s) not shown (--ledger-rows 0 shows all)"
    return text


def format_ledger_table(
    rows: list[LedgerRow], verification: Verification, *, limit: int = DEFAULT_ROWS
) -> str:
    """The table as plain text, for --plain output, logs and pipes."""
    shown, hidden = select_rows(rows, limit)
    header = ("#", "TIME", "METHOD", "STAGE", "DIGEST", "STATE")
    body = [
        (str(row.seq), row.timestamp, row.method, row.stage, row.digest, _STATE_LABEL[row.state])
        for row in shown
    ]
    widths = [max(len(line[i]) for line in [header, *body]) for i in range(len(header))]

    def line(cells: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths)).rstrip()

    out = [f"Audit ledger {verification.ledger}: {_caption(verification, hidden)}", line(header)]
    out.extend(line(cells) for cells in body)
    return "\n".join(out)


def render_ledger_table(
    rows: list[LedgerRow],
    verification: Verification,
    *,
    limit: int = DEFAULT_ROWS,
    console: Console | None = None,
) -> None:
    """The table with colour: problem rows in red so they are the first thing seen."""
    console = console or Console()
    shown, hidden = select_rows(rows, limit)
    table = Table(
        title=f"Audit ledger {verification.ledger}",
        caption=_caption(verification, hidden),
        title_justify="left",
        caption_justify="left",
        show_lines=False,
    )
    table.add_column("#", justify="right")
    table.add_column("Time", no_wrap=True)
    table.add_column("Method")
    table.add_column("Stage")
    table.add_column("Digest", style="dim")
    table.add_column("State")
    for row in shown:
        style = "bold red" if row.problem else "green"
        table.add_row(
            str(row.seq),
            row.timestamp,
            row.method,
            row.stage,
            row.digest,
            Text(_STATE_LABEL[row.state], style=style),
            style="red" if row.problem else None,
        )
    console.print(table)


def sarif_rule() -> dict[str, Any]:
    gate = gate_entry(RULE_ID)
    return {
        "id": RULE_ID,
        "name": RULE_TITLE,
        "shortDescription": {"text": RULE_TITLE},
        "help": {
            "text": (
                "The runtime log no longer matches the hash chain written beside it, or the "
                "chain no longer matches the digest published to the anchor. Treat the log as "
                "untrusted until the cause is known. A clean result is not a guarantee: only "
                "changes made after the last anchor, or before sealing, are outside what this "
                "can show."
            )
        },
        "properties": {
            "tags": ["security", "ALR15", "ASI10"],
            "shortId": RULE_ID,
            "gate": gate,
            "owaspCategories": category_entries(("ASI10",)),
        },
    }


def sarif_results(
    verification: Verification, ledger_uri: str, block_count: int
) -> list[dict[str, Any]]:
    """One SARIF result per problem the verifier found, located in the ledger file.

    Each ledger line is one block, so a block's sequence number doubles as its line number. A
    record that is gone has no line; it points at the nearest one.
    """
    if verification.status == STATUS_MISSING:
        return []
    gate = gate_entry(RULE_ID)
    results: list[dict[str, Any]] = []
    for issue in verification.issues:
        line = min(max(issue.seq, 1), max(block_count, 1))
        level = "warning" if issue.kind == STATUS_UNANCHORED else "error"
        where = f"#{issue.seq}" if issue.seq else "log"
        results.append({
            "ruleId": RULE_ID,
            "level": level,
            "message": {"text": f"{where}: {issue.detail}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": ledger_uri},
                    "region": {"startLine": line},
                }
            }],
            "properties": {
                "severity": "info" if level == "warning" else "high",
                "kind": issue.kind,
                "seq": issue.seq,
                "auditStatus": verification.status,
                "gate": gate,
                "owasp": ["ASI10"],
                "owaspCategories": category_entries(("ASI10",)),
            },
        })
    return results


def audit_properties(verification: Verification) -> dict[str, Any]:
    """The verdict as run-level SARIF properties, so a clean ledger still leaves a record."""
    return {
        "status": verification.status,
        "headline": verification.headline(),
        "ledger": verification.ledger,
        "records": verification.blocks,
        "headSeq": verification.head_seq,
        "headDigest": verification.head_digest,
        "anchored": verification.anchored,
        "anchorSeq": verification.anchor_seq,
        "anchorDigest": verification.anchor_digest,
        "anchorTime": verification.anchor_time,
        "traceChecked": verification.trace_checked,
    }
