"""Import a finished run in place: what ``proxy`` does when it stops.

The proxy cannot know when an agent is done, only when it is stopped. At that point this reads the
run's own trace and payloads (never anything else), writes ``events.csv``, ``gate-results.csv``
and ``gate-results.sarif`` beside them, and prints where they are. It is the same one-shot import
as ``import-logs --once``, run after traffic has stopped, so it is never in the request path.
Any failure is reported as a warning: a monitor must not turn a clean shutdown into an error.
"""

from __future__ import annotations

import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import TextIO

from agent_latch.runtime.importer import RuntimeLogImporter, discover_gates
from agent_latch.runtime.ledger.verify import verify_ledger


def _tool(name: str) -> str:
    """A command that works even when the install's ``bin`` folder is not on PATH."""
    sibling = Path(sys.executable).parent / name
    return shlex.quote(str(sibling)) if sibling.is_file() else name


def _count_rows(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open(encoding="utf-8", errors="replace") as stream:
        return max(0, sum(1 for _ in stream) - 1)  # minus the header


def import_run(
    trace_path: Path,
    ledger_path: Path | None,
    payloads_path: Path | None,
    out: TextIO,
) -> None:
    """Import one run folder and print a short summary to ``out``. Never raises."""

    def say(message: str) -> None:
        out.write(f"agent-latch-runtime: {message}\n")
        out.flush()

    folder = trace_path.parent.resolve()
    try:
        if not trace_path.is_file() or trace_path.stat().st_size == 0:
            say(f"run folder: {folder} (no traffic was recorded, nothing to import)")
            return
        # Imported lazily: the report module pulls in rich.
        from agent_latch.runtime.results import load_alerts

        results = folder / "gate-results.csv"
        events = folder / "events.csv"
        RuntimeLogImporter(
            trace_path,
            results,
            discover_gates(None),
            payloads_path=payloads_path if payloads_path and payloads_path.is_file() else None,
            events_csv=events,
            normalized_path=folder / "normalized.jsonl",
            summary=None,
            follow=False,
        ).run()
        alerts = load_alerts(results, None) if results.is_file() else []
        by_rule = Counter(alert.rule_id for alert in alerts)
        found = (
            f"{len(alerts)} finding(s) ({', '.join(f'{rule} x{n}' for rule, n in sorted(by_rule.items()))})"
            if alerts else "no findings"
        )
        verdict = ""
        if ledger_path is not None and ledger_path.is_file():
            verdict = f"; ledger {verify_ledger(ledger_path, trace_path=trace_path).status}"
        say(f"run folder: {folder}")
        say(f"{_count_rows(events)} event(s), {found}{verdict}")
        say(f"results: {results}  {results.with_suffix('.sarif')}")
        if payloads_path is None or not payloads_path.is_file():
            say("payloads were off, so the secrets gate (ALR10) had nothing to read;"
                " use --record-payloads to include them")
        has_ledger = ledger_path is not None and ledger_path.is_file()
        report = f'{_tool("agent-latch")} --runtime-result "$RUN/{results.name}"'
        if has_ledger:
            ledger_arg = (
                f"$RUN/{ledger_path.name}" if ledger_path.parent.resolve() == folder
                else str(ledger_path)
            )
            report += f' --ledger "{ledger_arg}"'
        say("to view the results, copy and paste:")
        out.write(f"RUN={shlex.quote(str(folder))}\n{report}\n")
        out.write('column -s, -t < "$RUN/events.csv" | less -S\n')
        out.flush()
        if has_ledger:
            say(f"anchor it (to a path the agent cannot write): agent-latch-runtime anchor"
                f" --ledger {ledger_path} --to <anchor file>")
    except Exception as error:  # noqa: BLE001 - shutdown must stay clean whatever the import hits
        say(f"run folder: {folder}")
        say(f"could not import this run automatically ({type(error).__name__}: {error});"
            f" run: agent-latch-runtime import-logs --dir {folder} --once")
