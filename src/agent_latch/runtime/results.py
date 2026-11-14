"""Print a runtime gate report from gate-results.csv.

Every gate writes the same CSV envelope. This report reads only the shared finding
fields, so a later gate appears here without a new formatter. A finding may name its
own source ``path`` and ``line``. When it does not, and it names ``entity.tool``,
the report looks for that function in the project and uses the docstring line.
"""

from __future__ import annotations

import ast
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent_latch import __version__
from agent_latch.catalog import GATES, GATES_BY_ID, Gate, gate_entry, gate_for
from agent_latch.owasp import category_entries, category_label
from agent_latch.rules import iter_project_files
from agent_latch.runtime.ledger import (
    STATUS_INTACT,
    STATUS_MISSING,
    STATUS_UNANCHORED,
    Verification,
    describe,
    verify_ledger,
)
from agent_latch.runtime.ledger.report import (
    DEFAULT_ROWS,
    audit_properties,
    format_ledger_table,
    ledger_rows,
    render_ledger_table,
    sarif_results,
    sarif_rule,
)
from agent_latch.runtime.store_check import StoreCheck, check_store, unsealed_finding

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
    "unknown": "dim",
}
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "warning",
}
_PATH_LINE = re.compile(r"^(?P<path>[^\s#]+?):(?P<line>\d+)(?::(?P<column>\d+))?$")
_MAX_SOURCE_BYTES = 1_000_000
_NOTE = "The report lists findings only. Nothing was blocked."


@dataclass(frozen=True)
class RuntimeAlert:
    severity: str
    rule_id: str
    location: str
    owasp: tuple[str, ...]
    title: str
    message: str
    evidence: str
    order: str


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 99)


def _shown(finding: dict[str, Any]) -> bool:
    if finding.get("suppressed") is True or finding.get("is_finding") is False:
        return False
    if finding.get("family") == "scan_summary":
        return False
    if finding.get("is_finding") is True:
        return True
    return finding.get("outcome") in {"FAIL", "INCONCLUSIVE"}


def _evidence(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in finding.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        signal = str(item.get("signal") or "").strip()
        field = str(item.get("field") or "").strip()
        if signal and field:
            parts.append(f"{signal} @ {field}")
        elif signal or field:
            parts.append(signal or field)
    return "; ".join(parts)


def _tool_sites(project: Path) -> dict[str, str]:
    """Function name to ``path:line`` of its docstring, preferring a tools/ folder."""
    sites: dict[str, tuple[int, str]] = {}
    if not project.exists():
        return {}
    for file in iter_project_files(project):
        if file.suffix != ".py":
            continue
        try:
            if file.stat().st_size > _MAX_SOURCE_BYTES:
                continue
            tree = ast.parse(file.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError):
            continue
        try:
            relative = file.relative_to(project).as_posix()
        except ValueError:
            relative = file.as_posix()
        rank = 0 if "tools" in file.parts else 1
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            line = node.lineno
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(getattr(node.body[0], "value", None), ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                line = node.body[0].lineno
            location = f"{relative}:{line}"
            previous = sites.get(node.name)
            if previous is None or (rank, location) < previous:
                sites[node.name] = (rank, location)
    return {name: location for name, (_rank, location) in sites.items()}


def _location(finding: dict[str, Any], order: str, sites: dict[str, str]) -> str:
    named = finding.get("location")
    if isinstance(named, str) and named.strip():
        return named  # a finding about a whole file or store, not one event
    path = finding.get("path")
    line = finding.get("line")
    if isinstance(path, str) and path.strip() and isinstance(line, int):
        column = finding.get("column")
        location = f"{path}:{line}"
        if isinstance(column, int):
            location += f":{column}"
        return location
    entity = finding.get("entity") if isinstance(finding.get("entity"), dict) else {}
    tool = str(entity.get("tool") or "")
    server = str(entity.get("server") or "")
    if tool and tool in sites:
        return sites[tool]
    where = "/".join(part for part in (server, tool) if part) or "event"
    return f"{where} #{order}"


def _alert(finding: dict[str, Any], order: str, sites: dict[str, str], fallback: str) -> RuntimeAlert:
    title = str(finding.get("family") or finding.get("title") or "").replace("_", " ")
    return RuntimeAlert(
        severity=str(finding.get("severity") or "unknown"),
        rule_id=str(finding.get("rule_id") or fallback),
        location=_location(finding, order, sites),
        owasp=tuple(str(item) for item in finding.get("owasp") or []),
        title=title,
        message=str(finding.get("message") or ""),
        evidence=_evidence(finding),
        order=order,
    )


def gate_of(rule_id: str) -> Gate | None:
    """The gate a runtime rule belongs to; a gate error carries only the gate's own ID."""
    return gate_for(rule_id) or GATES_BY_ID.get(rule_id) or GATES_BY_ID.get(rule_id.split("-")[0])


_GATE_ORDER = {item.id: index for index, item in enumerate(GATES)}


def _gate_rank(alert: RuntimeAlert) -> int:
    found = gate_of(alert.rule_id)
    return _GATE_ORDER[found.id] if found else len(_GATE_ORDER)


def sort_alerts(alerts: list[RuntimeAlert]) -> list[RuntimeAlert]:
    """Grouped by gate (catalog order, ungrouped last), then most severe first."""
    return sorted(alerts, key=lambda alert: (
        _gate_rank(alert), _rank(alert.severity), alert.location, alert.rule_id, alert.order
    ))


def _gate_heading(alert: RuntimeAlert) -> str:
    found = gate_of(alert.rule_id)
    return f"{found.id} {found.name}" if found else "No gate"


def load_alerts(csv_path: Path, project: Path) -> list[RuntimeAlert]:
    """Findings from a gate-results CSV. Rows that are not findings are left out."""
    sites = _tool_sites(project)
    alerts: list[RuntimeAlert] = []
    with csv_path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or "result_json" not in reader.fieldnames:
            raise ValueError("gate results CSV must have a result_json column")
        for row in reader:
            try:
                result = json.loads(row.get("result_json") or "")
            except json.JSONDecodeError:
                continue
            if not isinstance(result, dict):
                continue
            order = str(row.get("order") or "")
            if result.get("status") == "error":
                error = result.get("error") if isinstance(result.get("error"), dict) else {}
                alerts.append(RuntimeAlert(
                    severity="unknown",
                    rule_id=str(result.get("gate_id") or row.get("gate_id") or "gate"),
                    location=f"event #{order}",
                    owasp=(),
                    title="gate error",
                    message=str(error.get("type") or "the gate raised"),
                    evidence="",
                    order=order,
                ))
                continue
            for finding in result.get("findings") or []:
                if not isinstance(finding, dict) or not _shown(finding):
                    continue
                fallback = str(result.get("gate_id") or "gate")
                alerts.append(_alert(finding, order, sites, fallback))
    return sort_alerts(alerts)


def filter_severity(alerts: list[RuntimeAlert], min_severity: str) -> list[RuntimeAlert]:
    threshold = _SEVERITY_RANK[min_severity]
    return [
        alert for alert in alerts
        if alert.severity not in _SEVERITY_RANK or _rank(alert.severity) <= threshold
    ]


def format_report(alerts: list[RuntimeAlert]) -> str:
    if not alerts:
        return f"No runtime findings from the enabled gates.\n{_NOTE}"
    lines = [f"Runtime findings · {len(alerts)}", ""]
    heading = None
    for alert in sort_alerts(alerts):
        if _gate_heading(alert) != heading:
            heading = _gate_heading(alert)
            lines += [f"== {heading} ==", ""]
        owasp = "; ".join(category_label(item) for item in alert.owasp) or "—"
        lines.append(f"{alert.severity.upper():<8} {alert.rule_id}  {alert.location}")
        if alert.title:
            lines.append(f"  {alert.title}")
        if alert.message:
            lines.append(f"  {alert.message}")
        if alert.evidence:
            lines.append(f"  Evidence: {alert.evidence}")
        lines.append(f"  OWASP: {owasp}")
        lines.append("")
    lines.append(_NOTE)
    return "\n".join(lines)


def format_audit_status(verification: Verification, title: str | None = None) -> str:
    """The verdict as plain lines, for --plain output, logs and pipes."""
    lines = describe(verification)
    return "\n".join([f"{title}:", *lines] if title else lines)


def _render_audit_status(verification: Verification, title: str = "Audit trail") -> None:
    """The verdict in bold above the findings table: the first thing a reader sees."""
    console = Console()
    if verification.status == STATUS_INTACT:
        color = "green"
    elif verification.status == STATUS_UNANCHORED:
        color = "yellow"
    else:
        color = "red"
    body = Text(verification.headline(), style=f"bold {color}")
    for line in describe(verification)[1:]:
        body.append("\n" + line.strip(), style="dim")
    console.print(
        Panel(body, border_style=color, title=f"[bold]{title}[/bold]", title_align="left")
    )


def _alert_location(location: str) -> dict[str, Any]:
    match = _PATH_LINE.match(location)
    if match is None:
        return {"logicalLocations": [{"name": location}]}
    region: dict[str, Any] = {"startLine": int(match["line"])}
    if match["column"]:
        region["startColumn"] = int(match["column"])
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": match["path"]},
            "region": region,
        }
    }


def runtime_sarif(
    alerts: list[RuntimeAlert],
    verification: Verification | None,
    ledger_uri: str,
    block_count: int,
    *,
    store: Verification | None = None,
    store_uri: str = "",
) -> str:
    """Runtime gate findings and the audit verdicts as one SARIF 2.1.0 run.

    ``verification`` is the trace ledger's verdict and ``store`` the event store's; both are
    ``ALR15-R01``. An unsealed store arrives as an ``ALR15-R02`` alert.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    properties: dict[str, Any] = {"runtimeReport": True, "monitorOnly": True}
    if verification is not None:
        rules[sarif_rule()["id"]] = sarif_rule()
        results.extend(sarif_results(verification, ledger_uri, block_count))
        properties["auditTrail"] = audit_properties(verification)
    if store is not None:
        rules[sarif_rule()["id"]] = sarif_rule()
        results.extend(sarif_results(store, store_uri, store.blocks, by_line=False))
        properties["eventStore"] = audit_properties(store)
    for alert in sort_alerts(alerts):
        gate = gate_entry(alert.rule_id) or _gate_dict(alert.rule_id)
        rules.setdefault(alert.rule_id, {
            "id": alert.rule_id,
            "name": alert.title or alert.rule_id,
            "shortDescription": {"text": alert.title or alert.rule_id},
            "help": {"text": alert.message},
            "properties": {
                "tags": ["security", *([gate["id"]] if gate else []), *alert.owasp],
                "gate": gate,
                "owaspCategories": category_entries(alert.owasp),
            },
        })
        results.append({
            "ruleId": alert.rule_id,
            "level": _SARIF_LEVEL.get(alert.severity, "warning"),
            "message": {"text": alert.message or alert.title or alert.rule_id},
            "locations": [_alert_location(alert.location)],
            "properties": {
                "severity": alert.severity,
                "gate": gate,
                "owasp": list(alert.owasp),
                "owaspCategories": category_entries(alert.owasp),
                "evidence": alert.evidence,
                "eventOrder": alert.order,
            },
        })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AgentLatch",
                "version": __version__,
                "rules": list(rules.values()),
            }},
            "properties": properties,
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _gate_dict(rule_id: str) -> dict[str, str] | None:
    found = gate_of(rule_id)
    return {"id": found.id, "name": found.name} if found else None


def _render_table(alerts: list[RuntimeAlert]) -> None:
    console = Console()
    if not alerts:
        console.print(Panel(Text(_NOTE), title="[green]No runtime findings[/green]", border_style="green"))
        return
    table = Table(title=f"Runtime findings · {len(alerts)}", show_lines=True)
    table.add_column("Gate", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Location", style="dim")
    table.add_column("OWASP Agentic")
    table.add_column("Finding")
    for alert in sort_alerts(alerts):
        detail = Text(alert.title, style="bold")
        if alert.message:
            detail.append("\n" + alert.message)
        if alert.evidence:
            detail.append("\nEvidence: " + alert.evidence, style="dim")
        found = gate_of(alert.rule_id)
        table.add_row(
            Text(f"{found.id}\n{found.name}" if found else "—"),
            Text(alert.severity.upper(), style=_SEVERITY_STYLE.get(alert.severity, "white")),
            Text(alert.rule_id),
            Text(alert.location),
            Text("\n".join(category_label(item) for item in alert.owasp) or "—"),
            detail,
        )
    console.print(table)
    console.print(f"[dim]{_NOTE}[/dim]")


def _exit_code(
    verification: Verification | None,
    ledger: Path | None,
    alerts: list[RuntimeAlert],
    fail_on: str,
    *,
    store: StoreCheck | None = None,
) -> int:
    if verification is not None and verification.status == STATUS_MISSING:
        print(
            f"Error: no audit ledger at {ledger}; pass the file written by proxy --ledger",
            file=sys.stderr,
        )
        return 2
    if verification is not None and verification.failed:
        print(
            f"audit trail {verification.status}: the runtime log cannot be trusted",
            file=sys.stderr,
        )
        return 1
    if store is not None:
        # Like the ledger: store integrity is not a severity threshold, so --fail-on none does
        # not opt out of it.
        if store.unsealed is not None:
            print("event store unsealed: its record cannot be checked", file=sys.stderr)
            return 1
        if store.verification is not None and store.verification.failed:
            print(
                f"event store {store.verification.status}: the stored events cannot be trusted",
                file=sys.stderr,
            )
            return 1
    if fail_on == "none":
        return 0
    threshold = _SEVERITY_RANK[fail_on]
    blocking = [
        alert for alert in alerts
        if alert.severity == "unknown" or _rank(alert.severity) <= threshold
    ]
    if not blocking:
        return 0
    print(
        f"{len(blocking)} runtime finding(s) at or above --fail-on {fail_on}",
        file=sys.stderr,
    )
    return 1


def _store_error(store: StoreCheck, database: Path) -> str | None:
    """Why the store cannot be reported on at all (exit 2), or None."""
    if store.error is not None:
        return f"Error: {database} is not a usable event store: {store.error}"
    if store.verification is not None and store.verification.status == STATUS_MISSING:
        if not database.is_file():
            return (
                f"Error: no event store at {database}; pass the file written by"
                " import-logs --database"
            )
        return f"Error: the event store {database} holds no rows; there is nothing to verify"
    return None


def _write_sarif(sarif: str, output: Path | None) -> bool:
    if output is None:
        print(sarif)
        return True
    try:
        output.write_text(sarif + "\n", encoding="utf-8")
    except OSError as error:
        print(f"Error: could not write the sarif report to {output}: {error}", file=sys.stderr)
        return False
    print(f"Wrote sarif report to {output}", file=sys.stderr)
    return True


def report_runtime_results(
    csv_path: Path,
    project: Path,
    *,
    plain: bool,
    min_severity: str,
    fail_on: str,
    ledger: Path | None = None,
    anchor: Path | None = None,
    database: Path | None = None,
    database_anchor: Path | None = None,
    output_format: str = "text",
    output: Path | None = None,
    ledger_rows_limit: int = DEFAULT_ROWS,
) -> int:
    """Print the report. Returns 0, 1 when a trail failed or --fail-on matches, or 2.

    A trace ledger or event store that fails verification, or a store that does not seal its
    rows, always returns 1: log integrity is not a severity threshold, so ``--fail-on none`` does
    not opt out of it. Without ``ledger`` and ``database`` the exit code is unchanged.
    ``output_format`` is ``text`` (table, or plain lines) or ``sarif``.
    """
    if not csv_path.is_file():
        print(f"Error: runtime results file does not exist: {csv_path}", file=sys.stderr)
        return 2
    if not project.exists():
        print(f"Error: project path does not exist: {project}", file=sys.stderr)
        return 2
    verification = verify_ledger(ledger, anchor_path=anchor) if ledger is not None else None
    store = check_store(database, database_anchor) if database is not None else None
    if store is not None and database is not None:
        problem = _store_error(store, database)
        if problem is not None:
            print(problem, file=sys.stderr)
            return 2
    try:
        alerts = load_alerts(csv_path, project)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if store is not None and store.unsealed is not None and database is not None:
        finding = unsealed_finding(
            database.as_posix(),
            f"{database.name} is an older store whose rows are not sealed",
            "Run `agent-latch-runtime import-logs --database` once to upgrade and seal it; rows"
            " changed before that cannot be detected.",
        )
        alerts = sort_alerts([*alerts, _alert(finding, "store", {}, "ALR15")])
    alerts = filter_severity(alerts, min_severity)
    store_verdict = store.verification if store is not None else None
    rows = (
        ledger_rows(ledger, verification)
        if ledger is not None and verification is not None
        and verification.status != STATUS_MISSING
        else []
    )
    if output_format == "sarif":
        if verification is not None and verification.status == STATUS_MISSING:
            return _exit_code(verification, ledger, alerts, fail_on, store=store)
        ledger_uri = ledger.as_posix() if ledger is not None else ""
        sarif = runtime_sarif(
            alerts, verification, ledger_uri, len(rows),
            store=store_verdict, store_uri=database.as_posix() if database is not None else "",
        )
        if not _write_sarif(sarif, output):
            return 2
        if output is None:
            # SARIF is on stdout, so the human summary goes to stderr and the pipe stays clean.
            if verification is not None:
                print(format_audit_status(verification), file=sys.stderr)
            if store_verdict is not None:
                print(format_audit_status(store_verdict, "Event store"), file=sys.stderr)
            return _exit_code(verification, ledger, alerts, fail_on, store=store)
        # SARIF went to a file, so stdout is free for the readable report.
    if plain or not sys.stdout.isatty():
        if verification is not None:
            print(format_audit_status(verification))
            print()
            if rows:
                print(format_ledger_table(rows, verification, limit=ledger_rows_limit))
                print()
        if store_verdict is not None:
            print(format_audit_status(store_verdict, "Event store"))
            print()
        print(format_report(alerts))
    else:
        if verification is not None:
            _render_audit_status(verification)
            if rows:
                render_ledger_table(rows, verification, limit=ledger_rows_limit)
        if store_verdict is not None:
            _render_audit_status(store_verdict, "Event store")
        _render_table(alerts)
    return _exit_code(verification, ledger, alerts, fail_on, store=store)
