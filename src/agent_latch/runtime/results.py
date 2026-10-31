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
from agent_latch.catalog import gate_entry
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
                title = str(finding.get("family") or finding.get("title") or "").replace("_", " ")
                alerts.append(RuntimeAlert(
                    severity=str(finding.get("severity") or "unknown"),
                    rule_id=str(finding.get("rule_id") or result.get("gate_id") or "gate"),
                    location=_location(finding, order, sites),
                    owasp=tuple(str(item) for item in finding.get("owasp") or []),
                    title=title,
                    message=str(finding.get("message") or ""),
                    evidence=_evidence(finding),
                    order=order,
                ))
    alerts.sort(key=lambda alert: (_rank(alert.severity), alert.location, alert.rule_id, alert.order))
    return alerts


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
    for alert in alerts:
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


def format_audit_status(verification: Verification) -> str:
    """The verdict as plain lines, for --plain output, logs and pipes."""
    return "\n".join(describe(verification))


def _render_audit_status(verification: Verification) -> None:
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
        Panel(body, border_style=color, title="[bold]Audit trail[/bold]", title_align="left")
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
) -> str:
    """Runtime gate findings and the audit verdict as one SARIF 2.1.0 run."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    properties: dict[str, Any] = {"runtimeReport": True, "monitorOnly": True}
    if verification is not None:
        rules[sarif_rule()["id"]] = sarif_rule()
        results.extend(sarif_results(verification, ledger_uri, block_count))
        properties["auditTrail"] = audit_properties(verification)
    for alert in alerts:
        gate = gate_entry(alert.rule_id)
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


def _render_table(alerts: list[RuntimeAlert]) -> None:
    console = Console()
    if not alerts:
        console.print(Panel(Text(_NOTE), title="[green]No runtime findings[/green]", border_style="green"))
        return
    table = Table(title=f"Runtime findings · {len(alerts)}", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Location", style="dim")
    table.add_column("OWASP Agentic")
    table.add_column("Finding")
    for alert in alerts:
        detail = Text(alert.title, style="bold")
        if alert.message:
            detail.append("\n" + alert.message)
        if alert.evidence:
            detail.append("\nEvidence: " + alert.evidence, style="dim")
        table.add_row(
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
    output_format: str = "text",
    output: Path | None = None,
    ledger_rows_limit: int = DEFAULT_ROWS,
) -> int:
    """Print the report. Returns 0, 1 when the trail failed or --fail-on matches, or 2.

    A trail that fails verification always returns 1: log integrity is not a severity threshold,
    so ``--fail-on none`` does not opt out of it. Without a ledger the exit code is unchanged.
    ``output_format`` is ``text`` (table, or plain lines) or ``sarif``.
    """
    if not csv_path.is_file():
        print(f"Error: runtime results file does not exist: {csv_path}", file=sys.stderr)
        return 2
    if not project.exists():
        print(f"Error: project path does not exist: {project}", file=sys.stderr)
        return 2
    verification = verify_ledger(ledger, anchor_path=anchor) if ledger is not None else None
    try:
        alerts = filter_severity(load_alerts(csv_path, project), min_severity)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    rows = (
        ledger_rows(ledger, verification)
        if ledger is not None and verification is not None
        and verification.status != STATUS_MISSING
        else []
    )
    if output_format == "sarif":
        if verification is not None and verification.status == STATUS_MISSING:
            return _exit_code(verification, ledger, alerts, fail_on)
        ledger_uri = ledger.as_posix() if ledger is not None else ""
        sarif = runtime_sarif(alerts, verification, ledger_uri, len(rows))
        if not _write_sarif(sarif, output):
            return 2
        if verification is not None:
            print(format_audit_status(verification), file=sys.stderr)
        return _exit_code(verification, ledger, alerts, fail_on)
    if plain or not sys.stdout.isatty():
        if verification is not None:
            print(format_audit_status(verification))
            print()
            if rows:
                print(format_ledger_table(rows, verification, limit=ledger_rows_limit))
                print()
        print(format_report(alerts))
    else:
        if verification is not None:
            _render_audit_status(verification)
            if rows:
                render_ledger_table(rows, verification, limit=ledger_rows_limit)
        _render_table(alerts)
    return _exit_code(verification, ledger, alerts, fail_on)
