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
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent_latch.owasp import category_label
from agent_latch.rules import iter_project_files

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
    "unknown": "dim",
}
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


def report_runtime_results(
    csv_path: Path,
    project: Path,
    *,
    plain: bool,
    min_severity: str,
    fail_on: str,
) -> int:
    """Print the report. Returns 0, 1 when --fail-on matches, or 2 on a bad file."""
    if not csv_path.is_file():
        print(f"Error: runtime results file does not exist: {csv_path}", file=sys.stderr)
        return 2
    if not project.exists():
        print(f"Error: project path does not exist: {project}", file=sys.stderr)
        return 2
    try:
        alerts = filter_severity(load_alerts(csv_path, project), min_severity)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if plain or not sys.stdout.isatty():
        print(format_report(alerts))
    else:
        _render_table(alerts)
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
