"""Command-line entry point for AgentLatch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text
from rich_argparse import RawDescriptionRichHelpFormatter

from agent_latch import __version__
from agent_latch.manifest import ManifestError, find_manifest, scan_manifest
from agent_latch.report import json_report, sarif_report, severity_sort_key, text_report
from agent_latch.rules import (
    DependencyAuditError,
    Finding,
    audit_requirements,
    scan_project,
)
from agent_latch.suppress import ConfigError, filter_findings, load_ignore_rules

_EPILOG = """\
[bold bright_cyan]EXAMPLES:[/bold bright_cyan]
  [cyan]agent-latch scan[/cyan]                                   scan the current directory
  [cyan]agent-latch scan --config agent-manifest.yaml[/cyan]      audit tools and prompts in a manifest
  [cyan]agent-latch scan ./my-agent --fail-on high[/cyan]         fail CI on high-severity findings
  [cyan]agent-latch scan --format sarif --output results.sarif[/cyan]
  [cyan]agent-latch --interactive[/cyan]                          guided scan

[dim]Scans run locally. Findings are heuristics, not a security certification.[/dim]
"""


def build_parser() -> argparse.ArgumentParser:
    RawDescriptionRichHelpFormatter.styles.update(
        {"argparse.groups": "bold bright_cyan", "argparse.prog": "bold bright_cyan"}
    )
    RawDescriptionRichHelpFormatter.group_name_formatter = str.upper
    parser = argparse.ArgumentParser(
        prog="agent-latch",
        usage="agent-latch [scan] [path] [options]",
        description=(
            f"[bold bright_cyan]AgentLatch[/bold bright_cyan] [dim]v{__version__}[/dim]\n"
            "Local-first security checks for AI-agent projects."
        ),
        epilog=_EPILOG,
        formatter_class=RawDescriptionRichHelpFormatter,
    )
    parser.add_argument("path", nargs="?", default=".", help="Project directory or file (default: current directory)")
    parser.add_argument("-V", "--version", action="version", version=f"agent-latch {__version__}")

    checks = parser.add_argument_group("Checks")
    checks.add_argument(
        "--config",
        metavar="MANIFEST",
        help="Agent manifest declaring tools and prompts (default: agent-manifest.yaml in the target, if present)",
    )
    checks.add_argument(
        "--exclude",
        metavar="PATH",
        action="append",
        default=[],
        help="Skip findings under this path or glob, relative to the target (repeatable)",
    )
    checks.add_argument(
        "--ignore-file",
        metavar="FILE",
        help="Ignore file of accepted findings (default: .agent-latch-ignore in the target, if present)",
    )
    checks.add_argument(
        "--dependencies",
        action="store_true",
        help="Audit requirements*.txt with pip-audit (contacts advisory service; no package install)",
    )
    checks.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Launch the guided terminal scanner",
    )

    output = parser.add_argument_group("Output")
    output.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Report format (default: text)")
    output.add_argument("--output", metavar="FILE", help="Write report to a file instead of stdout")
    output.add_argument(
        "--plain",
        action="store_true",
        help="Plain-text report even in a terminal (the table is used only when stdout is a terminal)",
    )

    ci = parser.add_argument_group("CI")
    ci.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Exit 1 for this severity or higher; unknown-severity findings also fail closed",
    )
    return parser


def _render_findings(console: Console, findings: list[Finding]) -> None:
    if not findings:
        console.print(
            Panel(
                Text("No findings from the enabled checks. This does not mean the project is secure."),
                title="[green]Scan complete[/green]",
                border_style="green",
            )
        )
        return

    table = Table(title=f"Security findings · {len(findings)}", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Location", style="dim")
    table.add_column("OWASP")
    table.add_column("Finding")

    severity_styles = {
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
        "unknown": "dim",
    }
    for finding in sorted(findings, key=severity_sort_key):
        style = severity_styles.get(finding.severity, "white")
        detail = Text(finding.title, style="bold")
        detail.append("\n" + finding.message)
        detail.append("\nEvidence: " + finding.evidence, style="dim")
        table.add_row(
            Text(finding.severity.upper(), style=style),
            Text(finding.rule_id),
            Text(f"{finding.path}:{finding.line}:{finding.column}"),
            Text(", ".join(finding.owasp) or "—"),
            detail,
        )
    console.print(table)
    console.print("[dim]Findings need human review; they are not a security certification.[/dim]")


def _render_scan(
    console: Console,
    findings: list[Finding],
    target: Path,
    manifest: Path | None,
    dependency_manifests: int | None,
    suppressed: int = 0,
) -> None:
    target_message = Text("Target: ", style="bold")
    target_message.append(str(target))
    console.print(target_message)
    if manifest is not None:
        manifest_message = Text("Manifest: ", style="bold")
        manifest_message.append(str(manifest))
        console.print(manifest_message)
    if dependency_manifests is not None:
        if dependency_manifests:
            console.print(
                f"[dim]Dependency audit checked {dependency_manifests} requirements manifest(s).[/dim]"
            )
        else:
            console.print(
                "[yellow]No supported requirements*.txt files found; dependency audit had no coverage.[/yellow]"
            )
    if suppressed:
        console.print(f"[dim]{suppressed} finding(s) suppressed by ignore rules or inline comments.[/dim]")
    _render_findings(console, findings)


def _write_interactive_report(
    console: Console,
    findings: list[Finding],
    target: Path,
    dependency_manifests: int | None,
) -> None:
    report_format = Prompt.ask(
        "Export a machine-readable report?",
        choices=["skip", "json", "sarif"],
        default="skip",
    )
    if report_format == "skip":
        return

    default_name = f"agent-latch-report.{report_format}"
    output_text = Prompt.ask("Report filename", default=default_name)
    output_path = Path(output_text).expanduser()
    if output_path.exists() and not Confirm.ask(
        Text(f"{output_path} already exists. Overwrite it?", style="yellow"), default=False
    ):
        console.print("[yellow]Report export skipped.[/yellow]")
        return

    report = (
        json_report(findings, str(target), dependency_manifests)
        if report_format == "json"
        else sarif_report(findings, str(target), dependency_manifests)
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report + "\n", encoding="utf-8")
    saved_message = Text("Report saved: ", style="green")
    saved_message.append(str(output_path.resolve()))
    console.print(saved_message)


def interactive_main() -> int:
    console = Console()
    console.print(
        Panel.fit(
            "[bold bright_cyan]AgentLatch[/bold bright_cyan]"
            f"  [dim]v{__version__}[/dim]\n"
            "[white]Local-first security checks for AI-agent projects[/white]",
            border_style="bright_cyan",
        )
    )
    console.print("[dim]Selected static checks only—not a complete security assessment.[/dim]\n")

    try:
        target = Path(Prompt.ask("Project folder or file", default=".")).expanduser().resolve()
        if not target.exists():
            console.print(Text(f"Path not found: {target}", style="bold red"))
            return 2

        include_dependencies = Confirm.ask(
            "Run optional Python dependency audit? It contacts the advisory service with package names and versions.",
            default=False,
        )

        manifest = find_manifest(target)
        with console.status("[bold cyan]Scanning source and configuration files…"):
            findings = scan_project(target)
            if manifest is not None:
                findings.extend(scan_manifest(manifest, target))

        dependency_manifests: int | None = None
        if include_dependencies:
            with console.status("[bold cyan]Checking dependency advisories…"):
                dependency_findings, dependency_manifests = audit_requirements(target)
            findings.extend(dependency_findings)

        base = target if target.is_dir() else target.parent
        findings, suppressed = filter_findings(findings, base, load_ignore_rules(target))

        console.print()
        _render_scan(console, findings, target, manifest, dependency_manifests, suppressed)
        _write_interactive_report(console, findings, target, dependency_manifests)
        return 0
    except (ManifestError, ConfigError) as exc:
        error_message = Text("Configuration error: ", style="bold red")
        error_message.append(str(exc))
        console.print(error_message)
        return 2
    except DependencyAuditError as exc:
        error_message = Text("Dependency audit failed: ", style="bold red")
        error_message.append(str(exc))
        console.print(error_message)
        return 2
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Scan cancelled.[/yellow]")
        return 130
    except OSError as exc:
        error_message = Text("Could not complete the scan: ", style="bold red")
        error_message.append(str(exc))
        console.print(error_message)
        return 2


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # "scan" is an optional verb; `agent-latch <path>` keeps working. Use ./scan for a folder named scan.
    if argv[:1] == ["scan"]:
        argv = argv[1:]
    args = build_parser().parse_args(argv)
    if args.interactive:
        return interactive_main()

    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        print(f"Error: scan target does not exist: {target}", file=sys.stderr)
        return 2

    if args.config:
        manifest: Path | None = Path(args.config).expanduser()
        if not manifest.is_file():
            print(f"Error: manifest does not exist: {manifest}", file=sys.stderr)
            return 2
    else:
        manifest = find_manifest(target)

    findings = scan_project(target)
    if manifest is not None:
        try:
            findings.extend(scan_manifest(manifest, target))
        except ManifestError as exc:
            print(f"Manifest error: {exc}", file=sys.stderr)
            return 2
    manifest_text = str(manifest) if manifest is not None else None

    dependency_manifests: int | None = None
    if args.dependencies:
        try:
            dependency_findings, dependency_manifests = audit_requirements(target)
        except DependencyAuditError as exc:
            print(f"Dependency audit error: {exc}", file=sys.stderr)
            return 2
        findings.extend(dependency_findings)

    try:
        ignore_file = Path(args.ignore_file).expanduser() if args.ignore_file else None
        ignore_rules = load_ignore_rules(target, args.exclude, ignore_file)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    base = target if target.is_dir() else target.parent
    findings, suppressed = filter_findings(findings, base, ignore_rules)

    if args.format == "json":
        report = json_report(findings, str(target), dependency_manifests, manifest_text, suppressed)
    elif args.format == "sarif":
        report = sarif_report(findings, str(target), dependency_manifests, manifest_text)
    else:
        report = text_report(findings, str(target), dependency_manifests, manifest_text, suppressed)

    if args.format == "text" and not args.output and not args.plain and sys.stdout.isatty():
        _render_scan(Console(), findings, target, manifest, dependency_manifests, suppressed)
    elif args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 99}
    threshold = severity_rank[args.fail_on]
    if args.fail_on != "none" and any(
        finding.severity == "unknown"
        or severity_rank.get(finding.severity, 99) <= threshold
        for finding in findings
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
