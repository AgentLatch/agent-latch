"""GitHub Action post-processing: repo-relative SARIF paths and the job summary page.

Run by action.yml as `python -m agent_latch.action_summary` after the scan. Reads SARIF_FILE,
SCAN_PATH, FAIL_ON, EXIT_CODE, GITHUB_WORKSPACE, GITHUB_STEP_SUMMARY, and GITHUB_OUTPUT.

Paths, evidence, and messages come from the scanned project, which is untrusted, so every value is
escaped before it goes into Markdown: a crafted file name cannot add links, images, or HTML.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from agent_latch.owasp import OWASP_AGENTIC_TITLE, coverage_status

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}
_FAIL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ICONS = {"critical": "🟥", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪", "unknown": "⚪"}
# GitHub caps a step summary at 1 MiB; these keep large scans well under it.
MAX_BLOCKING_ROWS = 100
MAX_OTHER_ROWS = 200
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~])")


def cell(text: str, limit: int = 160) -> str:
    """Untrusted text as a single, inert Markdown table cell."""
    flat = " ".join(str(text).split())
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    return _MARKDOWN_SPECIAL.sub(r"\\\1", flat)


def code(text: str) -> str:
    """Untrusted text as inline code. Backticks and pipes are removed so the span cannot break out."""
    return "`" + " ".join(str(text).split()).replace("`", "'").replace("|", "/") + "`"


def rewrite_uris(run: dict[str, Any], workspace: Path, target: Path) -> None:
    """AgentLatch reports paths relative to the scan target; code scanning needs repo-relative URIs."""
    base = target if target.is_dir() else target.parent
    prefix = base.relative_to(workspace).as_posix() if base.is_relative_to(workspace) else ""
    for result in run.get("results", []):
        for location in result.get("locations", []):
            artifact = location["physicalLocation"]["artifactLocation"]
            if prefix not in ("", ".") and not artifact["uri"].startswith("/"):
                artifact["uri"] = f"{prefix}/{artifact['uri']}"
    run.pop("artifacts", None)


def _rows(run: dict[str, Any]) -> list[dict[str, str]]:
    titles = {rule["id"]: rule.get("name", rule["id"]) for rule in run["tool"]["driver"].get("rules", [])}
    rows = []
    for result in run.get("results", []):
        physical = result["locations"][0]["physicalLocation"]
        region = physical.get("region", {})
        severity = str(result.get("properties", {}).get("severity", "unknown")).lower()
        rows.append(
            {
                "severity": severity if severity in _RANK else "unknown",
                "rule": result["ruleId"],
                "title": titles.get(result["ruleId"], result["ruleId"]),
                "location": f"{physical['artifactLocation']['uri']}:{region.get('startLine', 1)}",
                "evidence": region.get("snippet", {}).get("text", ""),
            }
        )
    rows.sort(key=lambda row: (_RANK[row["severity"]], row["location"], row["rule"]))
    return rows


def is_blocking(severity: str, fail_on: str) -> bool:
    if fail_on not in _FAIL_RANK:
        return False
    # Mirrors the CLI: unknown severity fails closed.
    return severity == "unknown" or _RANK.get(severity, 99) <= _FAIL_RANK[fail_on]


def _short_rule(rule_id: str) -> str:
    return rule_id.removeprefix("AGENTLATCH-")


def _finding_table(rows: list[dict[str, str]], limit: int) -> list[str]:
    lines = ["| Severity | Rule | Location | Finding | Evidence |", "|---|---|---|---|---|"]
    for row in rows[:limit]:
        lines.append(
            f"| {_ICONS[row['severity']]} {row['severity'].upper()} | `{_short_rule(row['rule'])}` "
            f"| {code(row['location'])} | {cell(row['title'], 80)} | {cell(row['evidence'], 100)} |"
        )
    if len(rows) > limit:
        lines += ["", f"_…and {len(rows) - limit} more. Download the SARIF report for the full list._"]
    return lines


def render_summary(run: dict[str, Any], fail_on: str, exit_code: str) -> str:
    rows = _rows(run)
    counts = Counter(row["severity"] for row in rows)
    blocking = [row for row in rows if is_blocking(row["severity"], fail_on)]
    others = [row for row in rows if not is_blocking(row["severity"], fail_on)]

    if exit_code == "1" or blocking:
        headline = f"## ❌ AgentLatch: {len(blocking)} finding(s) at or above `{fail_on}`"
    elif fail_on == "none":
        headline = f"## ℹ️ AgentLatch: {len(rows)} finding(s) (`fail-on: none`)"
    else:
        headline = f"## ✅ AgentLatch: no findings at or above `{fail_on}`"
    lines = [headline, ""]

    shown = [severity for severity in SEVERITIES if counts[severity] or severity in ("critical", "high", "medium", "low")]
    lines += [
        "| " + " | ".join(f"{_ICONS[s]} {s.capitalize()}" for s in shown) + " | **Total** |",
        "|" + "---|" * (len(shown) + 1),
        "| " + " | ".join(str(counts[s]) for s in shown) + f" | **{len(rows)}** |",
        "",
    ]
    properties = run.get("properties", {})
    notes = []
    if properties.get("hiddenBelowMinSeverityCount"):
        notes.append(
            f"{properties['hiddenBelowMinSeverityCount']} finding(s) below `min-severity: "
            f"{cell(properties.get('minSeverity') or '', 20)}` not shown"
        )
    if properties.get("suppressedCount"):
        notes.append(f"{properties['suppressedCount']} finding(s) suppressed by `project-ignores`")
    if notes:
        lines += ["_" + "; ".join(notes) + "._", ""]
    if not rows:
        lines += ["No findings from the enabled checks. This does not mean the project is secure.", ""]

    if rows:
        by_rule: dict[str, dict[str, Any]] = {}
        for row in rows:
            entry = by_rule.setdefault(row["rule"], {"title": row["title"], "count": 0, "worst": row["severity"]})
            entry["count"] += 1
            if _RANK[row["severity"]] < _RANK[entry["worst"]]:
                entry["worst"] = row["severity"]
        lines += ["### Findings by rule", "", "| Rule | Title | Highest severity | Count |", "|---|---|---|---:|"]
        for rule, entry in sorted(by_rule.items(), key=lambda item: (_RANK[item[1]["worst"]], -item[1]["count"])):
            lines.append(
                f"| `{_short_rule(rule)}` | {cell(entry['title'], 80)} "
                f"| {_ICONS[entry['worst']]} {entry['worst'].upper()} | {entry['count']} |"
            )
        lines.append("")

    categories = run.get("properties", {}).get("owaspAgenticCoverage", [])
    if categories:
        lines += [f"### {OWASP_AGENTIC_TITLE}", "", "| ID | Category | Status |", "|---|---|---|"]
        for entry in categories:
            status = coverage_status(entry)
            if entry.get("finding_count"):
                status = f"**{status}**"
            elif not entry.get("has_checks"):
                status = f"_{status}_"
            lines.append(f"| {entry['id']} | {cell(entry['name'], 60)} | {status} |")
        lines += ["", "_Informational mapping, not a compliance assessment or OWASP endorsement._", ""]

    if blocking:
        lines += [f"### Blocking findings ({len(blocking)})", "", *_finding_table(blocking, MAX_BLOCKING_ROWS), ""]
    if others:
        label = "Other findings" if blocking else "Findings"
        lines += [
            "<details>",
            f"<summary>{label} ({len(others)})</summary>",
            "",
            *_finding_table(others, MAX_OTHER_ROWS),
            "",
            "</details>",
            "",
        ]
    lines.append("_Selected static checks only; findings need human review and are not a security certification._")
    return "\n".join(lines) + "\n"


def log_summary(run: dict[str, Any], fail_on: str) -> str:
    """A few lines for the step log; the CLI already printed the blocking findings."""
    rows = _rows(run)
    counts = Counter(row["severity"] for row in rows)
    parts = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]) or "none"
    blocking = sum(is_blocking(row["severity"], fail_on) for row in rows)
    return (
        f"AgentLatch: {len(rows)} finding(s) ({parts}); {blocking} at or above fail-on '{fail_on}'.\n"
        "See the job summary for tables, and the SARIF report for full details."
    )


def main() -> int:
    sarif_path = Path(os.environ["SARIF_FILE"])
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    rewrite_uris(
        run,
        Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve(),
        Path(os.environ.get("SCAN_PATH", ".")).resolve(),
    )
    sarif_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    fail_on = os.environ.get("FAIL_ON", "none")
    print(log_summary(run, fail_on))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write(render_summary(run, fail_on, os.environ.get("EXIT_CODE", "")))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"finding-count={len(run.get('results', []))}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
