"""Human-readable, JSON, and SARIF report serializers."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from agent_latch import __version__
from agent_latch.owasp import (
    OWASP_AGENTIC_TITLE,
    OWASP_AGENTIC_URL,
    category_entries,
    category_label,
    coverage,
    coverage_status,
)
from agent_latch.rules import Finding

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "warning",
}


def severity_sort_key(finding: Finding) -> tuple[int, str, int]:
    return (_SEVERITY_ORDER.get(finding.severity, 99), finding.path, finding.line)


def finding_dict(finding: Finding) -> dict[str, Any]:
    result = asdict(finding)
    result["owasp"] = list(finding.owasp)
    result["owasp_categories"] = category_entries(finding.owasp)
    return result


def owasp_labels(finding: Finding) -> str:
    return "; ".join(category_label(cid) for cid in finding.owasp) or "none"


def coverage_lines(findings: list[Finding]) -> list[str]:
    """Plain-text ASI01–ASI10 summary; categories without any rule are called out explicitly."""
    lines = [f"{OWASP_AGENTIC_TITLE} (informational mapping):"]
    for entry in coverage(findings):
        lines.append(f"  {entry['id']} {entry['name']}: {coverage_status(entry)}")
    return lines


def json_report(
    findings: list[Finding],
    scanned_path: str,
    dependency_manifests: int | None = None,
    manifest: str | None = None,
    suppressed: int = 0,
    min_severity: str | None = None,
    hidden: int = 0,
) -> str:
    payload = {
        "scanner": {"name": "AgentLatch", "version": __version__},
        "scan_target": scanned_path,
        "manifest": manifest,
        "finding_count": len(findings),
        "suppressed_count": suppressed,
        "min_severity": min_severity,
        "hidden_below_min_severity": hidden,
        "dependency_audit": (
            {
                "status": "completed" if dependency_manifests else "no_supported_manifests",
                "manifest_count": dependency_manifests,
                "note": "Uses pip-audit advisory data; package names and versions are sent to its configured vulnerability service. No package installation or dependency resolution is performed.",
            }
            if dependency_manifests is not None
            else None
        ),
        "findings": [finding_dict(item) for item in findings],
        "owasp_agentic": {
            "title": OWASP_AGENTIC_TITLE,
            "url": OWASP_AGENTIC_URL,
            "categories": coverage(findings),
            "note": "Informational mapping, not a compliance assessment. has_checks=false means AgentLatch has no rule for that category yet.",
        },
        "disclaimer": "Selected static checks only; this is not a certification or proof that the project is secure.",
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def sarif_report(
    findings: list[Finding],
    scanned_path: str,
    dependency_manifests: int | None = None,
    manifest: str | None = None,
    suppressed: int = 0,
    min_severity: str | None = None,
    hidden: int = 0,
) -> str:
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rules_by_id.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {
                    "text": f"{finding.message}\n\nOWASP Agentic mapping: {owasp_labels(finding)}"
                },
                "properties": {
                    "tags": ["security", *finding.owasp],
                    "owaspCategories": category_entries(finding.owasp),
                },
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                                "snippet": {"text": finding.evidence},
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "owasp": list(finding.owasp),
                    "owaspCategories": category_entries(finding.owasp),
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentLatch",
                        "version": __version__,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "artifacts": [{"location": {"uri": scanned_path}}],
                "properties": {
                    "agentManifest": manifest,
                    "dependencyAuditManifestCount": dependency_manifests,
                    "dependencyAuditStatus": (
                        ("completed" if dependency_manifests else "no_supported_manifests")
                        if dependency_manifests is not None
                        else "not_requested"
                    ),
                    "owaspAgenticCoverage": coverage(findings),
                    "suppressedCount": suppressed,
                    "minSeverity": min_severity,
                    "hiddenBelowMinSeverityCount": hidden,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def text_report(
    findings: list[Finding],
    scanned_path: str,
    dependency_manifests: int | None = None,
    manifest: str | None = None,
    suppressed: int = 0,
    min_severity: str | None = None,
    hidden: int = 0,
) -> str:
    header = f"AgentLatch scan: {scanned_path}"
    if manifest is not None:
        header += f"\nManifest: {manifest}"
    if suppressed:
        header += f"\n{suppressed} finding(s) suppressed by ignore rules or inline comments."
    if hidden:
        header += f"\n{hidden} finding(s) below --min-severity {min_severity} not shown."
    if not findings:
        lines = [
            header,
            "No findings from the enabled checks. This does not mean the project is secure.",
        ]
        if dependency_manifests is not None:
            lines.append(
                "Dependency audit: "
                + (
                    f"completed ({dependency_manifests} requirements manifest(s)); no known advisories found."
                    if dependency_manifests
                    else "not run; no supported requirements*.txt manifest found."
                )
            )
            lines.append(
                "The dependency audit sends package names and versions to the configured vulnerability service; it does not install packages."
            )
        lines.extend(["", *coverage_lines(findings)])
        return "\n".join(lines)
    lines = [header, f"Findings: {len(findings)}", ""]
    if dependency_manifests is not None:
        lines.insert(
            2,
            "Dependency audit: "
            + (
                f"completed ({dependency_manifests} requirements manifest(s))."
                if dependency_manifests
                else "not run; no supported requirements*.txt manifest found."
            ),
        )
        lines.insert(
            3,
            "Dependency audit sends package names and versions to the configured advisory service; no packages are installed.",
        )
    ordered = sorted(findings, key=severity_sort_key)
    for finding in ordered:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}",
                f"  {finding.path}:{finding.line}:{finding.column}",
                f"  {finding.message}",
                f"  OWASP Agentic: {owasp_labels(finding)} | confidence: {finding.confidence}",
                f"  Evidence: {finding.evidence}",
                "",
            ]
        )
    lines.extend([*coverage_lines(findings), ""])
    lines.append("Selected static checks only; findings require human review.")
    return "\n".join(lines)
