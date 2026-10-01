"""Human-readable, JSON, and SARIF report serializers."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from agent_latch import __version__
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


def finding_dict(finding: Finding) -> dict[str, Any]:
    result = asdict(finding)
    result["owasp"] = list(finding.owasp)
    return result


def json_report(
    findings: list[Finding], scanned_path: str, dependency_manifests: int | None = None
) -> str:
    payload = {
        "scanner": {"name": "AgentLatch", "version": __version__},
        "scan_target": scanned_path,
        "finding_count": len(findings),
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
        "disclaimer": "Selected static checks only; this is not a certification or proof that the project is secure.",
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def sarif_report(
    findings: list[Finding], scanned_path: str, dependency_manifests: int | None = None
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
                "help": {"text": finding.message},
                "properties": {"tags": ["security", *finding.owasp]},
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
                    "dependencyAuditManifestCount": dependency_manifests,
                    "dependencyAuditStatus": (
                        ("completed" if dependency_manifests else "no_supported_manifests")
                        if dependency_manifests is not None
                        else "not_requested"
                    ),
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def text_report(
    findings: list[Finding], scanned_path: str, dependency_manifests: int | None = None
) -> str:
    if not findings:
        lines = [
            f"AgentLatch scan: {scanned_path}",
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
        return "\n".join(lines)
    lines = [f"AgentLatch scan: {scanned_path}", f"Findings: {len(findings)}", ""]
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
    ordered = sorted(findings, key=lambda item: (_SEVERITY_ORDER.get(item.severity, 99), item.path, item.line))
    for finding in ordered:
        mappings = ", ".join(finding.owasp)
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}",
                f"  {finding.path}:{finding.line}:{finding.column}",
                f"  {finding.message}",
                f"  OWASP mapping: {mappings} | confidence: {finding.confidence}",
                f"  Evidence: {finding.evidence}",
                "",
            ]
        )
    lines.append("Selected static checks only; findings require human review.")
    return "\n".join(lines)
