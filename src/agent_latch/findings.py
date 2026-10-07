"""The Finding value type shared by every rule module."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    message: str
    path: str
    line: int
    column: int
    owasp: tuple[str, ...]
    confidence: str = "medium"
    evidence: str = ""


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Keep the first finding per rule and location, e.g. when the manifest and the project walker
    both check the same prompt file."""
    seen: set[tuple[str, str, int, int]] = set()
    kept: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line, finding.column)
        if key not in seen:
            seen.add(key)
            kept.append(finding)
    return sorted(kept, key=lambda finding: (finding.path, finding.line, finding.rule_id))
