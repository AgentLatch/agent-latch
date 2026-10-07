"""The Finding value type and helpers shared by every rule module."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

# Tests use fake credentials and switch safety features off on purpose. Rules that are noisy there
# still report test-file findings, at low severity, so a real problem in a test is not hidden.
_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing", "fixtures"}
_TEST_FILE = re.compile(r"(?i)^(?:test_.*|.*_test\.\w+|.*\.(?:test|spec)\.\w+|conftest\.py)$")


def is_test_path(relative_path: str) -> bool:
    parts = relative_path.split("/")
    return bool(_TEST_FILE.match(parts[-1])) or any(part.lower() in _TEST_DIRS for part in parts[:-1])


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
