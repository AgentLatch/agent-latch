"""Excluded paths, ignore files, and inline suppressions for accepted findings.

Sources, all applied after scanning:
- `.agent-latch-ignore` in the scan target (or --ignore-file): one entry per line,
  `PATH`, `RULE PATH`, or `RULE PATH:LINE`, with `#` comments for the reason.
- `[tool.agent-latch] exclude` in the target's pyproject.toml, and --exclude.
- Inline comments on the finding's line:

    eval(expr)  # agent-latch: ignore[PY001] -- sandboxed calculator input

The `.agent-latch-ignore` file, pyproject.toml, and inline comments live in the scanned project, so
whoever wrote the project controls them. They apply only with `--project-ignores`; --exclude and an
explicit --ignore-file always apply.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from agent_latch.rules import Finding

IGNORE_FILE = ".agent-latch-ignore"
_INLINE_IGNORE = re.compile(r"agent-latch:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE)
_RULE_ID = re.compile(r"^(?:AGENTLATCH-)?[A-Z]{2,4}\d{3}$", re.IGNORECASE)
_COMMENT = re.compile(r"(?:^|\s)#.*$")


class ConfigError(ValueError):
    """Raised when an ignore file or [tool.agent-latch] configuration is malformed."""


@dataclass(frozen=True)
class IgnoreRule:
    """Suppress findings matching a path pattern, optionally limited to one rule and line."""

    pattern: str
    rule: str | None = None
    line: int | None = None

    def matches(self, finding: Finding) -> bool:
        if self.rule is not None and _normalize_rule(finding.rule_id) != self.rule:
            return False
        if self.line is not None and finding.line != self.line:
            return False
        return is_excluded(finding.path, [self.pattern])


def _normalize_rule(rule_id: str) -> str:
    return rule_id.strip().upper().removeprefix("AGENTLATCH-")


def _base(target: Path) -> Path:
    return target if target.is_dir() else target.parent


def load_excludes(target: Path) -> list[str]:
    """Read `[tool.agent-latch] exclude` from pyproject.toml in the scan target directory."""
    pyproject = _base(target) / "pyproject.toml"
    if not pyproject.is_file():
        return []
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read {pyproject}: {exc}") from exc
    excludes = data.get("tool", {}).get("agent-latch", {}).get("exclude", [])
    if not isinstance(excludes, list) or not all(isinstance(item, str) for item in excludes):
        raise ConfigError(f"[tool.agent-latch] exclude in {pyproject} must be a list of strings")
    return excludes


def parse_ignore_file(text: str, source: str = IGNORE_FILE) -> list[IgnoreRule]:
    rules: list[IgnoreRule] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        tokens = _COMMENT.sub("", raw).split()
        if not tokens:
            continue
        if len(tokens) > 2 or (len(tokens) == 2 and not _RULE_ID.match(tokens[0])):
            raise ConfigError(
                f"{source}:{number}: expected 'PATH', 'RULE PATH', or 'RULE PATH:LINE', got {raw.strip()!r}"
            )
        rule = _normalize_rule(tokens[0]) if len(tokens) == 2 else None
        pattern, line = tokens[-1], None
        head, sep, tail = pattern.rpartition(":")
        if sep and tail.isdigit():
            pattern, line = head, int(tail)
        if line is not None and rule is None:
            raise ConfigError(f"{source}:{number}: a line number needs a rule, e.g. 'SEC001 {tokens[-1]}'")
        rules.append(IgnoreRule(pattern, rule, line))
    return rules


def load_ignore_rules(
    target: Path,
    excludes: Iterable[str] = (),
    ignore_file: Path | None = None,
    project_config: bool = False,
) -> list[IgnoreRule]:
    """Collect suppressions from --exclude, an explicit ignore file, and, if project_config,
    the target's own .agent-latch-ignore and pyproject.toml.
    """
    path = ignore_file if ignore_file is not None else _base(target) / IGNORE_FILE
    rules: list[IgnoreRule] = []
    if ignore_file is not None or (project_config and path.is_file()):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"could not read ignore file {path}: {exc.strerror or exc}") from exc
        rules.extend(parse_ignore_file(text, str(path)))
    project_excludes = load_excludes(target) if project_config else []
    rules.extend(IgnoreRule(pattern) for pattern in [*project_excludes, *excludes])
    return rules


def is_excluded(relative_path: str, patterns: Iterable[str]) -> bool:
    """Match a POSIX path relative to the scan root against directory prefixes or globs."""
    for pattern in patterns:
        pattern = pattern.strip().removeprefix("./")
        if not pattern:
            continue
        if any(char in pattern for char in "*?["):
            if fnmatch.fnmatch(relative_path, pattern):
                return True
        else:
            prefix = pattern.rstrip("/")
            if relative_path == prefix or relative_path.startswith(prefix + "/"):
                return True
    return False


def _inline_ignored(finding: Finding, line_text: str) -> bool:
    match = _INLINE_IGNORE.search(line_text)
    if not match:
        return False
    if match.group(1) is None:
        return True
    rules = {_normalize_rule(item) for item in match.group(1).split(",") if item.strip()}
    return _normalize_rule(finding.rule_id) in rules


def filter_findings(
    findings: list[Finding], base: Path, rules: Iterable[IgnoreRule], inline: bool = False
) -> tuple[list[Finding], int]:
    """Drop findings matched by an ignore rule or (if inline) an ignore comment on their line."""
    rules = list(rules)
    lines_by_file: dict[str, list[str]] = {}
    kept: list[Finding] = []
    for finding in findings:
        if any(rule.matches(finding) for rule in rules):
            continue
        if not inline:
            kept.append(finding)
            continue
        if finding.path not in lines_by_file:
            try:
                lines_by_file[finding.path] = (base / finding.path).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                lines_by_file[finding.path] = []
        lines = lines_by_file[finding.path]
        if 0 < finding.line <= len(lines) and _inline_ignored(finding, lines[finding.line - 1]):
            continue
        kept.append(finding)
    return kept, len(findings) - len(kept)
