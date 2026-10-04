"""Small, explainable static checks. Findings are heuristics, not proof of exploitability."""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_latch.taint import find_untrusted_prompt_flows

#pr workflow test
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


class DependencyAuditError(RuntimeError):
    """Raised when the optional dependency audit cannot complete reliably."""


# Deliberately avoids returning matched secret text as evidence.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|password|access[_-]?token|auth[_-]?token)"
    r"\b\s*[:=]\s*(['\"])([^'\"\s]{8,})\1"
)
_PLACEHOLDERS = {"changeme", "example", "placeholder", "your_api_key", "your-secret-key"}


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def scan_python(path: Path, root: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    dataframe_agent_names = {"create_pandas_dataframe_agent"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for imported in node.names:
                if imported.name == "create_pandas_dataframe_agent":
                    dataframe_agent_names.add(imported.asname or imported.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = node.func.id if isinstance(node.func, ast.Name) else None
        qualified_call = (
            f"{node.func.value.id}.{node.func.attr}"
            if isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            else None
        )
        if called in {"eval", "exec"}:
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-PY001",
                    title="Dynamic code execution",
                    severity="high",
                    message=f"{called}() executes dynamically supplied code; verify input provenance and necessity.",
                    path=_relative(path, root),
                    line=node.lineno,
                    column=node.col_offset + 1,
                    owasp=("ASI05", "ASI02"),
                    confidence="high",
                    evidence=f"{called}(...) call",
                )
            )

        if (
            called in dataframe_agent_names
            or (
                qualified_call is not None
                and qualified_call.endswith(".create_pandas_dataframe_agent")
            )
        ):
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-AG002",
                    title="Agent can execute model-generated Python",
                    severity="high",
                    message=(
                        "This LangChain dataframe-agent factory can execute generated Python. "
                        "Review allow_dangerous_code gating and isolate execution from secrets and sensitive files."
                    ),
                    path=_relative(path, root),
                    line=node.lineno,
                    column=node.col_offset + 1,
                    owasp=("ASI05", "ASI02"),
                    confidence="high",
                    evidence="create_pandas_dataframe_agent(...) call",
                )
            )

        if (
            qualified_call
            and qualified_call.startswith("subprocess.")
            and any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
        ):
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-PY002",
                    title="Subprocess uses shell=True",
                    severity="high",
                    message="Shell command construction can enable command injection, especially with untrusted or model-generated input.",
                    path=_relative(path, root),
                    line=node.lineno,
                    column=node.col_offset + 1,
                    owasp=("ASI05", "ASI02"),
                    confidence="high",
                    evidence="call with shell=True",
                )
            )

        if any(
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        ):
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-PY003",
                    title="TLS certificate verification disabled",
                    severity="high",
                    message="Disabling TLS verification weakens protection against interception of tool or API traffic.",
                    path=_relative(path, root),
                    line=node.lineno,
                    column=node.col_offset + 1,
                    owasp=("ASI02",),
                    confidence="high",
                    evidence="call with verify=False",
                )
            )

        if called == "Agent" and any(
            keyword.arg == "allow_delegation"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-AG001",
                    title="CrewAI delegation enabled",
                    severity="low",
                    message="Delegation expands agent actions; review delegated tools, permissions, and approval boundaries.",
                    path=_relative(path, root),
                    line=node.lineno,
                    column=node.col_offset + 1,
                    owasp=("ASI02", "ASI03"),
                    confidence="low",
                    evidence="Agent(..., allow_delegation=True)",
                )
            )

    for flow in find_untrusted_prompt_flows(tree):
        findings.append(
            Finding(
                rule_id="AGENTLATCH-AG003",
                title="Untrusted web/tool output inserted into prompt",
                severity="medium",
                message=(
                    "Content fetched from the web or a search/loader tool reaches an LLM message unfenced, "
                    "so instructions hidden in that content can hijack the agent (indirect prompt injection). "
                    "Wrap it in delimiters such as <search_results> tags, tell the model to treat it as data, "
                    "and limit what tools the agent can call afterwards."
                ),
                path=_relative(path, root),
                line=flow.line,
                column=flow.column,
                owasp=("ASI01",),
                confidence="low",
                evidence=f"web/tool output reaches {flow.sink}",
            )
        )

    return findings


def scan_secrets(path: Path, root: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        match = _SECRET_ASSIGNMENT.search(line)
        if not match:
            continue
        value = match.group(2)
        if value.lower() in _PLACEHOLDERS or value.lower().startswith(("your_", "example_")):
            continue
        findings.append(
            Finding(
                rule_id="AGENTLATCH-SEC001",
                title="Possible hardcoded credential",
                severity="high",
                message="A credential-like variable appears to contain a literal value. Use a secret manager or environment variable.",
                path=_relative(path, root),
                line=line_number,
                column=match.start() + 1,
                owasp=("ASI03", "ASI04"),
                confidence="medium",
                evidence="credential-like assignment; value redacted",
            )
        )
    return findings


def scan_project(target: Path, max_file_bytes: int = 1_000_000) -> list[Finding]:
    root = target.resolve()
    files = [root] if root.is_file() else sorted(root.rglob("*"))
    findings: list[Finding] = []
    ignored_parts = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"}
    supported_suffixes = {".py", ".env", ".txt", ".toml", ".yaml", ".yml"}

    for path in files:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            relative_parts = path.relative_to(root).parts if root.is_dir() else (path.name,)
            if any(part in ignored_parts for part in relative_parts):
                continue
            if path.suffix.lower() not in supported_suffixes and not path.name.startswith(".env"):
                continue
            if path.stat().st_size > max_file_bytes:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue

        if path.suffix.lower() == ".py":
            findings.extend(scan_python(path, root if root.is_dir() else root.parent, source))
        findings.extend(scan_secrets(path, root if root.is_dir() else root.parent, source))

    return sorted(findings, key=lambda finding: (finding.path, finding.line, finding.rule_id))


def _requirement_line(path: Path, package_name: str) -> int:
    normalized = re.sub(r"[-_.]+", "-", package_name).lower()
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            candidate = line.strip()
            if not candidate or candidate.startswith(("#", "-")):
                continue
            match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[]|$)", candidate)
            if match and re.sub(r"[-_.]+", "-", match.group(1)).lower() == normalized:
                return line_number
    except OSError:
        pass
    return 1


def audit_requirements(target: Path) -> tuple[list[Finding], int]:
    """Audit exact-pinned requirements via pip-audit without installing packages.

    This contacts the configured vulnerability service and discloses package names
    and versions, but not project source. Dependency resolution and pip are disabled.
    """
    root = target.resolve()
    if root.is_file():
        manifests = [root] if root.name.startswith("requirements") and root.suffix == ".txt" else []
        base = root.parent
    else:
        base = root
        manifests = sorted(
            path for path in root.rglob("requirements*.txt")
            if path.is_file()
            and not path.is_symlink()
            and not any(part in {".git", ".venv", "venv", "node_modules", "__pycache__"}
                        for part in path.relative_to(root).parts)
        )

    if not manifests:
        return [], 0

    findings: list[Finding] = []
    seen_advisories: set[tuple[str, str, str, str]] = set()
    for manifest in manifests:
        command = [
            sys.executable,
            "-m",
            "pip_audit",
            "--requirement",
            str(manifest),
            "--no-deps",
            "--disable-pip",
            "--format",
            "json",
            "--progress-spinner",
            "off",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=base,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DependencyAuditError(
                "Could not run pip-audit; install AgentLatch with its audit extra and retry"
            ) from exc

        try:
            payload: Any = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise DependencyAuditError(
                "pip-audit did not return valid JSON; check its availability, requirements format, and network access"
            ) from exc

        dependencies = dependency_entries(payload)
        if dependencies is None:
            raise DependencyAuditError("pip-audit returned an unexpected JSON format")

        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            package = str(dependency.get("name", "unknown"))
            version = str(dependency.get("version", "unknown"))
            vulnerabilities = dependency.get("vulns") or []
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                advisory = str(vulnerability.get("id", "unknown advisory"))
                dedupe_key = (
                    manifest.relative_to(base).as_posix(),
                    re.sub(r"[-_.]+", "-", package).lower(),
                    version,
                    advisory.upper(),
                )
                if dedupe_key in seen_advisories:
                    continue
                seen_advisories.add(dedupe_key)
                aliases = vulnerability.get("aliases") or []
                fixes = vulnerability.get("fix_versions") or []
                alias_text = ", ".join(sorted({str(alias) for alias in aliases})[:5])
                fix_text = ", ".join(sorted({str(fix) for fix in fixes})[:5]) or "no fix version listed"
                message = (
                    f"{package} {version} has known advisory {advisory}; "
                    f"suggested fix: {fix_text}. Advisory severity was not provided by pip-audit."
                )
                if alias_text:
                    message += f" Aliases: {alias_text}."
                findings.append(
                    Finding(
                        rule_id="AGENTLATCH-DEP001",
                        title="Known vulnerable Python dependency",
                        severity="unknown",
                        message=message,
                        path=manifest.relative_to(base).as_posix(),
                        line=_requirement_line(manifest, package),
                        column=1,
                        owasp=("ASI04",),
                        confidence="high",
                        evidence=f"{package}=={version} ({advisory})",
                    )
                )

        if completed.returncode not in {0, 1} or (
            completed.returncode == 1 and not vulnerabilities_in_payload(dependencies)
        ):
            raise DependencyAuditError(
                "pip-audit could not complete; verify exact-pinned requirements and network access (raw output is suppressed to avoid exposing credentials)"
            )

    return (
        sorted(findings, key=lambda finding: (finding.path, finding.line, finding.message)),
        len(manifests),
    )


def dependency_entries(payload: Any) -> list[Any] | None:
    """Accept pip-audit's current object schema and older list-shaped output."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("dependencies"), list):
        return payload["dependencies"]
    return None


def vulnerabilities_in_payload(dependencies: list[Any]) -> bool:
    return any(
        isinstance(dependency, dict)
        and isinstance(dependency.get("vulns"), list)
        and bool(dependency["vulns"])
        for dependency in dependencies
    )
