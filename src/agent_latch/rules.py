"""Small, explainable static checks. Findings are heuristics, not proof of exploitability."""

from __future__ import annotations

import ast
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_latch.agent_code import scan_agent_code, scan_prompt_yaml
from agent_latch.astutil import walk
from agent_latch.findings import Finding, demote_test_findings, is_test_path
from agent_latch.prompts import check_prompt_text, looks_like_system_prompt
from agent_latch.taint import (
    ProjectLinks,
    find_model_output_actions,
    find_untrusted_prompt_flows,
    link_project,
)

__all__ = ["DependencyAuditError", "Finding", "audit_requirements", "scan_project"]

MANIFEST_NAMES = ("agent-manifest.yaml", "agent-manifest.yml")
# Standalone prompt templates. .md and .txt count only inside a prompts/ (or prompt/) folder.
PROMPT_SUFFIXES = {".prompt", ".prompty", ".j2", ".jinja", ".jinja2"}
_PROMPT_DIRS = {"prompt", "prompts"}


class DependencyAuditError(RuntimeError):
    """Raised when the optional dependency audit cannot complete reliably."""


# Deliberately avoids returning matched secret text as evidence. The optional quote after the key
# matches JSON and JavaScript object literals.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|secret(?:[_-]?key)?|password|access[_-]?token|auth[_-]?token)"
    r"\b['\"]?\s*[:=]\s*(?P<quote>['\"])(?P<value>[^'\"\s]{8,})(?P=quote)"
)
# Values that are obviously not real credentials: placeholders, test values, and template
# references such as ${API_KEY}, {{ secret }}, <token>, or $TOKEN.
_PLACEHOLDER_PREFIXES = (
    "your", "test", "fake", "dummy", "mock", "example", "sample", "placeholder", "changeme",
    "not-", "not_", "my-", "my_", "replace", "insert", "xxx", "***", "<", "${", "{{", "{", "%(", "$",
)
# "\\u" catches JSON-escaped text, such as translated UI labels.
_PLACEHOLDER_PARTS = ("...", "xxxx", "****", "redacted", "placeholder", "anything", "arbitrary", "\\u")
# UI translation folders map keys like "password" to words; letter-only values there are labels.
_I18N_DIRS = {"translations", "locales", "locale", "i18n", "l10n", "lang", "langs"}


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


_KERNEL_EXEC_METHODS = {"execute_interactive", "run_cell", "runsource", "runcode"}
_KERNEL_NAME = re.compile(r"(?i)(?:^|_)(?:kc|kernel|kernel_client|km|repl|interpreter|shell)$")


def _code_runner(node: ast.Call) -> str | None:
    """eval/exec, or a Jupyter kernel / REPL call that runs a code string (kc.execute(code), shell.run_cell)."""
    if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
        return node.func.id
    if not isinstance(node.func, ast.Attribute):
        return None
    receiver = node.func.value
    receiver_name = receiver.attr if isinstance(receiver, ast.Attribute) else getattr(receiver, "id", "")
    method = node.func.attr
    if method in _KERNEL_EXEC_METHODS or (method == "execute" and _KERNEL_NAME.search(receiver_name or "")):
        return f"{receiver_name}.{method}" if receiver_name else method
    return None


def parse_python(path: Path, source: str) -> ast.Module | None:
    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError:
        return None


def scan_python(
    path: Path, root: Path, source: str, links: ProjectLinks | None = None, tree: ast.Module | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    tree = tree or parse_python(path, source)
    if tree is None:
        return findings

    dataframe_agent_names = {"create_pandas_dataframe_agent"}
    for node in walk(tree):
        if isinstance(node, ast.ImportFrom):
            for imported in node.names:
                if imported.name == "create_pandas_dataframe_agent":
                    dataframe_agent_names.add(imported.asname or imported.name)

    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = node.func.id if isinstance(node.func, ast.Name) else None
        qualified_call = (
            f"{node.func.value.id}.{node.func.attr}"
            if isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            else None
        )
        runner = _code_runner(node)
        if runner:
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-PY001",
                    title="Dynamic code execution",
                    severity="high",
                    message=f"{runner}() executes dynamically supplied code; verify input provenance and necessity.",
                    path=_relative(path, root),
                    line=node.lineno,
                    column=node.col_offset + 1,
                    owasp=("ASI05", "ASI02"),
                    confidence="high",
                    evidence=f"{runner}(...) call",
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

    for action in find_model_output_actions(tree, links):
        findings.append(
            Finding(
                rule_id="AGENTLATCH-AG008",
                title="Model output drives a dangerous operation",
                severity="high",
                message=(
                    f"An LLM response or a model-chosen tool argument reaches {_ACTION_TEXT[action.kind]} without "
                    "validation (possibly through another file). A prompt-injected or hallucinated response then "
                    "decides what runs. Allow-list or parse the output (for SQL, "
                    "read-only statements on a least-privilege account), and require approval for writes."
                ),
                path=_relative(path, root),
                line=action.line,
                column=action.column,
                owasp=("ASI02", "ASI05"),
                confidence="medium",
                evidence=f"model output reaches {action.sink}",
            )
        )

    findings.extend(_password_default_findings(tree, _relative(path, root)))
    findings.extend(scan_agent_code(tree, _relative(path, root)))
    return demote_test_findings(findings, _relative(path, root))


_ACTION_TEXT = {
    "code_execution": "code or command execution",
    "database": "a database query",
    "network": "a network request (server-side request forgery)",
    "filesystem": "a file operation",
}


def _password_default_findings(tree: ast.Module, relative_path: str) -> list[Finding]:
    """SEC001 for UI password fields with a literal default, e.g. st.text_input(type="password", value="admin")."""
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        kind = keywords.get("type")
        if not (isinstance(kind, ast.Constant) and kind.value == "password"):
            continue
        default = keywords.get("value", keywords.get("default"))
        if not (isinstance(default, ast.Constant) and isinstance(default.value, str) and default.value):
            continue
        if is_placeholder_secret(default.value):
            continue
        findings.append(
            Finding(
                rule_id="AGENTLATCH-SEC001",
                title="Possible hardcoded credential",
                severity="low" if is_test_path(relative_path) else "high",
                message="A password field has a literal default value. Leave it empty and load credentials from a secret manager or environment variable.",
                path=relative_path,
                line=default.lineno,
                column=default.col_offset + 1,
                owasp=("ASI03", "ASI04"),
                confidence="medium",
                evidence="password field default; value redacted",
            )
        )
    return findings


def is_prompt_file(relative_parts: tuple[str, ...]) -> bool:
    suffix = Path(relative_parts[-1]).suffix.lower()
    if suffix in PROMPT_SUFFIXES:
        return True
    return suffix in {".md", ".txt"} and any(part.lower() in _PROMPT_DIRS for part in relative_parts[:-1])


def scan_prompt_file(path: Path, root: Path, source: str) -> list[Finding]:
    """PRM001/PRM003 on a prompt template; PRM002 too when it is (or is written as) a system prompt."""
    is_system = "system" in path.name.lower() or looks_like_system_prompt(source)
    label = "System prompt file" if is_system else "Prompt file"
    return check_prompt_text(source, _relative(path, root), 1, label, is_system)


def _normalize_key(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.lower())


def is_placeholder_secret(value: str, key: str = "", relative_path: str = "") -> bool:
    lowered = value.lower()
    if (
        lowered.startswith(_PLACEHOLDER_PREFIXES)
        or any(part in lowered for part in _PLACEHOLDER_PARTS)
        or len(set(lowered)) <= 2
        or (key and _normalize_key(key) in _normalize_key(value))
    ):
        return True
    in_i18n = any(part.lower() in _I18N_DIRS for part in relative_path.split("/")[:-1])
    return in_i18n and value.isalpha()


def scan_secrets(path: Path, root: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    relative_path = _relative(path, root)
    in_tests = is_test_path(relative_path)
    for line_number, line in enumerate(source.splitlines(), start=1):
        match = _SECRET_ASSIGNMENT.search(line)
        if not match or is_placeholder_secret(match["value"], match["key"], relative_path):
            continue
        message = "A credential-like variable appears to contain a literal value. Use a secret manager or environment variable."
        if in_tests:
            message += " This is a test file, so it is reported at low severity; confirm the value is fake."
        findings.append(
            Finding(
                rule_id="AGENTLATCH-SEC001",
                title="Possible hardcoded credential",
                severity="low" if in_tests else "high",
                message=message,
                path=relative_path,
                line=line_number,
                column=match.start() + 1,
                owasp=("ASI03", "ASI04"),
                confidence="low" if in_tests else "medium",
                evidence="credential-like assignment; value redacted",
            )
        )
    return findings


# Installed environments hold third-party packages, not project code. A folder is skipped only when
# it really is one, so a project cannot hide code from the scan by naming a folder "venv".
_NODE_MODULES_MARKERS = (".package-lock.json", ".yarn-integrity", ".yarn-state.yml", ".modules.yaml")


def is_installed_environment(directory: Path) -> bool:
    name = directory.name
    try:
        if (directory / "pyvenv.cfg").is_file():
            return True
        if name == ".tox":
            return any((child / "pyvenv.cfg").is_file() for child in directory.iterdir())
        if name == "node_modules":
            return any((directory / marker).exists() for marker in _NODE_MODULES_MARKERS)
    except OSError:
        return False
    return False


def _is_text(sample: bytes) -> bool:
    return b"\0" not in sample


def iter_project_files(root: Path) -> list[Path]:
    """Every regular file under root, minus .git, installed environments, and symlinks.

    Symlinks are not followed because they can point outside the project (for example to ~/.ssh).
    """
    if root.is_file():
        return [root]
    files: list[Path] = []
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        current = Path(directory)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name != ".git" and not is_installed_environment(current / name)
        )
        files.extend(current / name for name in sorted(names))
    return files


def scan_project(target: Path, max_file_bytes: int = 1_000_000) -> list[Finding]:
    """Scan every text file under target: source and prompt rules where they apply, secrets everywhere."""
    root = target.resolve()
    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []
    python_files: list[tuple[Path, str, ast.Module | None]] = []

    for path in iter_project_files(root):
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > max_file_bytes:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if not _is_text(raw[:8192]):
            continue
        source = raw.decode("utf-8", errors="replace")
        relative_parts = path.relative_to(base).parts

        suffix = path.suffix.lower()
        if suffix == ".py":
            python_files.append((path, source, parse_python(path, source)))
        elif suffix in {".yaml", ".yml"} and path.name not in MANIFEST_NAMES:
            # Manifests get their own prompt checks in manifest.py; any other YAML may hold prompts.
            findings.extend(scan_prompt_yaml(_relative(path, base), source))
        elif is_prompt_file(relative_parts):
            findings.extend(scan_prompt_file(path, base, source))
        findings.extend(scan_secrets(path, base, source))

    links = link_project([tree for _, _, tree in python_files if tree is not None])
    for path, source, tree in python_files:
        if tree is not None:
            findings.extend(scan_python(path, base, source, links, tree))

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
        manifests = [
            path
            for path in iter_project_files(root)
            if fnmatch.fnmatch(path.name, "requirements*.txt") and path.is_file() and not path.is_symlink()
        ]

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
