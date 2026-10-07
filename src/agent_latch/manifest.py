"""Checks for agent manifests: tool definitions, permissions, and prompt templates.

Like the source rules, these are heuristics over declared configuration. They do not
observe what the agent actually does at runtime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agent_latch.findings import Finding
from agent_latch.prompts import check_prompt_text
from agent_latch.rules import MANIFEST_NAMES, scan_secrets
from agent_latch.yamlload import LineDict as _LineDict
from agent_latch.yamlload import LineLoader as _LineLoader
from agent_latch.yamlload import line_of as _line_of

_HIGH_RISK_CAPABILITIES = {
    "shell",
    "exec",
    "code_exec",
    "code_execution",
    "python",
    "subprocess",
    "filesystem:write",
    "fs:write",
    "file_write",
    "filesystem:delete",
    "database:write",
    "db:write",
    "email:send",
    "payments",
    "payments:write",
    "sudo",
    "admin",
}
_CODE_EXECUTION_CAPABILITIES = {"shell", "exec", "code_exec", "code_execution", "python", "subprocess"}
_WILDCARDS = {"*", "all", "any"}
_APPROVAL_KEYS = ("requires_approval", "human_in_the_loop", "require_confirmation")
_CAPABILITY_KEYS = ("capabilities", "permissions", "scopes")
_ENDPOINT_KEYS = ("endpoint", "url", "base_url", "server")
_NO_AUTH_VALUES = {"none", "false", "anonymous", "no", "off", ""}


class ManifestError(ValueError):
    """Raised when a manifest cannot be read or parsed."""


def find_manifest(target: Path) -> Path | None:
    directory = target if target.is_dir() else target.parent
    for name in MANIFEST_NAMES:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def load_manifest(manifest: Path) -> _LineDict:
    try:
        data = yaml.load(manifest.read_text(encoding="utf-8"), Loader=_LineLoader)  # SafeLoader subclass
    except OSError as exc:
        raise ManifestError(f"could not read {manifest}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise ManifestError(f"invalid YAML in {manifest}: {exc}") from exc
    if not isinstance(data, _LineDict):
        raise ManifestError(f"{manifest} must contain a YAML mapping at the top level")
    return data


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "always", "required", "on"}
    return value is True


def _iter_tools(manifest: _LineDict) -> list[_LineDict]:
    tools = [tool for tool in _as_list(manifest.get("tools")) if isinstance(tool, _LineDict)]
    for agent in _as_list(manifest.get("agents")):
        if isinstance(agent, _LineDict):
            tools.extend(tool for tool in _as_list(agent.get("tools")) if isinstance(tool, _LineDict))
    return tools


def _check_tool(tool: _LineDict, path: str) -> list[Finding]:
    findings: list[Finding] = []
    name = str(tool.get("name", "<unnamed>"))
    capability_key = next((key for key in _CAPABILITY_KEYS if key in tool), None)
    capabilities = [str(item).strip().lower() for item in _as_list(tool.get(capability_key))] if capability_key else []
    approved = any(_truthy(tool.get(key)) for key in _APPROVAL_KEYS)

    wildcards = [cap for cap in capabilities if cap in _WILDCARDS or cap.endswith(":*")]
    if wildcards:
        findings.append(
            Finding(
                rule_id="AGENTLATCH-MAN002",
                title="Tool grants wildcard permissions",
                severity="high",
                message=f"Tool '{name}' declares unbounded permissions. Scope it to the specific actions the agent needs.",
                path=path,
                line=_line_of(tool, capability_key or "name"),
                column=1,
                owasp=("ASI02", "ASI03"),
                confidence="high",
                evidence=f"tool '{name}' {capability_key}: {', '.join(wildcards)}",
            )
        )

    risky = [cap for cap in capabilities if cap in _HIGH_RISK_CAPABILITIES]
    if risky and not approved:
        executes_code = any(cap in _CODE_EXECUTION_CAPABILITIES for cap in risky)
        owasp = ("ASI02", "ASI05", "ASI09") if executes_code else ("ASI02", "ASI03", "ASI09")
        findings.append(
            Finding(
                rule_id="AGENTLATCH-MAN001",
                title="High-risk tool without human approval",
                severity="high",
                message=(
                    f"Tool '{name}' can perform high-impact actions with no approval gate declared. "
                    "Require human confirmation or narrow the capability."
                ),
                path=path,
                line=_line_of(tool, capability_key or "name"),
                column=1,
                owasp=owasp,
                confidence="medium",
                evidence=f"tool '{name}' {capability_key}: {', '.join(risky)}; no {'/'.join(_APPROVAL_KEYS)}",
            )
        )

    endpoint_key = next((key for key in _ENDPOINT_KEYS if key in tool), None)
    if endpoint_key:
        endpoint = str(tool.get(endpoint_key))
        if "auth" not in tool:
            explicit = False
            missing = True
        else:
            explicit = True
            auth = tool.get("auth")
            missing = auth is None or auth is False or (isinstance(auth, str) and auth.strip().lower() in _NO_AUTH_VALUES)
        if missing:
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-MAN003",
                    title="Remote tool without authentication",
                    severity="medium",
                    message=(
                        f"Tool '{name}' calls a remote endpoint "
                        + ("with authentication explicitly disabled. " if explicit else "with no auth declared. ")
                        + "Authenticate tool calls and scope credentials to this tool."
                    ),
                    path=path,
                    line=_line_of(tool, "auth" if explicit else endpoint_key),
                    column=1,
                    owasp=("ASI03", "ASI02"),
                    confidence="medium" if explicit else "low",
                    evidence=f"tool '{name}' {endpoint_key}: {endpoint}; auth: {tool.get('auth') if explicit else '<missing>'}",
                )
            )
    return findings


_check_prompt_text = check_prompt_text


def _block_offset(agent: _LineDict, key: str) -> int:
    """Literal block scalars (|, >) start on the line after their key."""
    return _line_of(agent, key) + 1


def _check_agent_prompts(
    agent: _LineDict,
    manifest_path: Path,
    display: str,
    root: Path,
    max_file_bytes: int,
) -> list[Finding]:
    findings: list[Finding] = []
    name = str(agent.get("name", "<unnamed>"))

    for key, is_system in (("system_prompt", True), ("prompt", False)):
        text = agent.get(key)
        if isinstance(text, str):
            start = _block_offset(agent, key) if "\n" in text else _line_of(agent, key)
            label = f"Agent '{name}' {key}"
            findings.extend(_check_prompt_text(text, display, start, label, is_system))

    referenced: list[tuple[str, bool, str]] = []
    for key in ("system_prompt_file", "system_prompt_template"):
        if isinstance(agent.get(key), str):
            referenced.append((agent[key], True, key))
    for key in ("prompt_templates", "prompt_template", "prompt_files"):
        referenced.extend((str(item), False, key) for item in _as_list(agent.get(key)))

    for reference, is_system, key in referenced:
        template = (manifest_path.parent / reference).resolve()
        template_display = _display_path(template, root)
        try:
            if template.stat().st_size > max_file_bytes:
                continue
            text = template.read_text(encoding="utf-8", errors="replace")
        except OSError:
            findings.append(
                Finding(
                    rule_id="AGENTLATCH-MAN000",
                    title="Referenced prompt file not found",
                    severity="info",
                    message=f"Agent '{name}' references a prompt file that could not be read, so it was not scanned.",
                    path=display,
                    line=_line_of(agent, key),
                    column=1,
                    owasp=(),
                    confidence="high",
                    evidence=f"{key}: {reference}",
                )
            )
            continue
        label = f"Prompt template for agent '{name}'"
        findings.extend(_check_prompt_text(text, template_display, 1, label, is_system))
        if not template.is_relative_to(root):
            # scan_project covers every file inside the target; templates outside it are checked here.
            findings.extend(scan_secrets(template, template.parent, text))
    return findings


def scan_manifest(manifest_path: Path, root: Path, max_file_bytes: int = 1_000_000) -> list[Finding]:
    """Audit tool definitions and prompts declared in an AgentLatch agent manifest."""
    manifest_path = manifest_path.resolve()
    root = root.resolve() if root.is_dir() else root.resolve().parent
    manifest = load_manifest(manifest_path)
    display = _display_path(manifest_path, root)

    findings: list[Finding] = []
    for tool in _iter_tools(manifest):
        findings.extend(_check_tool(tool, display))
    for agent in _as_list(manifest.get("agents")):
        if isinstance(agent, _LineDict):
            findings.extend(_check_agent_prompts(agent, manifest_path, display, root, max_file_bytes))

    # A template shared by several agents would otherwise be reported once per agent.
    return sorted(set(findings), key=lambda finding: (finding.path, finding.line, finding.rule_id))
