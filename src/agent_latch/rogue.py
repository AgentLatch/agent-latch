"""Rogue-agent checks that work from source code alone.

- ALR14-S01: the agent writes to its own prompts, instructions, or settings, so injected text can
  outlive the conversation.
- ALR14-S02: the agent installs persistence (crontab, systemd, launchd, shell profile, SSH keys,
  nohup/setsid) so it runs again after it is stopped.
- ALR14-S03: the agent installs packages at runtime, pulling unreviewed code into its own process.

                                 (ASI10 Rogue Agents)

Single-file, name-based heuristics over the AST. Only the destination path of a write and the
command of an execution call are inspected, never the text being written. Nothing is executed.
"""

from __future__ import annotations

import ast
import re

from agent_latch.astutil import walk
from agent_latch.findings import Finding

_EXEC_CALLS = {
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.popen",
    "os.spawnl",
    "os.spawnv",
    "os.system",
    "pty.spawn",
}
_WRITE_METHODS = {"write_bytes", "write_text"}
_MOVE_CALLS = {"os.rename", "os.replace", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move"}

# Prompt, instruction and settings files an agent has no reason to rewrite while it runs.
# Matched by path segment, basename or extension, so an ordinary output file that merely mentions
# "prompt" in its name (prompt_results.json, system_prompt_audit.json) is not reported.
_SELF_TARGET = re.compile(
    r"(?i)(?:"
    r"(?:^|/)(?:prompts?|instructions?)(?:/|$)"  # a prompts/ or instructions/ directory
    r"|\.(?:prompt|prompty|j2|jinja2?)$"  # prompt template extensions
    # A bare prompt name, or one with a prompt-template extension: a data, log or document
    # output file such as system_prompt_audit.json is not a prompt.
    r"|(?:^|/)(?:system_prompt|system_message|persona|personality)"
    r"(?:[\w.-]*\.(?:prompt|prompty|j2|jinja2?))?$"
    r"|(?:^|/)\.env(?:\.[\w.-]+)?$"  # .env, .env.local, ...
    r"|(?:^|/)agent-manifest[\w.-]*$"  # agent manifests
    r"|(?:^|/)\.mcp\.json$|(?:^|/)settings\.json$"
    r"|(?:^|/)\.(?:claude|codex|cursor)(?:/|$)"  # agent tool configuration
    r")"
)
# Paths that make a process come back after it is stopped.
_PERSISTENCE_TARGET = re.compile(
    r"(?i)(?:"
    r"\.bashrc|\.bash_profile|\.zshrc|\.profile\b|authorized_keys|"
    r"/etc/cron|/etc/systemd|/etc/rc\.local|/launchagents|/launchdaemons|"
    r"autostart|systemd/user"
    r")"
)
# crontab -l only lists the current entries, so it does not install anything.
_PERSISTENCE_COMMAND = re.compile(
    r"(?i)\b(?:"
    r"crontab(?!\s+-l\b)"
    r"|systemctl\s+enable|launchctl\s+(?:load|bootstrap)|schtasks|nohup|setsid"
    r")\b"
)
_INSTALL_COMMAND = re.compile(
    r"(?i)\b(?:pip3?|uv\s+pip|pipx|poetry|conda|npm|pnpm|yarn)\b(?:\s+\S+)*?\s+install\b"
)


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _last(name: str | None) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def _texts(node: ast.AST) -> list[str]:
    return [item.value for item in ast.walk(node) if isinstance(item, ast.Constant) and isinstance(item.value, str)]


def _is_write_mode(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(set(node.value) & set("wax+"))


def _write_target(call: ast.Call) -> ast.AST | None:
    """Expression naming where a call writes, or None when it does not write a file."""
    name = _dotted(call.func)
    method = _last(name)
    if method == "open" and isinstance(call.func, ast.Name):
        mode = next((keyword.value for keyword in call.keywords if keyword.arg == "mode"), None)
        if mode is None and len(call.args) > 1:
            mode = call.args[1]
        if _is_write_mode(mode) and call.args:
            return call.args[0]
        return None
    if method == "open":  # path.open("w"): the path is the receiver, the mode is the first argument
        mode = call.args[0] if call.args else next(
            (keyword.value for keyword in call.keywords if keyword.arg == "mode"), None
        )
        return call.func.value if _is_write_mode(mode) else None
    if method in _WRITE_METHODS and isinstance(call.func, ast.Attribute):
        return call.func.value
    if name in _MOVE_CALLS and len(call.args) >= 2:
        return call.args[1]
    return None


def _command(call: ast.Call) -> str | None:
    """The command a call runs, joined from its literal parts, or None for anything else."""
    name = _dotted(call.func)
    if not (name in _EXEC_CALLS or name.startswith(("subprocess.", "os.exec", "os.spawn"))):
        return None
    texts = _texts(call)
    return " ".join(texts) if texts else None


def _self_modification(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _write_target(node)
        if target is None:
            continue
        match = next((found for text in _texts(target) if (found := _SELF_TARGET.search(text))), None)
        if match is None:
            continue
        findings.append(
            Finding(
                rule_id="ALR14-S01",
                title="Agent can rewrite its own prompts or settings",
                severity="medium",
                message=(
                    f"The agent writes to a path containing {match.group(0)!r}, which holds prompts, "
                    "instructions, or settings. Text written there is read back as system-level "
                    "configuration, so injected content survives the conversation and applies to later "
                    "runs. Confine writes to a data directory, and keep prompts and configuration "
                    "read-only for the agent."
                ),
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=("ASI10",),
                confidence="medium",
                evidence=f"write to a *{match.group(0)}* path",
            )
        )
    return findings


def _persistence(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _write_target(node)
        matches = [
            found for text in _texts(target) if (found := _PERSISTENCE_TARGET.search(text))
        ] if target is not None else []
        command = _command(node)
        if command is not None:
            for pattern in (_PERSISTENCE_TARGET, _PERSISTENCE_COMMAND):
                if found := pattern.search(command):
                    matches.append(found)
                    break
        if not matches:
            continue
        findings.append(
            Finding(
                rule_id="ALR14-S02",
                title="Agent installs persistence on the host",
                severity="high",
                message=(
                    f"The agent makes itself run again after it is stopped ({matches[0].group(0)!r}: cron, "
                    "systemd, launchd, a shell profile, or SSH keys). An agent that can schedule itself "
                    "can keep acting after a user ends the session. Remove the persistence step and let "
                    "the operator schedule the job."
                ),
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=("ASI10",),
                confidence="medium",
                evidence=f"persistence via {matches[0].group(0)!r}",
            )
        )
    return findings


def _runtime_install(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        command = _command(node)
        match = _INSTALL_COMMAND.search(command) if command is not None else None
        if match is None:
            continue
        # Only the tool name is reported, so a token in the same command never reaches the report.
        tool = match.group(0).split()[0]
        findings.append(
            Finding(
                rule_id="ALR14-S03",
                title="Agent installs packages at runtime",
                severity="medium",
                message=(
                    f"The agent runs a package install at runtime ({tool!r}), so model- or user-chosen "
                    "code becomes part of its own process with no review. Have the operator add the "
                    "dependency to the project instead, and fail with an error when it is missing."
                ),
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=("ASI10",),
                confidence="medium",
                evidence=f"runtime {tool} install",
            )
        )
    return findings


def scan_rogue_agent(tree: ast.Module, path: str) -> list[Finding]:
    """ALR14-S01, ALR14-S02 and ALR14-S03 for one parsed Python file."""
    return [*_self_modification(tree, path), *_persistence(tree, path), *_runtime_install(tree, path)]
