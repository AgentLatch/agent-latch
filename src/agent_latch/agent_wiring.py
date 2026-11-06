"""Checks over how agents are wired together in one file (OpenAI Agents SDK style).

- ALR07-S01: an agent hands off to another agent that holds a high-risk tool without approval
  that the first agent does not have, so a user talking to the first agent can reach it.
                                                     (ASI03 Identity and Privilege Abuse)
- ALR01-S02: a guardrail is defined (@input_guardrail, @output_guardrail, InputGuardrail(...))
  in a file that builds agents, but nothing in the file attaches it, so it never runs.
                                                     (ASI01 Agent Goal Hijack)

Single-file, name-based heuristics over the AST. Nothing is imported or executed. Which tools
count as high-risk comes from the AG004 analysis in agent_code.py, passed in by the caller as
tool name -> what the tool can do ("send HTTP write requests").
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass, field

from agent_latch.astutil import walk
from agent_latch.findings import Finding

_GUARDRAIL_DECORATORS = {
    "input_guardrail",
    "output_guardrail",
    "tool_input_guardrail",
    "tool_output_guardrail",
}
_GUARDRAIL_CLASSES = {"InputGuardrail", "OutputGuardrail", "ToolInputGuardrail", "ToolOutputGuardrail"}


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):  # Agent[Context](...)
        return _dotted(node.value)
    return ""


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _is_agent_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _last(_dotted(node.func)) == "Agent"


def _list_items(call: ast.Call, name: str) -> list[ast.expr]:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, (ast.List, ast.Tuple)):
            return list(keyword.value.elts)
    return []


@dataclass
class _Agent:
    label: str
    call: ast.Call
    tools: set[str] = field(default_factory=set)


def _agent_label(call: ast.Call, variable: str | None) -> str:
    for keyword in call.keywords:
        if keyword.arg == "name" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
    return variable or "agent"


def _agent(call: ast.Call, variable: str | None) -> _Agent:
    tools = {item.id for item in _list_items(call, "tools") if isinstance(item, ast.Name)}
    return _Agent(_agent_label(call, variable), call, tools)


def _collect_agents(tree: ast.Module) -> tuple[dict[str, _Agent], list[_Agent]]:
    """Agents assigned to a name, and every Agent(...) call (named or inline)."""
    by_name: dict[str, _Agent] = {}
    by_call: dict[int, _Agent] = {}
    for node in walk(tree):
        if isinstance(node, ast.Assign) and _is_agent_call(node.value):
            assert isinstance(node.value, ast.Call)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    agent = _agent(node.value, target.id)
                    by_name[target.id] = agent
                    by_call[id(node.value)] = agent
    for node in walk(tree):
        if _is_agent_call(node) and id(node) not in by_call:
            assert isinstance(node, ast.Call)
            by_call[id(node)] = _agent(node, None)
    return by_name, list(by_call.values())


def _handoff_target(item: ast.expr, by_name: Mapping[str, _Agent], by_call: Mapping[int, _Agent]) -> _Agent | None:
    """The agent a handoffs=[...] entry points to: a name, handoff(agent), or an inline Agent(...)."""
    if isinstance(item, ast.Name):
        return by_name.get(item.id)
    if isinstance(item, ast.Call) and _last(_dotted(item.func)) == "handoff":
        target = next((kw.value for kw in item.keywords if kw.arg == "agent"), item.args[0] if item.args else None)
        return _handoff_target(target, by_name, by_call) if target is not None else None
    if isinstance(item, ast.Call):
        return by_call.get(id(item))
    return None


def _handoff_findings(tree: ast.Module, path: str, risky_tools: Mapping[str, tuple[str, ...]]) -> list[Finding]:
    """ALR07-S01: a handoff that gives the conversation high-risk tools the caller did not have."""
    if not risky_tools:
        return []
    by_name, agents = _collect_agents(tree)
    by_call = {id(agent.call): agent for agent in agents}
    results: list[Finding] = []
    for source in agents:
        for item in _list_items(source.call, "handoffs"):
            target = _handoff_target(item, by_name, by_call)
            if target is None or target is source:
                continue
            gained = sorted(tool for tool in target.tools - source.tools if tool in risky_tools)
            if not gained:
                continue
            actions = list(dict.fromkeys(action for tool in gained for action in risky_tools[tool]))
            tools_text = ", ".join(f"'{tool}'" for tool in gained)
            results.append(
                Finding(
                    rule_id="ALR07-S01",
                    title="Handoff to an agent with more privileged tools",
                    severity="medium",
                    message=(
                        f"Agent '{source.label}' can hand off to '{target.label}', which has {tools_text} "
                        f"(can {', '.join(actions)}) without an approval "
                        f"gate. '{source.label}' does not have these tools, so anyone talking to it can steer "
                        "the conversation into them. Require approval on those tools "
                        "(@function_tool(needs_approval=True)), or check who the user is before the handoff "
                        "(handoff(..., is_enabled=...) or on_handoff)."
                    ),
                    path=path,
                    line=item.lineno,
                    column=item.col_offset + 1,
                    owasp=("ASI03", "ASI02"),
                    confidence="medium",
                    evidence=f"'{source.label}' -> '{target.label}' gains {tools_text}",
                )
            )
    return results


def _exported_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
            and isinstance(node.value, (ast.List, ast.Tuple))
        ):
            names.update(
                item.value for item in node.value.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)
            )
    return names


def _guardrail_definitions(tree: ast.Module) -> list[tuple[str, str, ast.AST]]:
    """(name, how it was defined, node) for each guardrail defined in the file."""
    found: list[tuple[str, str, ast.AST]] = []
    for node in walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                kind = _last(_dotted(target))
                if kind in _GUARDRAIL_DECORATORS:
                    found.append((node.name, f"@{kind}", node))
                    break
        elif (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and _last(_dotted(node.value.func)) in _GUARDRAIL_CLASSES
        ):
            kind = _last(_dotted(node.value.func))
            found.extend((target.id, f"{kind}(...)", node) for target in node.targets if isinstance(target, ast.Name))
    return found


def _guardrail_findings(tree: ast.Module, path: str) -> list[Finding]:
    """ALR01-S02: a guardrail defined in a file that builds agents, but never used there."""
    if not any(_is_agent_call(node) for node in walk(tree)):
        return []  # a module of shared guardrails is attached wherever it is imported
    used = {node.id for node in walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    exported = _exported_names(tree)
    results: list[Finding] = []
    for name, kind, node in _guardrail_definitions(tree):
        if name in used or name in exported:
            continue
        side = "output" if "output" in kind.lower() else "input"
        results.append(
            Finding(
                rule_id="ALR01-S02",
                title="Guardrail defined but never attached",
                severity="medium",
                message=(
                    f"Guardrail '{name}' ({kind}) is defined but no agent in this file uses it, so it never "
                    f"runs and the agent's {side} goes through unchecked. Attach it, for example "
                    f"Agent(..., {side}_guardrails=[{name}]), or remove it so the code does not look protected."
                ),
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=("ASI01",),
                confidence="medium",
                evidence=f"{kind} '{name}' is not referenced",
            )
        )
    return results


def scan_agent_wiring(tree: ast.Module, path: str, risky_tools: Mapping[str, tuple[str, ...]]) -> list[Finding]:
    """ALR07-S01 and ALR01-S02 for one parsed Python file."""
    return [*_handoff_findings(tree, path, risky_tools), *_guardrail_findings(tree, path)]
