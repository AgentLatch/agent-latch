"""Human-oversight and runaway-loop checks that work from source code alone.

- AG006: human approval explicitly turned off, so the agent acts without confirmation
  (AutoGen human_input_mode="NEVER" with code execution, auto_approve=True,
  permission_mode="bypassPermissions", require_approval="never", ...).
                                  (ASI09 Human-Agent Trust Exploitation; ASI02 / ASI05)
- AG007: an agent loop with no effective bound: max_iterations=None, a very high iteration
  or recursion limit, or `while True:` around an agent call with no way out.
                                  (ASI08 Cascading Failures)

Single-file, name-based heuristics over the AST. Nothing is imported or executed.
"""

from __future__ import annotations

import ast

from agent_latch.astutil import walk
from agent_latch.findings import Finding

# ---------------------------------------------------------------- shared helpers


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _literal(node: ast.AST | None) -> object:
    return node.value if isinstance(node, ast.Constant) else ...


# ---------------------------------------------------------------- AG006: approval disabled

# Keyword set to True turns off confirmation before tool or code execution.
_AUTO_APPROVE_KWARGS = {
    "auto_approve",
    "auto_approve_tools",
    "auto_confirm",
    "skip_approval",
    "skip_confirmation",
    "bypass_approval",
    "dangerously_skip_permissions",
    "yolo",
}
# Keyword whose string value says "never ask a human".
_APPROVAL_MODE_KWARGS = {"approval_mode", "approval_policy", "permission_mode", "require_approval"}
_NO_APPROVAL_VALUES = {"never", "none", "auto", "always_approve", "bypasspermissions", "full-auto", "yolo"}


def _code_execution_enabled(call: ast.Call) -> bool:
    """AutoGen executes code unless code_execution_config is False or None."""
    for keyword in call.keywords:
        if keyword.arg == "code_execution_config":
            return _literal(keyword.value) not in (False, None)
        if keyword.arg == "code_executor":
            return _literal(keyword.value) is not None
    return False


def _approval_findings(tree: ast.Module, path: str) -> list[Finding]:
    results: list[Finding] = []

    def add(node: ast.AST, severity: str, owasp: tuple[str, ...], evidence: str, why: str) -> None:
        results.append(
            Finding(
                rule_id="AGENTLATCH-AG006",
                title="Human approval disabled for agent actions",
                severity=severity,
                message=(
                    f"{why} A user or reviewer can be steered into trusting actions they never see. "
                    "Keep a human confirmation step for code execution and other high-impact actions."
                ),
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=owasp,
                confidence="high" if severity == "high" else "medium",
                evidence=evidence,
            )
        )

    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _last(_dotted(node.func)) or "call"
        for keyword in node.keywords:
            value = _literal(keyword.value)
            if keyword.arg == "human_input_mode" and value == "NEVER":
                if _code_execution_enabled(node):
                    add(node, "high", ("ASI09", "ASI05"), f'{callee}(human_input_mode="NEVER", code execution on)',
                        f"{callee} runs model-written code with no human in the loop.")
            elif keyword.arg in _AUTO_APPROVE_KWARGS and value is True:
                add(node, "high", ("ASI09", "ASI02"), f"{callee}({keyword.arg}=True)",
                    f"{keyword.arg}=True approves the agent's actions automatically.")
            elif (
                keyword.arg in _APPROVAL_MODE_KWARGS
                and isinstance(value, str)
                and value.strip().lower() in _NO_APPROVAL_VALUES
            ):
                add(node, "high", ("ASI09", "ASI02"), f"{callee}({keyword.arg}={value!r})",
                    f"{keyword.arg}={value!r} lets the agent act without asking a human.")
    return results


# ---------------------------------------------------------------- AG007: unbounded loops

_LIMIT_KWARGS = {
    "max_iterations",
    "max_iter",
    "max_turns",
    "max_round",
    "max_rounds",
    "max_steps",
    "recursion_limit",
}
# Above this many steps, a limit no longer works as a circuit breaker. LangGraph defaults to 25,
# LangChain AgentExecutor to 15, CrewAI max_iter to 20-25.
_LIMIT_THRESHOLD = 100
_AGENT_METHODS = {"invoke", "ainvoke", "kickoff", "kickoff_async", "initiate_chat", "run_sync"}
# Generic method names count only when the receiver looks like an agent, crew, or graph.
_GENERIC_METHODS = {"run", "arun", "chat", "start", "stream", "astream"}
_AGENT_RECEIVER_HINTS = ("agent", "crew", "graph", "executor", "chain", "app", "team", "runner", "swarm")


def _limit_problem(node: ast.AST | None) -> str | None:
    value = _literal(node)
    if value is None:
        return "None"
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > _LIMIT_THRESHOLD:
        return str(value)
    if isinstance(node, ast.Attribute) and _dotted(node) in {"math.inf", "sys.maxsize"}:
        return _dotted(node)
    return None


def _is_agent_call(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    method = call.func.attr
    if method in _AGENT_METHODS:
        return True
    receiver = _dotted(call.func.value).lower()
    return method in _GENERIC_METHODS and any(hint in receiver for hint in _AGENT_RECEIVER_HINTS)


def _loop_exits(loop: ast.While) -> bool:
    """True if the loop body can leave the loop: break, return, raise, or sys.exit()."""
    stack: list[ast.AST] = list(loop.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Break, ast.Return, ast.Raise)):
            return True
        if isinstance(node, ast.Call) and _dotted(node.func) in {"sys.exit", "exit", "quit", "os._exit"}:
            return True
        # A break inside a nested loop or function does not leave this loop.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            stack.extend(child for child in ast.walk(node) if isinstance(child, (ast.Return, ast.Raise)))
            continue
        stack.extend(ast.iter_child_nodes(node))
    return False


def _loop_findings(tree: ast.Module, path: str) -> list[Finding]:
    results: list[Finding] = []
    for node in walk(tree):
        if isinstance(node, ast.Call):
            callee = _last(_dotted(node.func)) or "call"
            for keyword in node.keywords:
                if keyword.arg in _LIMIT_KWARGS:
                    problem = _limit_problem(keyword.value)
                    if problem:
                        results.append(_loop_finding(keyword.value, path, f"{callee}({keyword.arg}={problem})",
                                                     f"{keyword.arg}={problem} gives the agent no effective step limit."))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value in _LIMIT_KWARGS:
                    problem = _limit_problem(value)
                    if problem:
                        results.append(_loop_finding(value, path, f'{{"{key.value}": {problem}}}',
                                                     f"{key.value}={problem} gives the agent no effective step limit."))
        elif isinstance(node, ast.While) and _literal(node.test) is True and not _loop_exits(node):
            calls = [child for child in walk(node) if isinstance(child, ast.Call) and _is_agent_call(child)]
            if calls:
                results.append(_loop_finding(node, path, f"while True: ... {_dotted(calls[0].func)}(...) with no exit",
                                             "An agent is called in an endless loop with no break, return, or raise."))
    return results


def _loop_finding(node: ast.AST, path: str, evidence: str, why: str) -> Finding:
    return Finding(
        rule_id="AGENTLATCH-AG007",
        title="Agent loop without an effective limit",
        severity="medium",
        message=(
            f"{why} One bad step can then repeat or fan out without stopping. "
            "Set a small step limit, a timeout, or a circuit breaker."
        ),
        path=path,
        line=node.lineno,
        column=node.col_offset + 1,
        owasp=("ASI08",),
        confidence="medium",
        evidence=evidence,
    )


# ---------------------------------------------------------------- entry point


def scan_oversight(tree: ast.Module, path: str) -> list[Finding]:
    """AG006 and AG007 for one parsed Python file. scan_python lowers test-file severity."""
    return [*_approval_findings(tree, path), *_loop_findings(tree, path)]
