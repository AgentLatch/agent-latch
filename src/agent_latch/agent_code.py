"""Agent checks that work from source code alone, with or without an agent manifest.

- PRM001 / PRM002 on prompts written in Python (SystemMessage, ("system", ...) tuples,
  {"role": "system"} dicts, CrewAI goal/backstory, Agents SDK instructions, *_PROMPT variables)
  and in YAML prompt files such as CrewAI config/agents.yaml.        (ASI01 Agent Goal Hijack)
- AG004: a function exposed to the model as a tool runs shell commands, writes or deletes files,
  sends email, writes to a database, or sends HTTP writes, and no approval gate is visible.
- AG005: an agent is given an unrestricted built-in tool (shell, Python REPL, file system).
- AG006 / AG007 (human approval disabled, unbounded agent loops) live in oversight.py.
                                                     (ASI02 Tool Misuse and Exploitation; ASI05/ASI03)

All checks are single-file, name-based heuristics over the AST. Nothing is imported or executed.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from typing import Any

import yaml

from agent_latch.astutil import walk
from agent_latch.findings import Finding
from agent_latch.oversight import scan_oversight
from agent_latch.prompts import check_prompt_text
from agent_latch.yamlload import LineDict, line_of, load_yaml

# ---------------------------------------------------------------- shared helpers


def _dotted(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return None


def _last(name: str | None) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _str_constants(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


# ---------------------------------------------------------------- prompts in code (PRM001/PRM002)

_SYSTEM_ROLES = {"system", "developer"}
_USER_ROLES = {"user", "human"}
_SYSTEM_KEYWORDS = {"system_prompt", "system_message", "system", "instructions", "backstory", "goal"}
_PROMPT_KEYWORDS = {"description", "expected_output", "template", "user_prompt"}
_AGENT_FACTORIES = {"create_react_agent", "create_agent"}  # prompt= is the system prompt here
_SYSTEM_VAR = re.compile(r"(?i)system_?(?:prompt|message|instructions?)")
_PROMPT_VAR = re.compile(r"(?i)prompt")


def _render(node: ast.AST) -> str | None:
    """Prompt text for a string expression; interpolated values become {name} placeholders."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append("{" + _placeholder(value.value) + "}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _render(node.left), _render(node.right)
        if left is None and right is None:
            return None
        return (left if left is not None else "{" + _placeholder(node.left) + "}") + (
            right if right is not None else "{" + _placeholder(node.right) + "}"
        )
    return None


def _placeholder(node: ast.AST) -> str:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return str(node.slice.value)
    return _last(_dotted(node)) or "expr"


class _PromptCollector:
    def __init__(self, path: str) -> None:
        self.path = path
        self.seen: set[int] = set()
        self.findings: list[Finding] = []

    def check(self, node: ast.AST | None, label: str, is_system: bool) -> None:
        if node is None or id(node) in self.seen:
            return
        text = _render(node)
        if text is None:
            return
        self.seen.add(id(node))
        self.findings.extend(
            check_prompt_text(
                text, self.path, node.lineno, label, is_system, base_column=node.col_offset + 1
            )
        )

    def visit(self, tree: ast.Module) -> list[Finding]:
        for node in walk(tree):
            if isinstance(node, ast.Call):
                self._call(node)
            elif isinstance(node, ast.Tuple) and len(node.elts) == 2:
                role = node.elts[0]
                if isinstance(role, ast.Constant) and isinstance(role.value, str):
                    if role.value in _SYSTEM_ROLES:
                        self.check(node.elts[1], f"('{role.value}', ...) prompt message", True)
                    elif role.value in _USER_ROLES:
                        self.check(node.elts[1], f"('{role.value}', ...) prompt message", False)
            elif isinstance(node, ast.Dict):
                self._message_dict(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._assignment(node)
        return self.findings

    def _call(self, call: ast.Call) -> None:
        callee = _dotted(call.func) or ""
        name = _last(callee)
        first = call.args[0] if call.args else None
        if name == "SystemMessage":
            self.check(_keyword(call, "content") or first, "System prompt in SystemMessage(...)", True)
        elif name == "HumanMessage":
            self.check(_keyword(call, "content") or first, "Prompt in HumanMessage(...)", False)
        elif name == "from_template":
            is_system = _last(callee.rsplit(".", 1)[0]) == "SystemMessagePromptTemplate"
            self.check(_keyword(call, "template") or first, f"Prompt template in {callee}(...)", is_system)
        if name in _AGENT_FACTORIES:
            self.check(_keyword(call, "prompt"), f"System prompt passed to {name}(prompt=...)", True)
        for keyword in call.keywords:
            if keyword.arg in _SYSTEM_KEYWORDS:
                self.check(keyword.value, f"System-level {keyword.arg}= passed to {name}(...)", True)
            elif keyword.arg in _PROMPT_KEYWORDS:
                self.check(keyword.value, f"{keyword.arg}= passed to {name}(...)", False)

    def _message_dict(self, node: ast.Dict) -> None:
        entries = {
            key.value: value
            for key, value in zip(node.keys, node.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        role = entries.get("role")
        if isinstance(role, ast.Constant) and role.value in _SYSTEM_ROLES | _USER_ROLES:
            self.check(
                entries.get("content"),
                f'{{"role": "{role.value}"}} message content',
                role.value in _SYSTEM_ROLES,
            )

    def _assignment(self, node: ast.Assign | ast.AnnAssign) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [_last(_dotted(target)) for target in targets]
        if any(_SYSTEM_VAR.search(name) for name in names):
            self.check(node.value, f"System prompt assigned to {names[0]}", True)
        elif any(_PROMPT_VAR.search(name) for name in names):
            self.check(node.value, f"Prompt assigned to {names[0]}", False)


# ---------------------------------------------------------------- prompts in YAML files

_YAML_SYSTEM_KEYS = {"system_prompt", "system_message", "system", "instructions", "backstory", "goal"}
_YAML_PROMPT_KEYS = {"prompt", "user_prompt", "prompt_template", "template", "description", "expected_output"}


def scan_prompt_yaml(path: str, source: str) -> list[Finding]:
    """PRM001/PRM002 over prompt-like keys in any YAML file (CrewAI agents.yaml, prompt libraries)."""
    try:
        data = load_yaml(source)
    except yaml.YAMLError:
        return []
    findings: list[Finding] = []
    for mapping in _iter_mappings(data):
        role = mapping.get("role")
        content = mapping.get("content")
        if isinstance(role, str) and isinstance(content, str) and role in _SYSTEM_ROLES | _USER_ROLES:
            findings.extend(_yaml_prompt(mapping, "content", path, f"YAML '{role}' message", role in _SYSTEM_ROLES))
        for key, value in mapping.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            if key in _YAML_SYSTEM_KEYS:
                findings.extend(_yaml_prompt(mapping, key, path, f"YAML key '{key}'", True))
            elif key in _YAML_PROMPT_KEYS:
                findings.extend(_yaml_prompt(mapping, key, path, f"YAML key '{key}'", False))
    return findings


def _iter_mappings(data: Any) -> Iterator[LineDict]:
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, LineDict):
            yield item
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _yaml_prompt(mapping: LineDict, key: str, path: str, label: str, is_system: bool) -> list[Finding]:
    text = mapping[key]
    # Literal block scalars (|, >) start on the line after their key, as in manifest.py.
    start = line_of(mapping, key) + 1 if "\n" in text else line_of(mapping, key)
    return check_prompt_text(text, path, start, label, is_system)


# ---------------------------------------------------------------- AG004: risky tools without approval

_TOOL_DECORATORS = {"tool", "function_tool", "kernel_function"}
_TOOL_BASE_CLASSES = {"BaseTool"}
_TOOL_RUN_METHODS = {"_run", "_arun", "run", "arun"}
_TOOL_WRAPPERS = {"Tool", "StructuredTool", "FunctionTool", "from_function", "from_defaults"}
_TOOL_LIST_CALLS = {
    "create_react_agent",
    "create_agent",
    "create_tool_calling_agent",
    "create_openai_tools_agent",
    "ToolNode",
    "bind_tools",
}
_APPROVAL_KWARGS = {"needs_approval", "requires_approval", "require_approval", "require_confirmation", "human_in_the_loop"}
_FILE_APPROVAL_KWARGS = {"interrupt_before", "interrupt_after", "interrupt_on"}
_FILE_APPROVAL_NAMES = {"HumanApprovalCallbackHandler", "HumanInTheLoopMiddleware"}
_APPROVAL_CALL = re.compile(r"(?i)approv|confirm")

_CODE_EXEC_CALLS = {"eval", "exec", "os.system", "os.popen", "pty.spawn", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec"}
_FS_CALLS = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename", "os.replace", "shutil.rmtree", "shutil.move"}
_FS_METHODS = {"unlink", "rmdir", "write_text", "write_bytes"}
_HTTP_WRITE_CALLS = {f"{lib}.{verb}" for lib in ("requests", "httpx") for verb in ("post", "put", "patch", "delete")}
_EMAIL_CALLS = {"smtplib.SMTP", "smtplib.SMTP_SSL"}
_EMAIL_METHODS = {"sendmail", "send_message"}
_SQL_WRITE = re.compile(r"^\s*(?:INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|REPLACE)\b", re.IGNORECASE)

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _risky_operation(call: ast.Call) -> tuple[str, str] | None:
    """(kind, evidence) for a call that performs a high-impact action, else None."""
    callee = _dotted(call.func) or ""
    method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
    if callee in _CODE_EXEC_CALLS or callee.startswith(("subprocess.", "os.exec", "os.spawn")):
        return "code_execution", f"{callee}()"
    if callee in _FS_CALLS or method in _FS_METHODS:
        return "filesystem", f"{callee or method}()"
    if callee == "open":
        mode = _keyword(call, "mode") or (call.args[1] if len(call.args) > 1 else None)
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and set(mode.value) & set("wax+"):
            return "filesystem", f"open(..., {mode.value!r})"
    if callee in _HTTP_WRITE_CALLS:
        return "http_write", f"{callee}()"
    if callee in _EMAIL_CALLS or method in _EMAIL_METHODS:
        return "email", f"{callee or method}()"
    if method in {"execute", "executemany", "executescript"} and call.args:
        sql = _render(call.args[0])
        if sql and _SQL_WRITE.match(sql):
            return "database_write", f"{method}({sql.split()[0].upper()} ...)"
    return None


_KIND_TEXT = {
    "code_execution": "run shell commands or code",
    "filesystem": "write or delete files",
    "http_write": "send HTTP write requests",
    "email": "send email",
    "database_write": "modify a database",
}


def _approval_call(call: ast.Call) -> bool:
    callee = _dotted(call.func) or ""
    return _last(callee) in {"interrupt", "input"} or bool(_APPROVAL_CALL.search(_last(callee)))


def _decorator_tool(decorator: ast.expr) -> tuple[bool, bool]:
    """(is_tool, declares_approval) for one decorator."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if _last(_dotted(target)) not in _TOOL_DECORATORS:
        return False, False
    approved = isinstance(decorator, ast.Call) and any(
        kw.arg in _APPROVAL_KWARGS and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
        for kw in decorator.keywords
    )
    return True, approved


class _ToolAnalysis:
    def __init__(self, tree: ast.Module, path: str) -> None:
        self.tree = tree
        self.path = path
        self.functions: dict[str, _FunctionNode] = {
            node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    def file_has_approval_gate(self) -> bool:
        for node in walk(self.tree):
            if (
                isinstance(node, ast.keyword)
                and node.arg in _FILE_APPROVAL_KWARGS
                and not (isinstance(node.value, ast.Constant) and not node.value.value)
            ):
                return True
            if isinstance(node, (ast.Name, ast.Attribute)) and _last(_dotted(node)) in _FILE_APPROVAL_NAMES:
                return True
            if isinstance(node, ast.alias) and _last(node.name) in _FILE_APPROVAL_NAMES:
                return True
        return False

    def tools(self) -> list[tuple[str, ast.AST, list[_FunctionNode], bool]]:
        """(tool name, report node, bodies to inspect, declares approval)."""
        found: dict[str, tuple[str, ast.AST, list[_FunctionNode], bool]] = {}
        for node in walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                flags = [_decorator_tool(decorator) for decorator in node.decorator_list]
                if any(is_tool for is_tool, _ in flags):
                    found[f"def:{id(node)}"] = (node.name, node, [node], any(ok for _, ok in flags))
            elif isinstance(node, ast.ClassDef) and any(
                _last(_dotted(base)) in _TOOL_BASE_CLASSES for base in node.bases
            ):
                bodies = [
                    item
                    for item in node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in _TOOL_RUN_METHODS
                ]
                if bodies:
                    found[f"class:{id(node)}"] = (node.name, node, bodies, False)
        for name in self._referenced_tool_functions():
            function = self.functions.get(name)
            if function is not None and f"def:{id(function)}" not in found:
                found[f"def:{id(function)}"] = (name, function, [function], False)
        return list(found.values())

    def _referenced_tool_functions(self) -> set[str]:
        names: set[str] = set()
        for node in walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            callee = _last(_dotted(node.func))
            lists = [kw.value for kw in node.keywords if kw.arg == "tools"]
            if callee in _TOOL_LIST_CALLS:
                lists.extend(arg for arg in node.args if isinstance(arg, (ast.List, ast.Tuple)))
            for value in lists:
                if isinstance(value, (ast.List, ast.Tuple)):
                    names.update(elt.id for elt in value.elts if isinstance(elt, ast.Name))
            if callee in _TOOL_WRAPPERS:
                candidates = [kw.value for kw in node.keywords if kw.arg in {"func", "fn", "coroutine"}]
                if callee in {"from_function", "from_defaults"} and node.args:
                    candidates.append(node.args[0])
                names.update(c.id for c in candidates if isinstance(c, ast.Name))
        return names

    def inspect(self, bodies: list[_FunctionNode]) -> tuple[list[tuple[str, str]], bool]:
        """Risky operations reachable from the tool bodies (one level of same-file helpers)."""
        operations: list[tuple[str, str]] = []
        approved = False
        visited: set[int] = set()
        queue: list[tuple[_FunctionNode, int]] = [(body, 0) for body in bodies]
        while queue:
            function, depth = queue.pop()
            if id(function) in visited:
                continue
            visited.add(id(function))
            for node in walk(function):
                if not isinstance(node, ast.Call):
                    continue
                if _approval_call(node):
                    approved = True
                operation = _risky_operation(node)
                if operation and operation not in operations:
                    operations.append(operation)
                helper = self.functions.get(node.func.id) if isinstance(node.func, ast.Name) else None
                if helper is not None and depth < 1:
                    queue.append((helper, depth + 1))
        return operations, approved

    def findings(self) -> list[Finding]:
        if self.file_has_approval_gate():
            return []
        results: list[Finding] = []
        for name, node, bodies, declared in self.tools():
            operations, approved = self.inspect(bodies)
            if declared or approved or not operations:
                continue
            kinds = list(dict.fromkeys(kind for kind, _ in operations))
            executes_code = "code_execution" in kinds
            results.append(
                Finding(
                    rule_id="AGENTLATCH-AG004",
                    title="High-risk agent tool without human approval",
                    severity="high" if executes_code else "medium",
                    message=(
                        f"Tool '{name}' lets the model {', '.join(_KIND_TEXT[kind] for kind in kinds)}, "
                        "and no approval gate was found in this file (LangGraph interrupt() or interrupt_before, "
                        "HumanApprovalCallbackHandler, HumanInTheLoopMiddleware, needs_approval=True). "
                        "Require human confirmation for these actions or narrow what the tool can do."
                    ),
                    path=self.path,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    # ASI09: the PDF lists missing confirmation for sensitive actions as an example.
                    owasp=("ASI02", "ASI05", "ASI09") if executes_code else ("ASI02", "ASI03", "ASI09"),
                    confidence="medium",
                    evidence=f"tool '{name}' calls {', '.join(ev for _, ev in operations[:3])}; no approval gate",
                )
            )
        return results


# ---------------------------------------------------------------- AG005: unrestricted built-in tools

_SHELL_TOOLS = {"ShellTool", "BashProcess", "TerminalTool"}
_PYTHON_TOOLS = {"PythonREPLTool", "PythonAstREPLTool", "PythonREPL"}
_DANGEROUS_LOAD_TOOLS = {"terminal", "shell", "python_repl"}


def _builtin_tool_findings(tree: ast.Module, path: str) -> list[Finding]:
    results: list[Finding] = []

    def add(node: ast.Call, severity: str, owasp: tuple[str, ...], evidence: str, why: str) -> None:
        results.append(
            Finding(
                rule_id="AGENTLATCH-AG005",
                title="Agent given an unrestricted built-in tool",
                severity=severity,
                message=f"{why} Restrict the tool to the operations the agent needs, sandbox it, or require approval.",
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=owasp,
                confidence="high",
                evidence=evidence,
            )
        )

    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _last(_dotted(node.func))
        if name in _SHELL_TOOLS:
            add(node, "high", ("ASI02", "ASI05"), f"{name}(...)", f"{name} lets the model run arbitrary shell commands on the host.")
        elif name in _PYTHON_TOOLS:
            add(node, "high", ("ASI02", "ASI05"), f"{name}(...)", f"{name} lets the model run arbitrary Python on the host.")
        elif name == "load_tools" and node.args:
            dangerous = sorted(set(_str_constants(node.args[0])) & _DANGEROUS_LOAD_TOOLS)
            if dangerous:
                add(node, "high", ("ASI02", "ASI05"), f"load_tools([{', '.join(map(repr, dangerous))}])",
                    "load_tools() loads a tool that runs shell commands or Python on the host.")
        elif name == "CodeInterpreterTool" and _is_true(_keyword(node, "unsafe_mode")):
            add(node, "high", ("ASI02", "ASI05"), "CodeInterpreterTool(unsafe_mode=True)",
                "CodeInterpreterTool with unsafe_mode=True runs model-written code directly on the host.")
        elif name == "FileManagementToolkit":
            missing = [kw for kw in ("root_dir", "selected_tools") if _keyword(node, kw) is None]
            if missing:
                add(node, "medium", ("ASI02", "ASI03"), f"FileManagementToolkit(...) without {' or '.join(missing)}",
                    "FileManagementToolkit gives the model read, write, move, and delete access to files.")
        elif _is_true(_keyword(node, "allow_dangerous_requests")):
            add(node, "medium", ("ASI02", "ASI03"), f"{name}(allow_dangerous_requests=True)",
                "allow_dangerous_requests=True lets the model send arbitrary HTTP requests, including to internal services.")
    return results


# ---------------------------------------------------------------- entry point


def scan_agent_code(tree: ast.Module, path: str) -> list[Finding]:
    """Manifest-independent agent checks for one parsed Python file."""
    return [
        *_PromptCollector(path).visit(tree),
        *_ToolAnalysis(tree, path).findings(),
        *_builtin_tool_findings(tree, path),
        *scan_oversight(tree, path),
    ]
