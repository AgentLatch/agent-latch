"""Lightweight, intra-module taint tracking from web/tool output into LLM prompts.

Tracks values from known web-search tools, web loaders, and HTTP clients through
assignments, loops, function returns, call arguments, and dict state keys (as used by
LangGraph nodes). It is a heuristic: no aliasing, no cross-module flow, no sanitizer model.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from agent_latch.astutil import walk

SOURCE_CLASSES = {
    "TavilySearch",
    "TavilySearchResults",
    "TavilyClient",
    "DuckDuckGoSearchRun",
    "DuckDuckGoSearchResults",
    "BraveSearch",
    "SerpAPIWrapper",
    "GoogleSearchAPIWrapper",
    "GoogleSerperAPIWrapper",
    "BingSearchAPIWrapper",
    "WikipediaQueryRun",
    "WikipediaLoader",
    "ArxivQueryRun",
    "WebBaseLoader",
    "AsyncHtmlLoader",
    "AsyncChromiumLoader",
    "PlaywrightURLLoader",
    "SeleniumURLLoader",
    "RecursiveUrlLoader",
    "SitemapLoader",
    "RequestsGetTool",
    "FirecrawlLoader",
}
SOURCE_CALLS = {
    "requests.get",
    "requests.post",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "urllib.request.urlopen",
    "urlopen",
}
_TOOL_METHODS = {
    "invoke",
    "ainvoke",
    "run",
    "arun",
    "load",
    "aload",
    "lazy_load",
    "results",
    "search",
    "get_relevant_documents",
}
_MESSAGE_SINKS = {"HumanMessage", "SystemMessage", "ChatMessage"}
# Prompts that fence retrieved content in tags or label it as untrusted are treated as mitigated.
_MITIGATION = re.compile(r"<[A-Za-z][\w-]*>|untrusted|do not follow", re.IGNORECASE)

_Scope = ast.AST  # a FunctionDef/AsyncFunctionDef, or the Module for top-level code


@dataclass(frozen=True)
class PromptFlow:
    line: int
    column: int
    sink: str


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _callee(node: ast.Call) -> str | None:
    """Simple name of a locally callable function: f(...) or self.f(...)."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"self", "cls"}
    ):
        return node.func.attr
    return None


def _target_names(target: ast.AST) -> list[str]:
    return [node.id for node in ast.walk(target) if isinstance(node, ast.Name)]


def _scope_nodes(scope: _Scope) -> list[ast.AST]:
    """Nodes belonging to this scope, excluding nested function bodies. Cached on the scope."""
    cached = getattr(scope, "_agent_latch_scope_nodes", None)
    if cached is not None:
        return cached
    roots = scope.body if isinstance(scope, ast.Module) else [scope]
    nodes: list[ast.AST] = []
    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        if node is not scope and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        nodes.append(node)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    scope._agent_latch_scope_nodes = nodes
    return nodes


class _Analysis:
    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
            node.name: node
            for node in walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.scopes: list[_Scope] = [tree, *self.functions.values()]
        self.tainted: dict[int, set[str]] = {id(scope): set() for scope in self.scopes}
        self.tool_objects: set[str] = set()
        self.tainted_returns: set[str] = set()
        self.tainted_keys: set[str] = set()

    def is_tainted(self, expr: ast.AST, scope: _Scope) -> bool:
        names = self.tainted[id(scope)]
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in names:
                return True
            if isinstance(node, ast.Subscript):
                key = node.slice
                if isinstance(key, ast.Constant) and key.value in self.tainted_keys:
                    return True
            if not isinstance(node, ast.Call):
                continue
            if _dotted(node.func) in SOURCE_CALLS:
                return True
            if _callee(node) in self.tainted_returns:
                return True
            if isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if node.func.attr in _TOOL_METHODS and (
                    (isinstance(receiver, ast.Name) and receiver.id in self.tool_objects)
                    or (isinstance(receiver, ast.Call) and _dotted(receiver.func) in SOURCE_CLASSES)
                ):
                    return True
                if (
                    node.func.attr == "get"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value in self.tainted_keys
                ):
                    return True
        return False

    def _taint(self, scope: _Scope, names: list[str]) -> bool:
        before = len(self.tainted[id(scope)])
        self.tainted[id(scope)].update(names)
        return len(self.tainted[id(scope)]) != before

    def _propagate(self, scope: _Scope) -> bool:
        changed = False
        for node in _scope_nodes(scope):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if isinstance(value, ast.Call) and _dotted(value.func) in SOURCE_CLASSES:
                    for target in targets:
                        before = len(self.tool_objects)
                        self.tool_objects.update(_target_names(target))
                        changed |= len(self.tool_objects) != before
                elif self.is_tainted(value, scope):
                    for target in targets:
                        changed |= self._taint(scope, _target_names(target))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                if self.is_tainted(node.iter, scope):
                    changed |= self._taint(scope, _target_names(node.target))
            elif isinstance(node, ast.Return) and node.value is not None and scope is not self.tree:
                if isinstance(node.value, ast.Dict):
                    for key, value in zip(node.value.keys, node.value.values, strict=True):
                        if (
                            isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                            and key.value not in self.tainted_keys
                            and self.is_tainted(value, scope)
                        ):
                            self.tainted_keys.add(key.value)
                            changed = True
                elif scope.name not in self.tainted_returns and self.is_tainted(node.value, scope):
                    self.tainted_returns.add(scope.name)
                    changed = True
            elif isinstance(node, ast.Call):
                changed |= self._taint_parameters(node, scope)
        return changed

    def _taint_parameters(self, call: ast.Call, scope: _Scope) -> bool:
        target = self.functions.get(_callee(call) or "")
        if target is None:
            return False
        params = [arg.arg for arg in (*target.args.posonlyargs, *target.args.args)]
        if params[:1] in (["self"], ["cls"]) and isinstance(call.func, ast.Attribute):
            params = params[1:]
        tainted: list[str] = [
            params[index]
            for index, arg in enumerate(call.args)
            if index < len(params) and not isinstance(arg, ast.Starred) and self.is_tainted(arg, scope)
        ]
        tainted.extend(
            keyword.arg
            for keyword in call.keywords
            if keyword.arg and self.is_tainted(keyword.value, scope)
        )
        return self._taint(target, tainted) if tainted else False

    def run(self) -> list[PromptFlow]:
        for _ in range(20):  # fixed point; bounded for safety on pathological input
            changed = False
            for scope in self.scopes:  # every scope must propagate each pass, so no any()
                changed |= self._propagate(scope)
            if not changed:
                break

        flows: dict[tuple[int, int], PromptFlow] = {}
        for scope in self.scopes:
            for node in _scope_nodes(scope):
                content: ast.AST | None = None
                sink = ""
                if isinstance(node, ast.Call) and _dotted(node.func) is not None:
                    name = _dotted(node.func).rsplit(".", 1)[-1]
                    if name in _MESSAGE_SINKS:
                        sink = f"{name} content"
                        content = next(
                            (kw.value for kw in node.keywords if kw.arg == "content"),
                            node.args[0] if node.args else None,
                        )
                elif isinstance(node, ast.Dict):
                    keys = {key.value: value for key, value in zip(node.keys, node.values, strict=True)
                            if isinstance(key, ast.Constant)}
                    if "role" in keys and "content" in keys:
                        sink, content = "chat message content", keys["content"]
                if content is None or not self.is_tainted(content, scope):
                    continue
                literal_text = "".join(
                    part.value
                    for part in ast.walk(content)
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
                if _MITIGATION.search(literal_text):
                    continue
                flows.setdefault((node.lineno, node.col_offset), PromptFlow(node.lineno, node.col_offset + 1, sink))
        return sorted(flows.values(), key=lambda flow: (flow.line, flow.column))


def find_untrusted_prompt_flows(tree: ast.Module) -> list[PromptFlow]:
    return _Analysis(tree).run()
