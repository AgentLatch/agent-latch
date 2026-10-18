"""Lightweight, intra-module taint tracking from web/tool output into LLM prompts.

Tracks values from known web-search tools, web loaders, and HTTP clients through
assignments, loops, function returns, call arguments, and dict state keys (as used by
LangGraph nodes). It is a heuristic: no aliasing, no cross-module flow, no sanitizer model.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from agent_latch.astutil import walk
from agent_latch.prompts import looks_like_system_prompt

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
        defs = [node for node in walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {node.name: node for node in defs}
        self.scopes: list[_Scope] = [tree, *defs]  # every body, including methods that share a name
        self.tainted: dict[int, set[str]] = {id(scope): set() for scope in self.scopes}
        self.tool_objects: set[str] = set()
        self.tainted_returns: set[str] = set()
        self.tainted_keys: set[str] = set()

    source_classes = SOURCE_CLASSES
    track_state_keys = True  # LangGraph-style dict state: a key returned tainted is tainted wherever it is read

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
            if _callee(node) in self.tainted_returns or self.is_source(node):
                return True
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in self.tainted_keys
            ):
                return True
        return False

    def is_source(self, node: ast.Call) -> bool:
        """Web, HTTP, and search/loader tool calls whose result is untrusted content."""
        if _dotted(node.func) in SOURCE_CALLS:
            return True
        if isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            return node.func.attr in _TOOL_METHODS and (
                (isinstance(receiver, ast.Name) and receiver.id in self.tool_objects)
                or (isinstance(receiver, ast.Call) and _dotted(receiver.func) in SOURCE_CLASSES)
            )
        return False

    def is_tool_object(self, value: ast.AST) -> bool:
        return isinstance(value, ast.Call) and _dotted(value.func) in self.source_classes

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
                if self.is_tool_object(value):
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
                if isinstance(node.value, ast.Dict) and self.track_state_keys:
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

    def propagate_all(self) -> None:
        for _ in range(20):  # fixed point; bounded for safety on pathological input
            changed = False
            for scope in self.scopes:  # every scope must propagate each pass, so no any()
                changed |= self._propagate(scope)
            if not changed:
                break

    def run(self) -> list[PromptFlow]:
        self.propagate_all()
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


# ---------------------------------------------------------------- AG008: model output into actions

LLM_CLASSES = {
    "ChatOpenAI", "AzureChatOpenAI", "ChatAnthropic", "ChatGroq", "ChatOllama", "ChatGoogleGenerativeAI",
    "ChatVertexAI", "ChatMistralAI", "ChatCohere", "ChatBedrock", "ChatBedrockConverse", "ChatHuggingFace",
    "ChatLiteLLM", "OpenAI", "AsyncOpenAI", "AzureOpenAI", "Anthropic", "AsyncAnthropic", "Groq", "Ollama",
    "Llama", "LlamaCpp", "CTransformers", "HuggingFacePipeline", "GenerativeModel",
}
# Names that conventionally hold a model, chain, or agent, including ones created in another module
# (for example an `llm` parameter). Matched against every part of a call's receiver chain.
LLM_NAME = re.compile(r"(?i)(?:^|_)(?:llm|llms|chain|agent|model|chat|crew|graph)$")
_LLM_MODULES = {"openai", "anthropic", "ollama", "litellm", "genai", "cohere", "groq", "mistralai"}
_LLM_FUNCTIONS = {"completion", "acompletion"}
# LangChain wrappers whose function argument receives chain state (user input and model output).
# assign/pipe count only on a Runnable or model-like receiver, not on a pandas DataFrame.
_STATE_WRAPPERS = {"assign", "RunnableLambda", "pipe"}

_EXEC_SINKS = {"eval", "exec", "compile", "os.system", "os.popen", "pty.spawn",
               "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec"}
_SQL_FUNCTIONS = {"exec_driver_sql", "read_sql", "read_sql_query"}
# Generic names (tool.execute, agent.run) count only on a database-like receiver.
_DB_METHODS = {"execute", "executemany", "executescript", "raw", "run", "run_no_throw"}
_DB_NAME = re.compile(
    r"(?i)(?:^|_)(?:db|database|sql|sqldb|conn|connection|connect|cursor|cur|engine|session)$"
)
_HTTP_SINKS = {f"{lib}.{verb}" for lib in ("requests", "httpx")
               for verb in ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")}
_HTTP_SINKS |= {"urllib.request.urlopen", "urlopen"}
_FILE_SINKS = {"open", "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename", "os.replace",
               "shutil.rmtree", "shutil.move", "shutil.copy", "shutil.copyfile"}
# Keyword arguments that carry the dangerous part of a non-exec sink (not query parameters or bodies).
_SINK_KEYWORDS = {"sql", "query", "statement", "url", "file", "path", "src", "dst"}
# Path checks that keep a model-chosen file name inside a folder.
_PATH_CHECKS = {"is_relative_to", "relative_to", "commonpath", "secure_filename"}
_PATH_SANITIZER = re.compile(r"(?i)^_?(?:safe|sanitiz|clean_?(?:path|name|filename))")
# Functions the model calls as tools: their arguments are model output.
_TOOL_DECORATORS = {"tool", "function_tool", "kernel_function"}
_TOOL_WRAPPERS = {"Tool", "StructuredTool", "FunctionTool", "from_function", "from_defaults"}
# Names too generic to link across files by name alone.
_UNLINKABLE = {
    "run", "arun", "get", "set", "execute", "invoke", "call", "main", "process", "handle", "update", "send",
    "post", "put", "read", "write", "load", "save", "open", "close", "start", "stop", "format", "parse",
    "build", "create", "add", "append", "extend", "join", "split", "replace", "strip", "encode", "decode",
    "dumps", "loads", "print", "log", "info", "debug", "warning", "error", "exception", "copy", "items",
    "keys", "values", "pop", "insert", "remove", "sort", "reply", "chat", "search", "query", "find", "match",
    "submit", "result", "apply", "render", "init", "setup", "next", "send_message",
}


@dataclass(frozen=True)
class ProjectLinks:
    """Cross-file facts, linked by function name: which parameters receive model output from another file.

    Only arguments are linked. Linking return values by name spread taint across whole projects."""

    params: dict[str, frozenset[int | str]] = field(default_factory=dict)


def _linkable(name: str) -> bool:
    """Specific multi-word names (get_user_transactions) only; short ones (path, load) collide across files."""
    return len(name) >= 8 and "_" in name.strip("_") and not name.startswith("__") and name not in _UNLINKABLE


@dataclass(frozen=True)
class OutputFlow:
    line: int
    column: int
    kind: str
    sink: str


def _chain_parts(func: ast.AST) -> list[str]:
    """Names along a call target, e.g. self.llm.invoke -> [self, llm, invoke]."""
    parts: list[str] = []
    node = func
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, (ast.Call, ast.Subscript)):
            node = node.func if isinstance(node, ast.Call) else node.value
        else:
            break
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return list(reversed(parts))


def _sink(call: ast.Call) -> tuple[str, str] | None:
    """(kind, evidence) for a call that executes code, queries a database, fetches a URL, or touches files."""
    callee = _dotted(call.func) or ""
    method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
    if callee in _EXEC_SINKS or callee.startswith(("subprocess.", "os.exec", "os.spawn")):
        return "code_execution", f"{callee}()"
    if method in _SQL_FUNCTIONS:
        return "database", f"{method}()"
    if method in _DB_METHODS and isinstance(call.func, ast.Attribute):
        receiver = _chain_parts(call.func.value)
        if receiver and _DB_NAME.search(receiver[-1]):
            return "database", f"{'.'.join(receiver)}.{method}()"
    if callee in _HTTP_SINKS:
        return "network", f"{callee}()"
    if callee in _FILE_SINKS:
        return "filesystem", f"{callee}()"
    return None


class _OutputAnalysis(_Analysis):
    """Tracks LLM responses and model-chosen tool arguments (not web content) into calls that act on them."""

    source_classes = LLM_CLASSES
    # Generic keys ("data", "cells") would taint every .get() in the file; AG008 tracks values, not keys.
    track_state_keys = False

    def __init__(self, tree: ast.Module, links: ProjectLinks | None = None) -> None:
        super().__init__(tree)
        self.links = links or ProjectLinks()
        self._path_checked: dict[int, bool] = {}
        self._path_helpers: set[str] | None = None
        self._seed()

    def _seed(self) -> None:
        """Taint tool-function parameters, and parameters that other files pass model output to."""
        tools: set[str] = set()
        methods: dict[int, str] = {}
        for node in walk(self.tree):
            if isinstance(node, ast.Call) and (_chain_parts(node.func) or [""])[-1] in _TOOL_WRAPPERS:
                func = next((kw.value for kw in node.keywords if kw.arg in {"func", "coroutine", "fn"}), None)
                func = func or (node.args[0] if node.args else None)
                if isinstance(func, ast.Name):
                    tools.add(func.id)
            elif isinstance(node, ast.ClassDef):
                is_tool = any((_chain_parts(base) or [""])[-1].endswith("Tool") for base in node.bases)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods[id(item)] = f"{node.name}.{item.name}"
                        if is_tool and item.name in {"_run", "_arun"}:
                            tools.add(methods[id(item)])
        for scope in self.scopes:
            if scope is self.tree:
                continue
            params = _params(scope)
            decorated = any((_chain_parts(dec) or [""])[-1] in _TOOL_DECORATORS for dec in scope.decorator_list)
            is_function = id(scope) not in methods
            if decorated or (is_function and scope.name in tools) or methods.get(id(scope)) in tools:
                self._taint(scope, params)
            linked = self.links.params.get(scope.name)
            if linked:
                self._taint(scope, [name for index, name in enumerate(params) if index in linked or name in linked])

    def _is_llm_object(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tool_objects or bool(LLM_NAME.search(node.id))
        if isinstance(node, ast.Call):
            return self.is_tool_object(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return any(self._is_llm_object(part) for part in _pipe_parts(node))
        return False

    def is_tool_object(self, value: ast.AST) -> bool:
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
            return any(self._is_llm_object(part) for part in _pipe_parts(value))
        return isinstance(value, ast.Call) and (_chain_parts(value.func) or [""])[-1] in LLM_CLASSES

    def is_source(self, node: ast.Call) -> bool:
        if _sends_instructions(node):
            return True
        parts = _chain_parts(node.func)
        if not parts:
            return False
        if isinstance(node.func, ast.Name):
            name = parts[0]
            if name in self.tool_objects or name in _LLM_FUNCTIONS:
                return True
            # llm(...) is a model call; Agent(...) builds an object and a local def is tracked by its returns.
            return bool(LLM_NAME.search(name)) and not name[:1].isupper() and name not in self.functions
        receiver = parts[:-1]
        if not receiver:
            return False
        return (
            receiver[0] in _LLM_MODULES
            or receiver[-1] in LLM_CLASSES
            or any(part in self.tool_objects or LLM_NAME.search(part) for part in receiver)
        )

    def _propagate(self, scope: _Scope) -> bool:
        changed = super()._propagate(scope)
        for node in _scope_nodes(scope):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                seen_llm = False
                for part in _pipe_parts(node):
                    if seen_llm:
                        changed |= self._taint_callable(part, scope)
                    seen_llm = seen_llm or self._is_llm_object(part)
            elif isinstance(node, ast.Call) and self._is_state_wrapper(node):
                for value in (*node.args, *(keyword.value for keyword in node.keywords)):
                    changed |= self._taint_callable(value, scope)
        return changed

    def _is_state_wrapper(self, call: ast.Call) -> bool:
        parts = _chain_parts(call.func)
        if not parts or parts[-1] not in _STATE_WRAPPERS:
            return False
        return parts[-1] == "RunnableLambda" or any(
            part.startswith("Runnable") or part in self.tool_objects or LLM_NAME.search(part) for part in parts[:-1]
        )

    def _taint_callable(self, node: ast.AST, scope: _Scope) -> bool:
        """Taint the input parameter of a lambda or local function that a chain step receives."""
        if isinstance(node, ast.Call) and (_chain_parts(node.func) or [""])[-1] == "RunnableLambda" and node.args:
            node = node.args[0]
        if isinstance(node, ast.Lambda):
            return self._taint(scope, [arg.arg for arg in node.args.args[:1]])
        if isinstance(node, ast.Name) and node.id in self.functions:
            target = self.functions[node.id]
            params = [arg.arg for arg in (*target.args.posonlyargs, *target.args.args)][:1]
            return self._taint(target, params) if params else False
        return False

    def flows(self) -> list[OutputFlow]:
        self.propagate_all()
        found: dict[tuple[int, int], OutputFlow] = {}
        for scope in self.scopes:
            for node in _scope_nodes(scope):
                if not isinstance(node, ast.Call):
                    continue
                sink = _sink(node)
                if sink is None or (sink[0] == "filesystem" and self._checks_paths(scope)):
                    continue
                if any(self.is_tainted(argument, scope) for argument in _sink_arguments(node, sink[0])):
                    found.setdefault(
                        (node.lineno, node.col_offset),
                        OutputFlow(node.lineno, node.col_offset + 1, sink[0], sink[1]),
                    )
        return sorted(found.values(), key=lambda flow: (flow.line, flow.column))

    def _checks_paths(self, scope: _Scope) -> bool:
        """The scope rejects '..', confines the path to a folder, or calls a local helper that does,
        so its file sinks count as validated."""
        if self._path_helpers is None:
            self._path_helpers = set()
            changed = True
            while changed:  # helpers that call helpers: load -> file -> path -> _safe
                changed = False
                for candidate in self.scopes:
                    if candidate is self.tree or candidate.name in self._path_helpers:
                        continue
                    if self._checks_paths_directly(candidate):
                        self._path_helpers.add(candidate.name)
                        changed = True
        return self._checks_paths_directly(scope)

    def _checks_paths_directly(self, scope: _Scope) -> bool:
        helpers = self._path_helpers or set()
        if id(scope) not in self._path_checked or self._path_checked[id(scope)] is False:
            self._path_checked[id(scope)] = any(
                (
                    isinstance(node, ast.Compare)
                    and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
                    and any(isinstance(part, ast.Constant) and part.value == ".." for part in ast.walk(node))
                )
                or (
                    isinstance(node, ast.Call)
                    and (
                        (_chain_parts(node.func) or [""])[-1] in _PATH_CHECKS
                        or bool(_PATH_SANITIZER.search((_chain_parts(node.func) or [""])[-1]))
                        or _callee(node) in helpers
                    )
                )
                for node in _scope_nodes(scope)
            )
        return self._path_checked[id(scope)]

    def exports(self) -> dict[str, set[int | str]]:
        """Tainted arguments passed to functions defined elsewhere."""
        self.propagate_all()
        params: dict[str, set[int | str]] = {}
        for scope in self.scopes:
            for node in _scope_nodes(scope):
                if not isinstance(node, ast.Call):
                    continue
                name = (_chain_parts(node.func) or [""])[-1]
                if not _linkable(name) or _callee(node) in self.functions:
                    continue
                positions: set[int | str] = {
                    index for index, arg in enumerate(node.args)
                    if not isinstance(arg, ast.Starred) and self.is_tainted(arg, scope)
                }
                positions |= {kw.arg for kw in node.keywords if kw.arg and self.is_tainted(kw.value, scope)}
                if positions:
                    params.setdefault(name, set()).update(positions)
        return params


def _params(scope: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    names = [arg.arg for arg in (*scope.args.posonlyargs, *scope.args.args)]
    names = names[1:] if names[:1] in (["self"], ["cls"]) else names
    return names + [arg.arg for arg in scope.args.kwonlyargs]


def _sink_arguments(call: ast.Call, kind: str) -> list[ast.expr]:
    """The arguments that decide what a sink does: all of them for code execution, otherwise the
    statement, URL, or path (so parameterized queries and request bodies are not reported)."""
    if kind == "code_execution":
        return [*call.args, *(kw.value for kw in call.keywords)]
    positional = call.args[:1] if kind in {"database", "network"} else list(call.args)
    return [*positional, *(kw.value for kw in call.keywords if kw.arg in _SINK_KEYWORDS)]


def link_project(trees: list[ast.Module], rounds: int = 4) -> ProjectLinks:
    """Follow model output across files by function name, a few hops deep."""
    links = ProjectLinks()
    for _ in range(rounds):
        params: dict[str, set[int | str]] = {}
        for tree in trees:
            for name, positions in _OutputAnalysis(tree, links).exports().items():
                params.setdefault(name, set()).update(positions)
        new = ProjectLinks({name: frozenset(positions) for name, positions in params.items()})
        if new == links:
            break
        links = new
    return links


def _sends_instructions(call: ast.Call) -> bool:
    """A call given role or rule text ("You are ...", "Instruction: ...") is a model call, whatever it is named."""
    if not call.args or _sink(call) is not None:
        return False
    text = "".join(
        part.value for part in ast.walk(call.args[0]) if isinstance(part, ast.Constant) and isinstance(part.value, str)
    )
    return looks_like_system_prompt(text)


def _pipe_parts(node: ast.AST) -> list[ast.AST]:
    """Operands of an LCEL pipe a | b | c, left to right."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return [*_pipe_parts(node.left), *_pipe_parts(node.right)]
    return [node]


def find_model_output_actions(tree: ast.Module, links: ProjectLinks | None = None) -> list[OutputFlow]:
    return _OutputAnalysis(tree, links).flows()
