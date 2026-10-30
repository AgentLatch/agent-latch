"""Execution-containment and model-loading checks that work from source code alone.

- ALR06-S01: data is deserialized with a loader that can build objects and run code
  (yaml.load without a safe loader, pickle, torch.load without weights_only, or a framework
  option that explicitly allows it).
- ALR06-S02: model-written code runs without a sandbox (AutoGen use_docker=False, CrewAI
  code_execution_mode="unsafe", smolagents local executor, allow_dangerous_code=True).
- ALR11-S01: model weights or datasets are loaded with trust_remote_code=True, so the hub
  repository's own code runs in the agent process.

                                 (ASI05 Unexpected Code Execution (RCE); ASI04 Supply Chain)

Single-file, name-based heuristics over the AST. Nothing is imported or executed.
"""

from __future__ import annotations

import ast

from agent_latch.astutil import walk
from agent_latch.findings import Finding

# Loaders that construct arbitrary Python objects. Matched on the last dotted name, lowercased.
_UNSAFE_LOADERS = {"cunsafeloader", "cloader", "loader", "unsafe", "unsafeloader"}
# yaml.FullLoader avoids arbitrary object construction but is still not safe for untrusted input.
_RESTRICTED_LOADERS = {"cfullloader", "full", "fullloader"}
_YAML_LOADS = {"load", "load_all", "unsafe_load", "unsafe_load_all"}
_PICKLE_MODULES = {"cPickle", "dill", "pickle"}
_PICKLE_LOADS = {"load", "loads"}
_TORCH_LOADS = {"torch.load"}

_SANDBOX_OPTIONS = {
    # keyword: (value that removes the sandbox, explanation)
    "use_docker": (False, "use_docker=False runs model-written code on the host"),
    "code_execution_mode": ("unsafe", 'code_execution_mode="unsafe" runs model-written code on the host'),
    "executor_type": ("local", 'executor_type="local" runs model-written code on the host'),
    "allow_dangerous_code": (True, "allow_dangerous_code=True runs model-written Python in the agent process"),
}


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


def _constant(node: ast.AST | None) -> object:
    return node.value if isinstance(node, ast.Constant) else ...


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _loader_name(node: ast.AST | None) -> str:
    name = _dotted(node)
    return _last(name).lower()


def _deserialization(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []

    def add(
        node: ast.AST,
        evidence: str,
        why: str,
        severity: str = "high",
        consequence: str = (
            "A crafted file or response can then run code with the agent's privileges."
        ),
    ) -> None:
        findings.append(
            Finding(
                rule_id="ALR06-S01",
                title="Unsafe deserialization in the agent process",
                severity=severity,
                message=(
                    f"{why} {consequence} Use a data-only format (json, yaml.safe_load), or load only "
                    "artifacts you produced and verified."
                ),
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=("ASI05",),
                confidence="high" if severity == "high" else "medium",
                evidence=evidence,
            )
        )

    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        method = _last(name)
        if name.startswith("yaml.") and method in _YAML_LOADS:
            loader = _keyword(node, "Loader")
            if method.startswith("unsafe"):
                add(node, f"{name}(...) with an unsafe loader", f"{name}() can build arbitrary objects.")
            elif loader is not None and _loader_name(loader) in _UNSAFE_LOADERS:
                add(node, f"{name}(..., Loader={_dotted(loader)})", f"{name}() with this Loader can build arbitrary objects.")
            elif loader is not None and _loader_name(loader) in _RESTRICTED_LOADERS:
                add(
                    node,
                    f"{name}(..., Loader={_dotted(loader)})",
                    f"{name}() with this Loader is not safe for untrusted input.",
                    severity="medium",
                    consequence=(
                        "It avoids arbitrary object construction, but it still accepts more than a "
                        "data-only format."
                    ),
                )
            elif loader is None and method in {"load", "load_all"}:
                add(node, f"{name}(...) without a safe Loader", f"{name}() without Loader= can build arbitrary objects.")
        elif name.partition(".")[0] in _PICKLE_MODULES and method in _PICKLE_LOADS:
            add(node, f"{name}(...)", f"{name}() turns untrusted bytes into live Python objects.")
        elif name in _TORCH_LOADS and _constant(_keyword(node, "weights_only")) is not True:
            add(node, f"{name}(...) without weights_only=True", f"{name}() unpickles the checkpoint by default.",
                severity="medium")
        elif _constant(_keyword(node, "allow_dangerous_deserialization")) is True:
            add(node, f"{_last(name)}(allow_dangerous_deserialization=True)",
                "This loader option unpickles files from an untrusted source.")
    return findings


def _unsandboxed_execution(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _last(_dotted(node.func)) or "call"
        settings: list[tuple[str, ast.expr]] = [
            (keyword.arg, keyword.value) for keyword in node.keywords if keyword.arg in _SANDBOX_OPTIONS
        ]
        # The same options also appear in a config dict: code_execution_config={"use_docker": False}.
        settings.extend(
            (key.value, value)
            for key, value in _dict_items(node)
            if isinstance(key, ast.Constant) and key.value in _SANDBOX_OPTIONS
        )
        for keyword, value in settings:
            unsafe, why = _SANDBOX_OPTIONS[keyword]
            if not (isinstance(value, ast.Constant) and value.value == unsafe):
                continue
            findings.append(
                Finding(
                    rule_id="ALR06-S02",
                    title="Model-written code runs without a sandbox",
                    severity="high" if keyword == "allow_dangerous_code" else "medium",
                    message=(
                        f"{why}. A prompt-injected request then executes with the agent's own file, "
                        "network, and credential access. Run generated code in a container or a "
                        "sandboxed executor, or remove code execution from the agent."
                    ),
                    path=path,
                    line=value.lineno,
                    column=value.col_offset + 1,
                    owasp=("ASI05", "ASI02"),
                    confidence="high",
                    evidence=f"{callee}({keyword}={value.value!r})",
                )
            )
    return findings


def _dict_items(call: ast.Call) -> list[tuple[ast.expr, ast.expr]]:
    """Key/value pairs of a dict literal passed directly to this call.

    Only the call's own arguments are inspected, so a config dict that belongs to a nested call
    is reported once, by that call, instead of again by every enclosing call.
    """
    return [
        (key, value)
        for argument in (*call.args, *(keyword.value for keyword in call.keywords))
        if isinstance(argument, ast.Dict)
        for key, value in zip(argument.keys, argument.values, strict=True)
        if key is not None
    ]


def _model_loading(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        value = _keyword(node, "trust_remote_code")
        if not (isinstance(value, ast.Constant) and value.value is True):
            continue
        callee = _last(_dotted(node.func)) or "call"
        findings.append(
            Finding(
                rule_id="ALR11-S01",
                title="Remote model or dataset code trusted at load time",
                severity="high",
                message=(
                    f"{callee}(trust_remote_code=True) lets the model or dataset repository run its own "
                    "Python inside the agent process, so whoever controls that repository controls the "
                    "agent. Load weights that do not need remote code, or pin the revision and review "
                    "the code that runs."
                ),
                path=path,
                line=value.lineno,
                column=value.col_offset + 1,
                owasp=("ASI04",),
                confidence="high",
                evidence=f"{callee}(trust_remote_code=True)",
            )
        )
    return findings


def scan_sandbox(tree: ast.Module, path: str) -> list[Finding]:
    """ALR06-S01, ALR06-S02 and ALR11-S01 for one parsed Python file."""
    return [*_deserialization(tree, path), *_unsandboxed_execution(tree, path), *_model_loading(tree, path)]
