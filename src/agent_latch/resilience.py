"""Cascading-failure checks that work from source code alone.

- ALR08-S01: an outbound HTTP call has no timeout, so one stalled peer blocks the agent step
  and the calls behind it.
- ALR08-S02: a retry is unbounded (a bare tenacity @retry, backoff without max_tries, or
  max_retries/Retry(total=None)), so a failing dependency is retried forever.

                                 (ASI08 Cascading Failures)

Single-file, name-based heuristics over the AST. Nothing is imported or executed.
"""

from __future__ import annotations

import ast

from agent_latch.astutil import walk
from agent_latch.findings import Finding

# aiohttp is checked at ClientSession(...) instead: its request methods take no timeout= argument.
_HTTP_LIBRARIES = ("httpx.", "requests.", "urllib3.", "urllib.request.")
_HTTP_METHODS = {
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "send",
    "stream",
    "urlopen",
}
# Above this many attempts, a retry stops acting as a circuit breaker.
_RETRY_THRESHOLD = 100


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


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _has_timeout(call: ast.Call, *options: str) -> bool:
    """True when a timeout option is set to something other than a literal None."""
    for option in options:
        value = _keyword(call, option)
        if value is not None and not (isinstance(value, ast.Constant) and value.value is None):
            return True
    return False


def _has_positional_timeout(name: str, call: ast.Call) -> bool:
    """True when urlopen's third positional argument, its timeout, is set."""
    if name != "urllib.request.urlopen" or len(call.args) < 3:
        return False
    value = call.args[2]
    return not (isinstance(value, ast.Constant) and value.value is None)


def _missing_timeout(node: ast.Call, path: str, evidence: str, message: str) -> Finding:
    return Finding(
        rule_id="ALR08-S01",
        title="Outbound request without a timeout",
        severity="medium",
        message=message,
        path=path,
        line=node.lineno,
        column=node.col_offset + 1,
        owasp=("ASI08",),
        confidence="medium",
        evidence=evidence,
    )


def _timeout_findings(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        # aiohttp sets the timeout on the session, so its request methods take no timeout=.
        if name == "aiohttp.ClientSession" and not _has_timeout(node, "timeout", "timeout_total"):
            findings.append(
                _missing_timeout(
                    node,
                    path,
                    "aiohttp.ClientSession() without timeout=",
                    "aiohttp.ClientSession() opens a session with no timeout, so a peer that stops "
                    "responding blocks this agent step and every step queued behind it. Pass "
                    "timeout=aiohttp.ClientTimeout(total=...) to the session and fail the step "
                    "instead of waiting indefinitely.",
                )
            )
            continue
        if not name.startswith(_HTTP_LIBRARIES) or _last(name) not in _HTTP_METHODS:
            continue
        if _has_timeout(node, "timeout", "timeout_ms") or _has_positional_timeout(name, node):
            continue
        findings.append(
            _missing_timeout(
                node,
                path,
                f"{name}(...) without timeout=",
                f"{name}() has no timeout, so a peer that stops responding blocks this agent step "
                "and every step queued behind it. Pass an explicit timeout and fail the step "
                "instead of waiting indefinitely.",
            )
        )
    return findings


def _decorator_call(decorator: ast.expr) -> tuple[str, ast.Call | None]:
    if isinstance(decorator, ast.Call):
        return _last(_dotted(decorator.func)), decorator
    return _last(_dotted(decorator)), None


def _retry_problem(name: str, call: ast.Call | None) -> str | None:
    """Why this retry configuration never gives up, or None when it is bounded."""
    # tenacity: a bare @retry retries until the process stops.
    if name == "retry" and (call is None or not _bounded(call, ("stop", "stop_after_delay"))):
        return "tenacity @retry without stop="
    # backoff: on_exception() without max_tries or max_time never gives up.
    if name == "on_exception" and (call is None or not _bounded(call, ("max_tries", "max_time"))):
        return "backoff.on_exception() without max_tries="
    return None


def _bounded(call: ast.Call, options: tuple[str, ...]) -> bool:
    return any(_keyword(call, option) is not None for option in options)


def _retry_findings(tree: ast.Module, path: str) -> list[Finding]:
    findings: list[Finding] = []

    def add(node: ast.AST, evidence: str) -> None:
        findings.append(
            Finding(
                rule_id="ALR08-S02",
                title="Retry without a limit",
                severity="medium",
                message=(
                    f"{evidence} retries without a bound, so a dependency that keeps failing is retried "
                    "forever and the agent step never returns. Cap the attempts and the total wait, "
                    "then fail the step."
                ),
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
                owasp=("ASI08",),
                confidence="medium",
                evidence=evidence,
            )
        )

    for node in walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                name, call = _decorator_call(decorator)
                problem = _retry_problem(name, call)
                if problem:
                    add(decorator, problem)
        elif isinstance(node, ast.Call):
            name = _last(_dotted(node.func))
            total = _keyword(node, "total") if name == "Retry" else None
            if isinstance(total, ast.Constant) and total.value is None:
                add(node, "Retry(total=None)")
            for keyword in node.keywords:
                if keyword.arg != "max_retries":
                    continue
                value = keyword.value
                if isinstance(value, ast.Constant) and (
                    value.value is None or (isinstance(value.value, int) and value.value > _RETRY_THRESHOLD)
                ):
                    add(keyword.value, f"max_retries={value.value!r}")
    return findings


def scan_resilience(tree: ast.Module, path: str) -> list[Finding]:
    """ALR08-S01 and ALR08-S02 for one parsed Python file."""
    return [*_timeout_findings(tree, path), *_retry_findings(tree, path)]
