"""Endpoint checks for agent, tool and peer-agent traffic that crosses the network.

- ALR12-S01: an agent, tool or model endpoint is a plaintext http:// or ws:// URL for a host
  other than the loopback interface, so the traffic can be read or altered on the way.
- ALR03-S01: an agent or MCP server is bound to every interface (host="0.0.0.0"), so anything
  that can reach the machine can call it.

                                 (ASI07 Insecure Inter-Agent Communication; ASI03)

Single-file, name-based heuristics over the AST. Nothing is imported or executed.
"""

from __future__ import annotations

import ast
import re
from urllib.parse import SplitResult, urlsplit

from agent_latch.astutil import walk
from agent_latch.findings import Finding

# Keyword names that carry the address of a service the agent talks to.
_ENDPOINT_KWARGS = {
    "agent_url",
    "api_base",
    "api_url",
    "base_url",
    "endpoint",
    "endpoint_url",
    "mcp_url",
    "model_url",
    "server_url",
    "url",
    "webhook_url",
}
_PLAINTEXT = re.compile(r"(?i)^(?:http|ws)://")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

_BIND_KWARGS = {"bind", "host"}
_PUBLIC_BIND_VALUES = {"0.0.0.0", "::", "[::]"}  # matched as a string, never used as an address


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


def _redacted_url(parts: SplitResult) -> str:
    """scheme://host[:port] for a parsed URL, without userinfo, path, query or fragment.

    A URL can carry a password in its userinfo or a token in its query string, so only the parts
    needed to find the endpoint are ever reported.
    """
    host = parts.hostname or ""
    if ":" in host:  # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    try:
        port = f":{parts.port}" if parts.port is not None else ""
    except ValueError:  # a malformed port must not fail the scan
        port = ""
    return f"{parts.scheme}://{host}{port}"


def _endpoint_checks(tree: ast.Module, path: str) -> list[Finding]:
    """ALR12-S01: plaintext URL passed as an endpoint for a remote service."""
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg not in _ENDPOINT_KWARGS:
                continue
            value = keyword.value
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                continue
            if not _PLAINTEXT.match(value.value):
                continue
            try:
                parts = urlsplit(value.value)
                host = parts.hostname or ""
            except ValueError:
                continue
            if host in _LOOPBACK_HOSTS:
                continue
            callee = _last(_dotted(node.func)) or "call"
            endpoint = _redacted_url(parts)
            findings.append(
                Finding(
                    rule_id="ALR12-S01",
                    title="Plaintext agent endpoint",
                    severity="medium",
                    message=(
                        f"{callee}({keyword.arg}={endpoint}) uses an unencrypted scheme for a remote "
                        "service, so anyone on the path can read or rewrite agent, tool or model traffic. "
                        "Use https:// or wss://, and keep the host reachable only from where it is needed."
                    ),
                    path=path,
                    line=keyword.value.lineno,
                    column=keyword.value.col_offset + 1,
                    owasp=("ASI02", "ASI07"),
                    confidence="medium",
                    evidence=f"{callee}({keyword.arg}={endpoint}) over plaintext",
                )
            )
    return findings


def _bind_checks(tree: ast.Module, path: str) -> list[Finding]:
    """ALR03-S01: agent or MCP server listening on every interface."""
    findings: list[Finding] = []
    for node in walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _last(_dotted(node.func)) or "call"
        for keyword in node.keywords:
            if keyword.arg not in _BIND_KWARGS:
                continue
            value = keyword.value
            if not (isinstance(value, ast.Constant) and value.value in _PUBLIC_BIND_VALUES):
                continue
            findings.append(
                Finding(
                    rule_id="ALR03-S01",
                    title="Agent server bound to every interface",
                    severity="medium",
                    message=(
                        f"{callee}({keyword.arg}={value.value!r}) accepts connections from any address. "
                        "Anyone who can reach this machine can call the agent and its tools. Bind to "
                        "127.0.0.1 and put a gateway that authenticates callers in front, unless the "
                        "service is meant to be public."
                    ),
                    path=path,
                    line=keyword.value.lineno,
                    column=keyword.value.col_offset + 1,
                    owasp=("ASI03", "ASI07"),
                    confidence="low",
                    evidence=f"{callee}({keyword.arg}={value.value!r})",
                )
            )
    return findings


def scan_endpoints(tree: ast.Module, path: str) -> list[Finding]:
    """ALR12-S01 and ALR03-S01 for one parsed Python file."""
    return [*_endpoint_checks(tree, path), *_bind_checks(tree, path)]
