"""Memory and context checks that work from source code alone.

- ALR13-S01: content fetched from the web or a tool is written into agent memory or a vector
  store without validation, so it is replayed as context in a later turn or session.
- ALR13-S02: a memory or vector store is built once at module level, so every session and user
  shares it.

                                      (ASI06 Memory & Context Poisoning)

Single-file, name-based heuristics: web/tool output is traced by taint.py, everything else is
matched by class and method name. Nothing is imported or executed.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

from agent_latch.findings import Finding
from agent_latch.taint import MemoryFlow

# Memory objects whose class name ends in "Memory" (LangChain, Mem0, Letta) plus the vector-store
# clients that hold the same kind of state.
_VECTOR_STORES = {
    "Chroma",
    "FAISS",
    "MilvusClient",
    "Pinecone",
    "PineconeVectorStore",
    "QdrantClient",
    "WeaviateClient",
    "ZepClient",
}


def _last(name: str | None) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def _is_memory_class(name: str) -> bool:
    return name.endswith("Memory") or name in _VECTOR_STORES


def memory_write_findings(flows: Sequence[MemoryFlow], path: str) -> list[Finding]:
    """ALR13-S01 for the untrusted memory writes taint.py found in one file."""
    return [
        Finding(
            rule_id="ALR13-S01",
            title="Untrusted content written to agent memory",
            severity="medium",
            message=(
                f"Web or tool output reaches {flow.sink} without validation, so instructions hidden in "
                "that content are replayed as context in a later turn or session (memory poisoning). "
                "Validate or summarise the text before storing it, keep its source as metadata, and "
                "scope the write to the current session or user."
            ),
            path=path,
            line=flow.line,
            column=flow.column,
            owasp=("ASI06",),
            confidence="low",
            evidence=f"web/tool output reaches {flow.sink}",
        )
        for flow in flows
    ]


def shared_memory_findings(tree: ast.Module, path: str) -> list[Finding]:
    """ALR13-S02: memory or vector store created at module level instead of per session."""
    findings: list[Finding] = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            targets, value = statement.targets, statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            targets, value = [statement.target], statement.value
        else:
            continue
        if not isinstance(value, ast.Call):
            continue
        name = _last(_dotted(value.func))
        if not _is_memory_class(name):
            continue
        assigned = ", ".join(
            _dotted(target) for target in targets if _dotted(target)
        ) or "a module-level name"
        findings.append(
            Finding(
                rule_id="ALR13-S02",
                title="Agent memory shared across sessions",
                severity="low",
                message=(
                    f"{name}(...) is created once at module level and assigned to {assigned}, so every "
                    "session and user reads and writes the same memory. Build the memory per session or "
                    "user and filter retrieval by user or tenant."
                ),
                path=path,
                line=statement.lineno,
                column=statement.col_offset + 1,
                owasp=("ASI06",),
                confidence="low",
                evidence=f"module-level {name}(...)",
            )
        )
    return findings


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""
