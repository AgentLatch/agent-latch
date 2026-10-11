"""Cached AST traversal shared by the rule modules.

Each rule walks the same parsed file several times. Caching the node list on the node itself
makes repeat walks cheap. Scanned trees are never modified, so the cache cannot go stale.
"""

from __future__ import annotations

import ast

_CACHE = "_agent_latch_nodes"


def walk(node: ast.AST) -> list[ast.AST]:
    """Same nodes, in the same order, as ast.walk(node)."""
    cached = getattr(node, _CACHE, None)
    if cached is None:
        cached = list(ast.walk(node))
        setattr(node, _CACHE, cached)
    return cached
