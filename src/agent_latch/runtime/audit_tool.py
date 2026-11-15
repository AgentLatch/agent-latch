"""``agent-latch-runtime audit-tool``: a read-only view of the event store for an agent [needs fastmcp].

An agent sometimes needs to look at what was recorded. This MCP server gives it two tools and nothing
else, and it holds only a ``SQLiteEventReader``: a read-only connection that refuses every statement
that is not a read, even raw SQL. It never opens the store for writing, never migrates it, and never
sees the anchor.

Run it where the agent cannot reach the store's file: in its own container, with the store in a
volume mounted read-only (see docs/docker.md). The agent then holds a tool, not a path.

Stdout carries the MCP protocol, so nothing here prints to it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from agent_latch.runtime.sqlite_store import SQLiteEventReader


def build_audit_tool(database: Path, *, name: str = "audit-log") -> FastMCP:
    """An MCP server whose tools can read the store at ``database`` and nothing else."""
    reader = SQLiteEventReader(database)
    reader.open()  # fails early (and clearly) when the store is missing, unsealed or newer
    server = FastMCP(name)

    @server.tool(annotations={"readOnlyHint": True})
    def query_audit_log(sql: str) -> list[dict[str, Any]]:
        """Run one SQL statement against the audit log and return up to 200 rows.

        The connection is read-only: statements that change anything are refused.
        """
        return reader.query(sql)

    @server.tool(annotations={"readOnlyHint": True})
    def recent_events(limit: int = 5) -> list[dict[str, Any]]:
        """Return the newest stored events: time, tool or prompt name, stage and seal number."""
        return reader.query(
            "SELECT timestamp, name, stage, seal_seq FROM events ORDER BY seal_seq DESC"
            f" LIMIT {max(1, min(int(limit), 200))}"
        )

    return server
