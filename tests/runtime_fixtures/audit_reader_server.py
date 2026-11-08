"""Test MCP server that stands in for an agent-facing "query the audit log" tool [needs fastmcp].

Its tools hold only a ``SQLiteEventReader`` (read-only connection, every statement but a read
refused), never the writer. The query tool takes raw SQL on purpose, as a real one might, so a
test can ask it to delete, change, drop, alter or attach and show that each request fails.

Run directly (stdio, ``src`` on PYTHONPATH, database path in AGENTLATCH_AUDIT_DB):
python audit_reader_server.py
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from agent_latch.runtime.sqlite_store import SQLiteEventReader


def build_server(database: Path) -> FastMCP:
    reader = SQLiteEventReader(database)
    reader.open()
    server = FastMCP("audit-reader")

    @server.tool(annotations={"readOnlyHint": True})
    def query_audit_log(sql: str) -> list[dict[str, Any]]:
        """Run one SQL statement against the audit log and return up to 200 rows."""
        return reader.query(sql)

    @server.tool(annotations={"readOnlyHint": True})
    def recent_events(limit: int = 5) -> list[dict[str, Any]]:
        """Return the newest stored events: time, tool or prompt name, and stage."""
        return reader.query(
            "SELECT timestamp, name, stage, seal_seq FROM events ORDER BY seal_seq DESC"
            f" LIMIT {int(limit)}"
        )

    return server


if __name__ == "__main__":
    build_server(Path(os.environ["AGENTLATCH_AUDIT_DB"])).run(show_banner=False)
