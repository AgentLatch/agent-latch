"""Test MCP server that stands in for an agent-facing "query the audit log" tool [needs fastmcp].

The tool itself ships in the package (``agent_latch.runtime.audit_tool``, the ``audit-tool``
command): its tools hold only a ``SQLiteEventReader``, never the writer, and the query tool takes raw
SQL on purpose, so a test can ask it to delete, change, drop, alter or attach and show that each
request fails. This wrapper only lets a test or Claude Desktop start it by file path.

Run directly (stdio, ``src`` on PYTHONPATH, database path in AGENTLATCH_AUDIT_DB):
python audit_reader_server.py
"""

from __future__ import annotations

import os
from pathlib import Path

from fastmcp import FastMCP

from agent_latch.runtime.audit_tool import build_audit_tool


def build_server(database: Path) -> FastMCP:
    return build_audit_tool(database, name="audit-reader")


if __name__ == "__main__":
    build_server(Path(os.environ["AGENTLATCH_AUDIT_DB"])).run(show_banner=False)
