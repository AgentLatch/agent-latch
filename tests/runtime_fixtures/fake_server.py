"""Synthetic MCP server for runtime proxy tests; the server itself lives in the package.

Run directly (stdio, with ``src`` on PYTHONPATH): python fake_server.py
"""

from __future__ import annotations

from agent_latch.runtime.demo_server import server

if __name__ == "__main__":
    server.run(show_banner=False)
