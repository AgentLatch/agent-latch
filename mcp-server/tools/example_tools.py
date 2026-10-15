"""Example local tools. Every .py file in this folder is loaded at startup.

To add your own: copy this file, rename it, and add functions inside register().
The function name becomes the tool name, the docstring is what the agent reads,
and the type hints become the tool's input schema.
"""

from __future__ import annotations

from datetime import UTC, datetime


def register(mcp) -> None:
    @mcp.tool
    def echo(text: str) -> str:
        """Return the text unchanged. Useful to check that an agent is connected."""
        return text

    @mcp.tool
    def utc_now() -> str:
        """Return the current UTC time in ISO 8601 format."""
        return datetime.now(UTC).isoformat()
