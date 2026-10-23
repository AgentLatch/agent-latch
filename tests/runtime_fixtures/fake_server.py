"""Synthetic MCP server for runtime proxy tests: one normal tool, one failing tool, one prompt.

Run directly (stdio): python fake_server.py
"""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

server = FastMCP("fake-weather")


@server.tool(annotations={"readOnlyHint": True})
def get_weather(city: str, units: str = "metric") -> str:
    """Return a canned weather report for a city."""
    return f"Weather in {city}: 18 degrees ({units}), light rain."


@server.tool
def leaky_lookup(user: str) -> str:
    """Return a record that contains a credential-shaped value, to test redaction."""
    token = "sk-" + "FAKE0123456789abcdefFAKE"
    return f"user={user} token={token}"


@server.tool
def broken_tool(reason: str) -> str:
    """Always fail."""
    raise ToolError("broken on purpose")


@server.prompt
def summarize(topic: str) -> str:
    """Prompt template that asks for a summary."""
    return f"Summarize the latest news about {topic} in three bullet points."


if __name__ == "__main__":
    server.run(show_banner=False)
