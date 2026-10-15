"""Slack tools: let an agent post a message to Slack through the gateway.

Needs a Slack bot token in mcp-server/.env:

    SLACK_BOT_TOKEN=xoxb-...        # Bot User OAuth Token, scope chat:write
    SLACK_CHANNEL=#your-channel     # default channel (name or ID); optional

How to get the token (about 3 minutes):
  1. https://api.slack.com/apps -> Create New App -> From scratch.
  2. OAuth & Permissions -> Bot Token Scopes -> add `chat:write`
     (and `chat:write.public` to post to public channels the bot hasn't joined).
  3. Install to Workspace -> copy the "Bot User OAuth Token" (starts xoxb-).
  4. Invite the bot to the channel: in Slack, type `/invite @YourApp`.

No secrets live in this file. The token is read from the environment at call time.
"""

from __future__ import annotations

import json
import os
import urllib.request

from fastmcp.exceptions import ToolError

API_BASE = os.environ.get("SLACK_API_BASE", "https://slack.com/api")


def _slack_post(method: str, token: str, payload: dict) -> dict:
    """Call one Slack Web API method and return the parsed JSON response."""
    request = urllib.request.Request(
        f"{API_BASE}/{method}",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode())


def _token() -> str:
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        raise ToolError(
            "SLACK_BOT_TOKEN is not set. Add it to mcp-server/.env and restart the gateway. "
            "See tools/slack_tools.py for how to create one."
        )
    return token


def register(mcp) -> None:
    @mcp.tool
    def slack_send_message(text: str, channel: str | None = None) -> dict:
        """Post a message to a Slack channel. Sends to a real Slack workspace.

        text:    the message to send.
        channel: channel name (#general) or ID; defaults to SLACK_CHANNEL from .env.
        """
        target = channel or os.environ.get("SLACK_CHANNEL")
        if not target:
            raise ToolError("No channel given and SLACK_CHANNEL is not set in .env.")
        data = _slack_post("chat.postMessage", _token(), {"channel": target, "text": text})
        if not data.get("ok"):
            raise ToolError(f"Slack rejected the message: {data.get('error', 'unknown error')}")
        return {"ok": True, "channel": data.get("channel"), "ts": data.get("ts"), "text": text}

    @mcp.tool
    def slack_whoami() -> dict:
        """Check the Slack connection and return the bot and workspace it is signed in as."""
        data = _slack_post("auth.test", _token(), {})
        if not data.get("ok"):
            raise ToolError(f"Slack auth failed: {data.get('error', 'unknown error')}")
        return {"ok": True, "user": data.get("user"), "team": data.get("team")}
