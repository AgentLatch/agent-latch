"""Securely add or update a token in .env, without it showing on screen.

    python set_token.py                 # prompts for name and value
    python set_token.py SLACK_BOT_TOKEN # prompts only for the value

The value is read with hidden input (like a password prompt): it is never
echoed to the terminal and never stored in your shell history. It is written
only to mcp-server/.env, which is git-ignored and set to owner-only perms.
Never paste a token into a chat, a commit, or servers.json.
"""

from __future__ import annotations

import getpass
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENV = HERE / ".env"
EXAMPLE = HERE / ".env.example"
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def main() -> int:
    if not ENV.exists():
        ENV.write_text(EXAMPLE.read_text() if EXAMPLE.exists() else "", encoding="utf-8")
        print(f"Created {ENV.name} from .env.example")

    name = sys.argv[1] if len(sys.argv) > 1 else input("Variable name (e.g. SLACK_BOT_TOKEN): ").strip()
    if not NAME_RE.match(name):
        print(f"Invalid name '{name}'. Use UPPER_SNAKE_CASE, e.g. SLACK_BOT_TOKEN.", file=sys.stderr)
        return 1

    value = getpass.getpass(f"Paste the value for {name} (input hidden): ").strip()
    if not value:
        print("No value entered; nothing changed.", file=sys.stderr)
        return 1

    # Replace the line if the variable already exists, otherwise append it.
    lines = ENV.read_text(encoding="utf-8").splitlines()
    new_line = f"{name}={value}"
    found = False
    for i, line in enumerate(lines):
        if re.match(rf"^\s*{re.escape(name)}\s*=", line):
            lines[i] = new_line
            found = True
            break
    if not found:
        lines.append(new_line)
    ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    try:
        os.chmod(ENV, 0o600)  # owner read/write only
    except OSError:
        pass

    masked = value[:4] + "…" + value[-2:] if len(value) > 8 else "…"
    print(f"{'Updated' if found else 'Added'} {name} in {ENV.name} (value {masked}). Restart the gateway to load it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
