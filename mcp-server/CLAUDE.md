# CLAUDE.md: MCP gateway standards

This file is for Claude Code, other coding agents and people changing the MCP gateway in this folder. It sets the standard for adding tools, tool servers and environment variables. For first-time setup, see [SETUP.md](SETUP.md).

The gateway is a local developer tool, separate from the AgentLatch scanner:

- Don't import from `src/agent_latch`.
- Don't add gateway dependencies to the root `pyproject.toml`. They go in [`requirements.txt`](requirements.txt), pinned.

## Layout

| Path | Purpose |
|---|---|
| `server.py` | The gateway. Loads `tools/`, mounts `servers.json`, reads `.env`. Change it only when the gateway itself needs to work differently. |
| `tools/*.py` | Local Python tools. Every file not starting with `_` is loaded. |
| `servers.json` | Other MCP servers mounted behind the gateway. |
| `.env.example` | Committed list of every environment variable, with empty values. |
| `.env` | Each person's real values. Git-ignored; never commit it. |
| `logs/` | Output of local tool servers, one file per server. Git-ignored. |

## Standard 1: add a Python tool

1. **Pick the file.** Use `tools/<area>_tools.py`, lowercase snake_case, one file per service or area (for example `jira_tools.py`). Add to an existing file if the area already has one.
2. **Use this shape.** Tools are defined inside `register(mcp)`; the gateway calls it at startup.

   ```python
   """Jira tools: read issues from the team's Jira."""

   from __future__ import annotations

   import os

   from fastmcp.exceptions import ToolError


   def register(mcp) -> None:
       @mcp.tool
       def get_issue(key: str) -> dict:
           """Read one Jira issue by key, for example PROJ-123. Read-only."""
           token = os.environ.get("JIRA_API_TOKEN")
           if not token:
               raise ToolError("JIRA_API_TOKEN is not set. Add it to mcp-server/.env and restart.")
           ...
   ```

3. **Follow these rules:**
   - **Name:** `verb_noun` in snake_case, for example `get_issue` or `list_builds`. It must be unique across `tools/`. Local tools have no prefix, and mounted servers use `<server>_`, so never start a local tool's name with a server name from `servers.json`.
   - **Docstring:** the first line says what the tool does, in one sentence. Agents choose tools by reading it. If the tool changes anything (writes files, runs commands, sends messages, calls paid APIs), say so in that first line.
   - **Type hints:** on every parameter and the return value; they become the tool's input schema. Use simple types (`str`, `int`, `float`, `bool`, `list`, `dict`), `Literal[...]` for fixed choices, and defaults for optional parameters.
   - **Secrets:** read them with `os.environ.get("NAME")` inside the tool. Never hard-code them, and never return, log or print them. If one is missing, `raise ToolError(...)` saying which variable to set. Add the variable by following Standard 3.
   - **Errors:** raise `ToolError` with a message the agent can act on. Don't let raw exceptions leak secrets or file paths.
   - **Output:** return text or JSON-serializable data, kept short. Cap or summarize long results.
   - **No `print()`:** in stdio mode, stdout carries the MCP protocol, and printing breaks the connection. Use `logging`, which writes to stderr.
   - **Limits:** set a timeout on every network call. Tools that touch files stay inside a fixed folder such as `mcp-server/workspace/`.
   - **Dependencies:** if a tool needs a package, add it to `requirements.txt` with an exact version (`name==x.y.z`).
4. **Verify it** using the checklist below.

## Standard 2: add another MCP server

Add an entry under `mcpServers` in `servers.json`:

```json
"jira": {
  "description": "Read and update Jira issues. Needs JIRA_URL and JIRA_API_TOKEN in .env.",
  "enabled": false,
  "command": "uvx",
  "args": ["mcp-atlassian==0.21.0"],
  "env": {"JIRA_URL": "${JIRA_URL}", "JIRA_API_TOKEN": "${JIRA_API_TOKEN}"}
}
```

- **Key:** short, lowercase, no spaces. It becomes the tool prefix (`jira_...`).
- **`description`:** what the server does and which `.env` variables it needs.
- **`enabled`:** commit new servers as `false` unless they need no token and only read data. Each person turns them on locally.
- **Pin every version:** `uvx pkg==x.y.z` or `npx -y @scope/pkg@x.y.z`. Never `@latest`, and never an unpinned package. An unpinned server can change under you, which is the supply-chain risk documented in this repo's ASI04 challenges.
- **Local servers** use `command`, `args` and `env`. A local server only receives the variables listed in its `env` block, so pass exactly what it needs.
- **Remote servers** use `url` and `headers`, for example `"Authorization": "Bearer ${SERVICE_TOKEN}"`.
- **Secrets** only ever appear as `${NAME}`, never as literal values.
- **Source:** prefer the vendor's official server or the reference servers from the MCP project. Read the server's README before adding it.

## Standard 3: add an environment variable

1. **Name it** in UPPER_SNAKE_CASE with the service as a prefix: `GITHUB_TOKEN`, `JIRA_URL`, `JIRA_API_TOKEN`.
2. **Add it to `.env.example`** with an empty value and a one-line comment saying which tool or server uses it and where to get it:

   ```sh
   # jira server in servers.json. Create at https://id.atlassian.com/manage-profile/security/api-tokens
   JIRA_API_TOKEN=
   ```

   Never put a real or realistic-looking value in `.env.example`.
3. **Put the real value in your own `.env`.** Copy it from `.env.example` if you haven't yet.
4. **Use it** as `${NAME}` in `servers.json`, or with `os.environ.get("NAME")` in a Python tool.
5. **Restart the gateway.** If a variable a server needs is empty, the gateway skips that server and names the missing variable.

## Checklist before committing

- [ ] `python server.py --check` lists the new tools, with no unexpected `skip` lines.
- [ ] The tool works when called from a real agent.
- [ ] `ruff check mcp-server`, run from the repo root, passes.
- [ ] `agent-latch scan . --fail-on high --project-ignores`, run from the repo root, passes.
- [ ] `.env.example` lists every new variable, with empty values.
- [ ] No secrets in any committed file. `.env`, `logs/` and `workspace/` are not staged.
- [ ] `README.md` and `SETUP.md` are updated if setup or connection steps changed.

## Don'ts

- Don't commit `.env` or paste tokens into code, `servers.json`, issues or chat.
- Don't add unpinned servers, `@latest` or `npx -y` without a version.
- Don't widen `--host` beyond `127.0.0.1` without setting `MCP_GATEWAY_TOKEN`.
- Don't change the AgentLatch scanner from this folder.
