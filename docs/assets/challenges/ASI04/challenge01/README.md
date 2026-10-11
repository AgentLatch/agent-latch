# Autono — Unverified Remote MCP Tool Registration

### GitHub Link
[https://github.com/vortezwohl/Autono.git](https://github.com/vortezwohl/Autono.git)

### Target Vulnerable Files
* `autono/brain/mcp_agent.py` (lines 33–39)
* `autono/ability/mcp_ability.py` (lines 13–27)
* **(Execution)** `autono/ability/mcp_ability.py` (lines 30–35)

### Vulnerability
`fetch_abilities()` blindly converts every tool returned by `session.list_tools()` into an executable `McpAbility` without verifying the MCP server, authorizing the tool, validating its schema, or checking its provenance. A compromised or malicious MCP server can therefore inject an arbitrary tool definition into the agent's capability set, after which the agent can select and invoke that tool through `session.call_tool()`.