# Agent Zero — Unverified Remote MCP Server Registration

### GitHub Link
[https://github.com/agent0ai/agent-zero.git](https://github.com/agent0ai/agent-zero.git)

### Target Vulnerable Files
* `helpers/mcp_handler.py`, `MCPServerRemote` / `MCPConfig.__init__()` (lines 534–627 and 751 onward)
  * **(Execution)** `MCPClientRemote._create_stdio_transport()` (lines 1621–1660); `MCPClientBase.update_tools()` (lines 1430–1465)

### Vulnerability
Agent Zero accepts a remote MCP server configuration containing an arbitrary URL and connects to it without repository-level server identity, provenance, signature, or trust-policy verification beyond optional TLS certificate verification. The server's returned tools are subsequently incorporated into Agent Zero's executable capability set, allowing a compromised or malicious MCP endpoint to introduce attacker-controlled agent capabilities.