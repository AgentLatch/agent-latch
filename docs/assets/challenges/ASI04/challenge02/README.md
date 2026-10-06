# Challenge: ECC / Unvalidated Remote MCP Tool Schemas via `mcp-remote` (Challenge 02)

## 1. Upstream Source Repository

**GitHub Link:** https://github.com/affaan-m/ECC

**Target Vulnerable File:** [`.codex/config.toml`](https://github.com/affaan-m/ECC/blob/ef648e01899ba3e8dc6371642deaaf64b4477775/.codex/config.toml#L53-L56) (Lines 53–56)

## 2. What is the Vulnerability?

ECC's Codex configuration connects to a remote MCP server through `npx -y mcp-remote https://mcp.exa.ai/mcp`, so both the bridge package (unpinned and fetched from npm at launch) and the tool names, descriptions, and `inputSchema` definitions the remote server advertises are accepted at runtime with no version pin, schema allow-list, or descriptor hash to detect changes. Because line 32 tells the agent on every prompt to "use available MCP servers when they can help," an upstream that changes its tool descriptors (a "rug pull") or a bad `mcp-remote` release, a package that has already shipped a critical flaw triggered by a malicious server (CVE-2025-6514), can steer or compromise the agent without any local review.
