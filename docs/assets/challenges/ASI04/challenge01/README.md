# Challenge: ECC / Unpinned `npx -y` MCP Server Packages (Challenge 01)

## 1. Upstream Source Repository

**GitHub Link:** https://github.com/affaan-m/ECC

**Target Vulnerable File:** [`mcp-configs/mcp-servers.json`](https://github.com/affaan-m/ECC/blob/ef648e01899ba3e8dc6371642deaaf64b4477775/mcp-configs/mcp-servers.json#L23-L43) (Lines 23–43)

## 2. What is the Vulnerability?

ECC's shipped MCP server catalog launches most servers with `npx -y <package>` using either no version or an explicit `@latest` tag (for example `@supabase/mcp-server-supabase@latest`), so every agent start resolves and executes whatever release the npm registry serves at that moment, with the install prompt suppressed and no version pin, lockfile, or integrity hash. A malicious or compromised release therefore runs immediately with the developer's local privileges and the API tokens set in each server's `env` block, even though the same file shows the safe pattern by pinning `mcp-atlassian==0.21.0` (line 15).
