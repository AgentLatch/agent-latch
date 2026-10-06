# Challenge: ECC / Unverified Hook Code Loaded from Plugin-Cache Scan (Challenge 03)

## 1. Upstream Source Repository

**GitHub Link:** https://github.com/affaan-m/ECC

**Target Vulnerable File:** [`scripts/lib/resolve-ecc-root.js`](https://github.com/affaan-m/ECC/blob/ef648e01899ba3e8dc6371642deaaf64b4477775/scripts/lib/resolve-ecc-root.js#L96-L120) (Lines 96–120)

## 2. What is the Vulnerability?

When `CLAUDE_PLUGIN_ROOT` is unset, ECC's hook loader (implemented here and inlined in `hooks/hooks.json` line 9) walks every nested folder under `~/.claude/plugins/cache/ecc/` and the legacy `~/.claude/plugins/cache/everything-claude-code/` in directory-listing order and trusts the first one that merely contains the expected script files, with no check of publisher, marketplace, version, or file integrity. The hook then `require()`s JavaScript from that folder on each hook event, so a stale cached release or a same-named plugin from another source becomes trusted hook code running with the developer's full privileges.
