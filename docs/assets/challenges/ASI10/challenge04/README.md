# Challenge: ECC / Planted Instinct Files Persist as Active Instructions Across Sessions (Challenge 04)

## 1. Upstream Source Repository

GitHub Link: https://github.com/affaan-m/ECC

Target Vulnerable File: scripts/hooks/session-start.js (Lines 453–527)

## 2. What is the Vulnerability?

At every startup, ECC reads every instinct file in the project and global `personal/` and `inherited/` directories (`readInstinctsFromDir`, lines 415–440) and injects up to six of them into the session as "Active instincts", with no provenance check, signature, or expiry and without the "historical reference only" framing it applies to prior-session summaries (lines 726–738). A single instinct file planted once, by a compromised session, an injected prompt that uses the agent's own Write access, or a malicious tool, therefore keeps steering every future session indefinitely while the agent appears to work normally on its surface tasks.
