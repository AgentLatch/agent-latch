# Challenge: ECC / Unpinned Remote Instinct Import into Session Context (Challenge 04)

## 1. Upstream Source Repository

**GitHub Link:** https://github.com/affaan-m/ECC

**Target Vulnerable File:** [`skills/continuous-learning-v2/scripts/instinct-cli.py`](https://github.com/affaan-m/ECC/blob/ef648e01899ba3e8dc6371642deaaf64b4477775/skills/continuous-learning-v2/scripts/instinct-cli.py#L897-L965) (Lines 897–965)

## 2. What is the Vulnerability?

`/instinct-import <url>` fetches an instinct file from any public HTTPS URL (it blocks private addresses and caps the size) and stores its free-text guidance verbatim with no content hash, signature, or pinned revision, so a mutable source such as a branch-based raw GitHub URL can change between review and import. The file's self-declared `confidence` value decides whether it replaces a developer's existing instinct with the same ID and how highly it ranks when `scripts/hooks/session-start.js` (lines 453–527) injects instincts into every new session, letting an upstream author push persistent behavioral instructions into the agent.
