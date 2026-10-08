# Challenge: ECC2 / Delegate Guardrails Downgraded to Prompt Text for Non-Claude Agents (Challenge 03)

## 1. Upstream Source Repository

GitHub Link: https://github.com/affaan-m/ECC

Target Vulnerable File: ecc2/src/session/manager.rs (Lines 3398–3432)

## 2. What is the Vulnerability?

ECC2 enforces an agent profile's `allowed_tools`, `disallowed_tools`, `permission_mode`, and budget through CLI flags only for Claude sessions; for Codex, OpenCode, and Gemini sessions, `render_task_with_profile_projection` (lines 3501–3522) just prepends them to the task as an "ECC execution profile" text list that the delegate model is free to ignore. Because a lead session's handoff messages are turned directly into delegate tasks (lines 1118–1137) with no independent policy check between agents, an action that is blocked for a Claude session can be carried out by a teammate on another harness whose "Disallowed tools: Bash" is only a suggestion.
