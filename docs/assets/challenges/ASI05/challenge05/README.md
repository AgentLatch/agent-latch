# Challenge: [AIPass / "Arbitrary Drone Command" Skill Bypasses Its Own Prefix Check] (Challenge 10)

## 1. Upstream source repository
- GitHub Link: https://github.com/AIOSAI/AIPass
- Version analyzed: 2.8.18
- Target vulnerable file(s):
  - src/aipass/skills/lib/drone_commands/handler.py (lines 67-75)
  - src/aipass/skills/lib/drone_commands/apps/modules/command_runner.py (lines 64-67, 69)
  - src/aipass/skills/lib/drone_commands/apps/handlers/executor.py (lines 62-70)

## 2. What is the vulnerability?
- The `drone_commands` skill's `run` action (SKILL.md: "Execute an arbitrary drone command string")
  takes `args.get("command", "")` (handler.py:67-75) and passes it to `command_runner.run_command`,
  whose only guard (command_runner.py:64-67) is `if not cmd.startswith("drone"): cmd = f"drone {cmd}"`
  — a prefix check that inspects only the start of the string and does nothing to block `;`, `&&`,
  `|`, backticks, or `$()` appearing anywhere after it. The resulting string is then run via
  `subprocess.run(command, shell=True, ...)` in `executor.execute` (executor.py:62-70) with no
  further sanitization, so any shell metacharacter in the agent-supplied command string executes
  as a fully independent, unrestricted shell command alongside the intended drone call.