# Challenge: [MultiAgentTrainer / Autonomous Code-Executing Agent Unsandboxed by Default] (Challenge 02)

## 1. Upstream source repository
- GitHub Link: https://github.com/sroomberg/MultiAgentTrainer
- Version analyzed: 2.0.2
- Target vulnerable file(s):
  - src/multiagenttrainer/config.py (line 49)
  - src/multiagenttrainer/executor.py (lines 38-50)

## 2. What is the vulnerability?
- `ExecutionConfig.type` (config.py:49) defaults to `"local"` with no explicit opt-in required, and
  `LocalExecutor.run` (executor.py:38-50) runs `asyncio.create_subprocess_shell(cmd, ..., cwd=cwd,
  start_new_session=True)` directly on the host with the full privileges of whatever process invoked
  `mat train` — no container boundary, no restricted shell, no allow-listed command set, and no
  network or filesystem isolation. Because this executor is what the autonomous `autoresearch`
  coding agent uses to run whatever code it decides to write each iteration, the tool's default,
  out-of-the-box configuration gives an LLM-driven agent unrestricted host code execution unless a
  user manually opts into `ssh` or `docker` mode instead.