# Challenge: [MultiAgentTrainer / Unvetted Multi-Source Ingestion Feeds a Code-Executing Autonomous Agent] (Challenge 04)

## 1. Upstream source repository
- GitHub Link: https://github.com/sroomberg/MultiAgentTrainer
- Version analyzed: 2.0.2 (pyproject.toml)
- Target vulnerable file(s):
  - src/multiagenttrainer/ingest.py (lines 90-114)
  - src/multiagenttrainer/sources/github_org.py (lines 109-125)
  - src/multiagenttrainer/runner.py (lines 252-312)
  - src/multiagenttrainer/executor.py (lines 40-51, 83-96, 136-147)

## 2. What is the vulnerability?
- `Ingester.build_corpus` (ingest.py:90-114) concatenates raw content from every fetched source into one training corpus with only a `### FILE: {path}` provenance header — no content scanning, instruction-pattern filtering, or sanity check — and sources like `GitHubOrgSource.fetch` (github_org.py:109-125) will clone every repo in an entire GitHub org (up to `max_repos`, default 100) with no allow-list or review step, before that exact workspace is uploaded and handed to the autonomous `autoresearch` coding agent via `executor.run(cmd=agent_command, cwd=ar_dir, ...)` (runner.py:252-312), which executes with real subprocess, SSH, or Docker authority depending on the configured `Executor` (executor.py:40-51, 83-96, 136-147). Because the agent reads the ingested corpus as part of its own reasoning context while deciding what code to write and run next, a single instruction planted in any ingested file — by anyone who can merge content into any repo in a configured org, or get a `--repo` pointed at their own public repo — can hijack the agent's next action, and that action executes for real.