# Challenge: [Multi-Agent Research Lab / Unsanitized Tool Output Propagation] (Challenge 02)

## 1. Upstream source repository
- GitHub Link: https://github.com/KaitoKidKao/phase2-day5-multi-agent-lab
- Version analyzed: 0.1.0
- Target vulnerable file(s):
  - src/multi_agent_research_lab/agents/researcher.py (lines 28-31)
  - src/multi_agent_research_lab/services/search_client.py (lines 33-41)
  - src/multi_agent_research_lab/agents/analyst.py (line 24)
  - src/multi_agent_research_lab/agents/writer.py (lines 25-29)

## 2. What is the vulnerability?
- `ResearcherAgent.run` (researcher.py:28-31) concatenates raw `title`/`snippet` fields pulled
  directly from the Tavily search API response (search_client.py:33-41, i.e. arbitrary third-party
  web content) into an f-string `user_prompt` with no delimiters, escaping, or "treat as untrusted
  data" framing, then passes it straight to the LLM. The resulting output (`state.research_notes`)
  is interpolated unchanged into the Analyst's prompt (analyst.py:24) and then into the Writer's
  prompt (writer.py:25-29), so a single malicious web page indexed for a plausible query can inject
  instructions that propagate through three chained LLM calls and surface unfiltered in the final
  report the user reads, with no sanitization boundary anywhere in the agent-to-agent hand-off.