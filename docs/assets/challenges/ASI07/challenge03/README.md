# Challenge: [Multi-Agent AI Deep Researcher / Self-Defeating Source Validation & Markdown Injection] (Challenge 03)

## 1. Upstream source repository
- GitHub Link: https://github.com/VijayYadav123/Multi-Agent-AI-Deep-Researcher2
- Version analyzed: archive upload
- Target vulnerable file(s): copy_of_multi_agent_ai_deep_researcher.py
  - retriever_agent (line 198)
  - source_validator_agent (lines 260-270)
  - critical_analysis_agent (lines 312, 325, 338)
  - report_builder_agent (line 409)

## 2. What is the vulnerability?
- `retriever_agent` stores raw Tavily `title`/`url`/`content` verbatim (line 198, only length-capped),
  and `source_validator_agent` (lines 260-270) feeds that same unsanitized text to an LLM that is
  asked to assign each source its own `relevance`/`credibility`/`keep` verdict — so injected text in
  a source can talk the validator into scoring itself highly and suppressing competing sources,
  defeating the pipeline's only filtering step. The same unsanitized `title`/`content` then flows
  unescaped into `critical_analysis_agent`'s summary and contradiction prompts (lines 312, 325, 338)
  and into `report_builder_agent`'s final Markdown reference list (line 409, `[{title}]({url})` with
  no escaping of `]`, `)`, or the URL scheme), making this both a prompt-injection and a Markdown/link-
  injection vulnerability in the same unsanitized field.