# Agent Zero - Poisoning of Automatically Generated Persistent Memories 

**GitHub Link:** [https://github.com/vortezwohl/Agent-Zero.git](https://github.com/vortezwohl/Agent-Zero.git)

### Target Vulnerable Files
- `plugins/_memory/extensions/python/monologue_end/_50_memorize_fragments.py` (lines 40–110, 127–211)
- `plugins/_memory/helpers/memory_quality.py` (lines 60–80)
- `plugins/_memory/extensions/python/message_loop_prompts_after/_50_recall_memories.py` (lines 150–275)

### Vulnerability
Agent Zero uses an LLM to extract durable memories from conversation history, filters the resulting text primarily through content-pattern checks, and stores accepted entries for later retrieval. An attacker who can influence the history may be able to introduce a false durable instruction that passes these filters and reappears in subsequent agent context, although successful behavioural manipulation remains unverified.