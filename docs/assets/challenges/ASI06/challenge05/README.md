# Open WebUI - Automatic Memory Poisoning Followed by System-Context Promotion

**GitHub Link:** [https://github.com/vortezwohl/open-webui.git](https://github.com/vortezwohl/open-webui.git)

### Target Vulnerable Files
- `backend/open_webui/utils/memory.py` (lines 474–525)
- `backend/open_webui/utils/memory.py` (lines 528–609)
- `backend/open_webui/utils/memory.py` (lines 290–407)
- `backend/open_webui/routers/memories.py` (lines 234–249)

### Vulnerability
Open WebUI uses an LLM to review conversation content and propose persistent memory changes, then retrieves saved memories and adds them to later system-message context. If attacker-controlled content causes the reviewer to save a malicious instruction as durable memory, that instruction could be repeatedly exposed to the main model in a higher-priority message context, although the code alone does not prove that the model will follow it.