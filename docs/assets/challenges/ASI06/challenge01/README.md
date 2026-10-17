# Autono - Potential Poisoning of Agent Action History

**GitHub Link:** [https://github.com/vortezwohl/Autono.git](https://github.com/vortezwohl/Autono.git)

### Target Vulnerable Files
- `autono/brain/agent.py` (lines 174–193)
- `autono/brain/agent.py` (lines 118–146)
- `autono/brain/agent.py` (lines 64–69)

### Vulnerability
The agent records action summaries in its internal memory and passes that history into subsequent model decisions without an explicit trust classification in the identified code path. If an attacker can influence an action summary, that content may affect later decisions, although the source alone does not demonstrate successful instruction following.