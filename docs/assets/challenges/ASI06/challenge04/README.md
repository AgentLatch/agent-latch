# Omnigent - Unverified Instructions Stored Through Agent-Accessible Long-Term Memory 

**GitHub Link:** [https://github.com/vortezwohl/Omnigent.git](https://github.com/vortezwohl/Omnigent.git)

### Target Vulnerable Files
- `omnigent/tools/builtins/hindsight.py` (lines 168–184)
- `omnigent/tools/builtins/hindsight.py` (lines 223–247)
- `omnigent/tools/builtins/hindsight.py` (lines 103–110)

### Vulnerability
When Hindsight memory tools are configured, an agent can submit arbitrary textual content to a persistent memory bank without a source-trust check in the identified retain-tool implementation. Stored text can later be recalled as relevant memory, potentially allowing attacker-influenced instructions to affect subsequent interactions if the agent chooses to retain and trust them.