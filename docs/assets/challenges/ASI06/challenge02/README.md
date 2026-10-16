# ASI4-Labs-Demo - Persistent Poisoning of Retrieved Knowledge

**GitHub Link:** [https://github.com/vortezwohl/ASI4-Labs-Demo.git](https://github.com/vortezwohl/ASI4-Labs-Demo.git)

### Target Vulnerable Files
- `vulnerable-agent/app.py` (lines 1270–1309)
- `vulnerable-agent/app.py` (lines 805–825)
- `vulnerable-agent/app.py` (lines 789–795)

### Vulnerability
The application deliberately permits uploaded document content to be inserted into a persistent ChromaDB collection, creating a stored source of attacker-controlled information that can be retrieved during later queries. This is an intentional vulnerable training-lab mechanism, and its classification as ASI06 depends on treating the poisoned knowledge base as retained agent context rather than only a single retrieval-time prompt-injection example.