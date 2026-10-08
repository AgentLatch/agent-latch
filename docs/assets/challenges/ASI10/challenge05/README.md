# Challenge: ECC / Infinite Agentic Loop With No Circuit Breaker (Challenge 05)

## 1. Upstream Source Repository

GitHub Link: https://github.com/affaan-m/ECC

Target Vulnerable File: skills/autonomous-loops/SKILL.md (Lines 173–196)

## 2. What is the Vulnerability?

The shipped `autonomous-loops` skill tells users to create a `/project:infinite` command whose `infinite` mode deploys parallel sub-agents "in waves of 3-5 until context is low," so the only stop condition is context exhaustion, with no maximum wave count, cost or token budget, rate limit, human checkpoint, or kill switch. Once the orchestrator misreads the spec or enters an anomalous state, it keeps spawning agents that write to the output directory at scale, even though the same skill shows bounded alternatives (`--max-runs`, `--max-cost`, `--max-duration`) for its Continuous Claude loop at lines 232–233.
