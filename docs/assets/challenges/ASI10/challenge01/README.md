# Challenge: ECC / Self-Reinforcing Observer Loop Rewrites Agent Instincts (Challenge 01)

## 1. Upstream Source Repository

GitHub Link: https://github.com/affaan-m/ECC

Target Vulnerable File: skills/continuous-learning-v2/agents/observer-loop.sh (Lines 268–305)

## 2. What is the Vulnerability?

ECC's continuous-learning observer runs as a background `while true` loop (line 518) that periodically has a model read the agent's own recorded tool activity and, by explicit instruction, write or update instinct files in `instincts/personal/` without asking for confirmation (lines 269–273 and 302), with no human review step and no comparison against a fixed, developer-defined baseline. Any pattern seen six or more times is written at confidence 0.7 or higher, which meets the default injection threshold in `scripts/hooks/session-start.js`, so the agent's past behavior is fed back as standing instructions for every new session and can compound into goal drift over successive loops.
