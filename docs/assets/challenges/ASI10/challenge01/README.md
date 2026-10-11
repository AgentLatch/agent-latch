# Challenge: ECC / Self-Rewriting Instincts and a Gameable Score Loop (Challenge 01)

## 1. Upstream Source Repository

* GitHub Link: https://github.com/affaan-m/ECC
* Target Vulnerable File: skills/continuous-learning-v2/agents/observer-loop.sh (Lines 268-305); scripts/gan-harness.sh (Lines 248-303)

## 2. What is the Vulnerability?

* ASI10 vectors: #1 Goal Drift & Unanchored Autonomous Loops; #2 Reward Hacking & Proxy Optimization.
* ECC's background observer runs in an endless `while true` loop that has a model read the agent's own activity and write new instincts to `instincts/personal/` without asking for confirmation (observer-loop.sh lines 269-273 and 302), and `scripts/hooks/session-start.js` injects those at confidence 0.7 or higher into every new session, so the agent's past behavior becomes standing instructions with no human checkpoint or fixed baseline. Its GAN harness loops a generator agent until a score parsed from `gan-harness/feedback/feedback-NNN.md` reaches 7.0, but the rubric, the generator's self-reported state and the feedback folder all sit in the directory the generator edits with no boundary (gan-harness.sh lines 248-303), so it can reach PASS by gaming those files instead of building the spec.
