# Challenge: [Sentinel / Self-Attested Proof Bypasses Inter-Agent Trust Boundary] (Challenge 05)

## 1. Upstream source repository
- GitHub Link: https://github.com/gylshaurya/Sentinel
- Version analyzed: 1.0.0 (package.json)
- Target vulnerable file(s):
  - contracts/InferenceGuard.sol (lines 57-76)
  - agents/coordinator/index.js (lines 186-204)
  - agents/coordinator/priorityEngine.js (lines 50-62)
  - agents/riskAgent/index.js (lines 143-147, 179-186)

## 2. What is the vulnerability?
- `InferenceGuard.submitProof` (InferenceGuard.sol:57-71) stores whatever `rootHash` the caller passes with no on-chain recomputation or cross-check, `isProofValid` (lines 73-76) only checks `exists && !consumed`, and the Coordinator computes that `rootHash` itself from its own in-memory proposal object (coordinator/index.js:186-204) before submitting it with the same wallet that later verifies and consumes it — so the "proof" attests to nothing but its own submission. `priorityEngine.js:50-62` (`shouldExecute`) then unconditionally authorizes real execution (KeeperHub workflow trigger, x402 USDC payment approval, on-chain `consumeProof`/`incrementExperience`) for any `RISK` or `YIELD` proposal with no amount cap or deviation check, and `riskAgent/index.js:143-186` silently substitutes a fabricated, deterministically-seeded health factor whenever the real pool call fails, feeding that same unauthenticated path — meaning nothing in the chain between the inference-producing agent and the money-moving executor can distinguish a genuine, verified risk signal from a forged or fabricated one.