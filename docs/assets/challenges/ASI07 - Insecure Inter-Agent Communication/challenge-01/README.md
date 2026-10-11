# Challenge: [OpenMAIC PBL v2 Evaluator / Client-Trusted Inter-Agent Evidence] (Challenge 01)

## 1. Upstream source repository
- GitHub Link: https://github.com/THU-MAIC/OpenMAIC
- Version analyzed: v1.2.0-rc.1
- Target vulnerable file(s):
  - app/api/pbl/v2/evaluate/route.ts (lines 47, 56-58)
  - lib/pbl/v2/operations/runtime/eval-prompts.ts (lines 99-116, 224-316)
  - lib/pbl/v2/operations/runtime/evaluation.ts (lines 62, 76-80)

## 2. What is the vulnerability?
- `POST /api/pbl/v2/evaluate` accepts a full `PBLProjectV2` object from the client with only a TypeScript type assertion (`body = (await req.json()) as EvaluateRequest`, route.ts:58) and no runtime schema validation, so its `evaluations` array (evaluation.ts:76-80, a flat, unsigned list with no server-side authoritative copy) and per-microtask `engagement` fields flow straight from the request body into the grading LLM's prompt via `buildTaskEvalPrompt` (eval-prompts.ts:99-116, injected as "## Prior task evaluations for context") and `formatProjectEngagementRollup` (eval-prompts.ts:224-316, injected as "structured factual evidence"). Because this round-trip is the hand-off channel between one evaluator agent's output and the next evaluator agent that consumes it, and it carries zero integrity protection (no HMAC, no schema, no "treat as unverified" framing like the one used elsewhere in this codebase for the DOM-observation channel), a client can forge agent-to-agent evaluation evidence and have the final evaluator treat it as ground truth.