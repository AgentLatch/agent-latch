// A small JS agent: Claude answers a question using the gateway's tools.
// Every tool call Claude makes goes through the AgentLatch gateway.
//
//     export ANTHROPIC_API_KEY=...       # or sign in with `ant auth login`
//     node examples/claude-agent.js "What time is it in Tokyo and in London?"
//     node examples/claude-agent.js --url http://127.0.0.1:8765/mcp "..."
//     node examples/claude-agent.js --client cursor "..."   # use Cursor's gateway entry
//
// Needs @anthropic-ai/sdk (installed by `npm install` in this folder).

import { parseArgs } from "node:util";

import Anthropic from "@anthropic-ai/sdk";

import { GatewayError, GatewayTools } from "../src/index.js";

const MODEL = "claude-opus-5-5";
// Cap the loop: an agent that can call tools forever is the ASI10 (rogue agent) risk.
const MAX_TURNS = 8;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { url: { type: "string" }, client: { type: "string" } },
});
const question = positionals.join(" ") || "What time is it in Tokyo and in London right now?";

/** The Claude client couldn't send the request at all, for example no credentials were found. */
class ClaudeSetupError extends Error {}

async function ask(anthropic, params) {
  try {
    return await anthropic.beta.messages.create(params);
  } catch (err) {
    if (err instanceof Anthropic.APIError) throw err;
    throw new ClaudeSetupError(err.message, { cause: err });
  }
}

async function run(gateway) {
  const anthropic = new Anthropic();
  const tools = gateway.toClaudeTools();
  const messages = [{ role: "user", content: question }];

  for (let turn = 1; turn <= MAX_TURNS; turn++) {
    const response = await ask(anthropic, {
      model: MODEL,
      max_tokens: 16000,
      system: "Answer using the tools when they help. Be brief.",
      tools,
      messages,
      // If a safety classifier declines, the API retries on a fallback model in the same call.
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
    });
    messages.push({ role: "assistant", content: response.content });

    for (const block of response.content) {
      if (block.type === "text" && block.text.trim()) console.log(`\nClaude: ${block.text}`);
      if (block.type === "tool_use") console.log(`  -> ${block.name} ${JSON.stringify(block.input)}`);
    }

    if (response.stop_reason === "end_turn") return;
    if (response.stop_reason === "refusal") {
      console.log(`\nClaude declined (${response.stop_details?.category ?? "no category"}).`);
      return;
    }
    if (response.stop_reason === "max_tokens") {
      console.log("\nStopped: the response hit max_tokens.");
      return;
    }
    if (response.stop_reason === "pause_turn") continue;

    // stop_reason === "tool_use": run the calls through the gateway and send the results back.
    const results = await gateway.claudeToolResults(response.content);
    for (const result of results) {
      console.log(`  <- ${result.is_error ? "error: " : ""}${result.content.slice(0, 200)}`);
    }
    messages.push({ role: "user", content: results });
  }
  console.log(`\nStopped after ${MAX_TURNS} turns.`);
}

try {
  const gateway = values.client
    ? await GatewayTools.fromClientConfig(values.client, { stderr: "ignore" })
    : await GatewayTools.connect({ url: values.url, stderr: "ignore" });
  console.log(`Connected to the gateway: ${gateway.names().length} tool(s).\nYou: ${question}`);
  try {
    await run(gateway);
  } finally {
    await gateway.close();
  }
} catch (err) {
  process.exitCode = 1;
  if (err instanceof GatewayError) {
    console.error(`${err.name}: ${err.message}`);
  } else if (err instanceof Anthropic.AuthenticationError) {
    console.error("Claude rejected the API key. Set ANTHROPIC_API_KEY, or sign in with `ant auth login`.");
  } else if (err instanceof Anthropic.APIConnectionTimeoutError) {
    console.error("Timed out waiting for Claude. Check your network and try again.");
  } else if (err instanceof Anthropic.APIConnectionError) {
    console.error("Could not reach the Claude API. Check your network.");
  } else if (err instanceof Anthropic.APIError) {
    console.error(`Claude API error ${err.status}: ${err.message}`);
  } else if (err instanceof ClaudeSetupError) {
    console.error(`${err.message}\nSet ANTHROPIC_API_KEY, or sign in with \`ant auth login\`.`);
  } else {
    throw err;
  }
}
