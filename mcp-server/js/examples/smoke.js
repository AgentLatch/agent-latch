// Smoke test: connect, list tools, and call echo. Same check as `python bridge.py`.
//
//     node examples/smoke.js                                  # start the gateway over stdio
//     node examples/smoke.js --url http://127.0.0.1:8765/mcp  # use a running HTTP gateway
//     node examples/smoke.js --client cursor                  # connect the way Cursor does

import { parseArgs } from "node:util";

import { GatewayError, GatewayTools } from "../src/index.js";

const { values } = parseArgs({ options: { url: { type: "string" }, client: { type: "string" } } });

try {
  const gateway = values.client
    ? await GatewayTools.fromClientConfig(values.client, { stderr: "ignore" })
    : await GatewayTools.connect({ url: values.url, stderr: "ignore" });
  try {
    console.log(`${gateway.names().length} tool(s): ${gateway.names().join(", ")}`);
    console.log("echo ->", await gateway.call("echo", { text: "connector works" }));
  } finally {
    await gateway.close();
  }
} catch (err) {
  if (!(err instanceof GatewayError)) throw err;
  console.error(`${err.name}: ${err.message}`);
  process.exitCode = 1;
}
