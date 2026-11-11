// Runs against the real gateway in ../server.py, so it needs mcp-server/.venv
// (see SETUP.md Part 1). Without it these tests are skipped.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";

import {
  GATEWAY_DIR,
  GatewayAuthError,
  GatewayConnectionError,
  GatewayTimeoutError,
  GatewayToolError,
  GatewayTools,
} from "../src/index.js";

const PYTHON =
  process.platform === "win32"
    ? join(GATEWAY_DIR, ".venv", "Scripts", "python.exe")
    : join(GATEWAY_DIR, ".venv", "bin", "python");
const skip = !existsSync(PYTHON) && "mcp-server/.venv not found: set up the gateway first (SETUP.md Part 1)";
const TOKEN = "connector-test-token";

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer().listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}

async function waitForHttp(url, deadlineMs = 60_000) {
  const start = Date.now();
  while (Date.now() - start < deadlineMs) {
    try {
      await fetch(url);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error(`gateway did not start at ${url}`);
}

describe("stdio gateway", { skip }, () => {
  let gateway;
  before(async () => {
    gateway = await GatewayTools.connect({ stderr: "ignore" });
  });
  after(async () => {
    await gateway?.close();
  });

  test("lists the gateway's local tools", () => {
    assert.ok(gateway.names().includes("echo"));
    assert.ok(gateway.names().includes("utc_now"));
    assert.match(gateway.describe("echo"), /unchanged/);
    assert.deepEqual(gateway.inputSchema("echo").required, ["text"]);
  });

  test("calls a tool and returns its value", async () => {
    assert.equal(await gateway.call("echo", { text: "hello" }), "hello");
  });

  test("hands out tools as plain async functions", async () => {
    const echo = gateway.function("echo");
    assert.equal(echo.name, "echo");
    assert.equal(await echo({ text: "fn" }), "fn");
    assert.deepEqual(Object.keys(gateway.functions()), gateway.names());
  });

  test("an unknown tool throws GatewayToolError listing what exists", async () => {
    await assert.rejects(gateway.call("no_such_tool"), (err) => {
      assert.ok(err instanceof GatewayToolError);
      assert.match(err.message, /Available: .*echo/);
      return true;
    });
    assert.throws(() => gateway.function("no_such_tool"), GatewayToolError);
  });

  test("a tool that reports an error throws GatewayToolError", async () => {
    await assert.rejects(gateway.call("echo", {}), GatewayToolError);
  });

  test("converts tools to Claude tool definitions", () => {
    const echo = gateway.toClaudeTools().find((tool) => tool.name === "echo");
    assert.equal(echo.input_schema.type, "object");
    assert.ok(echo.input_schema.properties.text);
    assert.ok(echo.description.length > 0);
  });

  test("runs Claude tool_use blocks and returns tool_result blocks", async () => {
    const results = await gateway.claudeToolResults([
      { type: "text", text: "Let me check." },
      { type: "tool_use", id: "toolu_1", name: "echo", input: { text: "from claude" } },
      { type: "tool_use", id: "toolu_2", name: "no_such_tool", input: {} },
      { type: "tool_use", id: "toolu_3", name: "echo", input: {} },
    ]);
    assert.equal(results.length, 3);
    assert.deepEqual(results[0], { type: "tool_result", tool_use_id: "toolu_1", content: "from claude" });
    assert.equal(results[1].tool_use_id, "toolu_2");
    assert.equal(results[1].is_error, true);
    assert.equal(results[2].is_error, true);
  });
});

describe("HTTP gateway with a token", { skip }, () => {
  let server;
  let url;
  before(async () => {
    const port = await freePort();
    url = `http://127.0.0.1:${port}/mcp`;
    server = spawn(PYTHON, [join(GATEWAY_DIR, "server.py"), "--http", "--port", String(port)], {
      cwd: GATEWAY_DIR,
      env: { ...process.env, MCP_GATEWAY_TOKEN: TOKEN },
      stdio: "ignore",
    });
    await waitForHttp(url);
  });
  after(() => {
    server?.kill();
  });

  test("connects with the right token", async () => {
    const gateway = await GatewayTools.connect({ url, token: TOKEN });
    try {
      assert.equal(await gateway.call("echo", { text: "over http" }), "over http");
    } finally {
      await gateway.close();
    }
  });

  test("a wrong token throws GatewayAuthError without leaking it", async () => {
    await assert.rejects(GatewayTools.connect({ url, token: "wrong-token" }), (err) => {
      assert.ok(err instanceof GatewayAuthError);
      assert.doesNotMatch(err.message, /wrong-token/);
      return true;
    });
  });

  test("a missing token throws GatewayAuthError", async () => {
    await assert.rejects(GatewayTools.connect({ url, token: "" }), GatewayAuthError);
  });

  test("a connect that takes too long throws GatewayTimeoutError", async () => {
    await assert.rejects(GatewayTools.connect({ url, token: TOKEN, timeoutMs: 1 }), (err) => {
      assert.ok(err instanceof GatewayTimeoutError);
      assert.equal(err.timeoutMs, 1);
      return true;
    });
  });
});

describe("gateway not available", () => {
  test("nothing listening throws GatewayConnectionError", async () => {
    const port = await freePort();
    await assert.rejects(GatewayTools.connect({ url: `http://127.0.0.1:${port}/mcp` }), (err) => {
      assert.ok(err instanceof GatewayConnectionError);
      assert.match(err.message, /server\.py --http/);
      return true;
    });
  });

  test("a missing python throws GatewayConnectionError", async () => {
    await assert.rejects(
      GatewayTools.connect({ python: join(GATEWAY_DIR, "no-such-venv", "python") }),
      GatewayConnectionError,
    );
  });
});
