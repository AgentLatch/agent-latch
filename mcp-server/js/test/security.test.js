// Checks that the gateway token only goes where it should, that a piped log is never left unread,
// and that fromClientConfig honours the caller's env and cwd. No gateway or Python is needed:
// a small local web server records what it receives, and a node script stands in for the gateway.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import { GatewayAuthError, GatewayError, GatewayTools } from "../src/index.js";

const ENV_TOKEN = "env-token-do-not-leak";

/** Start a web server that answers 401 to everything and records each request's Authorization header. */
function listenRecording(host) {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push(req.headers.authorization);
    res.writeHead(401).end();
  });
  return new Promise((resolve) => {
    server.listen(0, host, () => resolve({ seen, port: server.address().port, close: () => server.close() }));
  });
}

/** An address of this machine that is not loopback, or undefined when there is none. */
function externalAddress() {
  for (const list of Object.values(networkInterfaces())) {
    for (const info of list ?? []) if (info.family === "IPv4" && !info.internal) return info.address;
  }
  return undefined;
}

/** Connect with a fixed environment token and return what the server saw. The 401 makes connect() reject. */
async function authorizationSeen(host, connectOptions, envToken = ENV_TOKEN) {
  const server = await listenRecording(host === "localhost" ? "127.0.0.1" : host);
  const before = process.env.MCP_GATEWAY_TOKEN;
  process.env.MCP_GATEWAY_TOKEN = envToken;
  try {
    await assert.rejects(
      GatewayTools.connect({ url: `http://${host}:${server.port}/mcp`, timeoutMs: 5000, ...connectOptions }),
      GatewayAuthError,
    );
  } finally {
    if (before === undefined) delete process.env.MCP_GATEWAY_TOKEN;
    else process.env.MCP_GATEWAY_TOKEN = before;
    server.close();
  }
  return server.seen.filter((value) => value !== undefined);
}

describe("gateway token", () => {
  test("the environment token is sent to a gateway on this machine", async () => {
    const seen = await authorizationSeen("127.0.0.1", {});
    assert.ok(seen.length > 0);
    assert.ok(seen.every((value) => value === `Bearer ${ENV_TOKEN}`));
  });

  test("the environment token is not sent to another host", { skip: !externalAddress() && "no non-loopback address" }, async () => {
    const seen = await authorizationSeen(externalAddress(), {});
    assert.deepEqual(seen, []);
  });

  test("a token you pass is sent, even to another host", { skip: !externalAddress() && "no non-loopback address" }, async () => {
    const seen = await authorizationSeen(externalAddress(), { token: "explicit-token" });
    assert.ok(seen.length > 0);
    assert.ok(seen.every((value) => value === "Bearer explicit-token"));
  });

  test("an Authorization header you set is kept, whatever its casing", async () => {
    const seen = await authorizationSeen("127.0.0.1", { headers: { authorization: "Bearer from-config" } });
    assert.ok(seen.length > 0);
    assert.ok(seen.every((value) => value === "Bearer from-config"));
  });

  test("an Authorization header you set wins over a token you pass", async () => {
    const seen = await authorizationSeen("127.0.0.1", { token: "explicit-token", headers: { Authorization: "Basic abc" } });
    assert.ok(seen.every((value) => value === "Basic abc"));
  });
});

describe("stderr pipe", () => {
  test("is refused without onStderr", async () => {
    await assert.rejects(GatewayTools.connect({ stderr: "pipe" }), (err) => {
      assert.ok(err instanceof GatewayError);
      assert.match(err.message, /onStderr/);
      return true;
    });
  });
});

describe("fromClientConfig env and cwd", () => {
  const dir = mkdtempSync(join(tmpdir(), "agentlatch-security-"));
  // The stand-in gateway takes a moment to exit after the connector closes it, and Windows won't delete
  // a folder that is some process's working directory. Retry for a few seconds.
  after(async () => {
    for (let attempt = 1; ; attempt++) {
      try {
        rmSync(dir, { recursive: true, force: true });
        return;
      } catch (err) {
        if (attempt >= 20) throw err;
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
  });

  // A stand-in "gateway": it reports its working directory and two variables on stderr, then waits
  // until the connector closes its input (which is how the SDK stops a child), and exits.
  const script =
    'process.stderr.write("CWD=" + process.cwd() + ";FROM_ENTRY=" + process.env.FROM_ENTRY + ";FROM_CALLER=" + process.env.FROM_CALLER + ";");' +
    'process.stdin.on("end", () => process.exit(0)); process.stdin.resume();';

  test("a caller's cwd finds .cursor/mcp.json there and starts the gateway there; env fills and overrides", async () => {
    const project = join(dir, "project");
    mkdirSync(join(project, ".cursor"), { recursive: true });
    writeFileSync(
      join(project, ".cursor", "mcp.json"),
      JSON.stringify({
        mcpServers: {
          "agentlatch-gateway": {
            command: process.execPath,
            args: ["-e", script],
            env: { FROM_ENTRY: "entry-value", FROM_CALLER: "${CALLER_VAR}" },
          },
        },
      }),
    );

    let log = "";
    await assert.rejects(
      GatewayTools.fromClientConfig("cursor", {
        cwd: project,
        env: { CALLER_VAR: "filled-in", FROM_ENTRY: "caller-wins" },
        stderr: "pipe",
        onStderr: (chunk) => (log += chunk.toString()),
        timeoutMs: 1500,
      }),
      GatewayError,
    );

    const reportedCwd = /CWD=([^;]*);/.exec(log)?.[1];
    assert.ok(reportedCwd, `the stand-in gateway reported nothing: ${log}`);
    assert.equal(realpathSync.native(reportedCwd), realpathSync.native(project));
    assert.match(log, /FROM_ENTRY=caller-wins;/);
    assert.match(log, /FROM_CALLER=filled-in;/);
  });
});
