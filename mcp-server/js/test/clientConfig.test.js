import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import { ClientConfigError, clientConfigPaths, GATEWAY_DIR, GatewayTools, readClientConfig } from "../src/index.js";

const dir = mkdtempSync(join(tmpdir(), "agentlatch-connector-"));
after(() => rmSync(dir, { recursive: true, force: true }));

function writeConfig(name, servers) {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify({ mcpServers: servers }));
  return path;
}

describe("clientConfigPaths", () => {
  test("Claude Desktop's config location per platform", () => {
    const env = { APPDATA: "C:\\Users\\me\\AppData\\Roaming" };
    assert.match(clientConfigPaths("claude", { env, platform: "win32" })[0], /Claude[\\/]claude_desktop_config\.json$/);
    assert.match(clientConfigPaths("claude", { env, platform: "darwin" })[0], /Application Support[\\/]Claude/);
  });

  test("Cursor checks the project before the global config", () => {
    const [project, global] = clientConfigPaths("cursor", { cwd: dir });
    assert.equal(project, join(dir, ".cursor", "mcp.json"));
    assert.match(global, /\.cursor[\\/]mcp\.json$/);
  });

  test("an unknown client is rejected", () => {
    assert.throws(() => clientConfigPaths("vim"), ClientConfigError);
  });
});

describe("readClientConfig", () => {
  test("reads a stdio entry and fills in ${VAR} and ${env:VAR}", () => {
    const configPath = writeConfig("stdio.json", {
      "agentlatch-gateway": { command: "${PY}", args: ["${env:SERVER}"], env: { A: "1" } },
    });
    const { entry, name } = readClientConfig("cursor", { configPath, env: { PY: "python", SERVER: "server.py" } });
    assert.equal(name, "agentlatch-gateway");
    assert.deepEqual(entry, { command: "python", args: ["server.py"], env: { A: "1" } });
  });

  test("reads an HTTP entry", () => {
    const configPath = writeConfig("http.json", {
      "agentlatch-gateway": { url: "http://127.0.0.1:8765/mcp", headers: { Authorization: "Bearer ${T}" } },
    });
    const { entry } = readClientConfig("cursor", { configPath, env: { T: "abc" } });
    assert.equal(entry.url, "http://127.0.0.1:8765/mcp");
    assert.equal(entry.headers.Authorization, "Bearer abc");
  });

  test("finds the project's .cursor/mcp.json", () => {
    mkdirSync(join(dir, ".cursor"), { recursive: true });
    writeFileSync(join(dir, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { "agentlatch-gateway": { command: "x" } } }));
    assert.equal(readClientConfig("cursor", { cwd: dir }).path, join(dir, ".cursor", "mcp.json"));
  });

  test("a config without the gateway names the servers it has", () => {
    const configPath = writeConfig("other.json", { github: { command: "npx" }, time: { command: "uvx" } });
    assert.throws(() => readClientConfig("claude", { configPath }), /has no "agentlatch-gateway" server\. It has: github, time/);
    assert.equal(readClientConfig("claude", { configPath, serverName: "time" }).entry.command, "uvx");
  });

  test("a missing file says where it looked", () => {
    assert.throws(() => readClientConfig("claude", { configPath: join(dir, "missing.json") }), /No claude MCP config found/);
  });

  test("invalid JSON and empty entries are reported", () => {
    const bad = join(dir, "bad.json");
    writeFileSync(bad, "{ not json");
    assert.throws(() => readClientConfig("cursor", { configPath: bad }), ClientConfigError);
    const empty = writeConfig("empty.json", { "agentlatch-gateway": {} });
    assert.throws(() => readClientConfig("cursor", { configPath: empty }), /neither "command" nor "url"/);
  });
});

const python =
  process.platform === "win32"
    ? join(GATEWAY_DIR, ".venv", "Scripts", "python.exe")
    : join(GATEWAY_DIR, ".venv", "bin", "python");

test("fromClientConfig connects the way Cursor would", { skip: !existsSync(python) && "mcp-server/.venv not found" }, async () => {
  const configPath = writeConfig("cursor-real.json", {
    "agentlatch-gateway": { command: python, args: [join(GATEWAY_DIR, "server.py")] },
  });
  const gateway = await GatewayTools.fromClientConfig("cursor", { configPath, stderr: "ignore" });
  try {
    assert.equal(await gateway.call("echo", { text: "via cursor config" }), "via cursor config");
  } finally {
    await gateway.close();
  }
});
