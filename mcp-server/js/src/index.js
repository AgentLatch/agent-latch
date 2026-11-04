// Connect JavaScript agents to the AgentLatch gateway. The JS counterpart of
// ../bridge.py: it connects to the gateway and hands back its tools as plain async
// functions, or as Claude tool definitions.
//
//     import { GatewayTools } from "@agentlatch/connector";
//
//     const tools = await GatewayTools.connect();   // starts the gateway over stdio
//     tools.names();                                // ['echo', 'utc_now', 'time_get_current_time', ...]
//     await tools.call("echo", { text: "hi" });
//     const echo = tools.function("echo");          // a normal async fn: await echo({ text: "hi" })
//     await tools.close();
//
// The gateway stays the single controlled boundary: an agent can only use the
// tools enabled in servers.json and tools/.

import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { readClientConfig } from "./clientConfig.js";
import {
  GatewayAuthError,
  GatewayConnectionError,
  GatewayError,
  GatewayToolError,
  toGatewayError,
} from "./errors.js";

export * from "./errors.js";
export { clientConfigPaths, readClientConfig, DEFAULT_SERVER_NAME } from "./clientConfig.js";

/** The mcp-server folder: this package lives in mcp-server/js. */
export const GATEWAY_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const DEFAULT_TIMEOUT_MS = 30_000;

const CLIENT_INFO = { name: "agentlatch-js-connector", version: "0.1.0" };

/** The gateway's own virtual environment, else whatever python is on PATH. */
function defaultPython() {
  const venv =
    process.platform === "win32"
      ? join(GATEWAY_DIR, ".venv", "Scripts", "python.exe")
      : join(GATEWAY_DIR, ".venv", "bin", "python");
  if (existsSync(venv)) return venv;
  return process.platform === "win32" ? "python" : "python3";
}

/** Turn an MCP tool result into a plain value, the way bridge.py returns result.data. */
function unwrap(result) {
  const structured = result.structuredContent;
  if (structured !== undefined && structured !== null) {
    // FastMCP wraps a tool's plain return value as {"result": value}.
    const keys = Object.keys(structured);
    return keys.length === 1 && keys[0] === "result" ? structured.result : structured;
  }
  const content = result.content ?? [];
  if (content.every((block) => block.type === "text")) return content.map((block) => block.text).join("\n");
  return content;
}

function textOf(result) {
  return (result.content ?? [])
    .filter((block) => block.type === "text")
    .map((block) => block.text)
    .join("\n");
}

/**
 * A live connection to the gateway, exposing its tools as async functions.
 * Create one with GatewayTools.connect() or GatewayTools.fromClientConfig().
 */
export class GatewayTools {
  #client;
  #tools;
  #where;
  #timeoutMs;

  constructor(client, tools, { where, timeoutMs }) {
    this.#client = client;
    this.#tools = new Map(tools.map((tool) => [tool.name, tool]));
    this.#where = where;
    this.#timeoutMs = timeoutMs;
  }

  /**
   * Connect to the gateway.
   *
   * url:       the gateway's HTTP address, for example http://127.0.0.1:8765/mcp.
   *            Omit it to start the gateway over stdio from the mcp-server folder.
   * token:     value of MCP_GATEWAY_TOKEN when the HTTP gateway requires one
   *            (defaults to the MCP_GATEWAY_TOKEN environment variable).
   * python:    python used for the stdio gateway (defaults to mcp-server/.venv).
   * command, args, env, cwd: start some other stdio command instead of server.py.
   * timeoutMs: limit for connecting and for each tool call (default 30 s).
   * stderr:    where the stdio gateway's log goes: "inherit" (default), "ignore" or "pipe".
   */
  static async connect({
    url,
    token = process.env.MCP_GATEWAY_TOKEN,
    headers,
    python,
    command,
    args,
    env,
    cwd,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    stderr = "inherit",
  } = {}) {
    let transport;
    let where;
    if (url) {
      const requestHeaders = { ...headers };
      if (token) requestHeaders.Authorization = `Bearer ${token}`;
      transport = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: requestHeaders } });
      where = url;
    } else {
      const program = command ?? python ?? defaultPython();
      // On Windows a missing executable only shows up as a closed connection, so check paths first.
      if (/[\\/]/.test(program) && !existsSync(program)) {
        throw toGatewayError(Object.assign(new Error(`${program} not found`), { code: "ENOENT" }), {
          what: "start the gateway",
          where: program,
          timeoutMs,
        });
      }
      transport = new StdioClientTransport({
        command: program,
        args: args ?? [join(GATEWAY_DIR, "server.py")],
        // Only the basics plus what's passed in: the gateway reads its own secrets from mcp-server/.env.
        env: { ...getDefaultEnvironment(), ...env },
        cwd: cwd ?? (command ? undefined : GATEWAY_DIR),
        stderr,
      });
      where = program;
    }

    const client = new Client(CLIENT_INFO);
    try {
      await client.connect(transport, { timeout: timeoutMs });
      const { tools } = await client.listTools(undefined, { timeout: timeoutMs });
      return new GatewayTools(client, tools, { where, timeoutMs });
    } catch (err) {
      await client.close().catch(() => {});
      throw toGatewayError(err, { what: "connect to the gateway", where, timeoutMs });
    }
  }

  /**
   * Connect the same way Claude Desktop or Cursor does, using the gateway entry
   * ("agentlatch-gateway" by default) from that app's MCP config.
   *
   * client: "claude" or "cursor".
   * configPath, serverName: override where to look and which entry to use.
   * Other options are passed to connect().
   */
  static async fromClientConfig(client, { configPath, serverName, ...options } = {}) {
    const { entry } = readClientConfig(client, { configPath, serverName });
    if (entry.url) return GatewayTools.connect({ ...options, url: entry.url, headers: entry.headers });
    return GatewayTools.connect({
      ...options,
      command: entry.command,
      args: entry.args ?? [],
      env: entry.env,
      cwd: entry.cwd,
    });
  }

  /** Every tool name the gateway exposes. */
  names() {
    return [...this.#tools.keys()];
  }

  /** A tool's description. */
  describe(name) {
    return (this.#tool(name).description ?? "").trim();
  }

  /** A tool's input JSON Schema. */
  inputSchema(name) {
    return this.#tool(name).inputSchema;
  }

  /**
   * Call a tool with an object of arguments and return its result: the tool's
   * return value when it has one, else its text. Throws GatewayToolError when
   * the tool reports an error.
   */
  async call(name, args = {}, { timeoutMs = this.#timeoutMs } = {}) {
    this.#tool(name);
    let result;
    try {
      result = await this.#client.callTool({ name, arguments: args }, undefined, { timeout: timeoutMs });
    } catch (err) {
      throw toGatewayError(err, { what: `call tool ${name}`, where: this.#where, timeoutMs });
    }
    if (result.isError) {
      throw new GatewayToolError(`Tool ${name} failed: ${textOf(result) || "no details"}`, {
        tool: name,
        content: result.content,
      });
    }
    return unwrap(result);
  }

  /** A plain async function for one tool, to register with an agent framework. */
  function(name) {
    const tool = this.#tool(name);
    const fn = (args = {}) => this.call(name, args);
    Object.defineProperty(fn, "name", { value: name });
    fn.description = (tool.description ?? "").trim();
    fn.inputSchema = tool.inputSchema;
    return fn;
  }

  /** Every tool as a { name: async function } object. */
  functions() {
    return Object.fromEntries(this.names().map((name) => [name, this.function(name)]));
  }

  /** The tools as Claude tool definitions, for the `tools` field of messages.create(). */
  toClaudeTools() {
    return [...this.#tools.values()].map((tool) => ({
      name: tool.name,
      description: (tool.description ?? "").trim(),
      input_schema: tool.inputSchema,
    }));
  }

  /**
   * Run every tool_use block in a Claude response through the gateway, and return
   * the tool_result blocks to send back as the next user message. A tool that fails
   * or times out comes back as is_error: true so Claude can react; a lost connection
   * or rejected token is thrown, since no later call would work either.
   */
  async claudeToolResults(content) {
    const calls = content.filter((block) => block.type === "tool_use");
    return Promise.all(
      calls.map(async (block) => {
        try {
          const value = await this.call(block.name, block.input ?? {});
          return {
            type: "tool_result",
            tool_use_id: block.id,
            content: typeof value === "string" ? value : JSON.stringify(value),
          };
        } catch (err) {
          if (!(err instanceof GatewayError) || err instanceof GatewayConnectionError || err instanceof GatewayAuthError) {
            throw err;
          }
          return { type: "tool_result", tool_use_id: block.id, content: err.message, is_error: true };
        }
      }),
    );
  }

  /** Disconnect from the gateway (and stop it, when it was started over stdio). */
  async close() {
    await this.#client.close();
  }

  async [Symbol.asyncDispose]() {
    await this.close();
  }

  #tool(name) {
    const tool = this.#tools.get(name);
    if (!tool) {
      throw new GatewayToolError(`No such tool: ${name}. Available: ${this.names().join(", ")}`, { tool: name });
    }
    return tool;
  }
}
