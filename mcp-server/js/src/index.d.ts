// Types for TypeScript users. The package itself is plain JavaScript (src/index.js).

export const GATEWAY_DIR: string;
export const DEFAULT_TIMEOUT_MS: number;
export const DEFAULT_SERVER_NAME: string;

export type JsonSchema = { type: "object"; properties?: Record<string, unknown>; required?: string[]; [key: string]: unknown };

export interface ConnectOptions {
  /** The gateway's HTTP address, for example http://127.0.0.1:8765/mcp. Omit to start it over stdio. */
  url?: string;
  /** MCP_GATEWAY_TOKEN for an HTTP gateway. Defaults to the MCP_GATEWAY_TOKEN environment variable. */
  token?: string;
  /** Extra HTTP headers. */
  headers?: Record<string, string>;
  /** Python used for the stdio gateway. Defaults to mcp-server/.venv. */
  python?: string;
  /** Start this stdio command instead of server.py. */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  /** Limit for connecting and for each tool call, in milliseconds. Default 30000. */
  timeoutMs?: number;
  /** Where the stdio gateway's log goes. Default "inherit". */
  stderr?: "inherit" | "ignore" | "pipe";
}

export interface ClientConfigOptions extends ConnectOptions {
  /** Read this file instead of the app's usual config location. */
  configPath?: string;
  /** Entry to use from mcpServers. Default "agentlatch-gateway". */
  serverName?: string;
}

export interface ToolFunction {
  (args?: Record<string, unknown>): Promise<unknown>;
  readonly name: string;
  description: string;
  inputSchema: JsonSchema;
}

export interface ClaudeTool {
  name: string;
  description: string;
  input_schema: JsonSchema;
}

export interface ClaudeToolResult {
  type: "tool_result";
  tool_use_id: string;
  content: string;
  is_error?: true;
}

export class GatewayTools {
  static connect(options?: ConnectOptions): Promise<GatewayTools>;
  static fromClientConfig(client: "claude" | "cursor", options?: ClientConfigOptions): Promise<GatewayTools>;
  names(): string[];
  describe(name: string): string;
  inputSchema(name: string): JsonSchema;
  call(name: string, args?: Record<string, unknown>, options?: { timeoutMs?: number }): Promise<unknown>;
  function(name: string): ToolFunction;
  functions(): Record<string, ToolFunction>;
  toClaudeTools(): ClaudeTool[];
  claudeToolResults(content: ReadonlyArray<{ type: string; [key: string]: unknown }>): Promise<ClaudeToolResult[]>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export class GatewayError extends Error {}
export class GatewayConnectionError extends GatewayError {}
export class GatewayAuthError extends GatewayError {}
export class GatewayTimeoutError extends GatewayError {
  timeoutMs: number;
}
export class GatewayToolError extends GatewayError {
  tool: string;
  content?: unknown[];
}
export class ClientConfigError extends GatewayError {}

export function clientConfigPaths(
  client: "claude" | "cursor",
  options?: { cwd?: string; env?: Record<string, string | undefined>; platform?: string },
): string[];

export function readClientConfig(
  client: "claude" | "cursor",
  options?: { configPath?: string; serverName?: string; cwd?: string; env?: Record<string, string | undefined> },
): {
  path: string;
  name: string;
  entry: { command?: string; args?: string[]; env?: Record<string, string>; cwd?: string; url?: string; headers?: Record<string, string> };
};
