// Errors the connector throws. Every one extends GatewayError, so callers can
// catch them all at once or one kind at a time. Messages say what to do next,
// and never include the gateway token.

import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";

/** The base class of every error the connector throws. The name is the subclass's name. */
export class GatewayError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** The gateway isn't reachable: not running, wrong URL, or the process exited. */
export class GatewayConnectionError extends GatewayError {}

/** The HTTP gateway rejected the token (MCP_GATEWAY_TOKEN missing or wrong). */
export class GatewayAuthError extends GatewayError {}

/** Connecting or a tool call took longer than timeoutMs. */
export class GatewayTimeoutError extends GatewayError {
  /** timeoutMs is the limit that was exceeded; other options (such as cause) go to Error. */
  constructor(message, { timeoutMs, ...options } = {}) {
    super(message, options);
    this.timeoutMs = timeoutMs;
  }
}

/** The tool ran but reported an error (the MCP result had isError: true). */
export class GatewayToolError extends GatewayError {
  /** tool is the tool's name and content its result blocks; other options (such as cause) go to Error. */
  constructor(message, { tool, content, ...options } = {}) {
    super(message, options);
    this.tool = tool;
    this.content = content;
  }
}

/** A Claude Desktop or Cursor config file is missing, unreadable, or has no gateway entry. */
export class ClientConfigError extends GatewayError {}

const START_HINT = "Start it with `python server.py --http` in the mcp-server folder.";

/**
 * Turn an error from the MCP SDK, fetch or child_process into one of ours.
 *
 * what:      what we were doing, for the message ("connect to the gateway", "call tool echo")
 * where:     the URL or command we were talking to
 * timeoutMs: the timeout in force, for the timeout message
 */
export function toGatewayError(err, { what, where, timeoutMs }) {
  if (err instanceof GatewayError) return err;

  if (err instanceof McpError && err.code === ErrorCode.RequestTimeout) {
    return new GatewayTimeoutError(
      `Timed out after ${timeoutMs} ms trying to ${what} (${where}). ` +
        "Raise timeoutMs if the tool is slow, or check that the gateway is responsive.",
      { timeoutMs, cause: err },
    );
  }

  const status = err instanceof StreamableHTTPError ? err.code : undefined;
  if (err instanceof UnauthorizedError || status === 401 || status === 403) {
    return new GatewayAuthError(
      `The gateway at ${where} rejected the token. ` +
        "Pass the same value as MCP_GATEWAY_TOKEN in mcp-server/.env as `token`. " +
        "For a gateway on this machine you can set the MCP_GATEWAY_TOKEN environment variable instead.",
      { cause: err },
    );
  }

  const code = err?.cause?.code ?? err?.code;
  if (code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "EHOSTUNREACH" || code === "ECONNRESET") {
    return new GatewayConnectionError(`Could not reach the gateway at ${where} (${code}). ${START_HINT}`, {
      cause: err,
    });
  }
  if (code === "ENOENT") {
    return new GatewayConnectionError(
      `Could not start the gateway: ${where} was not found. ` +
        "Create mcp-server/.venv (see SETUP.md) or pass `python`.",
      { cause: err },
    );
  }
  if (err instanceof McpError && err.code === ErrorCode.ConnectionClosed) {
    return new GatewayConnectionError(
      `The gateway closed the connection while trying to ${what} (${where}). Check its log for the reason.`,
      { cause: err },
    );
  }
  if (status !== undefined) {
    return new GatewayConnectionError(`The gateway at ${where} answered HTTP ${status} while trying to ${what}.`, {
      cause: err,
    });
  }
  if (err instanceof TypeError && /fetch failed/i.test(err.message)) {
    return new GatewayConnectionError(`Could not reach the gateway at ${where}. ${START_HINT}`, { cause: err });
  }

  return new GatewayError(`Failed to ${what} (${where}): ${err?.message ?? err}`, { cause: err });
}
