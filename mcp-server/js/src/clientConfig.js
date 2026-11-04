// Read the gateway's entry from Claude Desktop's or Cursor's MCP config, so a JS
// agent connects to the gateway exactly the way that app does. Both apps use the
// same `mcpServers` format as servers.json.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { ClientConfigError } from "./errors.js";

export const DEFAULT_SERVER_NAME = "agentlatch-gateway";

/** Where each app keeps its MCP config on this machine, most specific first. */
export function clientConfigPaths(client, { cwd = process.cwd(), env = process.env, platform = process.platform } = {}) {
  const home = homedir();
  switch (client) {
    case "claude":
      if (platform === "win32") return [join(env.APPDATA ?? join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json")];
      if (platform === "darwin") return [join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")];
      return [join(env.XDG_CONFIG_HOME ?? join(home, ".config"), "Claude", "claude_desktop_config.json")];
    case "cursor":
      // A project's .cursor/mcp.json takes precedence over the global one, as in Cursor.
      return [join(cwd, ".cursor", "mcp.json"), join(home, ".cursor", "mcp.json")];
    default:
      throw new ClientConfigError(`Unknown client "${client}". Use "claude" or "cursor".`);
  }
}

// Cursor writes ${env:NAME}; servers.json and others write ${NAME}. Accept both.
const ENV_REF = /\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}/g;

function fillEnv(value, env) {
  if (typeof value === "string") return value.replace(ENV_REF, (_, name) => env[name] ?? "");
  if (Array.isArray(value)) return value.map((item) => fillEnv(item, env));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fillEnv(item, env)]));
  }
  return value;
}

/**
 * Find the gateway entry in an app's MCP config.
 *
 * Returns { path, name, entry }, where entry is either
 * { command, args, env, cwd } (stdio) or { url, headers } (HTTP), with ${VAR} filled in.
 */
export function readClientConfig(client, { configPath, serverName = DEFAULT_SERVER_NAME, cwd, env = process.env } = {}) {
  const candidates = configPath ? [configPath] : clientConfigPaths(client, { cwd, env });
  const path = candidates.find((candidate) => existsSync(candidate));
  if (!path) {
    throw new ClientConfigError(
      `No ${client} MCP config found. Looked in: ${candidates.join(", ")}. ` +
        "Add the gateway with SETUP.md Option B, or pass configPath.",
    );
  }

  let servers;
  try {
    servers = JSON.parse(readFileSync(path, "utf8")).mcpServers ?? {};
  } catch (err) {
    throw new ClientConfigError(`Could not read ${path}: ${err.message}`, { cause: err });
  }

  const entry = servers[serverName];
  if (!entry) {
    const names = Object.keys(servers);
    throw new ClientConfigError(
      `${path} has no "${serverName}" server. ` +
        (names.length ? `It has: ${names.join(", ")}. Pass serverName to pick one.` : "Add it with SETUP.md Option B."),
    );
  }
  if (!entry.command && !entry.url) {
    throw new ClientConfigError(`"${serverName}" in ${path} has neither "command" nor "url".`);
  }
  return { path, name: serverName, entry: fillEnv(entry, env) };
}
