# JavaScript connector for the gateway

## What this is

The AgentLatch **gateway** (`mcp-server/server.py`) is a server that holds **tools**: small actions an AI can ask for, like "echo some text", "get the time in Tokyo" or "fetch a web page". The gateway decides which tools are allowed, so it's the one place that controls what an AI can do.

This **connector** is a small JavaScript library that lets a **JavaScript or TypeScript program** connect to the gateway and use those tools. It's the JavaScript version of [`bridge.py`](../bridge.py), which does the same for Python.

```
your JavaScript program ──(this connector)──▶ AgentLatch gateway ──▶ tools (echo, time, fetch, …)
```

It can also hand the tools to **Claude**, so Claude decides which tools to use. See [Using the tools from Claude in your own code](#using-the-tools-from-claude-in-your-own-code).

## Before you start

You need:

- **The gateway set up.** Follow [SETUP.md Part 1](../SETUP.md#part-1-set-up-the-server) first, so the `mcp-server/.venv` folder exists and `python server.py --check` lists the tools.
- **Node.js 20 or newer.** Step 1 shows how to install and check it.
- **A terminal.** In VS Code or Cursor, use **Terminal → New Terminal**. On Windows this is PowerShell.

Two things that tripped people up before:

- **Commands go in the terminal, code goes in a file.** Lines like `npm install` are typed into the terminal. Lines like `import { GatewayTools } ...` are JavaScript: they go in a `.js` file, and PowerShell gives an error if you type them in.
- **Check which folder you're in.** The terminal shows it at the start of each line, for example `PS C:\Users\you\Code\agent-latch\mcp-server\js>`. Most commands below must run in the `js` folder.

## Step 1: Install Node.js

Check whether you already have it:

```sh
node --version
npm --version
```

✅ If you see version numbers, and `node` shows `v20` or higher, skip to Step 2.

If you get *"The term 'node' is not recognized"* (or *"command not found"*), install it:

- **Windows:** `winget install OpenJS.NodeJS.LTS`
- **macOS:** `brew install node`

Then **fully quit VS Code or Cursor and open it again**. Opening a new terminal tab isn't enough, because the app keeps the old settings until it restarts. Run the two version commands again to check.

## Step 2: Open a terminal in the `js` folder

The connector lives in `agent-latch/mcp-server/js`. Go there, replacing the start of the path with where `agent-latch` is on your computer:

```sh
cd "C:\Users\you\Code\agent-latch\mcp-server\js"
```

✅ The folder at the start of the line ends in `mcp-server\js` (Windows) or `mcp-server/js` (macOS / Linux).

If you're already in `agent-latch`, `cd mcp-server/js` is enough. If you're already in `mcp-server\js`, skip this step: running `cd mcp-server/js` again gives *"Cannot find path"*.

## Step 3: Install the connector's packages

```sh
npm install
```

✅ It ends with `found 0 vulnerabilities` and creates a `node_modules` folder. You only do this once.

If you see *"Could not read package.json"*, you're in the wrong folder. Go back to Step 2.

## Step 4: Check that it works

```sh
npm run smoke
```

This starts the gateway, connects to it, lists its tools and calls the `echo` tool.

✅ You see something like:

```
7 tool(s): echo, utc_now, slack_send_message, slack_whoami, time_get_current_time, time_convert_time, fetch_fetch
echo -> connector works
```

The exact tools depend on what's turned on in `servers.json`. If you see an error instead, check [If something goes wrong](#if-something-goes-wrong).

## Step 5: Use it in your own code

The connector is a library: you don't run it on its own. You add a few lines of JavaScript to **your program's code**, and your program can then use the gateway's tools. Pick the option that matches where your program lives.

### Option 1: a file inside this folder (quickest)

1. In the `mcp-server/js` folder, create a new file called `my-agent.js`.
2. Paste this into the file (not into the terminal):

   ```js
   import { GatewayTools } from "./src/index.js";

   const tools = await GatewayTools.connect();                // start the gateway and connect
   console.log(tools.names());                                // list the tools
   console.log(await tools.call("echo", { text: "hello" }));  // use one tool
   await tools.close();                                       // disconnect
   ```

3. Save the file, then run it in the terminal, in the `js` folder:

   ```sh
   node my-agent.js
   ```

✅ You see the list of tools, then `hello`.

### Option 2: your own JavaScript project somewhere else

1. In the terminal, go to **your project's folder**, the one with its own `package.json`. Then install the connector from this repo, using the real path to `mcp-server/js`:

   ```sh
   npm install "C:\Users\you\Code\agent-latch\mcp-server\js"
   ```

2. Open the file in your project that should use tools (often `index.js` or `agent.js`) and add:

   ```js
   import { GatewayTools } from "@agentlatch/connector";

   const tools = await GatewayTools.connect();
   const result = await tools.call("echo", { text: "hello" });
   console.log(result);
   await tools.close();
   ```

   The only difference from Option 1 is the `import` line: once installed, you import the connector by its name, `@agentlatch/connector`.

3. Make sure your project's `package.json` contains `"type": "module"`. Without it, Node.js rejects the `import` line. You can add it with `npm pkg set type=module`.

4. Run your project as usual, for example `node index.js`.

✅ You see `hello`.

### Use the gateway you set up for Cursor or Claude Desktop

If you already added `agentlatch-gateway` to Cursor or Claude Desktop ([SETUP.md Option B](../SETUP.md#option-b-claude-desktop-or-cursor)), your code can connect exactly the way that app does:

```js
const tools = await GatewayTools.fromClientConfig("cursor");   // or "claude"
```

To check it from the terminal: `npm run smoke -- --client cursor`.

## If something goes wrong

| You see | What it means and what to do |
|---|---|
| `The term 'npm' is not recognized` or `node` not recognized | Node.js isn't installed, or your editor was open when you installed it. Do [Step 1](#step-1-install-nodejs), then fully quit and reopen VS Code or Cursor. |
| `Cannot find path ... mcp-server\js\mcp-server\js` | You're already in the `js` folder. Skip the `cd`. |
| `Cannot find path ... path\to\...` | `path/to/` is a placeholder. Use your real folder. |
| `Could not read package.json` | You're in the wrong folder. `cd` into `mcp-server/js` ([Step 2](#step-2-open-a-terminal-in-the-js-folder)). |
| `The term 'import' is not recognized` | That's JavaScript code, not a terminal command. Put it in a `.js` file and run the file with `node` ([Step 5](#step-5-use-it-in-your-own-code)). |
| `Cannot use import statement outside a module` | Your project needs `"type": "module"` in its `package.json` (Option 2, step 3). |
| `GatewayConnectionError: Could not start the gateway: ... was not found` | The gateway isn't set up yet. Follow [SETUP.md Part 1](../SETUP.md#part-1-set-up-the-server) so `mcp-server/.venv` exists. |
| `GatewayConnectionError: Could not reach the gateway at http://...` | You gave a `url`, but no gateway is running there. Start one with `python server.py --http` in `mcp-server`, and leave that terminal open. |
| `GatewayAuthError` | The gateway needs a password and yours is wrong or missing. Use the `MCP_GATEWAY_TOKEN` value from `mcp-server/.env`. |
| `GatewayTimeoutError` | The gateway or a tool took too long to answer. Try again, or pass a bigger `timeoutMs`. |
| `GatewayToolError: No such tool` | The tool name is wrong. The message lists the tools that exist. |
| `ClientConfigError` | The Cursor or Claude Desktop config is missing, has no `agentlatch-gateway` entry, or isn't valid JSON. Check [SETUP.md Option B](../SETUP.md#option-b-claude-desktop-or-cursor). A common cause is single backslashes in Windows paths. |

## Reference

This section is for when you're writing code with the connector.

### Everything you can do once connected

```js
tools.names();                               // every tool name: ['echo', 'utc_now', ...]
tools.describe("echo");                      // what a tool does
tools.inputSchema("echo");                   // what arguments a tool takes
await tools.call("echo", { text: "hi" });    // run a tool → 'hi'
const echo = tools.function("echo");         // one tool as a normal async function,
await echo({ text: "hi" });                  //   for agent frameworks that want functions
tools.functions();                           // every tool as { name: function }
tools.toClaudeTools();                       // the tools in Claude's format
await tools.claudeToolResults(content);      // run Claude's tool requests, get its replies
await tools.close();                         // always disconnect when you're done
```

### Ways to connect

| Code | Connects to |
|---|---|
| `GatewayTools.connect()` | Starts the gateway for you, using `mcp-server/.venv`'s Python. The simplest option. |
| `GatewayTools.connect({ url: "http://127.0.0.1:8765/mcp" })` | A gateway you already started with `python server.py --http` |
| `GatewayTools.connect({ url, token: "..." })` | The same, when the gateway needs a password (`MCP_GATEWAY_TOKEN`). If you leave out `token`, the `MCP_GATEWAY_TOKEN` environment variable is used, but only when the `url` is on this machine (`localhost`, `127.0.0.1` or `::1`). The token is never sent to another host. |
| `GatewayTools.fromClientConfig("cursor")` | The `agentlatch-gateway` entry in Cursor's `.cursor/mcp.json` (your project's first, then the one in your home folder) |
| `GatewayTools.fromClientConfig("claude")` | The `agentlatch-gateway` entry in Claude Desktop's `claude_desktop_config.json` |

`fromClientConfig` also takes `serverName` (if your entry isn't called `agentlatch-gateway`) and `configPath` (to read a different file). Pass `cwd` to read a project's `.cursor/mcp.json` from another folder (the gateway also starts there), and `env` to fill `${VAR}` references in the entry and add or override its environment variables.

### All connect options

| Option | Default | Meaning |
|---|---|---|
| `url` | none: start the gateway for you | The gateway's web address |
| `token` | `MCP_GATEWAY_TOKEN`, for a `url` on this machine only | The gateway's password, sent as `Authorization: Bearer …`. A token you pass is sent to any `url`. |
| `headers` | none | Extra HTTP headers. An `Authorization` header you set here is kept, and no token is added. |
| `python` | `mcp-server/.venv`'s Python | Which Python starts the gateway |
| `command`, `args`, `env`, `cwd` | `server.py` | Start a different program instead |
| `timeoutMs` | `30000` (30 seconds) | How long to wait when connecting and for each tool. `call()` also takes `{ timeoutMs }`. |
| `stderr` | `"inherit"` | Where the gateway's log messages go: `"inherit"` (your terminal), `"ignore"` or `"pipe"`. `"pipe"` needs `onStderr`. |
| `onStderr` | none | A function called with each chunk of the gateway's log when `stderr` is `"pipe"`. Without it, `"pipe"` is refused, because an unread pipe fills up and can stall the gateway. |

When the connector starts the gateway, it passes only basic settings like `PATH`. The gateway reads its own passwords from `mcp-server/.env`, so your program's API keys never reach it.

### Using the tools from Claude in your own code

Hand the tools to Claude, run the tools it asks for through the gateway, and send back the results. Set your Claude API key in `ANTHROPIC_API_KEY` first:

```js
import Anthropic from "@anthropic-ai/sdk";
import { GatewayTools } from "@agentlatch/connector";

const gateway = await GatewayTools.connect();
const anthropic = new Anthropic();               // reads ANTHROPIC_API_KEY
const messages = [{ role: "user", content: "What time is it in Tokyo?" }];

for (let turn = 0; turn < 8; turn++) {           // always limit the rounds
  const response = await anthropic.messages.create({
    model: "claude-opus-5-5",
    max_tokens: 16000,
    tools: gateway.toClaudeTools(),              // 1. tell Claude which tools exist
    messages,
  });
  messages.push({ role: "assistant", content: response.content });
  if (response.stop_reason !== "tool_use") break;   // Claude has answered
  // 2. run the tools Claude asked for, through the gateway, and send back the results
  messages.push({ role: "user", content: await gateway.claudeToolResults(response.content) });
}
await gateway.close();
```

Your own project needs the Claude SDK for this: `npm install @anthropic-ai/sdk`.

### Errors

Every error the connector throws is a `GatewayError`, so you can catch them all at once, or each kind separately. Messages say what to do next, and never include the password.

| Error | When |
|---|---|
| `GatewayConnectionError` | The gateway can't be reached, or couldn't start |
| `GatewayAuthError` | The gateway rejected the password |
| `GatewayTimeoutError` | Connecting or a tool took longer than `timeoutMs` |
| `GatewayToolError` | The tool doesn't exist, or it ran and failed |
| `ClientConfigError` | The Cursor or Claude Desktop config is missing, invalid, or has no gateway entry |

```js
import { GatewayAuthError, GatewayConnectionError, GatewayTimeoutError, GatewayTools } from "@agentlatch/connector";

try {
  const tools = await GatewayTools.connect({ url: "http://127.0.0.1:8765/mcp" });
} catch (err) {
  if (err instanceof GatewayConnectionError) console.log("Start the gateway first.");
  else if (err instanceof GatewayAuthError) console.log("Check MCP_GATEWAY_TOKEN.");
  else if (err instanceof GatewayTimeoutError) console.log("The gateway is too slow. Try again.");
  else throw err;
}
```

When Claude asks for a tool that fails, `claudeToolResults()` doesn't throw. It sends the error back to Claude, marked as an error, so Claude can try something else. It only throws if the gateway itself is unreachable or rejects the password.

### Tests

In the `js` folder:

```sh
npm test
```

The tests start the real gateway, both directly and as a web server with a password, and check every error above. They need `mcp-server/.venv`; without it, the gateway tests are skipped.

TypeScript users get types automatically from [`src/index.d.ts`](src/index.d.ts).
