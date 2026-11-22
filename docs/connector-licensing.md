# Separately licensed packages

AgentLatch can be extended with separately licensed (paid) packages: event stores used with
`--store` ([stores.md](stores.md)) and connectors used with `--connector`
([connectors.md](connectors.md)). This page says what such a package may and may not do. How a
package is delivered, and its own options, are documented with the package.

## What stays the same

- **The core stays MIT.** `agentlatch-security` (the `agent-latch` and `agent-latch-runtime`
  commands) stays under the MIT license in this repository, with no license checks, no feature locks
  and no code from paid packages. Its wheels and container images contain only MIT-licensed code.
- **Paid packages use the public contracts.** They are found through the same entry point groups
  (`agent_latch.stores`, `agent_latch.connectors`), follow the same rules as any other package, and
  are loaded only when the operator names them. Nothing is imported or checked otherwise.
- **The proxy and the scanner are never affected.** Packages run in the importer and the store
  commands, a separate process from the proxy, so a licensing problem can never block, slow or
  change MCP traffic.

## The license

A license is a small JSON file signed by AgentLatch (`agentlatch.license/1`). It names the
customer, the products it covers (`connector:<type>`), and when it starts and expires, with an
optional grace period. A package finds it in this order, first match wins:

1. its own `license` option (`--store-option license=FILE`, or `--connector-option NAME.license=FILE`);
2. the environment variable `AGENTLATCH_LICENSE_FILE`;
3. `~/.config/agentlatch/license.json` on Linux and macOS, `%APPDATA%\AgentLatch\license.json` on
   Windows.

The path comes from the operator, never from the scanned project or the MCP traffic.

**Validation is offline.** It uses the license file, public keys built into the package and the
system clock. It never uses or sends events, payloads, trace or ledger contents, file paths, host
names, user names or counts, and it opens no network connection: no activation server, no "phone
home", no usage reporting.

## When the license is a problem

| Situation | What happens |
|---|---|
| Missing, unreadable, not valid, not covering this product, not yet valid, or expired past its grace period | The command exits `2` when it starts, before the package writes anything, with a message that says what to do |
| Expired, inside the grace period | Works normally, with a warning that shows the days left |
| A store's license expires while `import-logs` runs | The store stops saving; the events wait, as for a database that cannot be reached, and the run exits `2` at the end. Renew and run it again: nothing is lost |
| A connector's license expires while `import-logs` runs | That connector stops with a message; every other output keeps running. Running `import-logs` again after renewal delivers the gap |

**A paid package needs a valid license for every use.** That includes reading a paid store with
`verify`, `anchor`, `audit-tool` or the report: without a license they exit `2`, and a running
`audit-tool` refuses its tools once the license lapses.

**No data is deleted or locked.** What a package already wrote stays where it is, in its normal
format, in the customer's own database or bucket, and stays readable with the customer's own tools.
Only the package's commands stop.

## What this is not

- Not a change to the core: no license checks, telemetry or feature locks are added to
  `agentlatch-security`.
- Not copy protection. A determined user can modify Python code they run. The check makes the terms
  clear and keeps honest use simple; it is not a security boundary.
- Not usage-based billing. Nothing is measured or reported.
