# Connector licensing and packaging: design

> **Status: proposed design, not implemented yet. Pending legal review** (see
> [section 8](#8-legal-review)). This document defines how separately licensed (paid) connector
> packages are distributed and how self-hosted customers receive and validate a license. It builds
> on the connector contract in `docs/connectors.md` (AgentLatch/agent-latch#77). Nothing here
> changes the AgentLatch core or its MIT license.

## 1. Goals and rules

- **The core stays MIT.** `agentlatch-security` (the `agent-latch` and `agent-latch-runtime`
  commands) stays under the MIT license in this repository, with no license checks, no feature
  locks and no code from paid packages.
- **Licensing never sees log data.** License validation is fully offline. No event, payload,
  trace record, ledger entry, file path, host name or count of events is sent anywhere for
  licensing. Paid packages make no licensing network calls at all.
- **A licensing problem never touches the agent.** Connectors run in the importer, a separate
  process from the proxy (`docs/runtime.md`). A missing or expired license can stop a paid
  connector. It can never block, slow or change MCP traffic, and it never deletes data already
  written.
- **Fail clearly at startup, not silently later.** License problems are reported when the
  importer starts, with a message that says what to do.

## 2. Free and paid packages

| | Free connectors | Paid connectors |
|---|---|---|
| Examples | `_template`, `jsonl-archive` | Enterprise stores and exporters (for example a warehouse or SIEM connector) |
| License | MIT | AgentLatch commercial license (an end-user license agreement) |
| Source | This repository, `connectors/` folder (`docs/connectors.md`, section 6.3) | Private repository `AgentLatch/agentlatch-connectors-pro`, same folder layout |
| Published to | Public PyPI | AgentLatch's private package index and offline bundles (section 3) |
| License check | None | Offline signed license file (section 4) |

Paid connectors follow every rule in `docs/connectors.md`: the same `Connector` contract,
`CONNECTOR_API` versioning, `connector-<type>-vX.Y.Z` tags, entry point group
`agent_latch.connectors`, opt-in payloads and error behavior. The only difference is where the
code lives and that the connector checks a license before it opens.

This changes one decision in `docs/connectors.md` section 6.3 for paid packages only: their source
cannot sit in the public MIT repository, so it lives in a second, private repository with the same
layout and CI rules. Free connectors stay in `connectors/` in this repository. The contract itself
(`runtime/connectors.py`) stays in the MIT core, so paid packages build on a public interface
rather than the other way round.

### 2.1 The shared license library

All paid connectors use one small private package, `agentlatch-license`, that verifies license
files. It is the only place the verification code and the public keys live:

- It depends on the `cryptography` package for Ed25519 signatures. That dependency belongs to
  paid packages only and never becomes a core dependency.
- It exposes one function, `require_license(product: str, context: ConnectorContext) ->
  LicenseInfo`, which each paid connector factory calls before it returns a connector.
- It is versioned on its own (SemVer). Paid connectors depend on a compatible range, for example
  `agentlatch-license>=1,<2`.

## 3. Distribution

Customers run AgentLatch on their own machines. Paid packages reach them in one of three ways:

1. **Private package index (online installs).** Each customer gets a read-only index token. They
   store it the way pip already supports for private indexes, in `~/.netrc` (mode `0600`) or a
   system keyring, never on the command line, where other users can see it in the process list.
   Then they install with their normal tools, for example:

   ```bash
   pip install --index-url "https://<private index host>/simple/" agentlatch-connector-<type>
   ```

   The token only grants download access. It is not the license, and the installed connector
   never uses it. Each token has a non-secret token ID. The index's download logs record that
   ID, the package and the version, never the token itself, and never any customer event data,
   because none is sent. Index logs are readable only by AgentLatch staff who run the index,
   and a customer can revoke and reissue their token from the customer portal at any time.

2. **Offline bundle (air-gapped installs).** A `.tar.gz` per release containing:
   - the wheels for the connector, `agentlatch-license` and all their dependencies;
   - a `requirements.txt` that pins every one of those packages to an exact version with its
     `--hash=sha256:` digest;
   - a `SHA256SUMS` file listing the digest of `requirements.txt` and of every wheel;
   - a detached signature of `SHA256SUMS`, made with the release key.

   The customer installs in this order and stops at the first failure:
   1. Verify the signature of `SHA256SUMS` against the AgentLatch release public key they
      obtained separately (published on the website and in the customer portal, never only
      inside the bundle).
   2. Check every digest in `SHA256SUMS` against the files in the bundle
      (`sha256sum --check --strict SHA256SUMS`). A missing or mismatched file means the bundle
      is not installed.
   3. Install only from the bundle with pip's hash checking:
      `pip install --no-index --find-links ./bundle --require-hashes -r requirements.txt`.

3. **Container image.** A paid runtime image built on the public runtime image
   (`docs/docker.md`), adding the paid wheels, pushed to a private registry. It follows the same
   image rules: pinned base digest, user `10001`, no compilers or source tree.

Every release is signed. Wheels and bundles carry SHA-256 hashes, and the `SHA256SUMS` file is
signed with a release key separate from the license-signing key, so a leaked download token
cannot be used to publish packages, and a leaked release key cannot mint licenses.

## 4. The license file

A license is a small JSON file signed by AgentLatch. The customer keeps it next to their
configuration; nothing about it is secret enough to need a vault, but it should still not be
committed to a public repository.

```json
{
  "schema": "agentlatch.license/1",
  "license_id": "lic_01J2X4…",
  "customer": "Example Ltd",
  "products": ["connector:splunk", "connector:snowflake"],
  "issued_at": "2026-11-01T00:00:00Z",
  "not_before": "2026-11-01T00:00:00Z",
  "expires_at": "2027-11-01T00:00:00Z",
  "grace_days": 14,
  "kind": "subscription",
  "kid": "2026-1",
  "signature": "base64 Ed25519 signature over the canonical JSON of every other field"
}
```

- **`products`** lists the connector types this license covers, as `connector:<entry point
  name>`. One file can cover several connectors.
- **`kind`** is `subscription` or `trial`. Trial licenses have `grace_days: 0`.
- **`kid`** names the signing key. `agentlatch-license` ships a small set of public keys by `kid`,
  so keys can be rotated: a new key is added in a library release before it is used, and an old
  key is removed only after every license it signed is past `expires_at` **plus** its
  `grace_days`. Removing it earlier would turn a license that is still inside its grace period
  into "not valid".
- **Canonical JSON** for the signature uses the same rules as the ledger
  (`runtime/ledger/canonical.py`): sorted keys, no spaces, UTF-8, so the same license always
  verifies the same way.

### 4.1 How the connector finds the license

In this order, first match wins:

1. `--connector-option NAME.license=FILE` (or `license = "FILE"` in `--connector-config`).
2. The environment variable `AGENTLATCH_LICENSE_FILE`.
3. The default path: `~/.config/agentlatch/license.json` on Linux and macOS,
   `%APPDATA%\AgentLatch\license.json` on Windows.

The license path comes from the operator, never from the scanned project or MCP traffic, the
same rule as all connector configuration (`docs/connectors.md`, section 6.2).

## 5. Validation

`require_license(product, context)` runs inside the connector factory, at the **create** step of
the connector lifecycle (`docs/connectors.md`, section 4), before the connector opens anything.
It:

1. Reads the license file (at most 64 KB) and parses it as JSON.
2. Checks `schema`, finds the public key for `kid`, and verifies the Ed25519 signature.
3. Checks that `product` is listed in `products`.
4. Compares the current time with `not_before` and `expires_at` (section 6).
5. Returns `LicenseInfo(license_id, customer, expires_at, state)` for logging.

**What validation uses:** the license file, the embedded public keys and the system clock.
**What it never uses or sends:** events, payloads, trace or ledger contents, file paths, host
names, user names, counts, or any network connection. There is no "phone home", no activation
server and no usage reporting. A test in each paid package asserts that validation succeeds with
networking disabled.

The importer logs one line at startup per licensed connector, for example
`agent-latch-runtime: connector "siem" licensed to Example Ltd (lic_01J2X4…) until 2027-11-01`.
It never logs the signature or the full file.

**Revocation** is by expiry. Subscriptions are short enough (one year, or less on request) that
an offline design does not need an online revocation list. If a license must be withdrawn early,
its `license_id` is added to a deny list shipped in the next `agentlatch-license` release.

## 6. Behavior on missing, expired or invalid licenses

All failures surface through the error types already defined in `docs/connectors.md`, section 5,
so the importer needs no licensing-specific code.

| Situation | When it is detected | What happens |
|---|---|---|
| **No license file found** | Create | `ConnectorConfigError`: `import-logs` exits `2` before opening any output. The message lists the three places it looked and how to get a license. |
| **File unreadable or not valid JSON** | Create | `ConnectorConfigError`, exit `2`. The message names the path, not the content. |
| **Bad signature, unknown `kid`, or edited fields** | Create | `ConnectorConfigError`, exit `2`: "license file is not valid". The importer does not say which check failed beyond that, so a modified file gets no hints. |
| **Product not covered** | Create | `ConnectorConfigError`, exit `2`, naming the connector type and the `license_id`. |
| **On deny list** | Create | `ConnectorConfigError`, exit `2`, asking the operator to contact AgentLatch. |
| **Not yet valid** (`not_before` in the future, beyond a 24-hour clock-skew allowance) | Create | `ConnectorConfigError`, exit `2`, showing the start date. |
| **Expired, inside the grace period** | Create | The connector works normally. A warning is printed at startup and in the final summary, with the number of days left. |
| **Expired, past the grace period** (trials have no grace period) | Create | `ConnectorConfigError`, exit `2`, showing the expiry date and how to renew. |
| **Expires while the importer is running** (follow mode) | `write`, at most once an hour, comparing the clock with the license already loaded (no file or network access) | Inside the grace period: one warning, then normal work. Past the grace period: the connector raises `ConnectorConfigError`, which the importer treats like any connector bug (`docs/connectors.md`, section 5): that connector is disabled for the rest of the run, its waiting batches count as undelivered, and every other output keeps running. See [section 6.1](#61-recovering-after-renewal). |

### 6.1 Recovering after renewal

A paid connector that stopped because its license lapsed missed the events that arrived while it
was stopped. Those events still exist in the proxy's log files, so they can be delivered later,
but only if the files are kept exactly as they are:

1. **Keep the log files whole until recovery is done.** Keep the original `trace.jsonl` from its
   first line, including everything written before the license lapsed, and, when the connector
   receives payloads, the matching `payloads.jsonl` for the same period. Do not rotate, truncate
   or edit them until step 4 is finished. The importer derives each event's identity from them:
   the run id is a hash of the first trace line, and an event's `order` is its trace line number.
   A file that was cut or rotated produces different identities, so connectors can no longer
   match events they already have, and recovery is incomplete.
2. **Stop the running follow-mode importer** (Ctrl+C, or stop its service). Never run a catch-up
   while it is still running: two importers writing to the same connector at once can deliver
   the same events twice.
3. **Install the renewed license** (section 4.1).
4. **Start follow mode again** with the same input paths, connector options and `--run-id` as
   before (`docs/connectors.md`, section 5). On start the importer reads the log files from the
   beginning, delivers every event the connector does not have yet (connectors deduplicate by
   event key), and then keeps following, so this one step both catches up and resumes live
   delivery.

**Rotating log files later.** Recovery is not the only reason to be careful with rotation: a
running follow-mode importer keeps reading the file it opened, so if `trace.jsonl` is renamed and
a new one is started underneath it, the importer misses everything written to the new file. Never
rotate the log files while a follow-mode importer is running. To rotate safely, stop the
importer, rotate the files, then start it again; it begins a new run on the new files. This is a
property of the importer today, not of licensing, and applies to free connectors too.

If the importer normally runs only with `--once` (for example from a scheduled job), step 4 is
simply the next `--once` run with the same options, after steps 2 and 3. A `--once` run alone
never resumes live delivery for a follow-mode setup, because it exits when it reaches the end of
the files.

Guarantees in every case:

- **Only the paid connector is affected.** Most failures happen at create, so the operator
  sees them immediately. They can renew, or remove that `--connector` and run everything else
  (CSVs, gates, `--database`, free connectors) exactly as before.
- **No data is deleted or locked.** Data a paid connector already wrote stays where it is, in its
  normal format, readable without a license. Expiry stops new writes only. Events that arrive
  while the connector is stopped can be delivered later as long as the log files are kept
  (section 6.1).
- **The proxy and the scanner are never affected.** Licensing code is loaded only when the
  operator names a paid connector with `--connector`.

## 7. Versioning and updates

- A valid license allows installing any release of the licensed connectors, including new major
  versions. There is no per-version licensing.
- `agentlatch.license/1` changes only additively. A new required field means
  `agentlatch.license/2`, and `agentlatch-license` keeps accepting `/1` files until they expire.
- Paid connectors follow the `CONNECTOR_API` compatibility rules in `docs/connectors.md`,
  section 6.4, exactly like free ones.

## 8. Legal review

**Status: pending.** This section records the proposed relationship between the MIT core and the
paid packages for legal review. It is not legal advice, and nothing here is final until legal
review confirms it.

Proposed position, to be confirmed:

1. **Using the MIT core from proprietary code is allowed.** The MIT license lets anyone use,
   copy, modify and distribute the core, including in proprietary software, provided the
   copyright and license notice are kept. Paid packages import the core's public contract and are
   loaded through a Python entry point; they do not change or relicense the core.
2. **No core code is copied into paid packages without its notice.** If a paid package copies any
   core code rather than importing it, that code keeps its MIT notice in the paid package.
3. **No paid code goes into the core.** The public repository, its wheels and its container images
   contain only MIT-licensed code. CI checks that no `agentlatch-license` or paid connector
   package is a dependency of `agentlatch-security`.
4. **Third-party dependencies of paid packages** (for example `cryptography`, database drivers or
   vendor SDKs) keep their own licenses. Their terms, including any copyleft terms, must be
   reviewed before a paid package ships, and their notices are included in each bundle and image.
5. **Contributions to the core** stay MIT. Whether outside contributions need a contributor
   agreement is a question for legal review.
6. **Trademarks.** The "AgentLatch" name in paid package names is a trademark question, separate
   from the MIT copyright license.
7. **The commercial license (EULA)** for paid packages, including what happens to data on expiry
   (section 6), needs to be drafted and approved.

Checklist for legal review:

- [ ] Items 1 to 3: MIT core and proprietary plugin relationship confirmed.
- [ ] Item 4: dependency licenses of each paid package reviewed before release.
- [ ] Item 5: decision on a contributor agreement.
- [ ] Item 6: trademark use in package names.
- [ ] Item 7: commercial license text approved, consistent with section 6.

Until every item is checked, paid packages are not published.

## 9. What this is not

- Not a change to the core: no license checks, telemetry or feature locks are added to
  `agentlatch-security`.
- Not copy protection. A determined user can modify Python code they run. The license check
  makes the terms clear and keeps honest use simple; it is not a security boundary, and it is
  never used as one.
- Not usage-based billing. Nothing is measured or reported.

## 10. Proposed rollout

1. Merge this document after legal review (section 8).
2. Create the private repository and `agentlatch-license`, with tests for every row of the table
   in section 6, including a test that validation works with networking disabled.
3. Set up the private package index, release signing and the offline bundle build.
4. Release the first paid connector once `docs/connectors.md` step 2 (the contract in the core)
   has shipped.
