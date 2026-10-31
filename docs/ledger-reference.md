# Audit ledger reference: formats, API and exit codes

Everything an integrator needs: the on-disk formats, the exact digest inputs, the Python API, the
CLI surface, and the rules for extending it without breaking old files. For the idea, read
[ledger.md](ledger.md); for the step-by-step, [ledger-setup.md](ledger-setup.md).

## Files

| File | Written by | Holds | Safe to keep next to the log? |
|---|---|---|---|
| `trace.jsonl` | `proxy --trace` | One redacted record per MCP message | Yes (that is the log itself) |
| `trace.ledger.jsonl` | `proxy --ledger` | One sealed block per trace record | Yes — digests, not payloads |
| `anchors.jsonl` | `agent-latch-runtime anchor` | One line per published head | **No.** Put it where the agent cannot write |

### Block format (`agentlatch.runtime.ledger/1`)

One JSON object per line, append-only:

```json
{"schema": "agentlatch.runtime.ledger/1", "seq": 1,
 "timestamp": "2026-10-29T11:29:39.727Z",
 "method": "tools/call", "stage": "request",
 "record_sha256": "ded85d9b…", "prev": "0000…0000", "digest": "2a75f939…"}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `agentlatch.runtime.ledger/1` |
| `seq` | int ≥ 1 | Position in the chain, starting at 1 |
| `timestamp` | string | When the block was sealed (ISO 8601 UTC, milliseconds) |
| `method` | string | MCP method of the record (`tools/call`, …) |
| `stage` | string | Stage of the record (`request`, `response`, `error`) |
| `record_sha256` | 64 hex | SHA-256 of the trace line this block seals, without its newline |
| `prev` | 64 hex | `digest` of the block before it; 64 zeros for the first block |
| `digest` | 64 hex | This block's own digest (below) |

`method` and `stage` are copied out of the record for readable reports. They are covered by the
digest, so editing them is detected.

### How the digests are computed

```python
record_sha256 = sha256(trace_line.encode("utf-8")).hexdigest()

digest = sha256(
    b"agentlatch.runtime.ledger/1\x00" +            # domain separation
    canonical_json({                                 # sorted keys, no whitespace, UTF-8
        "prev": prev, "seq": seq, "timestamp": timestamp,
        "method": method, "stage": stage, "record_sha256": record_sha256,
    })
).hexdigest()
```

`canonical_json` is `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
Sorting keys means a different serializer cannot look like tampering; changing any value still
does.

Three properties follow, and the tests rely on them:

- The **trace format is free to change.** Blocks hash the raw line as written, so adding a field to
  the trace does not affect verification.
- **The block format is not free to change.** Adding a field means a new `…ledger/2` schema, because
  the digest covers exactly the six fields above.
- **Timestamps are evidence, not enforcement.** They are covered by the digest, but nothing compares
  them to a clock; a block sealed with a wrong time still verifies.

### Anchor format (`agentlatch.runtime.anchor/1`)

```json
{"schema": "agentlatch.runtime.anchor/1", "seq": 4,
 "digest": "9bfbb512…", "records": 4,
 "timestamp": "2026-10-29T11:30:59.556Z", "ledger": "trace.ledger.jsonl"}
```

| Field | Meaning |
|---|---|
| `seq` | The block the ledger had reached |
| `digest` | That block's digest — the value an attacker must reproduce |
| `records` | Number of blocks at that moment |
| `timestamp` | When the point was published |
| `ledger` | File name of the ledger it belongs to, so two logs can share one anchor file |

Points are append-only and monotonic per destination: publishing a `seq` lower than the newest one
there is refused.

## Python API

```python
from agent_latch.runtime.ledger import (
    Ledger, verify_ledger, describe, FileAnchor, make_anchor, point_for,
    iter_blocks, seal, record_hash, block_digest, GENESIS,
)
```

| Call | Does |
|---|---|
| `Ledger(path)` | Open (or resume) a ledger. Creates the parent folder and the file with mode `0600` |
| `.append(record, *, method, stage, timestamp=None)` | Seal one record, return the `Block`. Raises `LedgerError` |
| `.head` | `(seq, digest)` of the newest block |
| `.close()` / `with Ledger(path) as chain:` | Flush and close |
| `Ledger.read_head(path)` | Newest block without opening for writing (reads the last 64 KiB) |
| `seal(record, *, seq, prev, method, stage, timestamp)` | Build a block without writing it |
| `iter_blocks(path)` | Yield blocks in order; a malformed line raises `LedgerError` instead of being skipped |
| `record_hash(record)` / `block_digest(...)` | The two hashes, for independent checks |
| `verify_ledger(path, *, trace_path=None, anchor_path=None)` | Returns a `Verification`; never writes |
| `describe(verification, limit=5)` | Plain lines: headline, then the first problems |
| `FileAnchor(path)` | `.publish(point)`, `.latest()`, `.points()` |
| `make_anchor(spec)` | `"file:/path"` or a bare path → an anchor destination |
| `point_for(ledger_path, *, seq, digest, records)` | Build an `AnchorPoint` for a head |
| `GENESIS` | The 64-zero `prev` of the first block |

`rewrite()` and `reseal()` exist in `agent_latch.runtime.ledger.chain` for tests and recovery. They
are **not** re-exported from the package on purpose: `reseal` rebuilds a chain from scratch, which is
exactly the forgery it is designed to detect.

### `Verification`

| Field | Meaning |
|---|---|
| `status` | `intact`, `unanchored`, `tampered`, `deleted`, `rewritten`, `missing` |
| `blocks`, `head_seq`, `head_digest` | What the chain holds now |
| `issues` | Tuple of `Issue(kind, seq, detail)` |
| `anchored`, `anchor_seq`, `anchor_digest`, `anchor_time` | What the anchor said, when given |
| `ledger`, `trace_checked` | Context for a report |

Properties: `ok` (nothing changed; `unanchored` counts as ok), `failed` (one of the three failing
statuses), `deleted`, `edited`, `reordered`. `headline()` returns the one sentence a report shows.

### Issue kinds

| `kind` | Produced when |
|---|---|
| `edited` | A block's digest no longer matches its content, a trace line is not the record it sealed, or the trace holds a line no block sealed |
| `deleted` | A `seq` gap; a trace line whose block exists; a trace file gone; a log shorter than the anchored head |
| `reordered` | A block whose `prev` is not the block before it (with no gap explaining it) |
| `rewritten` | The anchored block is present but has a different digest |
| `malformed` | A line is not JSON or not a block; a file cannot be read |
| `unanchored` | `--anchor` was given but holds no points |
| `missing` | There is no ledger at the path |

## CLI

### `agent-latch-runtime proxy --ledger FILE`

Seals every trace record as it is written. Requires `--trace`. Off unless given. A failed append
warns once on stderr and never interrupts the MCP session.

### `agent-latch-runtime anchor --ledger FILE --to PATH [--quiet]`

Appends one point for the current head. `PATH` may be `file:/path` or a bare path. Exit `2` on a
missing ledger, an empty one, an unwritable destination, or a `seq` that would go backwards.

### `agent-latch-runtime verify [PATH | --ledger FILE] [--all] [--trace FILE] [--anchor PATH]`

Read-only. Prints the headline and up to five problems.

- `--ledger FILE` checks one ledger, and compares a trace only when `--trace` is given.
- `PATH` as a ledger file does the same, but finds the trace by name (`x.ledger.jsonl` seals
  `x.jsonl` beside it). A trace that is missing is reported as `deleted`, not skipped.
- `PATH` as a folder checks every `*.ledger.jsonl` directly in it; `--all` also searches the
  subfolders (for example `runtime-logs/archive/`). Symlinks are not followed. The output is one
  row per ledger (records, whether the trace was compared, verdict), a count per verdict, then the
  details of every ledger that failed. `--trace` and `--anchor` belong to one ledger, so they are a
  usage error with a folder.

| Exit | Meaning |
|---|---|
| `0` | `intact` or `unanchored` (for a folder: every ledger) |
| `1` | `tampered`, `deleted` or `rewritten` (for a folder: any ledger, or an empty one) |
| `2` | No ledger at that path and nothing (anchor or trace) shows one existed, no ledger in the folder, or a usage error |

A ledger that is gone or empty counts as `deleted` (exit `1`) when `--anchor` has a point, or the
trace has lines. An empty ledger with neither is a fresh start (`missing`), because the proxy
creates the file before the first record.

### `agent-latch --runtime-result CSV --ledger FILE [--anchor PATH] [--ledger-rows N] [--format sarif]`

Prints the verdict above the findings table (bold panel in a terminal, the same words in
`--plain`), then an audit table with one row per record: `#`, time, method, stage, a short digest
and a state (`ok`, `EDITED`, `DELETED`, `REORDERED`, `MALFORMED`). A gap in the sequence gets its
own `DELETED` row. Every record with a problem is always listed. `--ledger-rows N` (default 20)
caps how many intact ones are shown, newest first, and `0` lists them all. `--anchor` without
`--ledger` is a usage error (`2`).

`--format sarif` writes a SARIF 2.1.0 run. With `--output FILE` the file gets the SARIF and the
terminal still shows the readable report above; without it the SARIF goes to stdout and the
verdict line to stderr, so a pipe stays clean. Each problem
the verifier found is a result for rule `ALR15-R01`, located in the ledger file (the line is the
record's sequence number; level `error`, or `warning` for a missing anchor). Runtime gate findings
are included as their own results. The verdict is always in the run properties (`auditTrail`), so a
clean ledger still leaves a record. `--format json` is not supported with `--runtime-result` and
exits `2`. Exit codes are the same as for text.

| Exit | Meaning |
|---|---|
| `0` | Trail `intact`/`unanchored` and no finding at or above `--fail-on` |
| `1` | Trail failed, **or** a finding matched `--fail-on`. A failed trail fails even with `--fail-on none` |
| `2` | No ledger at that path, or a missing CSV/project |

## Adding another anchor destination

The contract is three members:

```python
class MyVault:
    path: Path                                  # for messages and reports

    def publish(self, point: AnchorPoint) -> AnchorPoint: ...   # append, refuse to go backwards
    def latest(self) -> AnchorPoint | None: ...                 # newest point, or None
```

Then teach `make_anchor` your scheme prefix and return it. Two rules:

- **Refuse to go backwards.** A destination that accepts a lower `seq` silently destroys the
  evidence of a truncation.
- **Stay opt-in.** No network client becomes a required dependency; a destination that sends data
  off the machine must be documented as network behaviour, the same way `--database` is.

Anything that can store one line (an S3 object with object lock, a Git commit, a ticketing API, a
signed email) can be an anchor. The bytes are trivial; the trust boundary is the whole design.

## Compatibility

| Change | Allowed? |
|---|---|
| Add a field to a trace record | Yes — blocks hash the raw line |
| Add a field to a block | Only under a new `agentlatch.runtime.ledger/2` schema |
| Change the digest inputs, domain string or canonical encoding | Only under a new schema, and verification must keep reading `/1` |
| Change `status` names | No — reports, docs and exit-code tests depend on them |
| Change exit codes | No — CI and the GitHub Action depend on them; `0` pass, `1` findings or a failed trail, `2` error |

The verifier reads files written by any earlier 0.x version, because the schema string is checked
per line and the digest inputs are frozen. There is no migration step: keep the old file beside the
new one and verify each with its own anchor.

## Known limits

- `verify` loads the whole ledger into memory (`list(iter_blocks(...))`) — roughly 1 KiB per record.
  A million-record ledger needs about a gigabyte to verify. Split long runs by session if that
  matters.
- Verification is single-threaded and unoptimised; it is fast (about 0.7 ms per 1,000 records) but it
  is not incremental.
- No signature is applied to blocks, so nothing proves *which machine* wrote a block. Only the
  anchor path provides an off-host claim.
- The verifier trusts the filesystem to return bytes it wrote. Anything that lies at that level —
  a hostile kernel, a rewritten disk image — is outside the model.
