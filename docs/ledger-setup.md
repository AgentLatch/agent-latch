# Setting up the audit ledger

This is the hands-on guide: from nothing to a verified, anchored runtime log in about ten minutes.
It assumes you already run the runtime proxy ([runtime.md](runtime.md)). If you want the idea
first, read [ledger.md](ledger.md).

Everything here is local. No account, no network, no extra package.

## Before you start

| You need | Why |
|---|---|
| AgentLatch installed (`pipx install agentlatch-security`) | `agent-latch-runtime` provides every command below |
| A folder for the two files | They are a pair: the trace and its ledger |
| A path the agent cannot write | The anchor destination. This is the part people skip; do not skip it |

## Step 1 — Turn the ledger on

Add `--ledger` next to the `--trace` you already pass:

```sh
agent-latch-runtime proxy \
  --trace runtime-logs/trace.jsonl \
  --ledger runtime-logs/trace.ledger.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem ~/projects
```

That is the whole integration. `--ledger` needs `--trace`; with no trace there is nothing to seal,
so the command exits `2` instead of writing a ledger that proves nothing.

What happens on each MCP message, in order:

1. the trace line is written and flushed;
2. one block is appended to the ledger and flushed;
3. a one-line summary goes to stderr.

If step 2 fails — disk full, permissions — the tool call is **not** affected. The proxy prints one
warning and carries on:

```
agent-latch-runtime: ledger append failed (…); the trace is still being written and verification will report a gap
```

That is deliberate: a recorder must never break the thing it records. The gap it leaves is what
verification reports later.

A block looks like this:

```json
{"schema": "agentlatch.runtime.ledger/1", "seq": 1, "timestamp": "2026-10-29T11:29:39.727Z",
 "method": "tools/call", "stage": "request",
 "record_sha256": "ded85d9b…", "prev": "0000…0000", "digest": "2a75f939…"}
```

The ledger file is created with mode `0600` where the platform supports it. It holds digests, not
arguments or output, so it is safe to keep next to the log — but keep both.

## Step 2 — Check the chain

```sh
agent-latch-runtime verify --ledger runtime-logs/trace.ledger.jsonl
```

```
AUDIT TRAIL UNANCHORED — 4 record(s) verify locally, but nothing outside the machine proves the file was not rebuilt.
```

Read that verdict carefully. It means the blocks are consistent with each other; it does **not**
mean nobody rewrote the file. A rebuilt chain looks exactly like this. That is what step 3 is for.

Add `--trace` to compare every block with the line it sealed:

```sh
agent-latch-runtime verify \
  --ledger runtime-logs/trace.ledger.jsonl \
  --trace runtime-logs/trace.jsonl
```

Exit codes: `0` intact or unanchored, `1` altered, deleted or rewritten, `2` no ledger at that path.

## Step 3 — Publish an anchor

Pick a destination outside the agent's reach. Good options, in order of effort:

| Destination | How | Notes |
|---|---|---|
| A mounted share only you can write | `--to /Volumes/audit/anchors.jsonl` | Simplest. Mount it only when anchoring |
| A bucket with object lock / versioning | `--to ~/sync/anchors.jsonl`, then sync the folder | The sync client does the upload |
| Another machine | `--to` a path on an SSHFS/NFS mount | Keeps the bytes off this host entirely |
| A ticket, wiki or email | Paste the line by hand | Low volume, still real evidence |

```sh
agent-latch-runtime anchor \
  --ledger runtime-logs/trace.ledger.jsonl \
  --to /Volumes/audit/anchors.jsonl
```

```
agent-latch-runtime: anchored #4 9bfbb512b470… to /Volumes/audit/anchors.jsonl
```

Each run appends one line. Anchors never go backwards: pointing `--to` at an older file, or at one
belonging to a different ledger, is refused with exit `2` rather than silently overwriting history.

**Do not put the anchor file next to the ledger.** If the same process or account can write both,
the anchor proves nothing. This is the single most important sentence in this guide.

## Step 4 — Verify against the anchor

```sh
agent-latch-runtime verify \
  --ledger runtime-logs/trace.ledger.jsonl \
  --trace runtime-logs/trace.jsonl \
  --anchor /Volumes/audit/anchors.jsonl
```

```
AUDIT TRAIL INTACT — 4 record(s) verify and match the anchor of 2026-10-29T11:30:59.556Z.
  head #4 · anchor #4 · 4 record(s)
```

That header is now real evidence: the file verifies, and its newest digest is the one that left the
machine at that time.

## Step 5 — Put the verdict at the top of the runtime report

The report you already generate can carry the verdict as its first line:

```sh
agent-latch scan . \
  --runtime-result runtime-logs/gate-results.csv \
  --ledger runtime-logs/trace.ledger.jsonl \
  --anchor /Volumes/audit/anchors.jsonl
```

```
AUDIT TRAIL INTACT — 4 record(s) verify and match the anchor of 2026-10-29T11:30:59.556Z.
  head #4 · anchor #4 · 4 record(s)

Runtime findings · 1

HIGH     ALR04-004  tools/fixture.py:2
  sensitive access
  Tool definition crossed the threshold.
  …
```

When the trail fails, the report says so first, in bold in a terminal and in the same words in
`--plain`:

```
AUDIT TRAIL TAMPERED — a record was altered; the log cannot be trusted.
  #2: the block's digest does not match its content
```

Three rules for this report:

1. A failed trail exits `1` **even with `--fail-on none`**. Log integrity is not a severity
   threshold. If you want a report that cannot fail a pipeline, do not pass `--ledger`.
2. A missing ledger at the path you gave exits `2` — a wrong path should not look like a clean run.
3. Without `--anchor` the header still appears, as `UNANCHORED`. You always see which claim is being
   made.

## Step 6 — Make it a habit (or a cron job)

The ledger only has to be written; anchoring is the part that needs a schedule. Anchoring after
every session is plenty for a laptop. For a long-running proxy, anchor hourly or daily:

```sh
# crontab: every hour at :05
5 * * * * /usr/local/bin/agent-latch-runtime anchor \
  --ledger /srv/agent/runtime-logs/trace.ledger.jsonl \
  --to /Volumes/audit/anchors.jsonl --quiet
```

Then verify on a schedule too, and let it fail loudly:

```sh
agent-latch-runtime verify \
  --ledger /srv/agent/runtime-logs/trace.ledger.jsonl \
  --anchor /Volumes/audit/anchors.jsonl || notify-oncall "audit trail failed verification"
```

[ledger-operations.md](ledger-operations.md) covers cadence, retention, rotation and what to do when
that alert fires.

## Using it with the ChatGPT tunnel

`scripts/agentlatch-chatgpt.sh` writes a trace only; it does not pass `--ledger` and does not run
`import-logs`. If you want a chain for those sessions, run the proxy command the script prints and
add the two flags yourself:

```sh
agent-latch-runtime proxy \
  --trace ~/agentlatch-runtime/trace.jsonl \
  --ledger ~/agentlatch-runtime/trace.ledger.jsonl \
  -- <the server command the script uses>
```

The tunnel carries the MCP traffic; the ledger only watches what the proxy records. See
[clients/chatgpt.md](clients/chatgpt.md) for the tunnel setup itself.

## Troubleshooting

| Message | Meaning | Fix |
|---|---|---|
| `no ledger file at …` (exit 2) | Wrong path, or the proxy ran without `--ledger` | Check the path; a run without `--ledger` cannot be verified after the fact |
| `NO AUDIT TRAIL — nothing to verify` | The report was pointed at a path with nothing there | Same as above. The report exits `2` on purpose |
| `AUDIT TRAIL UNANCHORED` | No anchor given, or the anchor file is empty | Add `--anchor`, or run `anchor` first |
| `refusing to anchor #3: #5 is already anchored` | That destination already knows a later block | Correct behaviour. Use a fresh anchor file only if you are deliberately starting a new log |
| `cannot open ledger file: …` (exit 2) | Permissions or a missing folder the process cannot create | Fix the path or the ownership, then re-run |
| `ledger append failed (…)` on stderr | Disk full or I/O error during a live session | Free space. The gap is real and verification will report it |
| `the trace line is not the record this block sealed` | The trace and the ledger are not the pair you think | A rotated trace needs its own ledger. Keep the pair together |
| `#1: a record is missing here` after trimming | The ledger was replaced or shortened | Restore from backup; expect `deleted` until you do |

## Checklist

- [ ] `--ledger` next to `--trace` on every proxy you care about
- [ ] A destination for anchors that the agent's account cannot write
- [ ] One `anchor` run after each session, or a cron job
- [ ] `--ledger` (and `--anchor`) on the report, so the verdict is the first thing read
- [ ] A scheduled `verify` that alerts on exit `1`
- [ ] Trace and ledger treated as one pair when you copy, back up or rotate
