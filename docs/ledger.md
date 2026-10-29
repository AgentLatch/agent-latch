# The audit ledger: making the runtime log hard to rewrite

The runtime proxy writes a log of what an agent did. That log is the only record you have. If the
agent — or anyone with its account — can quietly edit it, it is not evidence: it is a story the
agent tells about itself.

The audit ledger is a small, local, standard-library layer that makes those edits visible. It does
**not** move your logs, call a chain, add a dependency, or sit in the request path.

- Preview. It records and reports; it never blocks a tool call.
- Off unless you ask for it (`--ledger`).
- Local only: no network, no upload, no LLM.

This page explains the idea, what the verdicts mean, and what it cannot do. To set it up, read
[ledger-setup.md](ledger-setup.md). For formats and the API, see
[ledger-reference.md](ledger-reference.md). For runbooks, see
[ledger-operations.md](ledger-operations.md).

## The problem in one picture

The trace file is a log of one JSON line per MCP message. Nothing in it links one line to the
next, so every line can be edited on its own and the file still looks perfectly normal:

```
trace.jsonl
  {"method": "tools/call", "tool": "read_file",  ...}   ← what if this said "send_email"?
  {"method": "tools/call", "tool": "send_email", ...}   ← what if this line was never there?
  {"method": "tools/call", "tool": "read_file",  ...}   ← what if this one is gone?
```

An agent that was prompted to exfiltrate data can remove the two lines that prove it, and every
remaining line is byte-for-byte valid. An operator reading the file sees a clean session.

## What the ledger adds

Three ideas, each cheap:

**1. Every record gets a seal.** When the proxy writes trace line *N*, it also appends one block to
a second file. The block stores the SHA-256 of that exact line.

**2. Each block commits to the one before it.** A block stores the digest of its predecessor, and
its own digest covers its predecessor plus its own fields. Change any block and every block after
it stops matching. This is the "chain" part:

```
 block 1                block 2                block 3
 ┌────────────────┐     ┌────────────────┐     ┌────────────────┐
 │ seq        1   │     │ seq        2   │     │ seq        3   │
 │ record_sha256  │     │ record_sha256  │     │ record_sha256  │
 │ prev  000…000  │◄────│ prev  digest 1 │◄────│ prev  digest 2 │
 │ digest 1       │     │ digest 2       │     │ digest 3       │
 └────────────────┘     └────────────────┘     └────────────────┘
        ▲                     ▲                      ▲
   seals trace           seals trace            seals trace
   line 1                line 2                 line 3
```

**3. One short digest leaves the machine.** A chain alone has a known weakness: an attacker who can
write the file can also *rebuild* the whole chain from scratch, and the rebuilt version is
internally perfect. The only thing that defeats that is a value that already left the machine.
So a second file holds **anchor points** — a few dozen bytes naming where the chain had reached
and when:

```
{"schema": "agentlatch.runtime.anchor/1", "seq": 4,
 "digest": "9bfbb512…", "records": 4, "timestamp": "2026-10-29T11:30:59.556Z",
 "ledger": "trace.ledger.jsonl"}
```

Publishing that line somewhere the agent cannot write — a mounted share, a bucket that syncs to
write-once storage, a second host, a ticket — turns a local file into something an attacker has to
defeat in two places at once.

## The six verdicts

`agent-latch-runtime verify` and the runtime report both lead with one of these. **Bold** marks a
verdict that fails the command.

| Verdict | Means | What produces it |
|---|---|---|
| `intact` | The chain verifies and the head is the digest that was published | Everything matches, including the newest anchor point |
| `unanchored` | The file verifies on its own, but nothing outside proves it was not rebuilt | No anchor given, or the anchor file is empty |
| **`tampered`** | A block's content no longer matches its digest, or a record is out of order | An edited field, a malformed block, blocks swapped |
| **`deleted`** | Records are missing | A gap in `seq`, a trace line with no block, a log shorter than the anchored head, a missing trace file |
| **`rewritten`** | The chain is self-consistent but its head is not what was published | The whole log was rebuilt, or replaced from an older copy |
| **`missing`** | There is no ledger to check | A wrong path, or a run that never had `--ledger` |

Each problem is reported with the block it affects, so a reader sees *where* the trail stops
making sense:

```
AUDIT TRAIL DELETED — records are missing; the log cannot be trusted.
  #3: record #3 is missing
  #4: this block does not follow the block before it
```

`tampered` and `deleted` are separated on purpose. "A record was altered" and "a record was
removed" are different claims, and a reader should not have to guess which one the evidence
supports.

## What it catches, and what it does not

| Attack | Caught? | By what |
|---|---|---|
| Edit a field in the trace file | Yes | `record_sha256` mismatch (`--trace`), or the block digest |
| Delete a trace line | Yes | Trace/ledger comparison, or the anchored head |
| Delete a ledger block | Yes | `seq` gap, and the broken `prev` link |
| Reorder blocks | Yes | `prev` link |
| Truncate the tail | Yes | Anchored head is higher than the log |
| Rebuild the entire chain consistently | Yes, **only with an anchor** | Published digest differs |
| Replace the log with an older, genuine copy | Yes, only with an anchor | Anchored head is higher than the log |
| Edit a tool's output before it is recorded | **No** | Out of scope: this is capture, not execution |
| Tamper with the ledger *and* every anchor | **No** | Out of scope: that is the boundary you choose |
| Do something harmful that was recorded faithfully | **No** | This layer proves integrity, not safety |

Two consequences worth stating plainly:

**`unanchored` is the normal state of a fresh setup.** A chain without an anchor catches careless
edits and accidental truncation, not a determined attacker. Anchor if you intend to use the log as
evidence.

**A clean verdict is not a security guarantee.** `intact` means "this log was not changed after it
was recorded". It says nothing about whether what was recorded was safe, whether the agent behaved,
or whether the tools it called were appropriate. That is the scanner's and the gates' job.

## Where it fits

The ledger is a gate in the same catalog as every other check: `ALR15`, *tamper-evident audit
trail*, mapped to `ASI10` (Rogue Agents) — an agent that covers its tracks is the behaviour this
outcome addresses. Its detector is `ALR15-R01`, a runtime check. Like every gate, it is
informational: no compliance claim, no OWASP endorsement. See [GATES.md](GATES.md).

The verifier is deliberately **not** a plugin under `src/agent_latch/gates/`. That package holds
plugins the importer loads per event; verification is a whole-file question, asked after a run and
answered by the report.

## Design choices you may want to revisit

| Choice | Why | Cost |
|---|---|---|
| Separate ledger file, not extra fields in the trace | The trace format stays stable and redacted; the chain can be verified or thrown away independently | Two files to keep together |
| One block per trace record | Any single record can be named precisely in a report | ~340 B per record |
| SHA-256, no signatures | Standard library only, nothing to manage | An attacker who controls the anchor path can forge everything; use a write-once destination |
| Anchoring is a manual command | The first version does not pretend to know where your trusted storage is | Someone must schedule it |
| Ambiguity fails closed | A record that cannot be parsed is `tampered`, not skipped | A crashed mid-write needs one truncation, not a silent pass |

The measured cost is small: about 0.7 ms of CPU to verify 1,000 records, and roughly 4 % on top of
the trace write. See [ledger-operations.md](ledger-operations.md) for the numbers and the
operational work that actually matters.
