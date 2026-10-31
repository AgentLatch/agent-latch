# Running the audit ledger: cost, schedule, retention, incidents

The ledger is cheap to run and easy to get wrong operationally. This page is the runbook: what it
costs, how often to anchor, how to retire old logs, and exactly what to do when verification fails.
Background in [ledger.md](ledger.md); setup in [ledger-setup.md](ledger-setup.md); formats in
[ledger-reference.md](ledger-reference.md).

## What it costs

Measured on a current laptop with this repository's own `TraceLog`, one tool call (request plus
response):

| Quantity | Measured |
|---|---|
| Trace record, request | ≈ 370 B |
| Trace record, response (200-char excerpt) | ≈ 610 B |
| Ledger block | ≈ 340 B |
| Appending one block (hash + write + flush) | ≈ 16 µs |
| Verifying 1,000 records | ≈ 0.9 ms |
| Verifying 100,000 records | ≈ 90 ms |

At 10,000 tool calls a day that is about 10 MB of trace, 7 MB of ledger, and 14 ms of CPU for the
whole day. There is no GPU, no model call, no database, no extra process, and no network. The ledger
runs inside the proxy you already run.

What it does not include:

- **Payload capture.** `--payloads` stores full arguments and outputs, masked. That is 10–100× the
  trace and the only part that grows without a bound. It is off by default for that reason.
- **Verification memory.** About 1 KiB per record, because the verifier loads the file.
- **The human work.** Choosing an anchor destination, owning the credentials, and answering an
  alert. That is the real budget, and it is measured in attention, not CPU.

## Cadence

Two separate schedules, often confused:

| Job | How often | What it protects |
|---|---|---|
| `proxy --ledger` | Always on | Every record, as it happens |
| `anchor` | Every session, or hourly/daily | The window in which a **full rewrite** can hide |
| `verify` | Same cadence as `anchor`, plus on demand | Detection of edits, deletions and rewrites |

The anchoring interval is your exposure window. If you anchor once a day, an attacker who rebuilds
the whole log has up to a day of "clean" history before the mismatch appears — and only at the next
anchor. A short interval costs one tiny append, so anchor as often as your destination comfortably
allows.

A reasonable default:

- laptop or single-user agent: anchor at the end of each session;
- long-running service: hourly;
- anything you would show a regulator, a customer or a court: every 15 minutes, and keep the anchor
  file in storage the service account cannot write.

## Retention and rotation

Nothing expires. The chain makes deletion **visible**, not automatic.

**Rotate per session or per day.** One ledger per run keeps files small and verification fast, and
makes "which run was altered" unambiguous:

```sh
agent-latch-runtime proxy \
  --trace "runtime-logs/$(date -u +%Y-%m-%d).jsonl" \
  --ledger "runtime-logs/$(date -u +%Y-%m-%d).ledger.jsonl" \
  -- <server command>
```

Name the pair `X.jsonl` and `X.ledger.jsonl`. `verify PATH` and `verify FOLDER` find a ledger's
trace by that rule, and report a trace they cannot find as `deleted`.

A ledger can also be resumed: run the proxy again against the same file and it continues from the
last block. Use that for a long-lived service.

**Retiring a pair.** Archive, do not delete:

1. verify and keep the output;
2. keep `trace.jsonl`, `trace.ledger.jsonl`, and the anchor line that covers its final head;
3. move all three to long-term storage together, named the same way;
4. only then remove them from the active folder.

Deleting or emptying the ledger does not hide anything: a later `verify` reports `deleted` (exit
`1`) when the anchor file or the trace shows records existed, and `missing` only when nothing does.
It does remove your ability to answer questions. If the anchor and the trace go too, nothing is
left to compare, which is why the anchor must live where the agent cannot write.

**Live checks and archived sessions.** Point routine checks at the live ledger, or at the live
folder without `--all`. `verify runtime-logs` looks only at ledgers directly in that folder, so
an archived session (for example one moved to `runtime-logs/archive/<date>-<time>/`) is not part
of it. `verify runtime-logs --all` searches subfolders too, which includes every archive: use it
to audit old sessions on purpose, and read its results as history. One altered archived session
makes that run exit `1`, so do not use `--all` as the pass/fail check for the current session.
Each session needs its own ledger and trace; pairing an old ledger with a new trace reports
false `deleted` results.

**Backups.** Back the three files up as one unit. Restoring a trace without its ledger produces
`deleted` (trace lines no block sealed); restoring a ledger without its trace produces `deleted`
(blocks whose lines are gone). That is the intended behaviour — a partial restore is a partial
record.

## Custody

| Thing | Who should hold it |
|---|---|
| Trace and ledger | The account running the agent — it must be able to write them |
| Anchor destination | **Not** that account. A different machine, a different bucket, a human |
| The `verify` schedule | Ideally something that also cannot edit the files |
| The report | Whoever reviews the agent's behaviour |

The one rule: **if the agent's account can write the anchor, the anchor proves nothing.** A
write-once bucket or a separate host is enough. It does not need to be exotic.

## Routine checks

```sh
# daily, cron, or in CI
agent-latch-runtime verify \
  --ledger /srv/agent/runtime-logs/trace.ledger.jsonl \
  --trace /srv/agent/runtime-logs/trace.jsonl \
  --anchor /mnt/audit/anchors.jsonl

# or, without an anchor, every ledger in the live folder (archives are not included)
agent-latch-runtime verify /srv/agent/runtime-logs
```

Alert on **exit 1**. Also alert on exit **2** at least once per deployment: a path typo should not
present as a clean run. Treat `UNANCHORED` as a configuration warning, not a pass.

## When verification fails

Work the verdict, then the issue list. Do not fix the file first — you will destroy the evidence.

**Step 1 — freeze, do not repair.** Stop writing to the pair if you can (stop the proxy). Copy
`trace.jsonl`, `trace.ledger.jsonl` and the anchor file to a read-only place. Never run anything
that rewrites the ledger: `reseal` and `rewrite` exist for tests, and using them on evidence is
destroying it.

**Step 2 — record what it said.** Save the exact output and the exit code, and hash the files so
later copies can be shown to be the same:

```sh
agent-latch-runtime verify --ledger trace.ledger.jsonl --trace trace.jsonl \
  --anchor anchors.jsonl > verify.txt 2>&1; echo "exit=$?" >> verify.txt
shasum -a 256 trace.jsonl trace.ledger.jsonl anchors.jsonl >> verify.txt
```

**Step 3 — classify.** The verdict tells you what kind of event this is.

| Verdict | Read it as | Usual causes |
|---|---|---|
| `tampered` | A record was changed after it was sealed | Deliberate edit; a tool that rewrote the file; a bad merge of two logs |
| `deleted` | Records are missing | Deliberate removal; a rotated or truncated trace; a partial restore; a crash mid-write |
| `rewritten` | The whole log was rebuilt | Deliberate forgery; restoring an older genuine copy; pointing at the wrong ledger |
| `missing` | Nothing to check | Wrong path; a run without `--ledger`; the file was moved or deleted |
| `unanchored` | Nothing outside confirms the file | No `--anchor` supplied; the anchor file is empty or on another host |

**Step 4 — separate accident from intent.** Accident is common and usually obvious:

- the trace was rotated but the ledger was not (or the reverse);
- the process was killed mid-write, leaving one partial last line;
- a backup restore brought back one file and not the other;
- the clock jumped, so timestamps look odd but the chain is fine (timestamps are not validated).

Intent looks like this: a `seq` gap with no matching operational change; an edited field inside a
block whose neighbours are untouched; a head that matches a *different* anchor; a trace that is
missing exactly the records around a sensitive tool call.

**Step 5 — escalate with the artefacts, not a summary.** Hand over the three files, `verify.txt`,
and the anchor line. Anyone can re-run the check independently; that is the point of the design.

**Step 6 — start clean, deliberately.** After an incident, do not append to the old ledger. Keep it,
and start a new pair with a new anchor file (or continue the same anchor file, which will refuse a
backwards `seq` — that refusal is your cue that you are looking at two different logs).

## Starting over on purpose

If you genuinely need a fresh log — a new machine, a rebuilt agent, a test environment — do it
explicitly, so it does not look like tampering later:

1. verify the old pair one last time and archive the output;
2. archive trace, ledger and anchor line together;
3. start a new ledger file (a new name, e.g. `2026-10-29.ledger.jsonl`);
4. optionally point the new ledger at a new anchor file, or keep the old one and accept that its
   `seq` history refers to the previous log.

Never delete the old anchor file to "reset" a refusal. That is exactly the operation the design is
trying to make impossible to do quietly.

## Framing it honestly

`ALR15` maps to `ASI10` (Rogue Agents) and the gate lists `EU AI Act Art. 12` (record-keeping) as an
informational reference. Neither is a compliance claim:

- the mapping is editorial, not a certification;
- `intact` proves the log was not changed after recording, not that the agent behaved;
- `unanchored` means exactly what it says, and should not be reported as "verified";
- keeping records is not the same as keeping *adequate* records — that judgement is yours.

Link to the OWASP publication rather than quoting it: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>.
