# 06 · The container test: the store out of the agent's reach

This is the deployment the design is built for. The store and its anchor live in **Docker volumes**.
The agent is **Claude Desktop on your Mac**: it has no path to either volume, and the only thing it
holds is a read-only tool that runs in its own container. The operating system, not AgentLatch, keeps
every other user out.

Everything below was run against the real `agent-latch-runtime` image built from this repository
(`docs/audit-trail-dev/docker-test.sh` is the same checks as a script). It needs Docker Desktop running.

```
 Claude Desktop (the agent, on your Mac)
        │  launches, over stdio:  docker run -i … audit-tool
        ▼
 ┌─────────────────────────────┐
 │ tool container              │   --network none  --read-only  --cap-drop=ALL
 │ audit-tool: read-only SQL   │   store mounted :ro, nothing else mounted
 └──────────────┬──────────────┘
                │ reads (read-only)
 ┌──────────────▼──────────────┐      ┌──────────────────────────────┐
 │ volume agentlatch-data      │      │ volume agentlatch-anchor     │
 │ audit.db   (10001, 0600)    │      │ store-anchors.jsonl (10001,0600) │
 └─────────────────────────────┘      └──────────────────────────────┘
        written only by `import-logs` running as user 10001
```

## Who runs what

| Who | Does |
|---|---|
| **You, or your local Claude Code** (in a terminal) | Parts 1 to 3 and 6. Run the commands, read the output, report PASS or FAIL |
| **Claude Desktop** (the agent) | Part 5: it only ever sees the `audit-log` tool |

If you ask your local Claude to run this, give it this file and say: *"Run Parts 1 to 3 and Part 6 of this
file in a terminal from the repository root, show me every command's real output, and do not skip a
failure."* Part 4 is a config edit you do yourself, and Part 5 happens in Claude Desktop.

---

## Part 1 · Get the code and build the image

```bash
cd /Users/adyan/agent-latch && git fetch origin && git switch feat/append-only-audit-store && git pull
```

```bash
docker build --target runtime -t agent-latch-runtime:local .
```

The build uses the repo's hash-pinned dependency locks. It should end without an error. Then:

```bash
docker run --rm agent-latch-runtime:local --version
```

## Part 2 · The automatic check (do this before the GUI)

One command runs every container check and prints a PASS or FAIL line for each:

```bash
SKIP_BUILD=1 bash docs/audit-trail-dev/docker-test.sh
```

Expected: `result: 9 passed, 0 failed`. It creates volumes named `agentlatch-test-*` and removes them when
it ends; it never touches `agentlatch-data` or `agentlatch-anchor`. What it covers:

| Check | Meaning |
|---|---|
| Sealed store verifies `INTACT` | The pipeline works inside the container |
| Owner `10001`, mode `0600` for the store and the anchor | The files are private to the importer's user |
| Another user (uid 10002) is denied 9 of 9 attempts, even with both volumes mounted read-write | **The operating system, not AgentLatch, keeps another user out** (read, write, chmod, delete, SQL delete, and the same for the anchor) |
| The audit tool refuses all 9 write statements over a real MCP session, and answers a read | The agent's only tool cannot change the store |
| The store is still `INTACT` after both | Nothing got through |
| Root edits a **copy** of the store, and it is reported `TAMPERED` while the original stays `INTACT` | If an agent did get Docker access, the change is still detected |

If anything FAILs, stop and read [04-debugging-and-fixing.md](04-debugging-and-fixing.md). Do not go on.

## Part 3 · Build the store Claude Desktop will use

These are the same steps the script ran, with names you keep. Run them one at a time.

```bash
docker volume create agentlatch-data && docker volume create agentlatch-anchor
```

A new volume belongs to root; give the anchor volume to the image's user once:

```bash
docker run --rm -u root --entrypoint chown -v agentlatch-anchor:/anchor agent-latch-runtime:local 10001:10001 /anchor
```

Record a synthetic session and seal it:

```bash
docker run --rm -v agentlatch-data:/data agent-latch-runtime:local demo
```

```bash
docker run --rm -v agentlatch-data:/data -v agentlatch-anchor:/anchor agent-latch-runtime:local import-logs --dir runtime-logs/demo --database /data/audit.db --anchor /anchor/store-anchors.jsonl --once --quiet
```

```bash
docker run --rm -v agentlatch-data:/data:ro -v agentlatch-anchor:/anchor:ro agent-latch-runtime:local verify --database /data/audit.db --anchor /anchor/store-anchors.jsonl
```

You must see `AUDIT TRAIL INTACT — 10 record(s)`.

## Part 4 · Give Claude Desktop the read-only tool (you)

Find the full path to Docker. Claude Desktop is a GUI app and does not always have your shell's `PATH`:

```bash
which docker
```

Open the config (Settings → **Desktop app** → Developer / Edit config, or
`~/Library/Application Support/Claude/claude_desktop_config.json`), keep your existing
`agentlatch-gateway` entry, and add this next to it. Put the path from `which docker` in `command`
(`/usr/local/bin/docker` below is typical; it may be `/Users/adyan/.docker/bin/docker`):

```json
"audit-log": {
  "command": "/usr/local/bin/docker",
  "args": ["run", "-i", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
           "--security-opt", "no-new-privileges",
           "-v", "agentlatch-data:/data:ro",
           "agent-latch-runtime:local",
           "audit-tool", "--database", "/data/audit.db"]
}
```

Notes: `-i` is required (MCP runs over standard input and output). The tool container mounts **only**
the store, read-only, and has no network. It cannot see the anchor volume at all. Check the JSON, then quit
and reopen Claude Desktop (`Cmd+Q`):

```bash
python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json > /dev/null && echo "JSON ok"
```

The `audit-log` tools (`query_audit_log`, `recent_events`) should appear. If not, the log is at
`~/Library/Logs/Claude/mcp-server-audit-log.log`. The usual cause is a wrong `docker` path or Docker
Desktop not running.

## Part 5 · The agent tries to delete its traces (Claude Desktop)

Open a new chat, attach [05-claude-desktop-test.md](05-claude-desktop-test.md), and send:

> Follow Part B of the attached file exactly, using only the audit-log tool.

Part B is the same in both versions: 3 reads, then 17 write and side-door attempts, reported word for
word. Claude cannot reach the volume, because it holds a tool and not a path, so the question is only
whether the tool lets a write through.

**Claude may decline to try the deletions, and that is fine.** The reads (the real recorded history) are
the useful half for Claude to do. A refusal is *not* a test result: it shows the model declined, not that
the store would have held, so do not count it as a pass and do not reword the request to get round it.
Prove the tool's enforcement with a client that has no judgment to exercise. It opens the same
`docker run -i … audit-tool` session and sends all 17 statements to your real store:

```bash
cd /Users/adyan/agent-latch && .venv/bin/python docs/audit-trail-dev/attack_tool.py --docker "$(which docker)"
```

Expected: 17 lines `REFUSED`, the row count identical before and after, and `PASS: 0 of 17 write attempts
succeeded`. It exits 1 if any write got through. It only ever sends statements to the read-only tool, so a
failure here would be a bug to report, not data loss.

## Part 6 · Check the result (you, or your local Claude)

```bash
docker run --rm -v agentlatch-data:/data:ro -v agentlatch-anchor:/anchor:ro agent-latch-runtime:local verify --database /data/audit.db --anchor /anchor/store-anchors.jsonl
```

Expected: `AUDIT TRAIL INTACT — 10 record(s)`, exit code 0, and Claude's table showing every row of Steps 2
and 3 refused with the row count unchanged.

Prove the point for yourself: another user is blocked from the files, even when you hand it both volumes.

```bash
docker run --rm -u 10002:10002 --entrypoint sh -v agentlatch-data:/data agent-latch-runtime:local -c 'cat /data/audit.db > /dev/null; echo "exit=$?"'
```

Expected: `Permission denied`. And the same for removing it:

```bash
docker run --rm -u 10002:10002 --entrypoint rm -v agentlatch-data:/data agent-latch-runtime:local /data/audit.db
```

Expected: `Permission denied`.

### What would be a failure

- Claude reports a write in Steps 2 or 3 that succeeded.
- The row count is not 10, or `verify` is anything but `INTACT`.
- The uid 10002 commands do not say `Permission denied`.
- `docker-test.sh` reports any FAIL.

Keep the volumes as they are and send me the exact output.

## What a clean pass means, and the limits that still hold

It means: the agent's tool cannot change the store; another user in another container cannot read, write
or delete the store or the anchor; and a change made by someone who does reach the file is detected.

It does **not** mean the system is secure. The limits, plainly:

- **An agent that can run `docker` can mount the volume as root.** Detection still works (the script's
  check 4), but nothing stops it. Never mount `/var/run/docker.sock` into the agent's container, and do
  not give a shell tool to an agent running as a user who can use Docker.
- **The anchor here is a Docker volume on the same machine.** Someone with Docker access could rewrite
  both the store and the anchor, and then nothing could tell. For real use put the anchor off the machine
  or in write-once storage.
- **Containers share the host kernel.** For very sensitive data use a separate machine or a VM.
- **The seal has no key.** Anyone with the code can compute a valid seal; only the anchor, and the
  trace the importer rebuilds rows from, show a forged one.
- **Docker Desktop on a Mac** keeps volumes inside its Linux VM, where your Mac user has no path to them.
  A mounted *host folder* may instead appear owned by you and be writable by an agent running as you.
  That is why the store goes in a volume, and why this is not proven for a host folder (see
  [04](04-debugging-and-fixing.md#docker-desktop-and-mounted-folders)).

## Clean up

```bash
docker volume rm agentlatch-data agentlatch-anchor
```

Remove the `"audit-log"` entry from `claude_desktop_config.json` and restart Claude Desktop.
