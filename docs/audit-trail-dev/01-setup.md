# 01 · Setup

## Environment

Python 3.11 or newer. Use a virtual environment outside the repository if you like; `.venv` inside it
is already ignored by git.

```sh
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev,runtime]"
```

`[runtime]` installs the pinned FastMCP, which the proxy tests and test 7 (the agent path) need. Without
it those tests skip; everything else still runs.

## Branch

Never work on `main`.

```sh
git fetch origin main
git switch --no-track -c feat/append-only-audit-store origin/main
```

## Baseline first

Before you change anything, prove the tree is green, so a failure later is yours and not inherited.

```sh
python -m pytest -q
ruff check .
agent-latch scan . --fail-on high --project-ignores --plain
```

All three must pass. The self-scan prints a few low-severity findings (the repo's own fixtures); it must
exit `0`. If you add a fixture that the scanner flags, add it to `.agent-latch-ignore` with a comment;
never weaken a rule.

## Try the feature by hand

This is the fastest way to see what the code does. It writes only to a scratch folder.

```sh
mkdir /tmp/audit-try && cd /tmp/audit-try
agent-latch-runtime demo --dir logs                       # records a synthetic MCP session
agent-latch-runtime import-logs --dir logs --database demo.db --anchor demo.anchor --once --quiet
agent-latch-runtime verify --database demo.db --anchor demo.anchor     # AUDIT TRAIL INTACT, exit 0
```

Now attack it the way an agent with the file could, and watch each attack get named:

```sh
cp demo.db tamper.db
python -I -c "
import sqlite3; c = sqlite3.connect('tamper.db')
c.execute('DROP TRIGGER events_no_update')                      # the careless guard is easy to remove
c.execute(\"UPDATE events SET name = 'evil' WHERE event_order = 2\")
c.commit()"
agent-latch-runtime verify --database tamper.db --anchor demo.anchor    # TAMPERED, #2, exit 1
agent-latch-runtime import-logs --dir logs --database tamper.db --anchor demo.anchor --once --quiet   # refused, exit 1
cd -                                                                    # back to the repository
```

## The second-user test (test 8)

Test 8 proves the operating system, not AgentLatch, blocks another user. How it runs depends on who you
are:

| You are | What happens |
|---|---|
| root (a container, a sandbox) | The test runs the "agent" as `nobody` with `subprocess.run(user=…)`. No setup |
| An ordinary user | The test **skips** unless you name a second user: `AGENTLATCH_SECOND_USER=<user>` and passwordless `sudo -n -u <user>` |
| CI | The workflow creates `agentlatch-agent`, sets `AGENTLATCH_SECOND_USER` and `AGENTLATCH_REQUIRE_SECOND_USER=1` so a missing user **fails** instead of skipping |

To run it on your own machine (Linux):

```sh
sudo useradd --create-home --shell /usr/sbin/nologin agentlatch-agent
AGENTLATCH_SECOND_USER=agentlatch-agent python -m pytest tests/test_audit_store.py -k second_os_user -v
```

On macOS the equivalent is `sudo sysadminctl -addUser …`, and the test only proves the file permissions
of the machine you run it on. It cannot prove how Docker Desktop shows a mounted host folder; check that
by hand (see [04](04-debugging-and-fixing.md#docker-desktop-and-mounted-folders)).

## Docker

The runtime image runs as user `10001` with `/data` as its working directory. To smoke-test the sealed
store inside it (what `images.yml` does), with Docker running:

```sh
docker build --target runtime -t agent-latch-runtime:test .
docker run --rm --entrypoint sh agent-latch-runtime:test -c '
  agent-latch-runtime demo >/dev/null 2>&1
  agent-latch-runtime import-logs --dir runtime-logs/demo --database demo.db --anchor demo.anchor --once --quiet
  agent-latch-runtime verify --database demo.db --anchor demo.anchor'
```

If you change dependencies in `pyproject.toml`, run `scripts/update-docker-locks.sh` and commit
`docker/requirements-*.txt`. This work adds none.
