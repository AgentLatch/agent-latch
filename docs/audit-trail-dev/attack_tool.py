"""Send write statements to the read-only audit tool the way an MCP client would, and report each result.

This is the deterministic version of the agent test. A model may decline to try a deletion, and its
refusal proves nothing about the store. This client has no judgment to apply: it opens the same
`docker run -i ... audit-tool` session Claude Desktop uses and sends the statements. Every write must
be refused, and the row count must not change.

Run it with a Python that has the runtime extra (the repo's .venv), from the repository root:

    .venv/bin/python docs/audit-trail-dev/attack_tool.py                      # store in a Docker volume
    .venv/bin/python docs/audit-trail-dev/attack_tool.py --local ~/audit-demo/audit.db   # a local file

Docker settings: --docker (path to the docker command), --image, --volume. With --local the tool
is started from this Python (``agent-latch-runtime audit-tool``) against that file instead, which
needs no Docker. Exit code 0 when every write was refused and the count is unchanged, 1 otherwise.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

ATTACKS = [
    "DELETE FROM events",
    "DELETE FROM events WHERE name = 'fetch'",
    "UPDATE events SET name = 'x'",
    "INSERT INTO events (run_id, event_order) VALUES ('forged', 1)",
    "REPLACE INTO events (run_id) VALUES ('forged')",
    "DROP TABLE events",
    "DROP TRIGGER events_no_update",
    "ALTER TABLE events ADD COLUMN notes TEXT",
    "CREATE TABLE evil (x)",
    "WITH x AS (SELECT 1) DELETE FROM events",
    "SELECT 1; DELETE FROM events",
    "PRAGMA query_only = OFF",
    "PRAGMA writable_schema = 1",
    "ATTACH DATABASE '/tmp/other.db' AS other",
    "VACUUM INTO '/tmp/copy-of-audit.db'",
    "SELECT load_extension('anything')",
    "BEGIN",
]


def docker_transport(docker: str, image: str, volume: str) -> StdioTransport:
    """The tool in its own container: no network, read-only filesystem, store mounted read-only."""
    return StdioTransport(
        command=docker,
        args=[
            "run", "-i", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges", "-v", f"{volume}:/data:ro", image,
            "audit-tool", "--database", "/data/audit.db",
        ],
    )


def local_transport(database: Path) -> StdioTransport:
    """The same tool, started from this Python against a store on this machine."""
    return StdioTransport(
        command=sys.executable,
        args=["-m", "agent_latch.runtime.cli", "audit-tool", "--database", str(database)],
    )


async def run(transport: StdioTransport) -> int:
    """Send every statement through the tool and report each result; 0 only if all were refused."""
    count_sql = "SELECT COUNT(*) AS n FROM events"
    async with Client(transport) as client:
        print("tools:", sorted(tool.name for tool in await client.list_tools()))
        before = (await client.call_tool("query_audit_log", {"sql": count_sql})).content[0].text
        print("rows before:", before)
        recent = await client.call_tool("recent_events", {"limit": 3})
        print("newest events:", recent.content[0].text[:300])
        succeeded = 0
        for number, sql in enumerate(ATTACKS, 1):
            result = await client.call_tool("query_audit_log", {"sql": sql}, raise_on_error=False)
            succeeded += not result.is_error
            verdict = "REFUSED  " if result.is_error else "SUCCEEDED"
            print(f"{number:>2} {verdict} {sql[:56]:56} {result.content[0].text[-40:]}")
        after = (await client.call_tool("query_audit_log", {"sql": count_sql})).content[0].text
        print("rows after: ", after)
    ok = succeeded == 0 and before == after
    print(f"\n{'PASS' if ok else 'FAIL'}: {succeeded} of {len(ATTACKS)} write attempts succeeded;"
          f" rows {before} -> {after}")
    return 0 if ok else 1


def main() -> int:
    """Parse the command line, pick the Docker or local transport, and run the attacks."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--local", type=Path, metavar="FILE",
                        help="a store on this machine, instead of a Docker volume")
    parser.add_argument("--docker", default="docker", help="path to the docker command")
    parser.add_argument("--image", default="agent-latch-runtime:local")
    parser.add_argument("--volume", default="agentlatch-data", help="volume that holds audit.db")
    args = parser.parse_args()
    if args.local is not None:
        return asyncio.run(run(local_transport(args.local)))
    return asyncio.run(run(docker_transport(args.docker, args.image, args.volume)))


if __name__ == "__main__":
    sys.exit(main())
