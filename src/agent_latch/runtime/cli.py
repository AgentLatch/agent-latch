"""``agent-latch-runtime`` command line (preview, monitor only: ``proxy``, ``import-logs``,
``demo``)."""

from __future__ import annotations

import argparse
import io
import ipaddress
import logging
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from rich_argparse import RawDescriptionRichHelpFormatter

from agent_latch import __version__
from agent_latch.runtime.autoimport import import_run
from agent_latch.runtime.connectors import (
    ConnectorConfigError,
    installed_connectors,
    load_connectors,
    parse_connector_settings,
)
from agent_latch.runtime.importer import (
    RuntimeLogImporter,
    discover_gates,
    load_policy,
    unknown_policy_keys,
)
from agent_latch.runtime.ledger import (
    Ledger,
    LedgerError,
    describe,
    make_anchor,
    point_for,
    verify_ledger,
)
from agent_latch.runtime.ledger.anchor import AnchorError
from agent_latch.runtime.ledger.event_seal import (
    SOURCE,
    StoreIntegrityError,
    downgrade_issues,
    downgrade_verdict,
    is_sqlite_file,
    verify_store,
)
from agent_latch.runtime.ledger.report import format_summary_table
from agent_latch.runtime.ledger.verify import (
    STATUS_MISSING,
    find_ledgers,
    trace_for,
)
from agent_latch.runtime.payloads import DEFAULT_PAYLOAD_MAX_CHARS, PayloadFile, PayloadTap
from agent_latch.runtime.sqlite_store import (
    SQLiteEventReader,
    SQLiteEventStore,
    stored_schema_version,
)
from agent_latch.runtime.store_check import check_store
from agent_latch.runtime.trace import DEFAULT_EXCERPT_CHARS, TraceLog

DEFAULT_LOG_DIR = "runtime-logs"

_EPILOG = """\
[bold bright_cyan]EXAMPLES:[/bold bright_cyan]
  [cyan]agent-latch-runtime proxy -- npx -y @modelcontextprotocol/server-github[/cyan]   (trace + ledger in ~/agent-latch/runtime-logs/NAME/TIMESTAMP)
  [cyan]agent-latch-runtime import-logs --dir ~/agent-latch/runtime-logs/server-github/20261122-074500 --once[/cyan]
  [cyan]agent-latch-runtime proxy --trace trace.jsonl -- npx -y @modelcontextprotocol/server-github[/cyan]
  [cyan]agent-latch-runtime proxy --http 127.0.0.1:8770 --upstream-url https://tools.example.com/mcp[/cyan]
  [cyan]agent-latch-runtime proxy --trace t.jsonl --ledger t.ledger.jsonl -- npx -y @modelcontextprotocol/server-github[/cyan]
  [cyan]agent-latch-runtime anchor --ledger t.ledger.jsonl --to ~/offbox/anchors.jsonl[/cyan]
  [cyan]agent-latch-runtime verify --ledger t.ledger.jsonl --anchor ~/offbox/anchors.jsonl[/cyan]
  [cyan]agent-latch-runtime verify runtime-logs/trace.ledger.jsonl[/cyan]   (path only: trace found beside it)
  [cyan]agent-latch-runtime verify runtime-logs/ --all[/cyan]   (every ledger below a folder)
  [cyan]agent-latch-runtime import-logs --database events.db --anchor ~/offbox/store-anchors.jsonl[/cyan]
  [cyan]agent-latch-runtime verify --database events.db --anchor ~/offbox/store-anchors.jsonl[/cyan]
  [cyan]agent-latch-runtime anchor --database events.db --to ~/offbox/store-anchors.jsonl[/cyan]
  [cyan]agent-latch-runtime import-logs --connector pg=postgres --connector-option pg.dsn=env:PG_DSN[/cyan]
  [cyan]agent-latch-runtime connectors[/cyan]   (list installed connector types; nothing is loaded)
  [cyan]agent-latch-runtime demo[/cyan]   (try it with a synthetic server, no setup)

In an MCP config, put [cyan]agent-latch-runtime[/cyan] as the command and move the real server
command after [cyan]--[/cyan] in "args".

[dim]Preview, monitor only: records tool lists, tool calls, tool results and prompts routed
through the proxy, and never changes or blocks them. It sees only traffic sent through it.[/dim]
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-latch-runtime",
        description="AgentLatch runtime checks for MCP tool traffic (preview).",
        formatter_class=RawDescriptionRichHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="subcommand", required=True)

    proxy = commands.add_parser(
        "proxy",
        help="run one MCP server (or several remote ones) behind AgentLatch and record its traffic",
        description=(
            "Run one MCP server behind AgentLatch and record its traffic (monitor only). With"
            " --http, repeat --upstream-url NAME=URL to front several remote servers in one proxy:"
            " each is served at /mcp/NAME, and all of them write to the same trace, payloads and"
            " ledger. Several servers must be remote URLs; a server started from a command needs"
            " its own proxy."
        ),
        epilog=_EPILOG,
        formatter_class=RawDescriptionRichHelpFormatter,
    )
    proxy.add_argument(
        "--upstream-url",
        action="append",
        default=[],
        metavar="[NAME=]URL",
        help="proxy a remote MCP server at URL. Repeat it with a NAME= on each (NAME is"
        " [a-z0-9_-], up to 32 characters) to front several servers with --http: each is served"
        " at /mcp/NAME and recorded with that name as its server",
    )
    proxy.add_argument(
        "--http",
        metavar="HOST:PORT",
        help="serve the proxy over HTTP on a loopback address instead of stdio",
    )
    proxy.add_argument("--name", help="server name used in the trace (default: from the command)")
    proxy.add_argument(
        "--trace",
        type=Path,
        metavar="FILE",
        help="append trace records (JSONL). Default: trace.jsonl in this run's folder"
        " (see --log-dir)",
    )
    proxy.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="root folder for the default trace and ledger. Each run gets its own folder,"
        " DIR/NAME/YYYYMMDD-HHMMSS (UTC), printed at startup. Default: agent-latch/runtime-logs in"
        " your home folder, so the files do not depend on where the proxy was started. Read a run"
        " back with `import-logs --dir <that folder>`",
    )
    proxy.add_argument(
        "--no-trace",
        action="store_true",
        help="do not record a trace (and so no ledger). Nothing is then available to import",
    )
    proxy.add_argument(
        "--excerpt-chars",
        type=int,
        default=DEFAULT_EXCERPT_CHARS,
        metavar="N",
        help=f"redacted output excerpt length in the trace, 0 for none (default {DEFAULT_EXCERPT_CHARS})",
    )
    proxy.add_argument(
        "--payloads",
        type=Path,
        metavar="FILE",
        help="append intercepted payloads (JSONL): argument values, tool output and tool"
        " definitions, secret-masked; the file is sensitive. Off unless set",
    )
    proxy.add_argument(
        "--record-payloads",
        action="store_true",
        help="same as --payloads, with the file in this run's folder (payloads.jsonl beside the"
        " trace), where `import-logs --dir` finds it. The file is sensitive. Off unless set",
    )
    proxy.add_argument(
        "--payload-max-chars",
        type=int,
        default=DEFAULT_PAYLOAD_MAX_CHARS,
        metavar="N",
        help=f"cut each string in --payloads to N characters (default {DEFAULT_PAYLOAD_MAX_CHARS})",
    )
    proxy.add_argument(
        "--ledger",
        type=Path,
        metavar="FILE",
        help="seal every trace record into a hash chain (JSONL) so edits, deletions and rewrites"
        " are detectable; verify it later with `agent-latch-runtime verify`. Default: beside the"
        " trace, as TRACE.ledger.jsonl",
    )
    proxy.add_argument(
        "--no-ledger",
        action="store_true",
        help="do not seal the trace into a ledger (the trace is still recorded)",
    )
    proxy.add_argument(
        "--no-import",
        action="store_true",
        help="do not import the run when the proxy stops. By default the run's logs are turned"
        " into events.csv, gate-results.csv and gate-results.sarif in the run folder, and the"
        " path and a summary are printed (the same as `import-logs --once`)",
    )
    proxy.add_argument("--quiet", action="store_true", help="no per-message summary on stderr")
    proxy.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="the real MCP server command, after --",
    )

    importer = commands.add_parser(
        "import-logs",
        help="turn the proxy's trace and payload logs into events (and gate results)",
        description=(
            "Follow the proxy's trace (and payloads) files, join each message into one normalized"
            " event, print it, append it to an events CSV, and run every installed gate on it."
            " Name the run to import with --dir: the proxy writes each run to its own folder"
            " (~/agent-latch/runtime-logs/NAME/YYYYMMDD-HHMMSS by default) and prints it. Pointing"
            " --dir at a folder of runs lists them and exits 2; nothing is guessed."
        ),
    )
    importer.add_argument(
        "--dir", type=Path, default=None, metavar="DIR",
        help="the run folder: the default input (trace.jsonl, payloads.jsonl) and output files"
        f" live here (default ./{DEFAULT_LOG_DIR}, where `demo` and older setups write)",
    )
    importer.add_argument(
        "--trace", type=Path, metavar="FILE",
        help="trace JSONL written by the proxy (--trace); default DIR/trace.jsonl",
    )
    importer.add_argument(
        "--payloads", type=Path, metavar="FILE",
        help="payloads JSONL written by the proxy (--payloads); default DIR/payloads.jsonl"
        " when --trace is not given; gates see payload null without it",
    )
    importer.add_argument(
        "--events-csv", type=Path, metavar="FILE",
        help="CSV with one row per event (default DIR/events.csv)",
    )
    importer.add_argument(
        "--output-csv", type=Path, metavar="FILE",
        help="CSV with one row per gate result, only written when gates are installed"
        " (default DIR/gate-results.csv)",
    )
    importer.add_argument("--quiet", action="store_true", help="no per-event line on stderr")
    importer.add_argument(
        "--normalized-out", type=Path, metavar="FILE",
        help="append the full normalized events: arguments, payload and response per event"
        " (default DIR/normalized.jsonl); the file is sensitive",
    )
    importer.add_argument(
        "--database", type=Path, metavar="FILE",
        help="also store the normalized events in this local SQLite file; it may hold payload data."
        " Off unless set. Nothing is uploaded",
    )
    importer.add_argument(
        "--anchor", type=Path, metavar="PATH",
        help="with --database: publish the newest seal here as the store grows, and refuse a store"
        " that no longer matches the newest point (exit 1). Keep this file where the agent"
        " cannot write. A new store creates the first point; a sealed store with no anchor is"
        " refused until `anchor --database` is run once",
    )
    importer.add_argument(
        "--policy", type=Path, metavar="FILE",
        help="operator policy (YAML or JSON) handed to the gates, for example"
        " allowed_secret_tools for ALR10. Trusted configuration: never a file from the monitored"
        " project",
    )
    importer.add_argument(
        "--connector", action="append", default=[], metavar="[NAME=]TYPE",
        help="send events to an installed connector (repeatable). NAME defaults to TYPE and lets"
        " you run two of one type. Nothing is loaded or sent unless you name it; list the"
        " installed types with `agent-latch-runtime connectors`",
    )
    importer.add_argument(
        "--connector-option", action="append", default=[], metavar="NAME.KEY=VALUE",
        help="a setting for a selected connector (repeatable). Write secrets as env:VARNAME, so the"
        " value is read from the environment and never appears on the command line or in output."
        " Every connector also takes payloads=true|false (default false), max_batch_events,"
        " max_pending_batches and timeout",
    )
    importer.add_argument(
        "--connector-config", type=Path, metavar="FILE",
        help="the same settings in a TOML file ([connectors.NAME] with type = \"...\"); options on"
        " the command line override it. Trusted configuration: never a file from the monitored"
        " project",
    )
    importer.add_argument("--run-id", help="run id for the events (default: hash of first trace line)")
    importer.add_argument(
        "--once", action="store_true",
        help="process what the files hold now and exit instead of following new lines",
    )

    commands.add_parser(
        "connectors",
        help="list the installed connector types (nothing is loaded or sent)",
        description=(
            "List the connector types installed in this Python environment, with the package and"
            " version that provides each. No connector is imported or started."
        ),
    )

    verify = commands.add_parser(
        "verify",
        help="check the audit ledger for edits, deletions and rewrites",
        description=(
            "Recompute the hash chain, compare each block with the trace line it sealed when"
            " --trace is given, and compare the head with the last published anchor when"
            " --anchor is given. Reads only; never writes. Give a ledger file, or a folder to"
            " check every *.ledger.jsonl in it (add --all to search subfolders too). With a"
            " path, the trace beside each ledger (x.ledger.jsonl seals x.jsonl) is compared"
            " automatically, and a missing trace is reported as deleted. Exit codes: 0 intact or"
            " unanchored, 1 altered, deleted, rewritten (or, for a folder, empty), 2 nothing to"
            " verify or a usage error. With --database, checks an event store's seals and schema"
            " the same way (see docs/ledger.md)."
        ),
    )
    verify.add_argument("path", nargs="?", type=Path, metavar="PATH",
                        help="a ledger file, or a folder holding ledgers")
    verify.add_argument("--ledger", type=Path, metavar="FILE",
                        help="the ledger written by proxy --ledger (same as giving it as PATH,"
                             " but the trace is only compared when --trace is given)")
    verify.add_argument("--database", type=Path, metavar="FILE",
                        help="verify the event store written by import-logs --database instead of"
                             " a ledger: every seal, the table layout, and (with --anchor) the"
                             " newest published point")
    verify.add_argument("--all", action="store_true",
                        help="with a folder: also search its subfolders")
    verify.add_argument("--trace", type=Path, metavar="FILE",
                        help="also compare every block with its trace line")
    verify.add_argument("--anchor", type=Path, metavar="PATH",
                        help="also compare the head with the newest anchor point in this file"
                             " (one ledger only: an anchor belongs to one ledger)")

    anchor = commands.add_parser(
        "anchor",
        help="publish the current ledger or event-store head to a file outside the agent's reach",
        description=(
            "Append one anchor point (sequence, digest, record count, time) for the current head"
            " of the ledger or event store. Put the file somewhere the agent cannot write: another"
            " host, a mounted share, or a bucket that syncs to write-once storage. For an event"
            " store the seals and schema are checked first, and a store that fails is not"
            " anchored (exit 1)."
        ),
    )
    target = anchor.add_mutually_exclusive_group(required=True)
    target.add_argument("--ledger", type=Path, metavar="FILE",
                        help="the ledger written by proxy --ledger")
    target.add_argument("--database", type=Path, metavar="FILE",
                        help="the event store written by import-logs --database")
    anchor.add_argument("--accept-unchecked-rows", action="store_true",
                        help="with --database: anchor rows added after the newest anchor point"
                             " without checking them against the logs. Only for a store you trust:"
                             " import-logs --anchor checks them first")
    anchor.add_argument("--to", type=Path, required=True, metavar="PATH",
                        help="where the anchor points go (appended, one JSON line each)")
    anchor.add_argument("--quiet", action="store_true", help="no confirmation on stderr")

    tool = commands.add_parser(
        "audit-tool",
        help="serve a read-only view of the event store to an agent over MCP (stdio)",
        description=(
            "Start an MCP server (stdio) with two tools, query_audit_log and recent_events, that"
            " can only read the event store written by import-logs --database. The connection is"
            " read-only and refuses every statement that is not a read. Run it where the agent"
            " cannot reach the store's file, for example in its own container with the store's"
            " volume mounted read-only. Needs the [runtime] extra. Exit 2 when the store is"
            " missing, not sealed yet, or newer than this AgentLatch."
        ),
    )
    tool.add_argument("--database", type=Path, required=True, metavar="FILE",
                      help="the event store written by import-logs --database")
    tool.add_argument("--name", default="audit-log", help="MCP server name (default audit-log)")

    demo = commands.add_parser(
        "demo",
        help="record a short synthetic MCP session through the proxy and import it",
        description=(
            "Run a bundled synthetic MCP server behind the proxy, make a few tool and prompt"
            " calls, then import the logs and print one line per event. Local only."
        ),
    )
    demo.add_argument(
        "--dir", type=Path, default=Path(DEFAULT_LOG_DIR) / "demo", metavar="DIR",
        help=f"folder for the demo's files, replaced on each run (default {DEFAULT_LOG_DIR}/demo)",
    )
    demo.add_argument(
        "--scenario", choices=("default", "poisoned-output", "secret-leak"), default="default",
        help="default: a mix of ordinary calls; poisoned-output: one web fetch whose result "
             "carries hidden and visible injection content for ALR05; secret-leak: sends a fake "
             "credential to a tool and reads one back so the ALR10 checks fire",
    )
    return parser


UPSTREAM_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
RESERVED_NAMES = frozenset({"mcp"})  # /mcp is where a single, unnamed upstream is served


def parse_upstreams(values: list[str]) -> tuple[str | None, dict[str, str]]:
    """``(url, {})`` for one bare URL, else ``(None, {name: url})``. Raises ``ValueError``.

    A value that starts with ``http://`` or ``https://`` is a URL, so an ``=`` in its query
    string is never read as a name. Anything else must be ``NAME=URL``.
    """
    bare: list[str] = []
    named: dict[str, str] = {}
    for value in values:
        if value.startswith(("http://", "https://")):
            bare.append(value)
            continue
        name, sep, url = value.partition("=")
        if not sep or not url.startswith(("http://", "https://")):
            raise ValueError(f"--upstream-url {value!r} must be a URL or NAME=URL")
        if not UPSTREAM_NAME.match(name):
            raise ValueError(
                f"--upstream-url name {name!r} must be 1 to 32 characters of [a-z0-9_-],"
                " starting with a letter or digit"
            )
        if name in RESERVED_NAMES:
            raise ValueError(f"--upstream-url name {name!r} is reserved")
        if name in named:
            raise ValueError(f"--upstream-url name {name!r} is used twice")
        named[name] = url
    if len(bare) == 1 and not named:
        return bare[0], {}
    if bare:
        raise ValueError("give every --upstream-url a NAME= when there is more than one")
    return None, named


def _default_name(command: list[str], upstream_url: str | None) -> str:
    if upstream_url:
        return urlparse(upstream_url).hostname or "upstream"
    # "npx -y @modelcontextprotocol/server-github" -> "server-github"; "python server.py" -> "server".
    words = [word for word in command[1:] if not word.startswith("-")] or command
    last = words[-1].replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[0] if "." in last else last


def _folder_name(name: str) -> str:
    """A server name as one safe folder name (no separators, no leading dots)."""
    cleaned = re.sub(r"[^a-z0-9_.-]+", "-", name.lower()).strip(".-")
    return cleaned[:64] or "proxy"


def default_log_root() -> Path:
    """``~/agent-latch/runtime-logs``: stable wherever an MCP client starts the proxy."""
    try:
        return Path.home() / "agent-latch" / "runtime-logs"
    except RuntimeError:  # no home folder can be determined
        return Path.cwd() / DEFAULT_LOG_DIR


def run_folder(root: Path, name: str, now: datetime | None = None) -> Path:
    """``root/NAME/YYYYMMDD-HHMMSS`` (UTC), never a folder that already exists."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d-%H%M%S")
    base = root / _folder_name(name)
    folder = base / stamp
    number = 2
    while folder.exists():
        folder = base / f"{stamp}-{number}"
        number += 1
    return folder


def _recording_paths(
    args: argparse.Namespace, name: str
) -> tuple[Path | None, Path | None, bool, bool]:
    """``(trace, ledger, trace_defaulted, ledger_defaulted)``. Raises ``ValueError``.

    The trace and the ledger are on unless ``--no-trace`` / ``--no-ledger`` say otherwise.
    """
    if args.no_trace and args.trace is not None:
        raise ValueError("--no-trace and --trace contradict each other")
    if args.no_ledger and args.ledger is not None:
        raise ValueError("--no-ledger and --ledger contradict each other")
    if args.no_trace and args.ledger is not None:
        raise ValueError("--ledger needs a trace to seal; remove --no-trace")
    if args.record_payloads and args.payloads is not None:
        raise ValueError("--record-payloads and --payloads contradict each other")
    if args.record_payloads and args.no_trace:
        raise ValueError("--record-payloads puts the file beside the trace; remove --no-trace")
    trace = None if args.no_trace else args.trace
    trace_defaulted = trace is None and not args.no_trace
    if trace_defaulted:
        trace = run_folder(args.log_dir or default_log_root(), name) / "trace.jsonl"
    ledger = args.ledger
    ledger_defaulted = trace is not None and ledger is None and not args.no_ledger
    if ledger_defaulted:
        stem = trace.name.removesuffix(".jsonl")
        ledger = trace.with_name(stem + ".ledger.jsonl")
    return trace, ledger, trace_defaulted, ledger_defaulted


def _parse_http(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"--http expects HOST:PORT, got {value!r}")
    host = host.strip("[]")
    if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
        # The preview listener has no authentication, so it must not be reachable from the network.
        raise ValueError("--http must use a loopback address such as 127.0.0.1")
    return host, int(port)


def _proxy(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        single_url, mounts = parse_upstreams(args.upstream_url)
    except ValueError as error:
        print(f"agent-latch-runtime: {error}", file=sys.stderr)
        return 2
    if bool(command) == bool(args.upstream_url):
        print("agent-latch-runtime: give the server command after --, or --upstream-url",
              file=sys.stderr)
        return 2
    if mounts and not args.http:
        print(
            "agent-latch-runtime: NAME=URL upstreams are served at /mcp/NAME, so they need --http",
            file=sys.stderr,
        )
        return 2
    if mounts and args.name:
        print("agent-latch-runtime: --name applies to a single unnamed upstream", file=sys.stderr)
        return 2
    try:
        http = _parse_http(args.http) if args.http else None
    except ValueError as error:
        print(f"agent-latch-runtime: {error}", file=sys.stderr)
        return 2
    try:
        from agent_latch.runtime.proxy import build_proxy
    except ImportError:
        print(
            "agent-latch-runtime: FastMCP is missing. Install AgentLatch with the runtime extra,"
            ' for example python -m pip install "agentlatch-security[runtime]" (see docs/runtime.md)',
            file=sys.stderr,
        )
        return 2

    # stdout carries the MCP protocol in stdio mode, so logging goes to stderr.
    logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
    name = args.name or (",".join(mounts) if mounts else _default_name(command, single_url))
    try:
        trace_path, ledger_path, trace_defaulted, ledger_defaulted = _recording_paths(args, name)
    except ValueError as error:
        print(f"agent-latch-runtime: {error}", file=sys.stderr)
        return 2

    def _warn(message: str) -> None:
        if not args.quiet:
            print(f"agent-latch-runtime: {message}", file=sys.stderr)

    ledger: Ledger | None = None
    if ledger_path is not None:
        try:
            ledger = Ledger(ledger_path)
        except (LedgerError, OSError) as error:
            if not ledger_defaulted:
                print(f"agent-latch-runtime: cannot open ledger file: {error}", file=sys.stderr)
                return 2
            # A default location must not stop the proxy: the server still works, unsealed.
            _warn(f"cannot open the default ledger {ledger_path} ({error}); not sealing."
                  " Pass --ledger FILE or --log-dir DIR, or --no-ledger to silence this")
    try:
        trace = TraceLog(
            trace_path,
            summary=None if args.quiet else sys.stderr,
            excerpt_chars=args.excerpt_chars,
            transport="http" if single_url or mounts else "stdio",
            ledger=ledger,
            warn=None if args.quiet else sys.stderr,
        )
    except OSError as error:
        if ledger is not None:
            ledger.close()
        if not trace_defaulted:
            print(f"agent-latch-runtime: cannot open trace file: {error}", file=sys.stderr)
            return 2
        _warn(f"cannot open the default trace {trace_path} ({error}); not recording."
              " Pass --trace FILE or --log-dir DIR, or --no-trace to silence this")
        trace = TraceLog(
            None,
            summary=None if args.quiet else sys.stderr,
            excerpt_chars=args.excerpt_chars,
            transport="http" if single_url or mounts else "stdio",
            warn=None if args.quiet else sys.stderr,
        )
        trace_path = ledger = None
    payloads_path = args.payloads
    if args.record_payloads:
        if trace_path is not None:
            payloads_path = trace_path.parent / "payloads.jsonl"
        else:
            _warn("--record-payloads needs the trace folder, which could not be opened;"
                  " payloads are not recorded")
    if trace_path is not None:
        sealed = "sealed in " + str(ledger_path.resolve()) if ledger is not None else "unsealed"
        _warn(f"recording trace to {trace_path.resolve()} ({sealed}); payloads "
              + (f"to {payloads_path.resolve()}" if payloads_path is not None
                 else "are off unless --payloads or --record-payloads is given"))
        if trace_defaulted:
            _warn(f"read this run back with: agent-latch-runtime import-logs --dir "
                  f"{trace_path.parent.resolve()} --once")
    payloads: PayloadFile | None = None
    if payloads_path is not None:
        try:
            payloads = PayloadFile(payloads_path, max_chars=args.payload_max_chars)
        except OSError as error:
            trace.close()
            print(f"agent-latch-runtime: cannot open payloads file: {error}", file=sys.stderr)
            return 2
    try:
        tap = PayloadTap([payloads]) if payloads is not None else None
        if mounts and http:
            import uvicorn

            from agent_latch.runtime.proxy import build_mount_app

            app = build_mount_app(mounts=mounts, trace=trace, tap=tap)
            print(
                f"agent-latch-runtime: monitoring {name!r} at "
                + ", ".join(f"http://{http[0]}:{http[1]}/mcp/{item}" for item in mounts)
                + " (preview; records traffic, never blocks)",
                file=sys.stderr,
            )
            uvicorn.run(app, host=http[0], port=http[1], log_level="warning", lifespan="on")
            return 0
        server = build_proxy(
            name=name,
            trace=trace,
            command=command,
            upstream_url=single_url,
            tap=tap,
        )
        print(
            f"agent-latch-runtime: monitoring {name!r} (preview; records traffic, never blocks)",
            file=sys.stderr,
        )
        if http:
            server.run(transport="http", host=http[0], port=http[1], show_banner=False)
        else:
            server.run(show_banner=False)
    except KeyboardInterrupt:
        # Ctrl+C is how a run is stopped: no traceback, so the summary below is the last thing shown.
        pass
    finally:
        trace.close()
        if payloads is not None:
            payloads.close()
        if trace_path is not None:
            if args.no_import:
                _warn(f"run folder: {trace_path.parent.resolve()}")
            else:
                import_run(
                    trace_path,
                    ledger_path if ledger is not None else None,
                    payloads_path,
                    io.StringIO() if args.quiet else sys.stderr,
                )
    return 0


def _runs_below(directory: Path) -> list[Path]:
    """Run folders (holding ``trace.jsonl``) up to two levels below ``directory``, oldest first."""
    found: list[Path] = []
    if not directory.is_dir():
        return found
    for child in sorted(directory.iterdir()):
        if child.is_symlink() or not child.is_dir():
            continue
        if (child / "trace.jsonl").is_file():
            found.append(child)
            continue
        found.extend(
            grand for grand in sorted(child.iterdir())
            if grand.is_dir() and not grand.is_symlink() and (grand / "trace.jsonl").is_file()
        )
    return found


def _import_logs(args: argparse.Namespace) -> int:
    """Run ``import-logs``: follow the logs into events, optionally sealed and anchored; exit 1
    when a store is refused.
    """
    logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
    directory: Path = args.dir or Path(DEFAULT_LOG_DIR)
    trace = args.trace or directory / "trace.jsonl"
    payloads = args.payloads or (None if args.trace else directory / "payloads.jsonl")
    events_csv = args.events_csv or directory / "events.csv"
    if args.trace is None and not trace.exists():
        search = directory
        runs = _runs_below(search)
        if not runs and args.dir is None:
            search = default_log_root()
            runs = _runs_below(search)
        if runs:
            # Every run has its own folder; guessing one could import the wrong (or a live) run.
            shown = "\n".join(f"  {run}" for run in runs[-10:])
            more = f"\n  ... and {len(runs) - 10} older" if len(runs) > 10 else ""
            print(
                f"agent-latch-runtime: {search} holds {len(runs)} run folder(s), not one run."
                f" Pass --dir with the run to import (newest last):\n{shown}{more}",
                file=sys.stderr,
            )
            return 2
    if args.once and not trace.exists():
        # A following import may wait for the proxy to create the file; a one-shot import cannot.
        print(
            f"agent-latch-runtime: no trace at {trace}. Check --dir: it must be the run folder"
            " the proxy printed (or give the file with --trace)",
            file=sys.stderr,
        )
        return 2
    if args.anchor is not None and not args.database:
        print("agent-latch-runtime: --anchor needs --database", file=sys.stderr)
        return 2
    try:
        loaded = []
        if args.connector or args.connector_option or args.connector_config:
            loaded = load_connectors(
                parse_connector_settings(
                    args.connector, args.connector_option, args.connector_config
                ),
                directory,
            )
        policy = load_policy(args.policy) if args.policy else None
        if policy:
            for key in unknown_policy_keys(policy):
                print(f"warning: policy key {key!r} is not read by any gate (typo?)", file=sys.stderr)
        gates = discover_gates(policy)
        store = SQLiteEventStore(args.database) if args.database else None
        importer = RuntimeLogImporter(
            trace,
            args.output_csv or directory / "gate-results.csv",
            gates,
            payloads_path=payloads,
            events_csv=events_csv,
            normalized_path=args.normalized_out or directory / "normalized.jsonl",
            summary=None if args.quiet else sys.stderr,
            store=store,
            anchor=make_anchor(args.anchor) if args.anchor else None,
            connectors=loaded,
            connector_dir=directory,
            run_id=args.run_id,
            follow=not args.once,
        )
        print(
            f"agent-latch-runtime: importing {trace} into {events_csv}"
            + (f" and {args.database}" if args.database else "")
            + (f" (anchoring to {args.anchor})" if args.anchor else "")
            + "".join(f" and connector {c.name} ({c.type})" for c in loaded)
            + f" with {len(gates)} gate(s)"
            + ("" if args.once else "; following new lines (Ctrl+C to stop)"),
            file=sys.stderr,
        )
        importer.run()
    except KeyboardInterrupt:
        return 0
    except StoreIntegrityError as error:
        # The store is not trusted: it is never repaired or re-sealed, and no forged head is anchored.
        # Exit 1, as verify does.
        print(f"agent-latch-runtime: {error}", file=sys.stderr)
        return 1
    except ConnectorConfigError as error:
        # Messages never carry option values; secrets are written as env: references.
        print(f"agent-latch-runtime: connector error: {error}", file=sys.stderr)
        return 2
    except (ImportError, OSError, ValueError, AnchorError) as error:
        print(f"agent-latch-runtime: importer failed: {error}", file=sys.stderr)
        return 2
    return 0


def _connectors(args: argparse.Namespace) -> int:
    """Run ``connectors``: list installed connector types without importing any of them."""
    try:
        found = installed_connectors()
    except ConnectorConfigError as error:
        print(f"agent-latch-runtime: connector error: {error}", file=sys.stderr)
        return 2
    if not found:
        print(
            "agent-latch-runtime: no connectors installed; a connector is a separate package that"
            " registers the 'agent_latch.connectors' entry point"
        )
        return 0
    width = max(len(item.type) for item in found)
    for item in found:
        print(f"{item.type:<{width}}  {item.package} {item.version}  ({item.target})")
    return 0


def _verify_one(ledger: Path, trace: Path | None, anchor: Path | None) -> int:
    verification = verify_ledger(ledger, trace_path=trace, anchor_path=anchor)
    if not ledger.is_file() and not verification.failed:
        # Nothing says records ever existed, so this is a wrong path, not a deletion.
        print(f"agent-latch-runtime: no ledger file at {ledger}", file=sys.stderr)
        return 2
    for line in describe(verification):
        print(line)
    return 1 if verification.failed else 0


def _verify_folder(args: argparse.Namespace, folder: Path) -> int:
    if args.trace is not None or args.anchor is not None:
        print(
            "agent-latch-runtime: --trace and --anchor belong to one ledger; give a ledger file"
            " instead of a folder",
            file=sys.stderr,
        )
        return 2
    ledgers = find_ledgers(folder, recursive=args.all)
    if not ledgers:
        hint = "" if args.all else " (add --all to search subfolders)"
        print(f"agent-latch-runtime: no *.ledger.jsonl in {folder}{hint}", file=sys.stderr)
        return 2
    results = [
        (ledger.relative_to(folder).as_posix(), verify_ledger(ledger, trace_path=trace_for(ledger)))
        for ledger in ledgers
    ]
    print(format_summary_table(results))
    # An empty ledger cannot be verified, so a folder check does not call it clean.
    problems = [(label, v) for label, v in results if v.failed or v.status == STATUS_MISSING]
    for label, verification in problems:
        print(f"\n{label}")
        for line in describe(verification):
            print(line)
    return 1 if problems else 0


def _verify_database(args: argparse.Namespace) -> int:
    """Run ``verify --database``: recompute every seal, the layout and the anchor; exit 1 if it
    cannot be trusted, 2 if there is nothing to verify.
    """
    database: Path = args.database
    if args.path is not None or args.ledger is not None or args.all or args.trace is not None:
        print(
            "agent-latch-runtime: --database checks one event store; do not combine it with a"
            " PATH, --ledger, --all or --trace",
            file=sys.stderr,
        )
        return 2
    # `--anchor file:/path` must name the file the anchor commands write to, so resolve it once.
    anchor_path = make_anchor(args.anchor).path if args.anchor else None
    found = check_store(database, anchor_path)
    if found.unsealed is not None or found.error is not None:
        print(f"agent-latch-runtime: {found.unsealed or found.error}", file=sys.stderr)
        return 2
    verification = found.verification
    assert verification is not None
    if verification.status == STATUS_MISSING:
        # No file (or no rows) and no anchor point: there is nothing to verify.
        if not database.is_file():
            print(f"agent-latch-runtime: no event store at {database}", file=sys.stderr)
        else:
            for line in describe(verification):
                print(line)
        return 2
    for line in describe(verification):
        print(line)
    return 1 if verification.failed else 0


def _verify(args: argparse.Namespace) -> int:
    """Run ``verify`` for a ledger, a folder of ledgers or, with ``--database``, an event store."""
    if args.database is not None:
        return _verify_database(args)
    for given in (args.path, args.ledger):
        if given is not None and given.is_file() and is_sqlite_file(given):
            print(
                f"agent-latch-runtime: {given} is a SQLite database, not a ledger;"
                " use --database to verify an event store",
                file=sys.stderr,
            )
            return 2
    if args.path is not None and args.ledger is not None:
        print("agent-latch-runtime: give a PATH or --ledger, not both", file=sys.stderr)
        return 2
    if args.path is None and args.ledger is None:
        print("agent-latch-runtime: verify needs a ledger file or a folder", file=sys.stderr)
        return 2
    if args.ledger is not None:
        if args.all:
            print("agent-latch-runtime: --all needs a folder, not --ledger", file=sys.stderr)
            return 2
        return _verify_one(args.ledger, args.trace, args.anchor)
    path: Path = args.path
    if path.is_dir():
        return _verify_folder(args, path)
    if args.all:
        print("agent-latch-runtime: --all needs a folder, not a file", file=sys.stderr)
        return 2
    return _verify_one(path, args.trace or trace_for(path), args.anchor)


def _anchor_database(args: argparse.Namespace) -> int:
    """Publish the head of a sealed store after checking it; refuse a failing store and rows that
    were never checked.
    """
    database: Path = args.database
    destination = make_anchor(args.to)
    try:
        earlier = destination.latest()
    except (AnchorError, OSError) as error:
        print(f"agent-latch-runtime: cannot anchor: {error}", file=sys.stderr)
        return 2
    # Before the reader refuses an "old" file: a version lowered below the anchor's is tampering.
    lowered = downgrade_issues(stored_schema_version(database), earlier)
    if lowered and earlier is not None:
        for line in describe(downgrade_verdict(database.name, earlier, lowered)):
            print(line, file=sys.stderr)
        print("agent-latch-runtime: not anchored: the event store fails its check", file=sys.stderr)
        return 1
    reader = SQLiteEventReader(database)
    try:
        reader.open()
    except (ValueError, OSError) as error:
        print(f"agent-latch-runtime: cannot anchor: {error}", file=sys.stderr)
        return 2
    try:
        if earlier is not None and earlier.source != SOURCE:
            print(
                f"agent-latch-runtime: cannot anchor: {args.to} holds points for a trace ledger;"
                " use one anchor file per ledger or event store",
                file=sys.stderr,
            )
            return 2
        # Never bless a store that already fails: check the seals, the schema and any earlier point.
        verification = verify_store(reader, name=database.name, anchor_path=destination.path)
        if verification.failed:
            for line in describe(verification):
                print(line, file=sys.stderr)
            print("agent-latch-runtime: not anchored: the event store fails its check",
                  file=sys.stderr)
            return 1
        head = reader.head()
        if verification.status == STATUS_MISSING or head is None:
            print(f"agent-latch-runtime: {database} has no sealed rows to anchor", file=sys.stderr)
            return 2
        if earlier is not None and head.seq > earlier.seq and not args.accept_unchecked_rows:
            # Rows past an earlier point were never compared with the logs. Anchoring them here
            # would make a forged row look trusted, so only import-logs --anchor (which checks
            # them) advances an existing anchor, unless the operator says to trust the store.
            print(
                f"agent-latch-runtime: not anchored: {head.seq - earlier.seq} row(s) after the"
                f" newest anchor point (#{earlier.seq}) have not been checked against the logs."
                " Run import-logs --database FILE --anchor PATH, which checks them and anchors"
                " them. To anchor them as they are, because you trust this store, run this"
                " command again with --accept-unchecked-rows",
                file=sys.stderr,
            )
            return 1
        point = point_for(
            database,
            seq=head.seq,
            digest=head.digest,
            records=head.seq,
            source=SOURCE,
            schema_sha256=reader.schema_sha256(),
            schema_version=reader.schema_version(),
        )
        destination.publish(point)
    except (AnchorError, OSError, ValueError) as error:
        print(f"agent-latch-runtime: cannot anchor: {error}", file=sys.stderr)
        return 2
    finally:
        reader.close()
    if not args.quiet:
        print(
            f"agent-latch-runtime: anchored #{point.seq} {point.digest[:12]}… to {destination.path}",
            file=sys.stderr,
        )
    return 0


def _anchor(args: argparse.Namespace) -> int:
    """Run ``anchor``: publish the newest seal of a ledger or an event store to an anchor file."""
    if args.database is not None:
        return _anchor_database(args)
    ledger: Path = args.ledger
    if not ledger.is_file():
        print(f"agent-latch-runtime: no ledger file at {ledger}", file=sys.stderr)
        return 2
    try:
        head = Ledger.read_head(ledger)
        if head is None:
            print(f"agent-latch-runtime: {ledger} has no blocks to anchor", file=sys.stderr)
            return 2
        destination = make_anchor(args.to)
        point = point_for(ledger, seq=head.seq, digest=head.digest, records=head.seq)
        destination.publish(point)
    except (LedgerError, AnchorError, OSError, ValueError) as error:
        print(f"agent-latch-runtime: cannot anchor: {error}", file=sys.stderr)
        return 2
    if not args.quiet:
        print(
            f"agent-latch-runtime: anchored #{point.seq} {point.digest[:12]}… to {destination.path}",
            file=sys.stderr,
        )
    return 0


def _demo(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
    try:
        import fastmcp  # noqa: F401 - only checks that the [runtime] extra is installed
    except ImportError:
        print(
            "agent-latch-runtime: FastMCP is missing. Install AgentLatch with the runtime extra,"
            ' for example python -m pip install "agentlatch-security[runtime]" (see docs/runtime.md)',
            file=sys.stderr,
        )
        return 2
    from agent_latch.runtime.demo import run_demo

    try:
        run_demo(args.dir, scenario=args.scenario)
    except KeyboardInterrupt:
        return 0
    except Exception as error:  # noqa: BLE001 - report any demo failure as a setup error
        print(
            f"agent-latch-runtime: demo failed: {type(error).__name__}: {error}"
            f" (proxy output: {args.dir / 'proxy.log'})",
            file=sys.stderr,
        )
        return 2
    return 0


def _audit_tool(args: argparse.Namespace) -> int:
    """Serve the read-only audit tool over MCP (stdio) for a sealed store."""
    try:
        from agent_latch.runtime.audit_tool import build_audit_tool
    except ImportError:
        print(
            "agent-latch-runtime: FastMCP is missing. Install AgentLatch with the runtime extra,"
            ' for example python -m pip install "agentlatch-security[runtime]" (see docs/runtime.md)',
            file=sys.stderr,
        )
        return 2
    # stdout carries the MCP protocol, so logging goes to stderr.
    logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
    try:
        server = build_audit_tool(args.database, name=args.name)
    except (ValueError, OSError) as error:
        print(f"agent-latch-runtime: {error}", file=sys.stderr)
        return 2
    print(
        f"agent-latch-runtime: serving {args.database} read-only (query_audit_log, recent_events)",
        file=sys.stderr,
    )
    server.run(show_banner=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse the arguments, run the chosen sub-command and return its exit code."""
    args = _parser().parse_args(argv)
    if args.subcommand == "proxy":
        return _proxy(args)
    if args.subcommand == "import-logs":
        return _import_logs(args)
    if args.subcommand == "connectors":
        return _connectors(args)
    if args.subcommand == "verify":
        return _verify(args)
    if args.subcommand == "anchor":
        return _anchor(args)
    if args.subcommand == "audit-tool":
        return _audit_tool(args)
    if args.subcommand == "demo":
        return _demo(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
