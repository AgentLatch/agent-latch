"""``agent-latch-runtime`` command line (preview: the monitor-only ``proxy`` command)."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

from rich_argparse import RawDescriptionRichHelpFormatter

from agent_latch import __version__
from agent_latch.runtime.payloads import DEFAULT_PAYLOAD_MAX_CHARS, PayloadFile, PayloadTap
from agent_latch.runtime.trace import DEFAULT_EXCERPT_CHARS, TraceLog

_EPILOG = """\
[bold bright_cyan]EXAMPLES:[/bold bright_cyan]
  [cyan]agent-latch-runtime proxy --trace trace.jsonl -- npx -y @modelcontextprotocol/server-github[/cyan]
  [cyan]agent-latch-runtime proxy --http 127.0.0.1:8770 --upstream-url https://tools.example.com/mcp[/cyan]

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
        help="run one MCP server behind AgentLatch and record its traffic",
        description="Run one MCP server behind AgentLatch and record its traffic (monitor only).",
        epilog=_EPILOG,
        formatter_class=RawDescriptionRichHelpFormatter,
    )
    proxy.add_argument("--upstream-url", metavar="URL", help="proxy a remote MCP server at URL")
    proxy.add_argument(
        "--http",
        metavar="HOST:PORT",
        help="serve the proxy over HTTP on a loopback address instead of stdio",
    )
    proxy.add_argument("--name", help="server name used in the trace (default: from the command)")
    proxy.add_argument("--trace", type=Path, metavar="FILE", help="append trace records (JSONL)")
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
        " definitions, secret-masked; the file is sensitive",
    )
    proxy.add_argument(
        "--payload-max-chars",
        type=int,
        default=DEFAULT_PAYLOAD_MAX_CHARS,
        metavar="N",
        help=f"cut each string in --payloads to N characters (default {DEFAULT_PAYLOAD_MAX_CHARS})",
    )
    proxy.add_argument("--quiet", action="store_true", help="no per-message summary on stderr")
    proxy.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="the real MCP server command, after --",
    )
    return parser


def _default_name(command: list[str], upstream_url: str | None) -> str:
    if upstream_url:
        return urlparse(upstream_url).hostname or "upstream"
    # "npx -y @modelcontextprotocol/server-github" -> "server-github"; "python server.py" -> "server".
    words = [word for word in command[1:] if not word.startswith("-")] or command
    last = words[-1].replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[0] if "." in last else last


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
    if bool(command) == bool(args.upstream_url):
        print("agent-latch-runtime: give the server command after --, or --upstream-url",
              file=sys.stderr)
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
            ' for example python -m pip install -e ".[runtime]" from a clone (see docs/runtime.md)',
            file=sys.stderr,
        )
        return 2

    # stdout carries the MCP protocol in stdio mode, so logging goes to stderr.
    logging.basicConfig(level=logging.WARNING, format="%(message)s", stream=sys.stderr)
    name = args.name or _default_name(command, args.upstream_url)
    try:
        trace = TraceLog(
            args.trace,
            summary=None if args.quiet else sys.stderr,
            excerpt_chars=args.excerpt_chars,
        )
    except OSError as error:
        print(f"agent-latch-runtime: cannot open trace file: {error}", file=sys.stderr)
        return 2
    payloads: PayloadFile | None = None
    if args.payloads is not None:
        try:
            payloads = PayloadFile(args.payloads, max_chars=args.payload_max_chars)
        except OSError as error:
            trace.close()
            print(f"agent-latch-runtime: cannot open payloads file: {error}", file=sys.stderr)
            return 2
    try:
        server = build_proxy(
            name=name,
            trace=trace,
            command=command,
            upstream_url=args.upstream_url,
            tap=PayloadTap([payloads]) if payloads is not None else None,
        )
        print(
            f"agent-latch-runtime: monitoring {name!r} (preview; records traffic, never blocks)",
            file=sys.stderr,
        )
        if http:
            server.run(transport="http", host=http[0], port=http[1], show_banner=False)
        else:
            server.run(show_banner=False)
    finally:
        trace.close()
        if payloads is not None:
            payloads.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.subcommand == "proxy":
        return _proxy(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
