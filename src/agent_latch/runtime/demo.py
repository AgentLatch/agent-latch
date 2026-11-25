"""``agent-latch-runtime demo``: record and import a short synthetic MCP session [needs fastmcp].

It starts the bundled demo server (``demo_server``) behind the real proxy with ``--trace`` and
``--payloads``, makes a few calls through it as an MCP client would, then imports the logs once.
The ``secret-leak`` scenario instead sends a GitHub-token-shaped fake value to ``search_issues``
and reads a fake AWS key back from ``read_config``, so ALR10-R01 and ALR10-R02 fire. Nothing
leaves the machine: the server is local and synthetic, and every fake credential is masked.
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import TextIO

from agent_latch.gates import alr02, alr04
from agent_latch.runtime.importer import RuntimeLogImporter, discover_gates
from agent_latch.runtime.tool_baseline import approve_candidate, capture_candidate, write_private

DEMO_SERVER = "demo-server"
SCENARIOS = ("default", "poisoned-output", "secret-leak", "tool-drift")
# A fake, token-shaped value (built by concatenation so secret scanners do not flag the source).
FAKE_GITHUB_TOKEN = "ghp_" + "DEMOFAKE" * 3
# The only files the demo writes; a rerun removes just these, so the demo starts clean.
DEMO_FILES = (
    "trace.jsonl", "payloads.jsonl", "events.csv", "gate-results.csv", "normalized.jsonl",
    "proxy.log",
)


async def _drive(
    directory: Path, log_file: TextIO, scenario: str, *, tools_mode: str = "",
    payload_max_chars: int | None = None,
) -> None:
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    transport = StdioTransport(
        command=sys.executable,
        args=[
            "-m", "agent_latch.runtime.cli", "proxy", "--quiet", "--no-import", "--name", DEMO_SERVER,
            "--trace", str(directory / "trace.jsonl"),
            "--payloads", str(directory / "payloads.jsonl"),
            *(["--payload-max-chars", str(payload_max_chars)] if payload_max_chars else []),
            "--", sys.executable, "-m", "agent_latch.runtime.demo_server",
        ],
        env={**os.environ, "AGENTLATCH_DEMO_TOOLS": tools_mode},
        keep_alive=False,
        log_file=log_file,
    )
    async with Client(transport) as client:
        await client.list_tools()
        if scenario == "tool-drift":
            return  # ALR02 only needs the tool list
        if scenario == "secret-leak":
            await client.call_tool(
                "search_issues", {"query": "is:open label:bug", "token": FAKE_GITHUB_TOKEN}
            )
            await client.call_tool("read_config", {"section": "aws"})
            return
        if scenario == "poisoned-output":
            # One fetch whose page hides an instruction in invisible characters and visibly
            # steers the agent toward the sibling send_email tool (ALR05-R02 and ALR05-R03).
            await client.call_tool("fetch_page", {"url": "https://example.com/news"})
            return
        await client.call_tool("get_weather", {"city": "London"})
        await client.call_tool("leaky_lookup", {"user": "alice"})
        await client.call_tool("broken_tool", {"reason": "demo"}, raise_on_error=False)
        # ALR05 contrast: instruction-like output (finding) vs ordinary instructions (none).
        await client.call_tool("echo_injection", {"city": "London"})
        await client.call_tool("recipe_steps", {"dish": "pancakes"})
        await client.list_prompts()
        await client.get_prompt("summarize", {"topic": "Mars"})


def run_demo(directory: Path, *, out: TextIO | None = None, scenario: str = "default") -> None:
    """Record a demo session into ``directory`` and import it; raises on failure."""
    # Resolve sys.stderr at call time: a default bound at import time can point at a stream
    # that has since been closed (for example a test harness's capture buffer).
    out = out if out is not None else sys.stderr
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown demo scenario {scenario!r}; choose from {', '.join(SCENARIOS)}")
    # Gates remember what they saw in this process; a fresh demo must not inherit it.
    alr04.reset_state()
    alr02.reset_state()
    if scenario == "tool-drift":
        _run_tool_drift(directory, out)
        return
    directory.mkdir(parents=True, exist_ok=True)
    for name in DEMO_FILES:
        (directory / name).unlink(missing_ok=True)
    out.write(
        f"agent-latch-runtime: demo: calling the synthetic {DEMO_SERVER} through the proxy"
        f" (scenario: {scenario})\n"
    )
    out.flush()
    # The proxy's own stderr (startup message, warnings) goes to proxy.log in the demo folder.
    with (directory / "proxy.log").open("w", encoding="utf-8") as log_file:
        asyncio.run(_drive(directory, log_file, scenario))
    gates = discover_gates()
    out.write(f"agent-latch-runtime: demo: importing the logs ({len(gates)} gate(s))\n")
    out.flush()
    RuntimeLogImporter(
        directory / "trace.jsonl",
        directory / "gate-results.csv",
        gates,
        payloads_path=directory / "payloads.jsonl",
        events_csv=directory / "events.csv",
        normalized_path=directory / "normalized.jsonl",
        summary=out,
        follow=False,
    ).run()
    written = [name for name in DEMO_FILES if (directory / name).exists()]
    out.write(f"agent-latch-runtime: demo: files in {directory}: {', '.join(written)}\n")
    out.flush()


# (folder, tools the server advertises, baseline used, payload cut) for each ALR02 demo run.
_DRIFT_RUNS = (
    ("1-unchanged", "", "approved", None),
    ("2-description-changed", "description", "approved", None),
    ("3-schema-changed", "schema", "approved", None),
    ("4-tool-added", "added", "approved", None),
    ("5-tool-removed", "removed", "approved", None),
    ("6-no-baseline", "", None, None),
    ("7-incomplete-snapshot", "", "approved", 40),
    ("8-poisoned-but-matching", "poisoned", "poisoned", None),
)


def _record_run(directory: Path, tools_mode: str, max_chars: int | None, label: str) -> None:
    for name in DEMO_FILES:
        (directory / name).unlink(missing_ok=True)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "proxy.log").open("w", encoding="utf-8") as log_file:
        asyncio.run(_drive(directory, log_file, "tool-drift", tools_mode=tools_mode,
                           payload_max_chars=max_chars))
    if not (directory / "payloads.jsonl").exists():
        raise RuntimeError(f"run {label} recorded no payloads")


def _import_run(directory: Path, baseline: Path | None, label: str) -> list[str]:
    alr02.reset_state()
    policy = {"alr02_baseline": str(baseline)} if baseline else {}
    RuntimeLogImporter(
        directory / "trace.jsonl", directory / "gate-results.csv", discover_gates(policy),
        payloads_path=directory / "payloads.jsonl", events_csv=directory / "events.csv",
        normalized_path=directory / "normalized.jsonl", summary=None, follow=False,
    ).run()
    lines = []
    with (directory / "gate-results.csv").open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["gate_id"] not in ("ALR02", "ALR04"):
                continue
            result = json.loads(row["result_json"])
            if result.get("status") != "ok":
                error = (result.get("error") or {}).get("type", "unknown")
                raise RuntimeError(f"{label}: gate {row['gate_id']} failed ({error})")
            for item in result.get("findings", []):
                if item.get("rule_id") == "ALR04-099" or item.get("is_finding") is False:
                    if item.get("rule_id") == alr02.RULE_SUMMARY:
                        lines.append(f"{item['rule_id']} {item['outcome']}: compared, "
                                     f"counts {item.get('counts')}")
                    continue
                notes = item.get("coverage_notes")
                what = (f"INCONCLUSIVE ({', '.join(notes)})" if notes
                        else item.get("change_type") or item.get("outcome"))
                tool = item.get("entity", {}).get("tool")
                lines.append(f"{item['rule_id']} {what}" + (f" tool={tool}" if tool else ""))
    return lines


def _outside_folder(directory: Path) -> tempfile.TemporaryDirectory[str]:
    """A temporary folder that is not inside the demo folder, so the baselines are out of reach
    of the logs even when TMPDIR points into it."""
    resolved = directory.resolve()
    for base in (tempfile.gettempdir(), str(Path.home())):
        where = Path(base).resolve()
        if where != resolved and resolved not in where.parents:
            return tempfile.TemporaryDirectory(prefix="agentlatch-alr02-", dir=where)
    raise RuntimeError("no temporary folder outside the demo folder; point TMPDIR elsewhere")


def _run_tool_drift(directory: Path, out: TextIO) -> None:
    """ALR02 demo: approve a baseline, then list tools again under eight conditions."""
    out.write("agent-latch-runtime: demo: tool-drift, synthetic server, no network\n")
    with _outside_folder(directory) as outside:
        baselines: dict[str, Path] = {}
        for name, mode in (("approved", ""), ("poisoned", "poisoned")):
            source = directory / f"baseline-source-{name}"
            _record_run(source, mode, None, name)
            candidate = source / "alr02-candidate.json"
            write_private(candidate, capture_candidate(source / "payloads.jsonl"), replace=True)
            # The explicit operator step; the baseline lives outside the demo's log folder.
            baselines[name] = Path(outside) / f"{name}.json"
            approve_candidate(candidate, baselines[name], [directory])
        out.write("agent-latch-runtime: demo: baseline approved outside the logs; runs:\n")
        for folder, mode, baseline, max_chars in _DRIFT_RUNS:
            _record_run(directory / folder, mode, max_chars, folder)
            lines = _import_run(directory / folder, baselines.get(baseline or ""), folder)
            out.write(f"  {folder}\n")
            out.writelines(f"    {line}\n" for line in lines or ["(no ALR02 or ALR04 records)"])
            out.flush()
