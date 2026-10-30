"""AgentLatch gates: the security outcomes that every detector reports against.

A gate is a stable outcome, for example "ALR09 Human approval for sensitive actions". Each
detector, a static rule or a runtime check, belongs to exactly one gate and is listed in that
gate's `detectors` group in GATES. DETECTORS is derived from those groups, so a new detector is
added in one place, next to the outcome it provides evidence for. Framework references are mapped
per gate: OWASP Agentic IDs come from owasp.py and EU AI Act articles from EU_AI_ACT_ARTICLES. A
detector's OWASP IDs are always a subset of its gate's (tested). Every mapping is informational,
never a compliance claim. ISO/IEC 42001 is not mapped yet.

IDs: `ALRnn` is a gate. New static detectors are `ALRnn-Snn` and new runtime detectors
`ALRnn-Rnn`. Existing detectors keep their IDs (`AGENTLATCH-PRM001`, `ALR04-001`). Reports show
them short with their gate (`PRM001 (ALR01)`); SARIF `ruleId` and JSON `rule_id` keep the full ID,
because code-scanning alert history is keyed on it.

`python -I -m agent_latch.catalog > docs/GATES.md` regenerates the gate reference.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_latch.owasp import (
    ASI_CATEGORIES,
    OWASP_AGENTIC_TITLE,
    OWASP_AGENTIC_URL,
    RULE_CATEGORIES,
)

EU_AI_ACT_TITLE = "EU AI Act (Regulation (EU) 2024/1689)"
EU_AI_ACT_ARTICLES: dict[str, str] = {
    "Art. 14": "Human oversight",
    "Art. 15": "Accuracy, robustness and cybersecurity",
}

# (detector id, mode, reason). A detector is declared inside its gate group, so the catalog reads
# as gate -> detectors and the gate a detector belongs to cannot drift from a second list.
DetectorSpec = tuple[str, str, str]


@dataclass(frozen=True)
class Gate:
    id: str
    name: str
    outcome: str
    owasp: tuple[str, ...]
    eu_ai_act: tuple[str, ...]
    detectors: tuple[DetectorSpec, ...]


@dataclass(frozen=True)
class Detector:
    id: str
    gate: str
    mode: str
    reason: str


# The ALR04 runtime checks are a single family; they are expanded into the gate below.
_ALR04_RUNTIME: tuple[DetectorSpec, ...] = (
    ("ALR04-001", "runtime",
     "The tool definition tells the model to ignore its instructions"),
    ("ALR04-002", "runtime",
     "The tool definition claims to speak for the system, developer or user"),
    ("ALR04-003", "runtime",
     "The tool definition asks the model to hide actions from the user"),
    ("ALR04-004", "runtime",
     "The tool definition steers the model toward secrets or private files"),
    ("ALR04-005", "runtime",
     "The tool definition asks the model to send data somewhere"),
    ("ALR04-006", "runtime",
     "The tool definition changes how the model uses other tools"),
    ("ALR04-007", "runtime",
     "Instructions are hidden with encoding or invisible characters"),
    ("ALR04-008", "runtime",
     "The tool definition pushes the model to always pick this tool"),
    ("ALR04-009", "runtime",
     "The tool definition demands a harmful step before it can be used"),
)

GATES: tuple[Gate, ...] = (
    Gate(
        "ALR01",
        "Prompt integrity",
        "System prompts carry no injected instructions or raw user input",
        ("ASI01",),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-PRM001", "static",
             "Injected text inside a prompt the author ships breaks the prompt itself"),
            ("AGENTLATCH-PRM002", "static",
             ("User text placed in the system prompt gains system-level authority over the "
              "agent's goal")),
            ("ALR01-S01", "static",
             ("Invisible or direction-control characters hide instructions from the reviewer "
              "while the model still reads them")),
        ),
    ),
    Gate(
        "ALR02",
        "Tool definition integrity",
        "Tool definitions are pinned and changes are detected",
        ("ASI02", "ASI04"),
        ("Art. 15",),
        detectors=(),
    ),
    Gate(
        "ALR03",
        "Tool and agent endpoint trust",
        "Remote tools, MCP servers and peer agents are identified and authenticated",
        ("ASI02", "ASI03", "ASI04", "ASI07"),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-MAN003", "manifest",
             ("The agent cannot tell a real remote tool from an impostor if the endpoint is "
              "unauthenticated")),
            ("ALR03-S01", "static",
             "A server on every interface lets any reachable peer call the agent and its tools"),
        ),
    ),
    Gate(
        "ALR04",
        "Tool schema injection",
        "Tool definitions contain no instruction-like or hidden content",
        ("ASI01", "ASI02", "ASI04"),
        ("Art. 15",),
        detectors=_ALR04_RUNTIME,
    ),
    Gate(
        "ALR05",
        "Untrusted content isolation",
        "Web, HTTP and tool output reaches the model fenced as data",
        ("ASI01",),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-AG003", "static",
             "Content from outside reaches the model as if it were instructions, not data"),
        ),
    ),
    Gate(
        "ALR06",
        "Code execution containment",
        "No unsandboxed eval, shell or model-driven code execution",
        ("ASI02", "ASI05"),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-PY001", "static",
             "Runs arbitrary code inside the agent process"),
            ("AGENTLATCH-PY002", "static",
             "Model-influenced strings can become shell commands"),
            ("AGENTLATCH-AG002", "static",
             "The agent writes Python and the framework executes it"),
            ("ALR06-S01", "static",
             "A loader that builds objects turns a crafted file into code in the agent process"),
            ("ALR06-S02", "static",
             "Model-written code without a sandbox runs with the agent's own access"),
        ),
    ),
    Gate(
        "ALR07",
        "Least-privilege tools",
        "Tools and delegation are scoped, not wildcard or unrestricted",
        ("ASI02", "ASI03", "ASI05"),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-AG001", "static",
             "The agent can hand work to other agents, and with it their tools"),
            ("AGENTLATCH-AG005", "static",
             "The tool has no scope limit, so the agent holds full shell or file access"),
            ("AGENTLATCH-MAN002", "manifest",
             "The manifest grants everything instead of what the tool needs"),
        ),
    ),
    Gate(
        "ALR08",
        "Bounded execution",
        "Agent loops and recursion have effective limits",
        ("ASI08",),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-AG007", "static",
             "An unbounded loop turns one bad step into runaway cost or repeated actions"),
            ("ALR08-S01", "static",
             "One stalled peer without a timeout holds up every step queued behind it"),
            ("ALR08-S02", "static",
             "A retry without a limit never gives up, so a failing dependency stalls the step"),
        ),
    ),
    Gate(
        "ALR09",
        "Human approval for sensitive actions",
        "Destructive or outward-facing actions need human approval",
        ("ASI02", "ASI03", "ASI05", "ASI09"),
        ("Art. 14",),
        detectors=(
            ("AGENTLATCH-AG004", "static",
             "The model can delete, write, send or pay without a human confirming"),
            ("AGENTLATCH-AG006", "static",
             "Approval exists in the framework but the code switches it off"),
            ("AGENTLATCH-MAN001", "manifest",
             "The manifest declares a dangerous capability with no approval step"),
        ),
    ),
    Gate(
        "ALR10",
        "Secret hygiene",
        "No credentials in source, config or prompts",
        ("ASI03", "ASI04"),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-SEC001", "static",
             ("A secret in the project can be read by the agent, its prompts or anyone with the "
              "code")),
        ),
    ),
    Gate(
        "ALR11",
        "Dependency integrity",
        "Pinned dependencies have no known advisories",
        ("ASI04",),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-DEP001", "dependency audit (opt-in)",
             "A known-vulnerable package is part of the agent's supply chain"),
            ("ALR11-S01", "static",
             "Trusting remote model code makes a hub repository part of the agent's supply chain"),
        ),
    ),
    Gate(
        "ALR12",
        "Secure transport",
        "TLS is verified and agent or tool traffic does not use plain HTTP",
        ("ASI02", "ASI07"),
        ("Art. 15",),
        detectors=(
            ("AGENTLATCH-PY003", "static",
             "Disabled TLS checks let anyone on the network read or alter the agent's traffic"),
            ("ALR12-S01", "static",
             "Plaintext endpoints let anyone on the path read or rewrite peer traffic"),
        ),
    ),
    Gate(
        "ALR13",
        "Memory and context integrity",
        "Untrusted content is not written to agent memory or vector stores",
        ("ASI06",),
        ("Art. 15",),
        detectors=(
            ("ALR13-S01", "static",
             "Untrusted text written to memory comes back as context the agent trusts"),
            ("ALR13-S02", "static",
             "One memory shared by every session lets one user's context reach another"),
        ),
    ),
    Gate(
        "ALR14",
        "Rogue agent containment",
        "Agents cannot modify their own prompts or config, or spawn agents without limits",
        ("ASI10",),
        ("Art. 14", "Art. 15"),
        detectors=(
            ("ALR14-S01", "static",
             ("An agent that rewrites its own prompts or settings keeps instructions after the "
              "session")),
            ("ALR14-S02", "static",
             "Persistence brings the agent back after it is stopped, outside a user's view"),
            ("ALR14-S03", "static",
             "Installing packages at runtime pulls unreviewed code into the agent process"),
        ),
    ),
)

# Derived from the gate groups above, flat and in gate order. Never add to this directly.
DETECTORS: tuple[Detector, ...] = tuple(
    Detector(detector_id, item.id, mode, reason)
    for item in GATES
    for detector_id, mode, reason in item.detectors
)

# Records that report on the scan itself rather than a security outcome; they belong to no gate.
DIAGNOSTICS: dict[str, str] = {
    "AGENTLATCH-MAN000": "Manifest could not be read or has an invalid field",
    "ALR04-090": "ALR04 could not inspect enough of a tool definition (coverage)",
    "ALR04-099": "ALR04 per-scan summary",
}

GATES_BY_ID: dict[str, Gate] = {gate.id: gate for gate in GATES}
DETECTORS_BY_ID: dict[str, Detector] = {detector.id: detector for detector in DETECTORS}


def gate(gate_id: str) -> Gate:
    return GATES_BY_ID[gate_id]


def gate_for(rule_id: str) -> Gate | None:
    detector = DETECTORS_BY_ID.get(rule_id)
    return GATES_BY_ID[detector.gate] if detector else None


def short_id(rule_id: str) -> str:
    """'AGENTLATCH-PRM001' -> 'PRM001'. Suppressions accept either form."""
    return rule_id.removeprefix("AGENTLATCH-")


def display_id(rule_id: str) -> str:
    """What people read: 'PRM001 (ALR01)'. A detector already named after its gate stays as is."""
    short = short_id(rule_id)
    found = gate_for(rule_id)
    if found is None or short.startswith(found.id):
        return short
    return f"{short} ({found.id})"


def gate_label(rule_id: str) -> str:
    found = gate_for(rule_id)
    return f"{found.id} {found.name}" if found else "none"


def gate_entry(rule_id: str) -> dict[str, str] | None:
    found = gate_for(rule_id)
    return {"id": found.id, "name": found.name} if found else None


def detectors_for(gate_id: str) -> list[Detector]:
    return [detector for detector in DETECTORS if detector.gate == gate_id]


def detector_owasp(detector: Detector) -> tuple[str, ...]:
    """Static detectors list their own categories in owasp.py; runtime ones cite their gate's."""
    return RULE_CATEGORIES.get(detector.id, GATES_BY_ID[detector.gate].owasp)


def gate_status(gate_id: str) -> str:
    detectors = detectors_for(gate_id)
    if not detectors:
        return "no checks yet"
    if all(detector.mode == "runtime" for detector in detectors):
        return "preview (runtime)"
    return "partial"


def _codes(ids: tuple[str, ...]) -> str:
    return ", ".join(f"`{item}`" for item in ids)


def render_markdown() -> str:
    lines: list[str] = [
        "# Gates",
        "",
        ("<!-- Generated by `python -I -m agent_latch.catalog > docs/GATES.md`."
        " Edit src/agent_latch/catalog.py instead. -->"),
        "",
        ("A gate is a security outcome AgentLatch checks for, such as \"destructive actions need"
        " human approval\". Every detector, whether a static scanner rule or a runtime check,"
        " belongs to exactly one gate. Framework references are mapped per gate."),
        "",
        ("- Gate IDs are `ALRnn`. New static detectors are named `ALRnn-Snn` and new runtime"
        " detectors `ALRnn-Rnn`."),
        ("- Existing detectors keep their IDs. Reports show them short with their gate, for example"
        " `PRM001 (ALR01)`. SARIF `ruleId` and JSON `rule_id` keep the full ID"
        " (`AGENTLATCH-PRM001`), and suppressions accept either form."),
        ("- `partial` means the gate has some checks, not that the outcome is fully verified."
        " `no checks yet` means AgentLatch has no detector for it. A gate without findings is not"
        " a guarantee."),
        "",
        "## Gates and frameworks",
        "",
        "| Gate | Name | Outcome | Detectors | OWASP Agentic | EU AI Act | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in GATES:
        detectors = ", ".join(f"`{short_id(d.id)}`" for d in detectors_for(item.id)) or "none"
        lines.append(
            f"| `{item.id}` | {item.name} | {item.outcome} | {detectors} | {_codes(item.owasp)}"
            f" | {', '.join(item.eu_ai_act)} | {gate_status(item.id)} |"
        )
    lines += [
        "",
        "## Detectors",
        "",
        ("Detection details and blind spots for the static rules are in [RULES.md](RULES.md);"
        " the runtime checks are described in [runtime.md](runtime.md)."),
        "",
        "| Detector | Gate | Mode | Why this gate | OWASP Agentic |",
        "|---|---|---|---|---|",
    ]
    for detector in DETECTORS:
        lines.append(
            f"| `{short_id(detector.id)}` | `{detector.gate}` | {detector.mode} | {detector.reason}"
            f" | {_codes(detector_owasp(detector))} |"
        )
    lines += [
        "",
        "Diagnostics report on the scan itself and belong to no gate: "
        + "; ".join(f"`{short_id(rule_id)}` {text.lower()}" for rule_id, text in DIAGNOSTICS.items())
        + ".",
        "",
        "## Framework references",
        "",
        ("These mappings are informational. They show where a gate may provide evidence relevant"
        " to a framework. They are not a compliance assessment, certification, or endorsement."),
        "",
        f"- [{OWASP_AGENTIC_TITLE}]({OWASP_AGENTIC_URL}): "
        + "; ".join(f"{cid} {name}" for cid, name in ASI_CATEGORIES.items())
        + ".",
        f"- {EU_AI_ACT_TITLE}: "
        + "; ".join(f"{article} {name}" for article, name in EU_AI_ACT_ARTICLES.items())
        + ". These articles set requirements for high-risk AI systems; whether they apply depends"
        " on the system and its use.",
        "- ISO/IEC 42001: not mapped yet.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_markdown(), end="")
