"""ALR10 Secret hygiene: secret-like values crossing the tool boundary.

Reads ``tools/call`` payload records and reports when the agent sent a credential to a tool
(``ALR10-R01``) or a tool returned one into the model's context (``ALR10-R02``). The gate works
on **masked** payloads by design: the proxy replaces secret-like values with ``[REDACTED]``
before anything is written (``redact.mask_value``), so the gate never sees a raw secret and
nothing it writes can leak one. The evidence is the masking itself: the ``masked`` list the
payload file attaches to each record names the JSON path and the kind of each masked spot
(``key_name``, ``assignment``, ``token:github``, ``token:aws``, ``jwt``, ``pem``, ``bearer``).

Older records without that metadata still work: the gate falls back to finding ``[REDACTED]``
markers, and to re-running the token-shape patterns over the stored strings (anything they match
is reported by kind only, never quoted).

Severity: ``high`` for a token-shaped secret in any argument or for any secret sent to a remote
(HTTP upstream) server; ``medium`` for a secret under a key name sent to a local server; a tool
whose purpose is authentication (named ``login``/``auth``, or with a password parameter in its
schema) is ``INCONCLUSIVE`` at ``low`` severity - still reported, never dropped. The operator
allowlist ``policy.allowed_secret_tools: [{server, tool}]`` turns an expected case into ``PASS``
with a note; ``policy`` must be trusted operator configuration, never the scanned project's.

Known blind spots: secrets the masking patterns do not recognize (the same limit as the proxy's
masking), secrets split across fields, encoded secrets, and a literal ``[REDACTED]`` in honest
tool output (reported as if masked). The gate reports findings only; it never clears a tool.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator, Mapping
from typing import Any

from agent_latch.runtime.redact import MASK, value_kind

GATE_ID = "ALR10"
# This check is about credentials crossing an identity boundary: ASI03, a subset of the gate's
# categories (agent_latch.catalog lists ASI03 and ASI04 for ALR10).
OWASP = ["ASI03"]

RULE_REQUEST = "ALR10-R01"
RULE_RESPONSE = "ALR10-R02"
RULE_COVERAGE = "ALR10-R90"

# Kinds whose shape alone marks a real credential (always high severity).
TOKEN_KINDS = frozenset(
    {"token", "token:openai", "token:github", "token:slack", "token:aws", "jwt", "pem", "bearer"}
)
MAX_EVIDENCE_REPORTED = 16
MAX_STRINGS = 4096

_AUTH_NAME = re.compile(r"(?i)(?:^|[^a-z])(?:login|logon|log_in|signin|sign_in|auth)(?:[^a-z]|$)")
_PASSWORD_PARAM = re.compile(r"(?i)^pass(?:word|phrase|wd)?$")
# Where in each payload body the agent's or the tool's data lives, by stage.
_SECTIONS = {
    "request": ("arguments",),
    "response": ("content", "structured"),
    "error": ("error_message",),
}


def _safe(text: Any, limit: int = 120) -> str:
    """Printable, single-line, length-limited text; names come from untrusted servers."""
    flat = "".join("?" if unicodedata.category(c).startswith("C") else c for c in str(text))
    return flat[:limit]


def _strings(value: Any, path: str) -> Iterator[tuple[str, str]]:
    """Every string in ``value`` with its JSON-pointer-like path, bounded."""
    stack: list[tuple[Any, str]] = [(value, path)]
    seen = 0
    while stack and seen < MAX_STRINGS:
        node, node_path = stack.pop()
        seen += 1
        if isinstance(node, str):
            yield node_path, node
        elif isinstance(node, Mapping):
            for key, item in node.items():
                segment = str(key).replace("~", "~0").replace("/", "~1")
                stack.append((item, f"{node_path}/{segment}"))
        elif isinstance(node, list | tuple):
            for index, item in enumerate(node):
                stack.append((item, f"{node_path}/{index}"))


def _masked_locations(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    entries = payload.get("masked")
    if not isinstance(entries, list):
        return []
    return [
        {"path": entry["path"], "kind": entry["kind"]}
        for entry in entries
        if isinstance(entry, Mapping)
        and isinstance(entry.get("path"), str)
        and isinstance(entry.get("kind"), str)
    ]


def _gather(payload: Mapping[str, Any], sections: tuple[str, ...]) -> list[dict[str, str]]:
    """Evidence of secrets in the named payload sections: kind and path only, never a value."""
    prefixes = tuple(f"$/{section}" for section in sections)
    evidence = [
        {"signal": item["kind"], "field": _safe(item["path"], 220), "source": "masking"}
        for item in _masked_locations(payload)
        if item["path"].startswith(prefixes)
    ]
    covered = {item["field"] for item in evidence}
    for section in sections:
        for path, text in _strings(payload.get(section), f"$/{section}"):
            field = _safe(path, 220)
            residual = value_kind(text)
            if residual is not None:
                evidence.append(
                    {"signal": f"unmasked:{residual}", "field": field, "source": "residual"}
                )
            elif MASK in text and field not in covered:
                # Fallback for records written before masked-location metadata existed.
                evidence.append({"signal": "redacted_marker", "field": field, "source": "marker"})
    return evidence


def _is_auth_tool(tool: str, definition: Any) -> bool:
    if _AUTH_NAME.search(tool):
        return True
    if isinstance(definition, Mapping):
        schema = definition.get("input_schema")
        if isinstance(schema, Mapping) and isinstance(schema.get("properties"), Mapping):
            return any(_PASSWORD_PARAM.match(str(name)) for name in schema["properties"])
    return False


def _is_allowlisted(policy: Mapping[str, Any] | None, server: str, tool: str) -> bool:
    entries = (policy or {}).get("allowed_secret_tools", ())
    if not isinstance(entries, list | tuple):
        return False
    return any(
        isinstance(entry, Mapping)
        and str(entry.get("server")) == server
        and str(entry.get("tool")) == tool
        for entry in entries
    )


def _token_shaped(evidence: list[dict[str, str]]) -> bool:
    return any(
        item["signal"] in TOKEN_KINDS or item["signal"].startswith("unmasked:")
        for item in evidence
    )


def _pointer(event: Mapping[str, Any]) -> str:
    return _safe(f"{event.get('run_id', '')}:{event.get('order', '')}")


def _record(
    *,
    rule_id: str,
    family: str,
    event: Mapping[str, Any],
    tool: str,
    server: str,
    outcome: str,
    severity: str,
    is_finding: bool,
    message: str,
    evidence: list[dict[str, str]],
    note: str | None = None,
) -> dict[str, Any]:
    return {
        "gate_id": GATE_ID,
        "rule_id": rule_id,
        "family": family,
        "entity": {"server": _safe(server), "tool": _safe(tool)},
        "record_id": _pointer(event),
        "stage": _safe(str(event.get("stage") or "")),
        "outcome": outcome,
        "is_finding": is_finding,
        "suppressed": False,
        "severity": severity,
        "note": note,
        "owasp": OWASP,
        "evidence": evidence[:MAX_EVIDENCE_REPORTED],
        "evidence_count": len(evidence),
        "message": message,
    }


def evaluate(event: dict[str, Any], *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Findings for one importer event. ``policy`` must be trusted operator configuration."""
    if not isinstance(event, Mapping) or event.get("method") != "tools/call":
        return {"findings": []}
    stage = event.get("stage")
    sections = _SECTIONS.get(str(stage))
    if sections is None:
        return {"findings": []}
    server = str(event.get("server") or "")
    tool = str(event.get("name") or "")
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        return {"findings": [_record(
            rule_id=RULE_COVERAGE, family="coverage", event=event, tool=tool, server=server,
            outcome="INCONCLUSIVE", severity="medium", is_finding=True,
            message="No payload record for this tool call (the proxy ran without --payloads),"
                    " so secrets crossing the tool boundary cannot be checked.",
            evidence=[],
        )]}
    tool = str(payload.get("tool") or tool)
    evidence = _gather(payload, sections)
    if not evidence:
        return {"findings": []}  # nothing secret-like seen; that is not a clearance

    sent = stage == "request"
    rule_id = RULE_REQUEST if sent else RULE_RESPONSE
    family = "secret_to_tool" if sent else "secret_in_output"
    remote = (event.get("metadata") or {}).get("transport") == "http"
    direction = (
        f"sent to tool {_safe(tool)!r} on {'remote ' if remote else ''}server {_safe(server)!r}"
        if sent
        else f"returned by tool {_safe(tool)!r} on server {_safe(server)!r} into the model's"
             " context"
    )
    base = (
        f"A secret-like value was {direction}. The payload file holds only [REDACTED];"
        " the masked locations name where it was."
    )
    if _is_allowlisted(policy, server, tool):
        return {"findings": [_record(
            rule_id=rule_id, family=family, event=event, tool=tool, server=server,
            outcome="PASS", severity="info", is_finding=False,
            note="allowed by policy.allowed_secret_tools",
            message=base + " This server/tool pair is on the operator's allowed_secret_tools"
                    " list, so it is recorded as expected.",
            evidence=evidence,
        )]}
    if _is_auth_tool(tool, payload.get("tool_definition")):
        return {"findings": [_record(
            rule_id=rule_id, family=family, event=event, tool=tool, server=server,
            outcome="INCONCLUSIVE", severity="low", is_finding=True,
            note="tool looks like an authentication tool",
            message=base + " The tool looks like an authentication tool, where sending a"
                    " credential can be legitimate; review it.",
            evidence=evidence,
        )]}
    severity = "high" if _token_shaped(evidence) or remote else "medium"
    return {"findings": [_record(
        rule_id=rule_id, family=family, event=event, tool=tool, server=server,
        outcome="FAIL", severity=severity, is_finding=True,
        message=base, evidence=evidence,
    )]}
