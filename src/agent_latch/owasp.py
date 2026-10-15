"""OWASP Top 10 for Agentic Applications 2026: the single source of category IDs and names.

Names follow the table of contents of the OWASP publication
"OWASP Top 10 for Agentic Applications 2026" (OWASP-Top-10-for-Agentic-Applications-2026-12.6-1.pdf).
The mapping is informational; it is not a compliance assessment or an OWASP endorsement.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

OWASP_AGENTIC_VERSION = "2026"
OWASP_AGENTIC_TITLE = "OWASP Top 10 for Agentic Applications 2026"
OWASP_AGENTIC_URL = (
    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
)

ASI_CATEGORIES: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# Every category a rule can emit. Rules whose mapping depends on context (MAN001) list all options.
# Keep in sync with the rules and with the coverage table in AGENTS.md.
RULE_CATEGORIES: dict[str, tuple[str, ...]] = {
    "AGENTLATCH-PY001": ("ASI05", "ASI02"),
    "AGENTLATCH-PY002": ("ASI05", "ASI02"),
    "AGENTLATCH-PY003": ("ASI02",),
    "AGENTLATCH-AG001": ("ASI02", "ASI03"),
    "AGENTLATCH-AG002": ("ASI05", "ASI02"),
    "AGENTLATCH-AG003": ("ASI01",),
    "AGENTLATCH-AG004": ("ASI02", "ASI03", "ASI05", "ASI09"),
    "AGENTLATCH-AG005": ("ASI02", "ASI03", "ASI05"),
    "AGENTLATCH-AG006": ("ASI09", "ASI02", "ASI05"),
    "AGENTLATCH-AG007": ("ASI08",),
    "AGENTLATCH-SEC001": ("ASI03", "ASI04"),
    "AGENTLATCH-DEP001": ("ASI04",),
    "AGENTLATCH-MAN000": (),
    "AGENTLATCH-MAN001": ("ASI02", "ASI03", "ASI05", "ASI09"),
    "AGENTLATCH-MAN002": ("ASI02", "ASI03"),
    "AGENTLATCH-MAN003": ("ASI03", "ASI02"),
    "AGENTLATCH-PRM001": ("ASI01",),
    "AGENTLATCH-PRM002": ("ASI01",),
}


class _HasMapping(Protocol):
    rule_id: str
    owasp: tuple[str, ...]


def category_name(category_id: str) -> str:
    return ASI_CATEGORIES.get(category_id, "Unknown category")


def category_label(category_id: str) -> str:
    """'ASI05 Unexpected Code Execution (RCE)'."""
    return f"{category_id} {category_name(category_id)}"


def category_entries(category_ids: Iterable[str]) -> list[dict[str, str]]:
    return [{"id": cid, "name": category_name(cid)} for cid in category_ids]


def rules_for_category(category_id: str) -> list[str]:
    return sorted(rule for rule, cats in RULE_CATEGORIES.items() if category_id in cats)


def coverage(findings: Iterable[_HasMapping]) -> list[dict[str, Any]]:
    """Per-category finding counts, plus whether AgentLatch has any check for the category.

    `has_checks` means a rule exists; it does not mean the category is fully covered,
    and some rules only run with a manifest or --dependencies.
    """
    counts = dict.fromkeys(ASI_CATEGORIES, 0)
    for finding in findings:
        for category_id in set(finding.owasp):
            if category_id in counts:
                counts[category_id] += 1
    return [
        {
            "id": category_id,
            "name": name,
            "finding_count": counts[category_id],
            "has_checks": bool(rules_for_category(category_id)),
            "rules": rules_for_category(category_id),
        }
        for category_id, name in ASI_CATEGORIES.items()
    ]


def coverage_status(entry: dict[str, Any]) -> str:
    if not entry["has_checks"]:
        return "no checks yet"
    count = entry["finding_count"]
    return f"{count} finding(s)" if count else "no findings from enabled checks"
