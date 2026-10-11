"""Prompt-text checks (PRM001, PRM002) shared by manifest and source-code scanning."""

from __future__ import annotations

import re

from agent_latch.findings import Finding

INJECTION_SIGNATURES = (
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|dan\b|jailbroken|unrestricted)"),
    re.compile(r"(?i)\b(?:reveal|print|output)\s+(?:your|the)\s+(?:system\s+prompt|hidden\s+instructions)"),
    re.compile(r"(?i)\bwithout\s+(?:telling|informing|notifying)\s+the\s+user\b"),
)
UNTRUSTED_PLACEHOLDER = re.compile(
    r"(\{\{\s*|\$\{|\{)\s*(\w*(?:user|input|query|message|request|question)\w*)\s*(?:\}\}|\})",
    re.IGNORECASE,
)
# Names like {message_count} or {user_id} hold numbers or identifiers, not user-written text.
_NON_TEXT_SUFFIX = re.compile(
    r"(?i)(?:_|^)(?:count|counts|id|ids|len|length|total|num|number|index|idx|size|type|time|at|ts)$"
)


def untrusted_placeholder(line: str) -> re.Match[str] | None:
    """First user-input-like placeholder on the line that could hold free text."""
    for match in UNTRUSTED_PLACEHOLDER.finditer(line):
        if not _NON_TEXT_SUFFIX.search(match.group(2).split(".")[-1]):
            return match
    return None


def check_prompt_text(
    text: str,
    path: str,
    base_line: int,
    label: str,
    is_system: bool,
    base_column: int = 1,
) -> list[Finding]:
    """Run PRM001 (injection phrases) and, for system prompts, PRM002 (user-input placeholders).

    `base_column` applies to the first line only, for strings that start mid-line in source code.
    """
    findings: list[Finding] = []
    for offset, line in enumerate(text.splitlines()):
        column_shift = base_column - 1 if offset == 0 else 0
        for signature in INJECTION_SIGNATURES:
            match = signature.search(line)
            if match:
                findings.append(
                    Finding(
                        rule_id="AGENTLATCH-PRM001",
                        title="Prompt-injection signature in prompt",
                        severity="medium",
                        message=(
                            f"{label} contains an instruction-override phrase commonly used in prompt injection. "
                            "Check whether this text came from an untrusted source."
                        ),
                        path=path,
                        line=base_line + offset,
                        column=match.start() + 1 + column_shift,
                        owasp=("ASI01",),
                        confidence="medium",
                        evidence=f'"{match.group(0)[:80]}"',
                    )
                )
                break
        if is_system:
            match = untrusted_placeholder(line)
            if match:
                findings.append(
                    Finding(
                        rule_id="AGENTLATCH-PRM002",
                        title="Untrusted input interpolated into system prompt",
                        severity="medium",
                        message=(
                            f"{label} inserts a user-controlled variable into system-level instructions. "
                            "Pass user input in the user turn, delimited and labeled as data."
                        ),
                        path=path,
                        line=base_line + offset,
                        column=match.start() + 1 + column_shift,
                        owasp=("ASI01",),
                        confidence="low",
                        evidence=f"placeholder {match.group(0)}",
                    )
                )
    return findings
