"""Prompt-text checks (PRM001, PRM002, ALR01-S01) shared by manifest and source-code scanning."""

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
# Zero-width, bidi-control and tag characters that can hide instructions from a reader.
_HIDDEN = re.compile(
    "[\u00ad\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
# Joiners inside an emoji or a non-Latin word are legitimate, so they are skipped there.
_JOINERS = {"\u200c", "\u200d"}


def hidden_character(line: str) -> tuple[int, str] | None:
    """(index, 'U+XXXX') for the first invisible or bidi character a reader cannot see."""
    for match in _HIDDEN.finditer(line):
        char = match.group(0)
        if char in _JOINERS:
            before = line[match.start() - 1] if match.start() else ""
            after = line[match.end()] if match.end() < len(line) else ""
            if any(item and ord(item) > 0x7F for item in (before, after)):
                continue
        return match.start(), f"U+{ord(char):04X}"
    return None


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
    """Run PRM001, ALR01-S01 and, for system prompts, PRM002 over one prompt.

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
        hidden = hidden_character(line)
        if hidden is not None and hidden[1] == "U+FEFF" and hidden[0] == 0 and base_line + offset == 1:
            hidden = None  # a UTF-8 byte-order mark at the start of the file is not an injection
        if hidden is not None:
            index, code_point = hidden
            findings.append(
                Finding(
                    rule_id="ALR01-S01",
                    title="Invisible character in prompt",
                    severity="medium",
                    message=(
                        f"{label} contains an invisible or direction-control character ({code_point}). "
                        "Text hidden this way changes what the model reads without changing what a "
                        "reviewer sees. Remove the character, and review how it was added."
                    ),
                    path=path,
                    line=base_line + offset,
                    column=index + 1 + column_shift,
                    owasp=("ASI01",),
                    confidence="medium",
                    evidence=f"invisible character {code_point}",
                )
            )
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
