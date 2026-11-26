"""Prompt-injection detection, quarantine, and untrusted-data framing."""
from __future__ import annotations

import re
from dataclasses import dataclass

INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"(?i)disregard\s+(the\s+)?(system|safety|security)\s+(prompt|rules|policy)", "policy_bypass"),
    (r"(?i)(reveal|print|dump|output)\s+(your\s+)?(system\s+prompt|hidden\s+instructions)", "prompt_exfiltration"),
    (r"(?i)you\s+are\s+now\s+(dan|unrestricted|jailbroken|root)", "role_hijack"),
    (r"<\|im_start\|>|<\|im_end\|>|<\|system\|>", "chat_template_smuggling"),
    (r"(?i)\b(auto[- ]?approve|mark\s+all\s+compliant|skip\s+human\s+review)\b", "approval_tampering"),
]


@dataclass
class ScanResult:
    source_id: str
    safe: bool
    reasons: list[str]
    text: str


def scan_and_quarantine(excerpts: list[dict]) -> tuple[list[dict], list[dict]]:
    """Separate clean excerpts from excerpts containing prompt-injection indicators."""
    clean: list[dict] = []
    quarantined: list[dict] = []

    for item in excerpts:
        text = str(item.get("text", ""))
        reasons = [label for pattern, label in INJECTION_PATTERNS if re.search(pattern, text)]
        if reasons:
            flagged = dict(item)
            flagged["quarantined"] = True
            flagged["quarantine_reasons"] = reasons
            quarantined.append(flagged)
        else:
            clean.append(item)

    return clean, quarantined


def frame_untrusted_text(source_id: str, text: str) -> str:
    """Wrap untrusted stakeholder or document text in explicit non-executable data delimiters."""
    sanitized = text.replace("<<<END_UNTRUSTED_DATA>>>", "[ESCAPED_END]")
    return f"<<<UNTRUSTED_DATA id=\"{source_id}\">>>\n{sanitized}\n<<<END_UNTRUSTED_DATA>>>"
