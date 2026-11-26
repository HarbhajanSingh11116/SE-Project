"""Sensitive-data classification and masking prior to LLM exposure or logging."""
from __future__ import annotations

import re
from typing import Any


def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse = digits[::-1]
    for idx, ch in enumerate(reverse):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api_key|apikey|token|private_key)\s*[:=]\s*(['\"]?)([^\s'\";,]{4,})\2"
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
_API_TOKEN_RE = re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_LABELED_NAME_RE = re.compile(r"(?im)^(Name|User|Customer|Employee|Stakeholder)\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})$")


def mask_text(text: str) -> tuple[str, dict[str, int]]:
    """Mask PII, credentials, IPs, and financial identifiers with deterministic placeholders."""
    if not text:
        return text, {}

    counts: dict[str, int] = {}
    value_to_token: dict[tuple[str, str], str] = {}

    def _token(kind: str, raw: str) -> str:
        key = (kind, raw)
        if key not in value_to_token:
            counts[kind] = counts.get(kind, 0) + 1
            value_to_token[key] = f"<{kind}_{counts[kind]}>"
        return value_to_token[key]

    masked = text

    def _replace_secret_kv(match: re.Match[str]) -> str:
        label = match.group(1)
        secret_val = match.group(3)
        return f"{label}={_token('SECRET', secret_val)}"

    masked = _SECRET_KV_RE.sub(_replace_secret_kv, masked)
    masked = _BEARER_RE.sub(lambda m: f"Bearer {_token('TOKEN', m.group(0))}", masked)
    masked = _API_TOKEN_RE.sub(lambda m: _token("API_KEY", m.group(0)), masked)
    masked = _EMAIL_RE.sub(lambda m: _token("EMAIL", m.group(0)), masked)
    masked = _PAN_RE.sub(lambda m: _token("PAN", m.group(0)), masked)
    masked = _SSN_RE.sub(lambda m: _token("SSN", m.group(0)), masked)

    def _replace_card(match: re.Match[str]) -> str:
        raw = match.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if _luhn_valid(digits):
            return _token("CARD", digits)
        return raw

    masked = _CARD_CANDIDATE_RE.sub(_replace_card, masked)
    masked = _IPV4_RE.sub(lambda m: _token("IP", m.group(0)), masked)
    masked = _PHONE_RE.sub(lambda m: _token("PHONE", m.group(0)), masked)
    masked = _LABELED_NAME_RE.sub(lambda m: f"{m.group(1)}: {_token('PERSON', m.group(2))}", masked)

    return masked, counts


def mask_payload(obj: Any) -> tuple[Any, dict[str, int]]:
    """Recursively mask all strings inside nested dicts/lists."""
    total_counts: dict[str, int] = {}

    def _merge(c: dict[str, int]) -> None:
        for k, v in c.items():
            total_counts[k] = total_counts.get(k, 0) + v

    def _walk(item: Any) -> Any:
        if isinstance(item, str):
            out, c = mask_text(item)
            _merge(c)
            return out
        if isinstance(item, list):
            return [_walk(x) for x in item]
        if isinstance(item, dict):
            return {k: _walk(v) for k, v in item.items()}
        return item

    return _walk(obj), total_counts
