"""Deterministic grounding, citation verification, number checking, and confidence scoring."""
from __future__ import annotations

import re
from typing import Any

from config import CONFIDENCE_REVIEW_THRESHOLD

_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_STOPWORDS = {
    "the", "shall", "system", "must", "with", "from", "that", "this", "for", "and", "all",
    "any", "into", "using", "before", "after", "only", "when", "where", "each", "are", "via",
}


def verify_requirement_grounding(
    req: dict[str, Any],
    kb_excerpts: list[dict[str, Any]],
    doc_excerpts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Check citations, numeric grounding, and lexical support against retrieved sources."""
    source_texts = [e.get("text", "") for e in kb_excerpts] + [d.get("text", "") for d in doc_excerpts]
    combined_source = "\n".join(source_texts).lower()

    known_ids: set[str] = set()
    for kb in kb_excerpts:
        known_ids.add(str(kb.get("id", "")).upper())
        for sfr in kb.get("sfr_ids", []):
            known_ids.add(str(sfr).upper())
    for doc in doc_excerpts:
        known_ids.add(str(doc.get("excerpt_id", "")).upper())
        for sfr in doc.get("sfr_ids", []):
            known_ids.add(str(sfr).upper())

    cited = [str(c).strip() for c in req.get("citations", []) if str(c).strip()]
    source_ref = str(req.get("source_ref", "")).strip()
    if source_ref and source_ref not in cited:
        cited.append(source_ref)

    valid_citations: list[str] = []
    invalid_citations: list[str] = []
    for c in cited:
        cu = c.upper()
        if any(kid and kid in cu for kid in known_ids) or cu in known_ids:
            valid_citations.append(c)
        else:
            invalid_citations.append(c)

    citation_score = 1.0 if valid_citations and not invalid_citations else (0.65 if valid_citations else 0.2)

    # Number grounding: numbers inside statement should appear in source text (ignore version/req IDs)
    stmt = str(req.get("statement", ""))
    stmt_nums = set(_NUMBER_RE.findall(stmt))
    source_nums = set(_NUMBER_RE.findall(combined_source))
    ungrounded_nums = [n for n in stmt_nums if n not in source_nums and int(float(n)) > 1]
    number_score = 1.0 if not ungrounded_nums else max(0.3, 1.0 - 0.25 * len(ungrounded_nums))

    # Lexical claim support
    tokens = [w for w in re.findall(r"[a-zA-Z]{4,}", stmt.lower()) if w not in _STOPWORDS]
    if tokens and combined_source:
        hits = sum(1 for t in tokens if t in combined_source)
        support_score = min(1.0, hits / max(1, len(tokens) * 0.65))
    else:
        support_score = 0.5

    confidence = round(0.45 * citation_score + 0.20 * number_score + 0.35 * support_score, 3)

    flags: list[str] = []
    if not valid_citations:
        flags.append("missing_verified_citation")
    if invalid_citations:
        flags.append(f"unverified_citation:{','.join(invalid_citations)}")
    if ungrounded_nums:
        flags.append(f"ungrounded_numbers:{','.join(ungrounded_nums)}")

    needs_review = confidence < CONFIDENCE_REVIEW_THRESHOLD or bool(flags)

    return {
        "confidence": confidence,
        "citation_score": round(citation_score, 3),
        "number_score": round(number_score, 3),
        "support_score": round(support_score, 3),
        "valid_citations": valid_citations,
        "flags": flags,
        "needs_human_review": needs_review,
    }
