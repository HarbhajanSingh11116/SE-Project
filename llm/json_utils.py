"""Robust JSON extraction and repair for LLM outputs (fixes raw prefix / code-fence issues)."""
from __future__ import annotations

import json
import re
from typing import Any

from json_repair import repair_json

_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def extract_json_payload(raw_text: str) -> Any:
    """Extract and repair the first JSON object or array from an LLM response."""
    if not raw_text or not raw_text.strip():
        raise ValueError("Empty LLM response.")

    text = raw_text.strip()
    fence_match = _CODE_FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1).strip()

    # Locate earliest '[' or '{' to skip prose prefixes like "Based on the retrieved source material..."
    arr_idx = text.find("[")
    obj_idx = text.find("{")
    candidates = [i for i in (arr_idx, obj_idx) if i != -1]
    if not candidates:
        raise ValueError(f"No JSON object or array found in output: {text[:160]}")

    start = min(candidates)
    open_ch = text[start]
    close_ch = "]" if open_ch == "[" else "}"
    end = text.rfind(close_ch)
    snippet = text[start : end + 1] if end > start else text[start:]

    try:
        return json.loads(snippet)
    except json.JSONDecodeError:
        repaired = repair_json(snippet, return_objects=True)
        if repaired in ("", None) and snippet not in ("[]", "{}"):
            raise ValueError(f"Unable to repair JSON output: {snippet[:200]}")
        return repaired
