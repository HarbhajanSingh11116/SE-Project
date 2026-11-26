"""Tamper-evident hash-chained audit trail (JSONL)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import AUDIT_LOG_PATH
from security.masking import mask_payload


def _compute_hash(record_without_hash: dict[str, Any]) -> str:
    canonical = json.dumps(record_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLogger:
    """Append-only SHA-256 hash-chained audit log."""

    def __init__(self, log_path: Path | str = AUDIT_LOG_PATH) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return "GENESIS"
        last_line = ""
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return "GENESIS"
        return json.loads(last_line).get("entry_hash", "GENESIS")

    def log(
        self,
        action: str,
        actor: str = "system",
        role: str = "system",
        project_id: str = "",
        run_id: str = "",
        details: Any = None,
    ) -> dict[str, Any]:
        masked_details, mask_counts = mask_payload(details if details is not None else {})
        prev_hash = self._last_hash()
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "actor": actor,
            "role": role,
            "project_id": project_id,
            "run_id": run_id,
            "details": masked_details,
            "mask_counts": mask_counts,
            "prev_hash": prev_hash,
        }
        payload["entry_hash"] = _compute_hash(payload)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return payload

    def read_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        with self.log_path.open("r", encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
        return rows[-limit:]


def verify_audit_chain(log_path: Path | str = AUDIT_LOG_PATH) -> tuple[bool, str, int]:
    """Verify every hash link in the audit log. Returns (valid, message, count)."""
    path = Path(log_path)
    if not path.exists():
        return True, "No audit log created yet (empty chain).", 0

    expected_prev = "GENESIS"
    count = 0
    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            recorded_hash = record.pop("entry_hash", "")
            if record.get("prev_hash") != expected_prev:
                return False, f"Chain broken at line {idx}: prev_hash mismatch.", count
            recomputed = _compute_hash(record)
            if recorded_hash != recomputed:
                return False, f"Tampering detected at line {idx}: entry_hash mismatch.", count
            expected_prev = recorded_hash
            count += 1
    return True, f"Verified {count} audit records intact.", count
