"""SQLite persistence for projects, runs, baselines, change requests, and stakeholder feedback."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import DB_PATH


class ProjectStore:
    """Thread-safe SQLite store for project runs, baselines, change requests, and feedback."""

    def __init__(self, db_path: Path | str = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    project_name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    status TEXT NOT NULL,
                    state_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS baselines (
                    baseline_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    locked_by TEXT NOT NULL,
                    locked_at TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS change_requests (
                    cr_id TEXT PRIMARY KEY,
                    baseline_id TEXT NOT NULL,
                    req_id TEXT NOT NULL,
                    proposed_statement TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    status TEXT NOT NULL,
                    decided_by TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    stakeholder TEXT NOT NULL,
                    rating INTEGER NOT NULL,
                    comment TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )

    def save_run(self, run_state: dict[str, Any]) -> str:
        run_id = run_state.get("run_id") or f"RUN-{uuid.uuid4().hex[:8].upper()}"
        run_state["run_id"] = run_id
        now = run_state.get("created_at") or datetime.now(timezone.utc).isoformat()
        run_state["created_at"] = now
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs (run_id, project_name, domain, created_at, created_by, status, state_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    run_state.get("project_name", "Untitled"),
                    run_state.get("domain", "Cybersecurity"),
                    now,
                    run_state.get("created_by", "system"),
                    run_state.get("status", "Awaiting Review"),
                    json.dumps(run_state, ensure_ascii=False),
                ),
            )
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT state_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return json.loads(row["state_json"]) if row else None

    def list_runs(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT run_id, project_name, domain, created_at, created_by, status FROM runs ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def lock_baseline(self, run_id: str, locked_by: str) -> dict[str, Any]:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found.")
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS max_v FROM baselines WHERE project_name = ?",
                (run["project_name"],),
            ).fetchone()
            next_v = int(row["max_v"]) + 1
            bid = f"BASE-{run['project_name'][:8].upper().replace(' ', '')}-V{next_v}"
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                INSERT INTO baselines (baseline_id, run_id, project_name, version, locked_by, locked_at, snapshot_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (bid, run_id, run["project_name"], next_v, locked_by, now, json.dumps(run, ensure_ascii=False)),
            )
        run["status"] = f"Baseline Locked (v{next_v})"
        run["baseline_id"] = bid
        self.save_run(run)
        return {"baseline_id": bid, "version": next_v, "locked_by": locked_by, "locked_at": now}

    def list_baselines(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT baseline_id, run_id, project_name, version, locked_by, locked_at FROM baselines ORDER BY locked_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def create_change_request(
        self, baseline_id: str, req_id: str, proposed_statement: str, reason: str, requested_by: str
    ) -> str:
        cr_id = f"CR-{uuid.uuid4().hex[:6].upper()}"
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO change_requests (cr_id, baseline_id, req_id, proposed_statement, reason, requested_by, status, decided_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'Pending', NULL, ?)
                """,
                (cr_id, baseline_id, req_id, proposed_statement, reason, requested_by, now),
            )
        return cr_id

    def list_change_requests(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM change_requests ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def decide_change_request(self, cr_id: str, decision: str, decided_by: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE change_requests SET status = ?, decided_by = ? WHERE cr_id = ?",
                (decision, decided_by, cr_id),
            )

    def add_feedback(self, run_id: str, stakeholder: str, rating: int, comment: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO feedback (run_id, stakeholder, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)",
                (run_id, stakeholder, int(rating), comment, now),
            )

    def list_feedback(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM feedback ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
