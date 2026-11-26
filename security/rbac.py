"""Role-Based Access Control (RBAC), agent least-privilege permissions, and local auth."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from config import DATA_DIR, RBAC_ROLES, SDLC_JOINT_VOTE_ROLES

USERS_FILE = DATA_DIR / "users.json"

# Least-privilege allowlist: each agent only receives the state keys it needs.
AGENT_PERMISSIONS: dict[str, dict[str, list[str]]] = {
    "interview": {
        "read": ["domain", "stakeholder_role", "history", "kb_hints"],
        "write": ["interview_transcripts"],
    },
    "extractor": {
        "read": ["project_brief", "retrieved_doc_excerpts", "retrieved_kb_excerpts"],
        "write": ["requirements"],
    },
    "quality": {
        "read": ["requirements", "retrieved_kb_excerpts"],
        "write": ["quality_issues", "clarification_questions", "conflicts"],
    },
    "compliance_risk": {
        "read": ["requirements", "retrieved_kb_excerpts"],
        "write": ["compliance_mappings", "risk_register", "suggested_controls"],
    },
    "sdlc": {
        "read": ["requirements", "sdlc_factors", "project_metadata"],
        "write": ["sdlc_recommendation"],
    },
    "workflow": {
        "read": ["sdlc_recommendation", "requirements", "compliance_mappings"],
        "write": ["sdlc_workflow"],
    },
}

ACTION_ROLES: dict[str, set[str]] = {
    "manage_kb": {"admin"},
    "manage_users": {"admin"},
    "view_audit": {"admin", "compliance_officer", "security_officer"},
    "review_general": {"admin", "analyst", "architect", "security_officer", "compliance_officer", "project_manager"},
    "approve_security_req": {"admin", "security_officer"},
    "approve_compliance_mapping": {"admin", "compliance_officer"},
    "approve_architecture_req": {"admin", "architect"},
    "approve_conflict": {"admin", "project_manager"},
    "vote_sdlc": set(SDLC_JOINT_VOTE_ROLES) | {"admin"},
    "lock_baseline": {"admin", "project_manager"},
    "approve_change_request": {"admin", "project_manager"},
    "approve_production_readiness": {"admin", "project_manager", "security_officer", "compliance_officer"},
}


def filter_state_for_agent(agent_name: str, full_state: dict[str, Any]) -> dict[str, Any]:
    """Enforce least privilege by exposing only permitted state fields to an agent."""
    allowed = AGENT_PERMISSIONS.get(agent_name, {}).get("read", [])
    return {k: full_state[k] for k in allowed if k in full_state}


def authorize_action(user_roles: list[str], action: str) -> tuple[bool, str]:
    allowed = ACTION_ROLES.get(action, set())
    if not allowed:
        return True, "No restriction configured."
    if set(user_roles) & allowed:
        return True, "Authorized."
    return False, f"Action '{action}' requires one of roles: {sorted(allowed)}"


def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return salt, digest


class AuthManager:
    """Lightweight local user/role store with salted PBKDF2 password hashing."""

    def __init__(self, users_path: Path | str = USERS_FILE) -> None:
        self.users_path = Path(users_path)
        self.users_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.users_path.exists():
            self._seed_defaults()

    def _seed_defaults(self) -> None:
        default_users = {
            "admin": ["admin", "analyst", "architect", "security_officer", "compliance_officer", "project_manager"],
            "analyst": ["analyst"],
            "architect": ["architect"],
            "sec_officer": ["security_officer"],
            "compliance": ["compliance_officer"],
            "pm": ["project_manager"],
        }
        records: dict[str, dict[str, Any]] = {}
        for username, roles in default_users.items():
            salt, digest = _hash_password(os.getenv("SECREQ_DEMO_PASS", "demo1234"))
            records[username] = {"salt": salt, "password_hash": digest, "roles": roles}
        self._save(records)

    def _load(self) -> dict[str, dict[str, Any]]:
        with self.users_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data: dict[str, dict[str, Any]]) -> None:
        with self.users_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        users = self._load()
        rec = users.get(username)
        if not rec:
            return None
        _, candidate = _hash_password(password, rec["salt"])
        if hmac.compare_digest(candidate, rec["password_hash"]):
            return {"username": username, "roles": rec["roles"]}
        return None

    def register(self, username: str, password: str, roles: list[str] | None = None) -> tuple[bool, str]:
        users = self._load()
        if not username.strip() or username in users:
            return False, "Invalid or duplicate username."
        valid_roles = [r for r in (roles or ["analyst"]) if r in RBAC_ROLES] or ["analyst"]
        salt, digest = _hash_password(password)
        users[username] = {"salt": salt, "password_hash": digest, "roles": valid_roles}
        self._save(users)
        return True, f"User '{username}' created with roles {valid_roles}."

    def list_users(self) -> list[dict[str, Any]]:
        return [{"username": u, "roles": info["roles"]} for u, info in self._load().items()]

    def set_roles(self, username: str, roles: list[str]) -> bool:
        users = self._load()
        if username not in users:
            return False
        users[username]["roles"] = [r for r in roles if r in RBAC_ROLES]
        self._save(users)
        return True
