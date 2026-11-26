"""Central configuration for SecReqAgents."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
KB_DIR = BASE_DIR / "kb"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
CASE_STUDIES_DIR = BASE_DIR / "case_studies"

AGENT1_ADAPTER_DIR = MODELS_DIR / "qwen2.5-3b-cc-agent1"
AGENT2_ADAPTER_DIR = MODELS_DIR / "qwen2.5-3b-cc-agent2"
BASE_MODEL_ID = os.getenv("SECREQ_BASE_MODEL", "unsloth/qwen2.5-3b-instruct-unsloth-bnb-4bit")
EMBEDDING_MODEL_ID = os.getenv("SECREQ_EMBED_MODEL", "all-MiniLM-L6-v2")

DB_PATH = DATA_DIR / "secreq.db"
AUDIT_LOG_PATH = LOGS_DIR / "audit_log.jsonl"

DOMAIN_SCOPES = [
    "Network & Boundary Protection (Firewalls / IDS / IPS / VPN)",
    "Identity, Access Control & Zero-Trust IAM (RBAC / MFA)",
    "Trusted Computing & Firmware Security (TPM / Secure Boot / OTA)",
    "Data Protection & Cryptography Platforms (KMS / DLP / Privacy)",
    "Security Operations, Audit & Compliance (SIEM / Logging / Incident Response)",
    "Cloud-Native & DevSecOps Services (API Gateways / Containers)",
]

REQUIREMENT_CATEGORIES = [
    "Business",
    "Stakeholder",
    "Functional",
    "Security",
    "Privacy",
    "Compliance / Regulatory",
    "Performance",
    "Availability & Reliability",
    "Usability",
    "Data Management",
    "Integration",
    "Audit & Reporting",
    "Operational & Maintenance",
]

STAKEHOLDER_ROLES = [
    "Customer / End User",
    "Business / Security Analyst",
    "Product Owner",
    "System Architect / Developer",
    "Information Security Engineer",
    "Compliance / Legal Officer",
    "Risk Management Officer",
    "Operations / SOC Lead",
    "Auditor / Common Criteria Evaluator",
]

RBAC_ROLES = [
    "admin",
    "analyst",
    "architect",
    "security_officer",
    "compliance_officer",
    "project_manager",
]

SDLC_JOINT_VOTE_ROLES = [
    "project_manager",
    "architect",
    "security_officer",
    "compliance_officer",
]

CONFIDENCE_REVIEW_THRESHOLD = 0.72

VAGUE_TERMS = [
    "fast",
    "quick",
    "quickly",
    "appropriate",
    "adequate",
    "sufficient",
    "user-friendly",
    "easy",
    "secure",
    "robust",
    "scalable",
    "flexible",
    "etc.",
    "and so on",
    "as needed",
    "timely",
    "efficient",
    "reasonable",
    "seamless",
    "state-of-the-art",
]

BASELINE_SECURITY_CONTROLS = [
    {
        "control_id": "BASE-AUTH",
        "title": "Multi-Factor & Interface-Bound Authentication",
        "keywords": ["mfa", "multi-factor", "authentication", "fia_uau", "credential", "step-up"],
        "default_statement": "The system shall enforce multi-factor authentication (MFA) for all administrative and privileged access sessions.",
        "standard_ref": "FIA_UAU.1 / NIST IA-2 / OWASP ASVS V2",
    },
    {
        "control_id": "BASE-CRYPTO",
        "title": "Encryption in Transit and at Rest",
        "keywords": ["encrypt", "tls", "aes", "cipher", "fcs_cop", "cryptographic", "key"],
        "default_statement": "The system shall protect sensitive data in transit using TLS 1.3 and at rest using AES-256-GCM with managed keys.",
        "standard_ref": "FCS_COP.1 / NIST SC-8, SC-28 / ISO 27001 A.8.24",
    },
    {
        "control_id": "BASE-AUDIT",
        "title": "Tamper-Evident Security Audit Logging",
        "keywords": ["audit", "log", "fau_gen", "siem", "trail", "tamper"],
        "default_statement": "The system shall record immutable, time-synchronized audit logs for authentication, privilege changes, and policy violations.",
        "standard_ref": "FAU_GEN.1 / NIST AU-2, AU-9 / ISO 27001 A.8.15",
    },
    {
        "control_id": "BASE-RBAC",
        "title": "Least-Privilege Access Control",
        "keywords": ["rbac", "role-based", "access control", "fdp_acc", "least privilege", "authorization"],
        "default_statement": "The system shall enforce role-based access control (RBAC) with restrictive default permissions across all subjects and objects.",
        "standard_ref": "FDP_ACC.2 / FMT_MSA.3 / NIST AC-3, AC-6",
    },
]
