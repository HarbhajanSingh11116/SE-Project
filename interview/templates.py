"""Role-specific stakeholder templates and 12 adaptive security engineering topics."""
from __future__ import annotations

INTERVIEW_TOPICS = [
    {
        "id": "objectives",
        "title": "System Objectives & Protected Assets",
        "prompt": "What core system functionality and high-value assets must be protected (e.g., network perimeter, IAM credentials, TPM keys, audit logs)?",
        "requires_quant": False,
    },
    {
        "id": "users_roles",
        "title": "Users, Roles & Privilege Boundaries",
        "prompt": "Which user roles and administrative tiers interact with the system, and what separation of duties is required?",
        "requires_quant": False,
    },
    {
        "id": "workflow",
        "title": "Operational Workflow & Data Flows",
        "prompt": "Describe the end-to-end operational flow, ingress/egress interfaces, and trusted vs. untrusted boundaries.",
        "requires_quant": False,
    },
    {
        "id": "authn_authz",
        "title": "Authentication & Access Control",
        "prompt": "What authentication mechanisms (e.g., MFA, certificate, interface binding) and authorization rules (RBAC/ABAC, default-deny) must be enforced?",
        "requires_quant": False,
    },
    {
        "id": "crypto_data",
        "title": "Data Protection & Cryptography",
        "prompt": "What encryption algorithms, key sizes, key rotation schedules, and sensitive data retention limits apply?",
        "requires_quant": True,
    },
    {
        "id": "exceptions",
        "title": "Exceptional Conditions & Tamper Handling",
        "prompt": "How should the system behave under invalid signatures, tampered hardware/packets, or failed self-tests (fail-closed vs. fail-open)?",
        "requires_quant": False,
    },
    {
        "id": "audit",
        "title": "Audit Logging & Forensics",
        "prompt": "Which security events must be logged, where are logs stored/forwarded (e.g., SIEM), and for how many days?",
        "requires_quant": True,
    },
    {
        "id": "performance",
        "title": "Performance, Throughput & Availability",
        "prompt": "Specify measurable latency, throughput, and uptime/SLA targets (e.g., <10ms inspection, 99.99% availability).",
        "requires_quant": True,
    },
    {
        "id": "legacy_integration",
        "title": "Legacy & External System Integration",
        "prompt": "Which legacy hardware, identity providers, HSMs, or external APIs must integrate with this system, and what constraints do they impose?",
        "requires_quant": False,
    },
    {
        "id": "compliance",
        "title": "Regulatory & Standards Targets",
        "prompt": "Which standards or regulations apply (Common Criteria EAL level, NIST 800-53, ISO 27001, OWASP ASVS, GDPR)?",
        "requires_quant": False,
    },
    {
        "id": "change_cadence",
        "title": "Expected Change Frequency & Delivery Model",
        "prompt": "How frequently will rules, policies, or firmware change (daily CI/CD updates vs. immutable post-manufacture release)?",
        "requires_quant": False,
    },
    {
        "id": "budget_schedule",
        "title": "Schedule, Budget & Verification Constraints",
        "prompt": "What are the target delivery timeline, budget boundaries, and formal evaluation/pen-test gates?",
        "requires_quant": True,
    },
]

ROLE_TEMPLATES: dict[str, dict] = {
    "Customer / End User": {
        "focus_topics": ["objectives", "workflow", "performance", "exceptions"],
        "opening": "Focus on daily operational usability, response latency expectations, and failure visibility.",
    },
    "Business / Security Analyst": {
        "focus_topics": ["objectives", "users_roles", "workflow", "compliance", "exceptions"],
        "opening": "Focus on asset scope, business justification, role boundaries, and measurable acceptance criteria.",
    },
    "Product Owner": {
        "focus_topics": ["objectives", "change_cadence", "budget_schedule", "performance"],
        "opening": "Focus on release priorities, expected feature/rule churn, schedule, and stakeholder availability.",
    },
    "System Architect / Developer": {
        "focus_topics": ["workflow", "authn_authz", "crypto_data", "legacy_integration", "performance"],
        "opening": "Focus on trust boundaries, interface protocols, cryptographic primitives, and legacy constraints.",
    },
    "Information Security Engineer": {
        "focus_topics": ["authn_authz", "crypto_data", "exceptions", "audit", "change_cadence"],
        "opening": "Focus on threat vectors, Common Criteria SFRs, tamper resistance, and CI/CD security gates.",
    },
    "Compliance / Legal Officer": {
        "focus_topics": ["compliance", "audit", "crypto_data", "users_roles"],
        "opening": "Focus on regulatory jurisdiction, retention mandates, evidence trails, and mandatory sign-off gates.",
    },
    "Risk Management Officer": {
        "focus_topics": ["exceptions", "legacy_integration", "compliance", "budget_schedule"],
        "opening": "Focus on worst-case failure impact, unmitigated threats, and risk tolerance thresholds.",
    },
    "Operations / SOC Lead": {
        "focus_topics": ["audit", "performance", "exceptions", "change_cadence"],
        "opening": "Focus on SIEM alerting, incident containment SLAs, patching cadence, and operational uptime.",
    },
    "Auditor / Common Criteria Evaluator": {
        "focus_topics": ["compliance", "audit", "authn_authz", "crypto_data"],
        "opening": "Focus on objective testability, independent evidence artifacts, and non-repudiation.",
    },
}
