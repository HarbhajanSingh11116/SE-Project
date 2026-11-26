"""Security controls: masking, prompt-injection defense, RBAC, and audit logging."""
from security.audit import AuditLogger, verify_audit_chain
from security.injection import frame_untrusted_text, scan_and_quarantine
from security.masking import mask_payload, mask_text
from security.rbac import AGENT_PERMISSIONS, AuthManager, authorize_action, filter_state_for_agent

__all__ = [
    "AGENT_PERMISSIONS",
    "AuditLogger",
    "AuthManager",
    "authorize_action",
    "filter_state_for_agent",
    "frame_untrusted_text",
    "mask_payload",
    "mask_text",
    "scan_and_quarantine",
    "verify_audit_chain",
]
