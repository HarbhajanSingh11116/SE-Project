"""Compliance & Security Mapping Agent + Threat & Risk Analysis Agent."""
from __future__ import annotations

import re
from typing import Any

from agents.schemas import ComplianceMapping, RequirementItem, RiskEntry
from llm.engine import LLMEngine
from rag.retriever import KnowledgeBaseRetriever


class ComplianceRiskAgent:
    """Maps requirements to KB regulations/standards and builds the Threat & Risk Register."""

    def __init__(self, kb: KnowledgeBaseRetriever, llm: LLMEngine) -> None:
        self.kb = kb
        self.llm = llm

    def run(self, requirements: list[RequirementItem]) -> tuple[list[ComplianceMapping], list[RiskEntry]]:
        mappings: list[ComplianceMapping] = []
        risks: list[RiskEntry] = []

        for idx, req in enumerate(requirements, start=1):
            hits = self.kb.retrieve(f"{req.statement} {' '.join(req.citations)}", top_k=2)
            primary = hits[0] if hits else {
                "id": "KB-OWASP-ASVS",
                "standard": "OWASP ASVS v4.0.3",
                "jurisdiction": "Global Application Security",
                "controls": ["Input Validation & Security Verification"],
                "retention_duty": "Retain compliance audit logs per policy.",
                "text": "Apply least privilege and strict validation controls.",
            }

            controls = ", ".join(primary.get("controls", [])) or primary.get("title", "Security Control")
            lower = req.statement.lower()
            gap = "None identified"
            if req.confidence_score < 0.72:
                gap = "Low grounding confidence; verify standard clause and measurable metric."
            elif "encrypt" in lower and not re.search(r"aes|tls|rsa|ecdsa|sha|256|384", lower):
                gap = "Cryptographic requirement omits explicit approved algorithm/key-length."
            elif "log" in lower and not re.search(r"\d+\s*(day|month|year)", lower):
                gap = "Audit requirement omits explicit retention period."

            high_impact = req.priority in {"Critical", "High"} or gap != "None identified"
            mappings.append(
                ComplianceMapping(
                    mapping_id=f"CMP-{idx:03d}",
                    req_id=req.req_id,
                    kb_id=primary.get("id", "KB-GEN"),
                    standard=primary.get("standard", "Cybersecurity Standard"),
                    jurisdiction=primary.get("jurisdiction", "International"),
                    required_control=controls,
                    evidence_excerpt=primary.get("text", "")[:220],
                    compliance_gap=gap,
                    mandatory_checkpoint="Compliance & Security Officer Review before Architecture Freeze" if high_impact else "Standard Peer Review",
                    retention_obligation=primary.get("retention_duty", "Retain verification evidence for 365 days."),
                    requires_compliance_officer_approval=high_impact,
                )
            )

            # Threat & Risk Register entry
            if any(w in lower for w in ["tamper", "physical", "firmware", "signature", "tpm"]):
                threat = f"Unauthorized firmware modification or hardware tampering bypassing {req.req_id}."
                category = "Security"
                likelihood = "Medium"
                impact = "Critical"
                rating = "Critical"
                mitigation = "Enforce cryptographic signature verification (ECDSA/RSA-3072), hardware tamper zeroization, and boot self-tests."
            elif any(w in lower for w in ["firewall", "traffic", "network", "interface", "authentication", "rbac", "access"]):
                threat = f"Privilege escalation or cross-interface access bypass violating {req.req_id}."
                category = "Security"
                likelihood = "High"
                impact = "High"
                rating = "High"
                mitigation = "Enforce default-deny SFP, interface-bound MFA/auth, and automated negative authorization tests in CI."
            elif any(w in lower for w in ["audit", "log", "retention", "compliance", "regulation"]):
                threat = f"Audit blind spots or regulatory non-compliance due to incomplete enforcement of {req.req_id}."
                category = "Compliance"
                likelihood = "Medium"
                impact = "High"
                rating = "High"
                mitigation = "Forward immutable logs to external SIEM with automated retention & hash-chain verification."
            else:
                threat = f"Operational or technical failure degrading control effectiveness for {req.req_id}."
                category = "Technical"
                likelihood = "Low"
                impact = "Medium"
                rating = "Medium"
                mitigation = "Add automated regression tests and runtime health checks in staging."

            risks.append(
                RiskEntry(
                    risk_id=f"RSK-{idx:03d}",
                    req_id=req.req_id,
                    threat_description=threat,
                    category=category,  # type: ignore[arg-type]
                    likelihood=likelihood,  # type: ignore[arg-type]
                    impact=impact,  # type: ignore[arg-type]
                    risk_rating=rating,  # type: ignore[arg-type]
                    mitigation=mitigation,
                    owner_role="Information Security Engineer" if category == "Security" else "Compliance / Legal Officer",
                )
            )

        return mappings, risks
