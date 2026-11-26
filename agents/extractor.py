"""Agent 1: Requirement Extraction & Multi-Label Classification Agent.
Directly integrates the user's fine-tuned `qwen2.5-3b-cc-agent1` LoRA adapter with robust JSON parsing,
13-class multi-label classification, Given/When/Then acceptance criteria, and grounding verification."""
from __future__ import annotations

import re
from typing import Any

from agents.schemas import RequirementItem
from config import REQUIREMENT_CATEGORIES
from llm.engine import LLMEngine
from llm.json_utils import extract_json_payload
from rag.grounding import verify_requirement_grounding
from security.injection import frame_untrusted_text


def _infer_categories(text: str, base_cat: str = "") -> list[str]:
    lower = f"{base_cat} {text}".lower()
    cats: list[str] = []
    rules = [
        ("Security", ["security", "firewall", "access control", "authentication", "authorization", "tamper", "signature", "encrypt", "tsf", "intrusion"]),
        ("Compliance / Regulatory", ["compliance", "regulation", "protection profile", "standard", "cc ", "sfr", "nist", "iso", "policy", "gdpr"]),
        ("Audit & Reporting", ["audit", "log", "siem", "trail", "record", "report"]),
        ("Privacy", ["privacy", "pii", "mask", "personal", "anonym"]),
        ("Performance", ["latency", "throughput", "ms", "real time", "real-time", "bandwidth", "tps"]),
        ("Availability & Reliability", ["uptime", "availability", "failover", "self-test", "redundancy", "recovery"]),
        ("Data Management", ["retention", "storage", "backup", "database", "data"]),
        ("Integration", ["interface", "api", "external", "legacy", "protocol", "interconnection"]),
        ("Operational & Maintenance", ["update", "firmware", "patch", "admin", "monitor", "startup", "shutdown"]),
        ("Functional", ["shall", "enforce", "filter", "drop", "verify", "query", "initiate"]),
    ]
    for label, kws in rules:
        if label in REQUIREMENT_CATEGORIES and any(kw in lower for kw in kws):
            cats.append(label)
    if not cats:
        cats = ["Functional", "Security"]
    return cats[:4]


def _infer_kind(categories: list[str], statement: str) -> str:
    lower = statement.lower()
    if any(k in lower for k in ["encrypt", "signature", "firewall", "rbac", "authentication", "tamper", "audit", "mfa"]):
        return "Security"
    if any(c in categories for c in ["Performance", "Availability & Reliability", "Usability", "Operational & Maintenance"]):
        return "Non-Functional"
    return "Functional"


def _infer_mandatory_role(categories: list[str], statement: str) -> str | None:
    lower = statement.lower()
    if "Compliance / Regulatory" in categories or any(w in lower for w in ["regulation", "legal", "gdpr", "retention"]):
        return "compliance_officer"
    if "Security" in categories or any(w in lower for w in ["encrypt", "tamper", "authentication", "firewall", "signature"]):
        return "security_officer"
    if "Integration" in categories or any(w in lower for w in ["architecture", "legacy", "protocol", "hardware", "tpm"]):
        return "architect"
    return None


def _build_acceptance_criteria(statement: str) -> str:
    clean = statement.rstrip(".")
    return f"Given an operational request under defined security policy, When the actor invokes the function, Then {clean.lower()} and the outcome is verifiable in test and audit logs."


class RequirementExtractionAgent:
    """Extracts structured requirements using `cc-agent1` LoRA + deterministic grounding & enrichment."""

    def __init__(self, llm: LLMEngine) -> None:
        self.llm = llm

    def _format_context(self, kb_excerpts: list[dict], doc_excerpts: list[dict]) -> str:
        lines: list[str] = []
        for kb in kb_excerpts:
            sfrs = ", ".join(kb.get("sfr_ids", [])) or kb.get("id", "")
            lines.append(f"- {sfrs} ({kb.get('standard', kb.get('title', 'KB'))}) [{kb.get('id')}]: {kb.get('text', '')}")
        for doc in doc_excerpts:
            lines.append(f"- {doc.get('excerpt_id')} ({doc.get('source', 'Stakeholder Input')}): {frame_untrusted_text(doc.get('excerpt_id', 'DOC'), doc.get('text', ''))}")
        return "\n".join(lines)

    def _deterministic_extract(
        self,
        functionality: str,
        kb_excerpts: list[dict],
        doc_excerpts: list[dict],
        stakeholder_role: str,
        max_reqs: int,
    ) -> list[dict[str, Any]]:
        """Deterministic grounded extractor used when GPU model is not loaded or returns insufficient output."""
        if not kb_excerpts and not doc_excerpts:
            return []

        raw_items: list[dict[str, Any]] = []
        idx = 1

        # Extract concrete requirements from document excerpts first (if they contain 'shall'/'must')
        for doc in doc_excerpts:
            sentences = re.split(r"(?<=[.!?])\s+", doc.get("text", ""))
            for sent in sentences:
                sent_clean = sent.strip()
                if len(sent_clean) < 25:
                    continue
                if any(w in sent_clean.lower() for w in ["shall", "must", "require", "enforce", "verify", "encrypt", "log", "block"]):
                    sfrs = doc.get("sfr_ids", [])
                    ref = f"{sfrs[0]} ({doc.get('excerpt_id')})" if sfrs else doc.get("excerpt_id", "DOC-1")
                    stmt = sent_clean if "shall" in sent_clean.lower() else f"The system shall ensure that {sent_clean[0].lower()}{sent_clean[1:]}"
                    raw_items.append(
                        {
                            "req_id": f"REQ-{idx:03d}",
                            "statement": stmt,
                            "category": "Security - Grounded Input",
                            "source_ref": ref,
                            "citations": [doc.get("excerpt_id", "")] + sfrs[:2],
                            "reasoning": f"Derived directly from stakeholder input {doc.get('excerpt_id')} for {functionality}.",
                            "stakeholder": doc.get("stakeholder_role", stakeholder_role),
                        }
                    )
                    idx += 1
                    if len(raw_items) >= max_reqs:
                        return raw_items

        # Complement with KB-grounded SFR requirements
        for kb in kb_excerpts:
            if len(raw_items) >= max_reqs:
                break
            sfrs = kb.get("sfr_ids") or [kb.get("id", "KB")]
            kb_sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", kb.get("text", "")) if len(s.strip()) > 25]
            for s in kb_sentences[:2]:
                if len(raw_items) >= max_reqs:
                    break
                stmt = s
                if "shall" not in stmt.lower():
                    stmt = f"The system shall enforce {s[0].lower()}{s[1:]}"
                raw_items.append(
                    {
                        "req_id": f"REQ-{idx:03d}",
                        "statement": stmt,
                        "category": f"Security - {kb.get('type', 'Standard').title()}",
                        "source_ref": f"{sfrs[0]} ({kb.get('id')})",
                        "citations": [kb.get("id", "")] + sfrs[:2],
                        "reasoning": f"Grounded in {kb.get('standard', kb.get('title'))}; mitigates gaps addressed by {', '.join(sfrs)}.",
                        "stakeholder": stakeholder_role,
                    }
                )
                idx += 1

        return raw_items

    def run(
        self,
        functionality: str,
        kb_excerpts: list[dict[str, Any]],
        doc_excerpts: list[dict[str, Any]],
        stakeholder_role: str = "Information Security Engineer",
        max_reqs: int = 8,
    ) -> tuple[list[RequirementItem], dict[str, Any]]:
        context_str = self._format_context(kb_excerpts, doc_excerpts)
        raw_reqs: list[dict[str, Any]] = []
        used_adapter = "deterministic"
        mask_counts: dict[str, int] = {}
        raw_llm_text = ""

        if self.llm.active_mode == "local_gpu":
            # Matches the exact prompt format used to train `qwen2.5-3b-cc-agent1`!
            user_prompt = (
                "You are a requirements engineering assistant. Given a functionality and relevant security documentation, "
                "generate specific software requirements with reasoning.\n\n"
                f"Functionality: {functionality}\n\n"
                f"Relevant source material:\n{context_str or '(no relevant source material was retrieved)'}\n\n"
                "Generate the security functional requirements with reasoning, citing the specific source SFR for each."
            )
            messages = [
                {
                    "role": "system",
                    "content": "You are a requirements engineering assistant for IT Security. Given a functionality and Common Criteria context, output a JSON array of requirements with specific security reasoning.",
                },
                {"role": "user", "content": user_prompt},
            ]
            raw_llm_text, mask_counts = self.llm.generate(messages, adapter="agent1", max_new_tokens=1100, temperature=0.2)
            used_adapter = "qwen2.5-3b-cc-agent1" if "agent1" in self.llm.loaded_adapters else "base_qwen2.5_3b"
            if raw_llm_text:
                try:
                    parsed = extract_json_payload(raw_llm_text)
                    if isinstance(parsed, list):
                        raw_reqs = parsed
                    elif isinstance(parsed, dict) and isinstance(parsed.get("requirements"), list):
                        raw_reqs = parsed["requirements"]
                except Exception:
                    raw_reqs = []

        # Respect trained negative abstention if no evidence exists; otherwise supplement/fallback cleanly
        if not raw_reqs and (kb_excerpts or doc_excerpts):
            raw_reqs = self._deterministic_extract(functionality, kb_excerpts, doc_excerpts, stakeholder_role, max_reqs)
            if used_adapter != "deterministic":
                used_adapter = f"{used_adapter}+grounded_fallback"

        structured: list[RequirementItem] = []
        for idx, item in enumerate(raw_reqs[:max_reqs], start=1):
            stmt = str(item.get("statement", "")).strip()
            if not stmt:
                continue
            categories = _infer_categories(stmt, str(item.get("category", "")))
            kind = _infer_kind(categories, stmt)
            source_ref = str(item.get("source_ref", "")).strip()
            citations = list(item.get("citations", []))
            if source_ref and source_ref not in citations:
                citations.append(source_ref)

            grounding = verify_requirement_grounding(
                {"statement": stmt, "source_ref": source_ref, "citations": citations},
                kb_excerpts,
                doc_excerpts,
            )

            mandatory_role = _infer_mandatory_role(categories, stmt)
            priority = "Critical" if any(w in stmt.lower() for w in ["tamper", "digital signature", "mfa", "encrypt", "block malicious"]) else "High"
            risk_level = "Critical" if priority == "Critical" else "High"

            structured.append(
                RequirementItem(
                    req_id=f"REQ-{idx:03d}",
                    statement=stmt,
                    kind=kind,
                    categories=categories,
                    source_stakeholder=str(item.get("stakeholder", stakeholder_role)),
                    business_justification=str(item.get("reasoning", "")).strip() or f"Required to protect {functionality}.",
                    priority=priority,
                    dependencies=[f"REQ-{idx-1:03d}"] if idx > 1 and "role" in stmt.lower() else [],
                    assumptions=["Authorized identity provider / PKI root trust store is available."] if "signature" in stmt.lower() or "mfa" in stmt.lower() else [],
                    acceptance_criteria=_build_acceptance_criteria(stmt),
                    applicable_regulations=grounding["valid_citations"] or citations[:2],
                    source_ref=source_ref,
                    citations=grounding["valid_citations"] or citations,
                    risk_level=risk_level,
                    confidence_score=grounding["confidence"],
                    confidence_flags=grounding["flags"],
                    needs_human_review=grounding["needs_human_review"] or mandatory_role is not None,
                    mandatory_approval_role=mandatory_role,
                    approval_status="Pending",
                )
            )

        meta = {
            "adapter_used": used_adapter,
            "mask_counts": mask_counts,
            "raw_llm_preview": raw_llm_text[:400],
            "insufficient_grounding": len(structured) == 0,
        }
        return structured, meta
