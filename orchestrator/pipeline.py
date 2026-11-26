"""Central Multi-Agent Orchestrator with least-privilege state, HITL gates, and audit trail."""
from __future__ import annotations

import time
import uuid
from typing import Any

from agents import (
    ComplianceRiskAgent,
    QualityClarificationAgent,
    RequirementExtractionAgent,
    SDLCSelectionAgent,
    WorkflowGeneratorAgent,
)
from agents.schemas import ComplianceMapping, RequirementItem, SDLCRecommendation
from config import SDLC_JOINT_VOTE_ROLES
from llm.engine import LLMEngine
from orchestrator.store import ProjectStore
from rag.retriever import KnowledgeBaseRetriever, chunk_document
from security.audit import AuditLogger
from security.injection import scan_and_quarantine
from security.masking import mask_payload, mask_text
from security.rbac import authorize_action, filter_state_for_agent


class MultiAgentOrchestrator:
    """Coordinates retrieval, extraction, quality, compliance/risk, SDLC, workflow, and HITL gates."""

    def __init__(
        self,
        kb: KnowledgeBaseRetriever | None = None,
        llm: LLMEngine | None = None,
        store: ProjectStore | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.kb = kb or KnowledgeBaseRetriever()
        self.llm = llm or LLMEngine(mode="auto")
        self.store = store or ProjectStore()
        self.audit = audit or AuditLogger()

        self.extractor = RequirementExtractionAgent(self.llm)
        self.quality = QualityClarificationAgent(self.llm)
        self.compliance_risk = ComplianceRiskAgent(self.kb, self.llm)
        self.sdlc = SDLCSelectionAgent(self.llm)
        self.workflow = WorkflowGeneratorAgent()

    def run_pipeline(
        self,
        project_name: str,
        domain: str,
        functionality: str,
        raw_documents: list[dict[str, str]] | None = None,
        interview_excerpts: list[dict[str, Any]] | None = None,
        stakeholder_role: str = "Information Security Engineer",
        project_meta: dict[str, Any] | None = None,
        max_reqs: int = 8,
        actor: str = "analyst",
        actor_roles: list[str] | None = None,
        auto_approve: bool = False,
    ) -> dict[str, Any]:
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        t_start = time.perf_counter()
        timings: dict[str, float] = {}
        roles = actor_roles or ["analyst"]

        # 1. Masking & Prompt-Injection Defense
        t0 = time.perf_counter()
        safe_func, func_mask = mask_text(functionality)
        excerpts: list[dict[str, Any]] = []
        for doc in raw_documents or []:
            masked_doc_text, _ = mask_text(doc.get("text", ""))
            excerpts.extend(chunk_document(masked_doc_text, doc.get("name", "UploadedSpec")))
        for ix in interview_excerpts or []:
            masked_ix, _ = mask_payload(ix)
            excerpts.append(masked_ix)

        clean_docs, quarantined_docs = scan_and_quarantine(excerpts)
        kb_hits = self.kb.retrieve(f"{safe_func} {' '.join(d.get('text', '')[:120] for d in clean_docs[:3])}", top_k=5)
        timings["context_rag"] = round(time.perf_counter() - t0, 3)

        self.audit.log(
            "pipeline_started",
            actor=actor,
            role=",".join(roles),
            project_id=project_name,
            run_id=run_id,
            details={
                "domain": domain,
                "kb_version": self.kb.kb_version,
                "kb_digest": self.kb.kb_digest(),
                "quarantined_count": len(quarantined_docs),
                "func_mask_counts": func_mask,
            },
        )

        # 2. Agent 1: Extraction & Multi-Label Classification (least-privilege slice)
        t0 = time.perf_counter()
        shared_state: dict[str, Any] = {
            "project_brief": safe_func,
            "retrieved_doc_excerpts": clean_docs,
            "retrieved_kb_excerpts": kb_hits,
        }
        ext_input = filter_state_for_agent("extractor", shared_state)
        reqs, ext_meta = self.extractor.run(
            functionality=ext_input["project_brief"],
            kb_excerpts=ext_input["retrieved_kb_excerpts"],
            doc_excerpts=ext_input["retrieved_doc_excerpts"],
            stakeholder_role=stakeholder_role,
            max_reqs=max_reqs,
        )
        timings["extraction_agent"] = round(time.perf_counter() - t0, 3)
        self.audit.log("agent_extraction_completed", actor="extractor_agent", project_id=project_name, run_id=run_id, details={"count": len(reqs), **ext_meta})

        # 3. Quality, Ambiguity & Conflict Detection Agent
        t0 = time.perf_counter()
        qual_res = self.quality.run(reqs, kb_hits)
        timings["quality_agent"] = round(time.perf_counter() - t0, 3)
        self.audit.log("agent_quality_completed", actor="quality_agent", project_id=project_name, run_id=run_id, details={"issues": len(qual_res["issues"]), "conflicts": len(qual_res["conflicts"])})

        # 4. Compliance & Threat/Risk Analysis Agent
        t0 = time.perf_counter()
        comp_mappings, risk_register = self.compliance_risk.run(reqs)
        timings["compliance_risk_agent"] = round(time.perf_counter() - t0, 3)
        self.audit.log("agent_compliance_risk_completed", actor="compliance_risk_agent", project_id=project_name, run_id=run_id, details={"mappings": len(comp_mappings), "risks": len(risk_register)})

        # 5. Agent 2: SDLC Selection (cc-agent2 LoRA + MCDA)
        t0 = time.perf_counter()
        sdlc_rec, sdlc_meta = self.sdlc.run(reqs, project_meta=project_meta)
        timings["sdlc_agent"] = round(time.perf_counter() - t0, 3)
        self.audit.log("agent_sdlc_completed", actor="sdlc_agent", project_id=project_name, run_id=run_id, details={"recommended": sdlc_rec.recommended_sdlc, **sdlc_meta})

        # 6. Tailored SDLC Workflow Generator
        t0 = time.perf_counter()
        wf_phases = self.workflow.run(sdlc_rec, reqs, comp_mappings)
        timings["workflow_agent"] = round(time.perf_counter() - t0, 3)
        timings["total"] = round(time.perf_counter() - t_start, 3)

        if auto_approve:
            for r in reqs:
                r.approval_status = "Approved"
            for m in comp_mappings:
                m.approval_status = "Approved"
            sdlc_rec.approval_status = "Approved"
            sdlc_rec.votes = {role: "Approved" for role in SDLC_JOINT_VOTE_ROLES}

        state: dict[str, Any] = {
            "run_id": run_id,
            "project_name": project_name,
            "domain": domain,
            "functionality": safe_func,
            "created_by": actor,
            "status": "Approved" if auto_approve else "Awaiting Human Review",
            "kb_version": self.kb.kb_version,
            "kb_digest": self.kb.kb_digest(),
            "doc_excerpts": clean_docs,
            "quarantined_excerpts": quarantined_docs,
            "kb_excerpts": kb_hits,
            "requirements": [r.model_dump() for r in reqs],
            "quality_issues": [q.model_dump() for q in qual_res["issues"]],
            "conflicts": qual_res["conflicts"],
            "clarification_questions": qual_res["clarification_questions"],
            "suggested_controls": qual_res["suggested_controls"],
            "compliance_mappings": [m.model_dump() for m in comp_mappings],
            "risk_register": [rk.model_dump() for rk in risk_register],
            "sdlc_recommendation": sdlc_rec.model_dump(),
            "sdlc_workflow": [w.model_dump() for w in wf_phases],
            "production_readiness": {"approved": auto_approve, "approved_by": actor if auto_approve else None},
            "agent_meta": {"extractor": ext_meta, "sdlc": sdlc_meta},
            "timings": timings,
        }
        self.store.save_run(state)
        return state

    def decide_requirement(
        self,
        run_id: str,
        req_id: str,
        decision: str,
        user: str,
        user_roles: list[str],
        edited_statement: str | None = None,
        comment: str = "",
    ) -> tuple[bool, str]:
        run = self.store.get_run(run_id)
        if not run:
            return False, "Run not found."

        target = next((r for r in run["requirements"] if r["req_id"] == req_id), None)
        if not target:
            return False, f"Requirement {req_id} not found."

        mandatory_role = target.get("mandatory_approval_role")
        if mandatory_role:
            action = f"approve_{mandatory_role.replace('_officer', '')}_req" if "officer" in mandatory_role else "approve_architecture_req"
            if mandatory_role == "security_officer":
                action = "approve_security_req"
            elif mandatory_role == "compliance_officer":
                action = "approve_compliance_mapping"
            ok, msg = authorize_action(user_roles, action)
            if not ok:
                self.audit.log("access_denied", actor=user, role=",".join(user_roles), project_id=run["project_name"], run_id=run_id, details={"req_id": req_id, "reason": msg})
                return False, msg

        before = dict(target)
        target["approval_status"] = decision
        target["reviewer_comment"] = comment
        if edited_statement and edited_statement.strip() and edited_statement.strip() != target["statement"]:
            target["statement"] = mask_text(edited_statement.strip())[0]
            target["version"] = int(target.get("version", 1)) + 1

        self.store.save_run(run)
        self.audit.log(
            "hitl_requirement_decision",
            actor=user,
            role=",".join(user_roles),
            project_id=run["project_name"],
            run_id=run_id,
            details={"req_id": req_id, "decision": decision, "before": before["statement"], "after": target["statement"]},
        )
        return True, f"{req_id} marked '{decision}'."

    def decide_compliance_mapping(
        self, run_id: str, mapping_id: str, decision: str, user: str, user_roles: list[str]
    ) -> tuple[bool, str]:
        ok, msg = authorize_action(user_roles, "approve_compliance_mapping")
        if not ok:
            return False, msg
        run = self.store.get_run(run_id)
        if not run:
            return False, "Run not found."
        for m in run["compliance_mappings"]:
            if m["mapping_id"] == mapping_id:
                m["approval_status"] = decision
                self.store.save_run(run)
                self.audit.log("hitl_compliance_decision", actor=user, role=",".join(user_roles), project_id=run["project_name"], run_id=run_id, details={"mapping_id": mapping_id, "decision": decision})
                return True, f"{mapping_id} marked '{decision}'."
        return False, "Mapping not found."

    def vote_sdlc(
        self, run_id: str, vote_role: str, decision: str, user: str, user_roles: list[str], override_model: str | None = None
    ) -> tuple[bool, str]:
        ok, msg = authorize_action(user_roles, "vote_sdlc")
        if not ok:
            return False, msg
        if vote_role not in user_roles and "admin" not in user_roles:
            return False, f"You must hold role '{vote_role}' (or admin) to cast this vote."
        run = self.store.get_run(run_id)
        if not run:
            return False, "Run not found."
        sdlc = run["sdlc_recommendation"]
        if override_model:
            sdlc["recommended_sdlc"] = override_model
            # Regenerate workflow for newly chosen SDLC
            reqs = [RequirementItem(**r) for r in run["requirements"]]
            comps = [ComplianceMapping(**m) for m in run["compliance_mappings"]]
            wf = self.workflow.run(SDLCRecommendation(**sdlc), reqs, comps)
            run["sdlc_workflow"] = [w.model_dump() for w in wf]

        sdlc.setdefault("votes", {})[vote_role] = decision
        votes = sdlc["votes"]
        if all(votes.get(r) == "Approved" for r in SDLC_JOINT_VOTE_ROLES):
            sdlc["approval_status"] = "Approved"
        elif any(v == "Rejected" for v in votes.values()):
            sdlc["approval_status"] = "Rejected"
        else:
            sdlc["approval_status"] = "Pending"

        self.store.save_run(run)
        self.audit.log("hitl_sdlc_vote", actor=user, role=vote_role, project_id=run["project_name"], run_id=run_id, details={"decision": decision, "status": sdlc["approval_status"]})
        return True, f"Recorded vote '{decision}' for {vote_role} (Overall: {sdlc['approval_status']})."

    def lock_run_baseline(self, run_id: str, user: str, user_roles: list[str]) -> tuple[bool, str]:
        ok, msg = authorize_action(user_roles, "lock_baseline")
        if not ok:
            return False, msg
        run = self.store.get_run(run_id)
        if not run:
            return False, "Run not found."
        pending_reqs = [r["req_id"] for r in run["requirements"] if r.get("approval_status") != "Approved"]
        if pending_reqs:
            return False, f"Cannot lock baseline; unapproved requirements remain: {', '.join(pending_reqs[:5])}"
        if run["sdlc_recommendation"].get("approval_status") != "Approved":
            return False, "Cannot lock baseline; joint 4-role SDLC approval is still pending."
        res = self.store.lock_baseline(run_id, user)
        self.audit.log("baseline_locked", actor=user, role=",".join(user_roles), project_id=run["project_name"], run_id=run_id, details=res)
        return True, f"Locked baseline {res['baseline_id']} (v{res['version']})."
