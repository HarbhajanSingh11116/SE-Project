"""Project-Specific SDLC Workflow Customizer Agent."""
from __future__ import annotations

from pathlib import Path

import yaml

from agents.schemas import ComplianceMapping, RequirementItem, SDLCRecommendation, WorkflowPhase
from config import KB_DIR


class WorkflowGeneratorAgent:
    """Customizes the selected SDLC template with requirement traceability and HITL gates."""

    def __init__(self, policies_path: Path | str = KB_DIR / "sdlc_policies.yaml") -> None:
        with Path(policies_path).open("r", encoding="utf-8") as f:
            self.policies = yaml.safe_load(f) or {}

    def run(
        self,
        sdlc: SDLCRecommendation,
        requirements: list[RequirementItem],
        compliance_mappings: list[ComplianceMapping],
    ) -> list[WorkflowPhase]:
        models = self.policies.get("models", {})
        model_cfg = models.get(sdlc.recommended_sdlc) or next(iter(models.values()), {})
        raw_phases = model_cfg.get("phases", [])

        req_ids = [r.req_id for r in requirements]
        high_sec_reqs = [r.req_id for r in requirements if r.priority == "Critical" or r.mandatory_approval_role == "security_officer"]
        comp_req_ids = [m.req_id for m in compliance_mappings if m.requires_compliance_officer_approval]

        phases: list[WorkflowPhase] = []
        n_phases = max(1, len(raw_phases))
        for idx, p in enumerate(raw_phases):
            # Distribute requirements sequentially across lifecycle phases + keep traceability
            slice_reqs = req_ids[idx::n_phases] if req_ids else []
            extra_gates: list[str] = list(p.get("compliance_checkpoints", []))
            if idx == 0 and comp_req_ids:
                extra_gates.append(f"Mandatory Compliance Officer sign-off for {', '.join(comp_req_ids[:4])}")
            if idx == n_phases - 1 and high_sec_reqs:
                extra_gates.append(f"Production Readiness Gate covering Critical security controls ({', '.join(high_sec_reqs[:4])})")

            phases.append(
                WorkflowPhase(
                    name=p.get("name", f"Phase {idx+1}"),
                    activities=list(p.get("activities", [])),
                    roles=list(p.get("roles", [])),
                    deliverables=list(p.get("deliverables", [])),
                    security_activities=list(p.get("security_activities", [])),
                    testing_requirements=list(p.get("testing_requirements", [])),
                    compliance_checkpoints=extra_gates,
                    approval_gate=p.get("approval_gate", "Stakeholder Gate"),
                    entry_criteria=list(p.get("entry_criteria", [])),
                    exit_criteria=list(p.get("exit_criteria", [])),
                    mapped_req_ids=slice_reqs,
                )
            )
        return phases
