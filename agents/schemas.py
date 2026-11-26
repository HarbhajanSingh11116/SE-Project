"""Structured Pydantic schemas shared across agents, orchestrator, and artefacts."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RequirementItem(BaseModel):
    req_id: str
    statement: str
    kind: Literal["Functional", "Non-Functional", "Security"] = "Security"
    categories: list[str] = Field(default_factory=lambda: ["Security"])
    source_stakeholder: str = "Information Security Engineer"
    business_justification: str = ""
    priority: Literal["Critical", "High", "Medium", "Low"] = "High"
    dependencies: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    acceptance_criteria: str = ""
    applicable_regulations: list[str] = Field(default_factory=list)
    source_ref: str = ""
    citations: list[str] = Field(default_factory=list)
    risk_level: Literal["Critical", "High", "Medium", "Low"] = "High"
    confidence_score: float = 0.8
    confidence_flags: list[str] = Field(default_factory=list)
    needs_human_review: bool = False
    mandatory_approval_role: str | None = None
    approval_status: Literal["Pending", "Approved", "Rejected", "Needs Revision"] = "Pending"
    reviewer_comment: str = ""
    version: int = 1


class QualityIssue(BaseModel):
    issue_id: str
    req_id: str
    issue_type: str
    severity: Literal["High", "Medium", "Low"] = "Medium"
    description: str
    target_stakeholder: str = "Business / Security Analyst"
    clarification_question: str = ""


class ComplianceMapping(BaseModel):
    mapping_id: str
    req_id: str
    kb_id: str
    standard: str
    jurisdiction: str
    required_control: str
    evidence_excerpt: str
    compliance_gap: str = "None identified"
    mandatory_checkpoint: str
    retention_obligation: str
    requires_compliance_officer_approval: bool = True
    disclaimer: str = "Advisory AI mapping only; final regulatory determination requires Compliance/Legal Officer sign-off."
    approval_status: Literal["Pending", "Approved", "Rejected"] = "Pending"


class RiskEntry(BaseModel):
    risk_id: str
    req_id: str
    threat_description: str
    category: Literal["Security", "Compliance", "Technical", "Operational"] = "Security"
    likelihood: Literal["High", "Medium", "Low"] = "Medium"
    impact: Literal["Critical", "High", "Medium", "Low"] = "High"
    risk_rating: Literal["Critical", "High", "Medium", "Low"] = "High"
    mitigation: str
    owner_role: str = "Information Security Engineer"


class SDLCFactorRating(BaseModel):
    factor: str
    rating: Literal["High", "Medium", "Low"]
    evidence: str


class SDLCWeightEntry(BaseModel):
    req_id: str
    weight: Literal["High", "Medium", "Low"]
    pulls_toward: str
    reason: str


class SDLCModelScore(BaseModel):
    model_name: str
    score_percent: float
    rationale: str


class SDLCRecommendation(BaseModel):
    recommended_sdlc: str
    dominant_constraint: str
    justification: str
    requirements_weighting: list[SDLCWeightEntry] = Field(default_factory=list)
    ranked_models: list[SDLCModelScore] = Field(default_factory=list)
    decision_factors: list[SDLCFactorRating] = Field(default_factory=list)
    phase_mapping: list[dict] = Field(default_factory=list)
    votes: dict[str, str] = Field(default_factory=dict)
    approval_status: Literal["Pending", "Approved", "Rejected"] = "Pending"


class WorkflowPhase(BaseModel):
    name: str
    activities: list[str]
    roles: list[str]
    deliverables: list[str]
    security_activities: list[str]
    testing_requirements: list[str]
    compliance_checkpoints: list[str]
    approval_gate: str
    entry_criteria: list[str]
    exit_criteria: list[str]
    mapped_req_ids: list[str] = Field(default_factory=list)
