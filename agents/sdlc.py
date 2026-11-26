"""Agent 2: Hybrid SDLC Selection Agent.
Combines the user's fine-tuned `qwen2.5-3b-cc-agent2` LoRA adapter (requirement weighting & dominant
constraint) with deterministic Multi-Criteria Decision Analysis (MCDA) across 13 SDLC factors."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from agents.schemas import (
    RequirementItem,
    SDLCFactorRating,
    SDLCModelScore,
    SDLCRecommendation,
    SDLCWeightEntry,
)
from config import KB_DIR
from llm.engine import LLMEngine
from llm.json_utils import extract_json_payload

_RATING_VALUE = {"Low": 1.0, "Medium": 2.0, "High": 3.0}


class SDLCSelectionAgent:
    """Recommends ranked SDLC models using cc-agent2 LoRA + MCDA rules."""

    def __init__(self, llm: LLMEngine, policies_path: Path | str = KB_DIR / "sdlc_policies.yaml") -> None:
        self.llm = llm
        with Path(policies_path).open("r", encoding="utf-8") as f:
            self.policies = yaml.safe_load(f) or {}

    def derive_13_factors(
        self,
        requirements: list[RequirementItem],
        project_meta: dict[str, Any] | None = None,
    ) -> list[SDLCFactorRating]:
        meta = project_meta or {}
        combined = " ".join(r.statement.lower() for r in requirements)

        has_hw = any(w in combined for w in ["tpm", "hardware", "silicon", "physical", "firmware", "boot"])
        has_live = any(w in combined for w in ["real-time", "real time", "telemetry", "dynamic", "anomaly", "continuous", "ci/cd", "api"])
        has_reg = any("Compliance / Regulatory" in r.categories for r in requirements) or any(w in combined for w in ["cc", "sfr", "audit", "nist", "iso", "gdpr"])
        has_legacy = any("Integration" in r.categories for r in requirements) or any(w in combined for w in ["legacy", "external", "interconnection"])

        def _pick(key: str, auto_val: str) -> str:
            val = meta.get(key)
            return val if val in {"Low", "Medium", "High"} else auto_val

        factors = [
            ("requirement_stability", _pick("requirement_stability", "High" if has_hw and not has_live else ("Low" if has_live else "Medium")), "Derived from hardware/firmware immutability vs. dynamic threat rule churn."),
            ("regulatory_criticality", _pick("regulatory_criticality", "High" if has_reg else "Medium"), f"{sum(1 for r in requirements if 'Compliance / Regulatory' in r.categories)} compliance-tagged requirements."),
            ("security_risk", _pick("security_risk", "High" if any(r.risk_level in {"Critical", "High"} for r in requirements) else "Medium"), "Presence of Critical/High security controls and threat surface."),
            ("project_complexity", _pick("project_complexity", "High" if len(requirements) >= 6 or (has_hw and has_live) else "Medium"), f"{len(requirements)} extracted requirements across multi-domain controls."),
            ("system_size", _pick("system_size", "High" if len(requirements) >= 8 else "Medium"), "Measured by requirement count and integration breadth."),
            ("legacy_dependence", _pick("legacy_dependence", "High" if has_legacy else "Low"), "Detected external/interconnection or legacy interface references."),
            ("change_frequency", _pick("change_frequency", "High" if has_live else ("Low" if has_hw else "Medium")), "Live telemetry/signature/rule updates increase expected release cadence."),
            ("continuous_delivery", _pick("continuous_delivery", "High" if has_live else ("Low" if has_hw else "Medium")), "Continuous deployment suitability based on target runtime environment."),
            ("stakeholder_availability", _pick("stakeholder_availability", "Medium"), "Assumed periodic availability across security, compliance, and ops teams."),
            ("testing_rigor", _pick("testing_rigor", "High" if has_hw or has_reg else "Medium"), "Common Criteria / regulated environments demand strict V&V evidence."),
            ("budget_schedule", _pick("budget_schedule", "Medium"), "Balanced schedule and security assurance budget."),
            ("formal_verification", _pick("formal_verification", "High" if has_hw or has_reg else "Medium"), "Cryptographic, tamper, or Common Criteria SFR verification requirements."),
            ("failure_consequence", _pick("failure_consequence", "High" if any(r.priority == "Critical" for r in requirements) else "Medium"), "Critical security/tamper failures risk breach or compliance failure."),
        ]
        return [SDLCFactorRating(factor=f, rating=r, evidence=e) for f, r, e in factors]  # type: ignore[arg-type]

    def score_mcda(
        self,
        factors: list[SDLCFactorRating],
        agent2_recommendation: str = "",
    ) -> list[SDLCModelScore]:
        factor_map = {f.factor: _RATING_VALUE[f.rating] for f in factors}
        models = self.policies.get("models", {})
        raw_scores: list[tuple[str, float, str]] = []

        for name, cfg in models.items():
            weights: dict[str, float] = cfg.get("weights", {})
            score = 0.0
            max_pos = 0.0
            for fkey, w in weights.items():
                val = factor_map.get(fkey, 2.0)
                if w > 0:
                    score += w * val
                    max_pos += w * 3.0
                else:
                    # Negative weight penalizes high values of opposing factors
                    score += abs(w) * (4.0 - val)
                    max_pos += abs(w) * 3.0
            pct = (score / max_pos * 100.0) if max_pos > 0 else 50.0
            # Light alignment boost if fine-tuned Agent 2 explicitly points to this family
            if agent2_recommendation and any(tok in agent2_recommendation.lower() for tok in name.lower().split("-")[0].split()):
                pct = min(98.5, pct + 4.0)
            raw_scores.append((name, round(max(15.0, min(99.0, pct)), 1), cfg.get("description", "")))

        raw_scores.sort(key=lambda x: x[1], reverse=True)
        return [SDLCModelScore(model_name=n, score_percent=s, rationale=d) for n, s, d in raw_scores]

    def _deterministic_weighting(self, requirements: list[RequirementItem], ranked: list[SDLCModelScore]) -> tuple[list[SDLCWeightEntry], str, str, list[dict]]:
        top_model = ranked[0].model_name if ranked else "Agile-DevSecOps Hybrid"
        weights: list[SDLCWeightEntry] = []
        for req in requirements:
            lower = req.statement.lower()
            if any(w in lower for w in ["tpm", "physical", "hardware", "silicon", "tamper", "boot"]):
                w, pulls, reason = "High", "High-Assurance V-Model", "Hardware/silicon or immutable boot constraints cannot be hot-patched post-deployment."
            elif any(w in lower for w in ["real-time", "real time", "telemetry", "dynamic", "signature", "anomaly", "ci/cd"]):
                w, pulls, reason = "High", "DevSecOps (Continuous Agile)", "Dynamic threat rules and live telemetry require automated CI/CD releases."
            elif any(w in lower for w in ["digital signature", "firmware", "cryptographic", "encrypt", "mfa", "access control", "firewall"]):
                w, pulls, reason = "High", top_model, "Core security enforcement requires strict verification gates alongside iterative testing."
            elif any(w in lower for w in ["audit", "log", "query", "version"]):
                w, pulls, reason = "Low", "Agnostic", "Standard logging/query logic is adaptable across lifecycle models."
            else:
                w, pulls, reason = "Medium", top_model, "Requires structured traceability and security regression verification."
            weights.append(SDLCWeightEntry(req_id=req.req_id, weight=w, pulls_toward=pulls, reason=reason))  # type: ignore[arg-type]

        high_reqs = [x.req_id for x in weights if x.weight == "High"]
        dom = f"High-assurance security & regulatory constraints ({', '.join(high_reqs[:3]) or 'core controls'}) outweigh routine operational items."
        just = (
            f"{top_model} achieves the highest MCDA score ({ranked[0].score_percent}%) by balancing "
            f"strict security/compliance verification gates with required delivery agility."
        )
        phases = [
            {"phase": "Requirements, Threat Modeling & Compliance Baseline", "applicable_reqs": [r.req_id for r in requirements[:3]]},
            {"phase": "Hardened Build, Security Verification & Release Gate", "applicable_reqs": [r.req_id for r in requirements[3:]] or [r.req_id for r in requirements]},
        ]
        return weights, dom, just, phases

    def run(
        self,
        requirements: list[RequirementItem],
        project_meta: dict[str, Any] | None = None,
    ) -> tuple[SDLCRecommendation, dict[str, Any]]:
        factors = self.derive_13_factors(requirements, project_meta)
        agent2_json: dict[str, Any] | None = None
        used_adapter = "mcda_rules"

        if self.llm.active_mode == "local_gpu" and requirements:
            # Matches the exact prompt format used to train `qwen2.5-3b-cc-agent2`!
            compact_reqs = [
                {
                    "req_id": r.req_id,
                    "category": ", ".join(r.categories[:2]),
                    "source_ref": r.source_ref,
                    "statement": r.statement,
                    "reasoning": r.business_justification,
                }
                for r in requirements[:8]
            ]
            messages = [
                {
                    "role": "system",
                    "content": "You are a Secure SDLC Architect. Evaluate the provided requirements, assign a weight/pull factor to each to determine the dominant constraint, and output a JSON object recommending the optimal SDLC with justification.",
                },
                {"role": "user", "content": "Requirements:\n" + json.dumps(compact_reqs, indent=2)},
            ]
            raw, _ = self.llm.generate(messages, adapter="agent2", max_new_tokens=1024, temperature=0.2)
            used_adapter = "qwen2.5-3b-cc-agent2+mcda" if "agent2" in self.llm.loaded_adapters else "base_qwen2.5_3b+mcda"
            if raw:
                try:
                    parsed = extract_json_payload(raw)
                    if isinstance(parsed, dict):
                        agent2_json = parsed
                except Exception:
                    agent2_json = None

        agent2_rec_name = str((agent2_json or {}).get("recommended_sdlc", ""))
        ranked = self.score_mcda(factors, agent2_rec_name)
        det_weights, det_dom, det_just, det_phases = self._deterministic_weighting(requirements, ranked)

        weights: list[SDLCWeightEntry] = []
        if agent2_json and isinstance(agent2_json.get("requirements_weighting"), list):
            for item in agent2_json["requirements_weighting"]:
                if isinstance(item, dict) and item.get("req_id"):
                    w_val = item.get("weight", "Medium")
                    if w_val not in {"High", "Medium", "Low"}:
                        w_val = "Medium"
                    weights.append(
                        SDLCWeightEntry(
                            req_id=str(item.get("req_id")),
                            weight=w_val,  # type: ignore[arg-type]
                            pulls_toward=str(item.get("pulls_toward", ranked[0].model_name)),
                            reason=str(item.get("reason", "")),
                        )
                    )
        if not weights:
            weights = det_weights

        chosen_model = ranked[0].model_name if ranked else (agent2_rec_name or "Agile-DevSecOps Hybrid")
        rec = SDLCRecommendation(
            recommended_sdlc=chosen_model,
            dominant_constraint=str((agent2_json or {}).get("dominant_constraint") or det_dom),
            justification=str((agent2_json or {}).get("justification") or det_just),
            requirements_weighting=weights,
            ranked_models=ranked,
            decision_factors=factors,
            phase_mapping=(agent2_json or {}).get("phase_mapping") or det_phases,
        )
        return rec, {"adapter_used": used_adapter, "agent2_raw_sdlc": agent2_rec_name}
