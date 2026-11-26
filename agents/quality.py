"""Quality, Ambiguity, Duplication, Conflict Detection, and Clarification Agent."""
from __future__ import annotations

import re
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from agents.schemas import QualityIssue, RequirementItem
from config import BASELINE_SECURITY_CONTROLS, VAGUE_TERMS
from llm.engine import LLMEngine
from llm.json_utils import extract_json_payload

_ACRONYM_RE = re.compile(r"\b[A-Z]{3,6}\b")
_KNOWN_ACRONYMS = {
    "REQ", "TSF", "TOE", "SFP", "SFR", "RBAC", "ABAC", "MFA", "TLS", "AES", "RSA", "ECDSA",
    "SHA", "TPM", "OTA", "SIEM", "API", "SQL", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "DNS",
    "TCP", "UDP", "IP", "VPN", "IDS", "IPS", "HSM", "PKI", "KMS", "DLP", "SAST", "DAST",
    "SBOM", "SLA", "SLO", "NIST", "ISO", "OWASP", "GDPR", "PII", "RTM", "SRS", "SDLC", "JSON",
}


class QualityClarificationAgent:
    """Runs deterministic quality/conflict/baseline checks plus optional LLM clarification enrichment."""

    def __init__(self, llm: LLMEngine) -> None:
        self.llm = llm

    def run(
        self,
        requirements: list[RequirementItem],
        kb_excerpts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        issues: list[QualityIssue] = []
        conflicts: list[dict[str, Any]] = []
        issue_idx = 1

        def _add_issue(req_id: str, issue_type: str, severity: str, desc: str, role: str, question: str) -> None:
            nonlocal issue_idx
            issues.append(
                QualityIssue(
                    issue_id=f"ISS-{issue_idx:03d}",
                    req_id=req_id,
                    issue_type=issue_type,
                    severity=severity,  # type: ignore[arg-type]
                    description=desc,
                    target_stakeholder=role,
                    clarification_question=question,
                )
            )
            issue_idx += 1

        # 1. Per-requirement checks: ambiguity, completeness, testability, source, undefined terms
        for req in requirements:
            lower = req.statement.lower()
            has_num = bool(re.search(r"\d+", req.statement))
            vague_hits = [t for t in VAGUE_TERMS if re.search(rf"\b{re.escape(t)}\b", lower)]
            if vague_hits and not has_num:
                _add_issue(
                    req.req_id,
                    "Ambiguity",
                    "High",
                    f"Contains subjective term(s) {vague_hits} without measurable thresholds.",
                    req.source_stakeholder,
                    f"For {req.req_id}, what exact numeric threshold or standard replaces '{vague_hits[0]}'?",
                )

            if not req.acceptance_criteria.strip() or not req.business_justification.strip():
                _add_issue(
                    req.req_id,
                    "Incompleteness",
                    "Medium",
                    "Missing acceptance criteria or business justification.",
                    req.source_stakeholder,
                    f"Please provide measurable acceptance criteria and justification for {req.req_id}.",
                )

            if not req.citations and not req.source_ref:
                _add_issue(
                    req.req_id,
                    "Missing Source",
                    "High",
                    "Requirement lacks a verified stakeholder or knowledge-base citation.",
                    "Business / Security Analyst",
                    f"Which approved document, standard, or stakeholder statement authorizes {req.req_id}?",
                )

            if len(req.statement.split()) < 6 or not any(v in lower for v in ["shall", "must", "verify", "enforce", "log", "encrypt", "block"]):
                _add_issue(
                    req.req_id,
                    "Lack of Testability",
                    "Medium",
                    "Statement lacks a clear verifiable action predicate ('shall ...').",
                    "Auditor / Common Criteria Evaluator",
                    f"How can QA or an evaluator objectively pass/fail {req.req_id}?",
                )

            acronyms = [a for a in _ACRONYM_RE.findall(req.statement) if a not in _KNOWN_ACRONYMS]
            if acronyms:
                _add_issue(
                    req.req_id,
                    "Undefined Terminology",
                    "Low",
                    f"Acronym(s) {sorted(set(acronyms))} not defined in glossary/KB.",
                    "Business / Security Analyst",
                    f"Please define {', '.join(sorted(set(acronyms)))} used in {req.req_id}.",
                )

        # 2. Duplication detection via TF-IDF cosine similarity
        if len(requirements) >= 2:
            stmts = [r.statement for r in requirements]
            mat = TfidfVectorizer(stop_words="english").fit_transform(stmts)
            sims = cosine_similarity(mat)
            for i in range(len(requirements)):
                for j in range(i + 1, len(requirements)):
                    if sims[i, j] >= 0.78:
                        _add_issue(
                            requirements[j].req_id,
                            "Duplication",
                            "Medium",
                            f"{requirements[j].req_id} closely duplicates {requirements[i].req_id} (similarity {sims[i, j]:.2f}).",
                            "Business / Security Analyst",
                            f"Should {requirements[i].req_id} and {requirements[j].req_id} be merged?",
                        )

        # 3. Conflict detection (numeric threshold mismatches & allow/deny contradictions)
        num_unit_re = re.compile(r"\b(\d+)[\s-]*(days?|ms|seconds?|minutes?|hours?|bits?|%)\b", re.I)
        for i in range(len(requirements)):
            for j in range(i + 1, len(requirements)):
                r1, r2 = requirements[i], requirements[j]
                m1 = num_unit_re.findall(r1.statement)
                m2 = num_unit_re.findall(r2.statement)
                shared_words = set(re.findall(r"[a-z]{4,}", r1.statement.lower())) & set(re.findall(r"[a-z]{4,}", r2.statement.lower()))
                for n1, u1 in m1:
                    for n2, u2 in m2:
                        if u1.lower().rstrip("s") == u2.lower().rstrip("s") and n1 != n2 and len(shared_words) >= 3:
                            msg = f"Numeric conflict between {r1.req_id} ({n1} {u1}) and {r2.req_id} ({n2} {u2})."
                            conflicts.append({"req_a": r1.req_id, "req_b": r2.req_id, "description": msg})
                            _add_issue(
                                r2.req_id,
                                "Inconsistency / Conflict",
                                "High",
                                msg,
                                "Project Manager",
                                f"Resolve conflicting values ({n1} {u1} vs {n2} {u2}) between {r1.req_id} and {r2.req_id}.",
                            )

                l1, l2 = r1.statement.lower(), r2.statement.lower()
                if len(shared_words) >= 4 and (
                    ("allow" in l1 and ("block" in l2 or "deny" in l2 or "prohibit" in l2 or "shall not" in l2))
                    or ("allow" in l2 and ("block" in l1 or "deny" in l1 or "prohibit" in l1 or "shall not" in l1))
                ):
                    msg = f"Policy conflict between {r1.req_id} and {r2.req_id} on overlapping scope ({', '.join(sorted(shared_words)[:3])})."
                    conflicts.append({"req_a": r1.req_id, "req_b": r2.req_id, "description": msg})
                    _add_issue(
                        r2.req_id,
                        "Conflicting Stakeholder Expectations",
                        "High",
                        msg,
                        "Project Manager",
                        f"Which rule takes precedence between {r1.req_id} and {r2.req_id}?",
                    )

        # 4. Missing baseline security/compliance controls
        combined_text = " ".join(r.statement.lower() for r in requirements)
        suggested_controls: list[dict[str, str]] = []
        for ctrl in BASELINE_SECURITY_CONTROLS:
            if not any(kw in combined_text for kw in ctrl["keywords"]):
                suggested_controls.append(ctrl)
                _add_issue(
                    "SYSTEM",
                    "Missing Security Control",
                    "Medium",
                    f"Baseline control missing: {ctrl['title']} ({ctrl['standard_ref']}).",
                    "Information Security Engineer",
                    f"Should we include baseline control '{ctrl['title']}': {ctrl['default_statement']}",
                )

        # 5. Optional LLM clarification enrichment when GPU model is active
        if self.llm.active_mode == "local_gpu" and requirements:
            req_summary = "\n".join(f"- {r.req_id}: {r.statement}" for r in requirements[:8])
            messages = [
                {"role": "system", "content": "You are a Requirements Quality Reviewer. Output a JSON array of at most 2 concise clarification objects with keys: req_id, issue_type, severity, description, target_stakeholder, clarification_question."},
                {"role": "user", "content": f"Check these requirements for infeasibility or hidden edge-case gaps:\n{req_summary}"},
            ]
            raw, _ = self.llm.generate(messages, adapter=None, max_new_tokens=450, temperature=0.2)
            if raw:
                try:
                    extra = extract_json_payload(raw)
                    if isinstance(extra, list):
                        for item in extra[:2]:
                            if isinstance(item, dict) and item.get("description"):
                                _add_issue(
                                    str(item.get("req_id", "REQ-001")),
                                    str(item.get("issue_type", "AI Quality Check")),
                                    str(item.get("severity", "Medium")) if item.get("severity") in {"High", "Medium", "Low"} else "Medium",
                                    str(item.get("description")),
                                    str(item.get("target_stakeholder", "Business / Security Analyst")),
                                    str(item.get("clarification_question", "Please clarify this edge case.")),
                                )
                except Exception:
                    pass

        clarification_questions = [
            {
                "issue_id": iss.issue_id,
                "req_id": iss.req_id,
                "stakeholder": iss.target_stakeholder,
                "question": iss.clarification_question,
                "severity": iss.severity,
            }
            for iss in issues
        ]

        return {
            "issues": issues,
            "conflicts": conflicts,
            "clarification_questions": clarification_questions,
            "suggested_controls": suggested_controls,
        }
