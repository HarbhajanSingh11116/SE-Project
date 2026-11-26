"""Deterministic Requirement & SDLC Artefact Bundle Generator (MD, DOCX, CSV, XLSX, Mermaid, ZIP)."""
from __future__ import annotations

import csv
import io
import zipfile
from typing import Any

import docx
import openpyxl


def _to_csv_bytes(headers: list[str], rows: list[list[Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


def _to_xlsx_bytes(sheet_name: str, headers: list[str], rows: list[list[Any]]) -> bytes:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name[:31]
    ws.append(headers)
    for r in rows:
        ws.append([str(x) if isinstance(x, (list, dict)) else x for x in r])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def generate_artefacts(run_data: dict[str, Any]) -> dict[str, bytes]:
    """Build all 11 engineering artefacts + downloadable ZIP bundle."""
    project_name = run_data.get("project_name", "CyberSec Project")
    functionality = run_data.get("functionality", "")
    reqs = run_data.get("requirements", [])
    issues = run_data.get("quality_issues", [])
    mappings = run_data.get("compliance_mappings", [])
    risks = run_data.get("risk_register", [])
    sdlc = run_data.get("sdlc_recommendation", {})
    workflow = run_data.get("sdlc_workflow", [])

    files: dict[str, bytes] = {}

    # 1. IEEE 830 SRS (Markdown + DOCX)
    srs_lines = [
        f"# Software Requirements Specification (SRS): {project_name}",
        "",
        "## 1. Introduction",
        f"- **System Scope / Functionality:** {functionality}",
        f"- **Recommended SDLC:** {sdlc.get('recommended_sdlc', 'TBD')}",
        f"- **KB Version:** {run_data.get('kb_version', '2026.1')}",
        "",
        "## 2. Extracted & Classified Requirements",
        "",
    ]
    for r in reqs:
        srs_lines.extend(
            [
                f"### {r['req_id']} — [{r['kind']}] ({', '.join(r.get('categories', []))})",
                f"- **Statement:** {r['statement']}",
                f"- **Stakeholder:** {r.get('source_stakeholder')} | **Priority:** {r.get('priority')} | **Risk:** {r.get('risk_level')}",
                f"- **Justification:** {r.get('business_justification')}",
                f"- **Acceptance Criteria:** {r.get('acceptance_criteria')}",
                f"- **Citations:** {', '.join(r.get('citations', [])) or r.get('source_ref', '')}",
                f"- **Confidence:** {r.get('confidence_score')} | **Approval Status:** {r.get('approval_status')}",
                "",
            ]
        )
    srs_lines.extend(
        [
            "## 3. SDLC Recommendation & Justification",
            f"- **Selected Model:** {sdlc.get('recommended_sdlc', '')}",
            f"- **Dominant Constraint:** {sdlc.get('dominant_constraint', '')}",
            f"- **Justification:** {sdlc.get('justification', '')}",
        ]
    )
    srs_md = "\n".join(srs_lines)
    files["srs.md"] = srs_md.encode("utf-8")

    doc = docx.Document()
    doc.add_heading(f"Software Requirements Specification: {project_name}", level=0)
    doc.add_paragraph(f"Scope: {functionality}")
    doc.add_paragraph(f"Recommended SDLC: {sdlc.get('recommended_sdlc', 'TBD')}")
    doc.add_heading("Requirements", level=1)
    for r in reqs:
        doc.add_heading(f"{r['req_id']} ({', '.join(r.get('categories', []))})", level=2)
        doc.add_paragraph(f"Statement: {r['statement']}")
        doc.add_paragraph(f"Acceptance Criteria: {r.get('acceptance_criteria', '')}")
        doc.add_paragraph(f"Citations: {', '.join(r.get('citations', []))} | Confidence: {r.get('confidence_score')} | Status: {r.get('approval_status')}")
    doc_buf = io.BytesIO()
    doc.save(doc_buf)
    files["srs.docx"] = doc_buf.getvalue()

    # 2. User Stories & Acceptance Criteria
    us_lines = [f"# User Stories & Acceptance Criteria — {project_name}", ""]
    for idx, r in enumerate(reqs, start=1):
        us_lines.extend(
            [
                f"## US-{idx:03d} (Linked: {r['req_id']})",
                f"**As a** {r.get('source_stakeholder', 'Security Stakeholder')}, **I want** {r['statement'].rstrip('.')} **so that** {r.get('business_justification', 'system security is maintained')}.",
                f"- **Acceptance Criteria:** {r.get('acceptance_criteria', '')}",
                "",
            ]
        )
    files["user_stories.md"] = "\n".join(us_lines).encode("utf-8")

    # 3. Use Cases
    uc_lines = [f"# Use Case Descriptions — {project_name}", ""]
    for idx, r in enumerate(reqs[:8], start=1):
        uc_lines.extend(
            [
                f"## UC-{idx:03d}: Enforce {r['req_id']}",
                f"- **Primary Actor:** {r.get('source_stakeholder', 'System Administrator')}",
                f"- **Preconditions:** System initialized with valid security policy and KB baseline.",
                f"- **Main Flow:** {r['statement']}",
                f"- **Postconditions:** Action verified and recorded in tamper-evident audit trail.",
                "",
            ]
        )
    files["use_cases.md"] = "\n".join(uc_lines).encode("utf-8")

    # 4. Mermaid Process Flowchart
    mmd_lines = ["flowchart TD", "    INP[Stakeholder & Standards Input] --> EXT[Agent 1: Extraction]"]
    prev_node = "EXT"
    for r in reqs[:8]:
        nid = r["req_id"].replace("-", "_")
        label = r["statement"][:48].replace('"', "'")
        mmd_lines.append(f'    {nid}["{r["req_id"]}: {label}..."]')
        mmd_lines.append(f"    {prev_node} --> {nid}")
    last_req = reqs[min(len(reqs), 8) - 1]["req_id"].replace("-", "_") if reqs else "EXT"
    mmd_lines.extend(
        [
            f"    {last_req} --> QUAL[Quality & Conflict Gate]",
            "    QUAL --> COMP[Compliance & Risk Analysis]",
            f'    COMP --> SDLC["Agent 2 SDLC: {sdlc.get("recommended_sdlc", "Hybrid")}"]',
            "    SDLC --> HITL{Human-in-the-Loop Approval}",
            "    HITL -->|Approved| BASE[Locked Baseline & Artefacts]",
        ]
    )
    mmd_str = "\n".join(mmd_lines)
    files["process_workflow.mmd"] = mmd_str.encode("utf-8")
    files["process_workflow.md"] = f"# Requirements & SDLC Process Workflow\n\n```mermaid\n{mmd_str}\n```\n".encode("utf-8")

    # 5. Data & Interface Requirements
    di_lines = [f"# Data & Interface Requirements — {project_name}", ""]
    data_reqs = [r for r in reqs if any(c in r.get("categories", []) for c in ["Data Management", "Integration", "Privacy", "Audit & Reporting"])] or reqs[:3]
    for r in data_reqs:
        di_lines.append(f"- **{r['req_id']}** ({', '.join(r.get('categories', []))}): {r['statement']}")
    files["data_interface_requirements.md"] = "\n".join(di_lines).encode("utf-8")

    # 6. Risk Register (CSV + XLSX)
    risk_headers = ["Risk ID", "Req ID", "Category", "Threat Description", "Likelihood", "Impact", "Rating", "Mitigation", "Owner Role"]
    risk_rows = [[rk["risk_id"], rk["req_id"], rk["category"], rk["threat_description"], rk["likelihood"], rk["impact"], rk["risk_rating"], rk["mitigation"], rk["owner_role"]] for rk in risks]
    files["risk_register.csv"] = _to_csv_bytes(risk_headers, risk_rows)
    files["risk_register.xlsx"] = _to_xlsx_bytes("Risk Register", risk_headers, risk_rows)

    # 7. Compliance Control Matrix (CSV + XLSX)
    cmp_headers = ["Mapping ID", "Req ID", "KB ID", "Standard", "Jurisdiction", "Required Control", "Gap", "Mandatory Checkpoint", "Retention Obligation", "Approval Status"]
    cmp_rows = [[m["mapping_id"], m["req_id"], m["kb_id"], m["standard"], m["jurisdiction"], m["required_control"], m["compliance_gap"], m["mandatory_checkpoint"], m["retention_obligation"], m["approval_status"]] for m in mappings]
    files["compliance_control_matrix.csv"] = _to_csv_bytes(cmp_headers, cmp_rows)
    files["compliance_control_matrix.xlsx"] = _to_xlsx_bytes("Compliance Matrix", cmp_headers, cmp_rows)

    # 8. Requirements Traceability Matrix (CSV + XLSX)
    cmp_by_req = {m["req_id"]: m for m in mappings}
    risk_by_req = {rk["req_id"]: rk for rk in risks}
    rtm_headers = ["Req ID", "Kind", "Categories", "Source Stakeholder", "Citations", "Compliance KB", "Risk ID / Rating", "Confidence", "Approval Status"]
    rtm_rows = []
    for r in reqs:
        m = cmp_by_req.get(r["req_id"], {})
        rk = risk_by_req.get(r["req_id"], {})
        rtm_rows.append([
            r["req_id"],
            r["kind"],
            ", ".join(r.get("categories", [])),
            r.get("source_stakeholder", ""),
            ", ".join(r.get("citations", [])),
            m.get("kb_id", ""),
            f"{rk.get('risk_id', '')} ({rk.get('risk_rating', '')})",
            r.get("confidence_score", ""),
            r.get("approval_status", ""),
        ])
    files["traceability_matrix.csv"] = _to_csv_bytes(rtm_headers, rtm_rows)
    files["traceability_matrix.xlsx"] = _to_xlsx_bytes("Traceability Matrix", rtm_headers, rtm_rows)

    # 9. Assumptions & Dependencies Register (CSV + XLSX)
    ad_headers = ["Req ID", "Dependencies", "Assumptions"]
    ad_rows = [[r["req_id"], ", ".join(r.get("dependencies", [])) or "None", "; ".join(r.get("assumptions", [])) or "Standard operational environment"] for r in reqs]
    files["assumptions_dependencies.csv"] = _to_csv_bytes(ad_headers, ad_rows)
    files["assumptions_dependencies.xlsx"] = _to_xlsx_bytes("Assumptions_Deps", ad_headers, ad_rows)

    # 10. Open Issues List (CSV + XLSX)
    iss_headers = ["Issue ID", "Req ID", "Type", "Severity", "Description", "Target Stakeholder", "Clarification Question"]
    iss_rows = [[i["issue_id"], i["req_id"], i["issue_type"], i["severity"], i["description"], i["target_stakeholder"], i["clarification_question"]] for i in issues]
    files["open_issues.csv"] = _to_csv_bytes(iss_headers, iss_rows)
    files["open_issues.xlsx"] = _to_xlsx_bytes("Open Issues", iss_headers, iss_rows)

    # 11. Tailored SDLC Workflow
    wf_lines = [f"# Tailored SDLC Workflow: {sdlc.get('recommended_sdlc', 'SDLC')}", ""]
    for ph in workflow:
        wf_lines.extend(
            [
                f"## {ph['name']}",
                f"- **Mapped Requirements:** {', '.join(ph.get('mapped_req_ids', [])) or 'All'}",
                f"- **Responsible Roles:** {', '.join(ph.get('roles', []))}",
                f"- **Activities:** {'; '.join(ph.get('activities', []))}",
                f"- **Security Activities:** {'; '.join(ph.get('security_activities', []))}",
                f"- **Testing Requirements:** {'; '.join(ph.get('testing_requirements', []))}",
                f"- **Compliance Checkpoints:** {'; '.join(ph.get('compliance_checkpoints', []))}",
                f"- **Human Approval Gate:** {ph.get('approval_gate', '')}",
                f"- **Deliverables:** {', '.join(ph.get('deliverables', []))}",
                "",
            ]
        )
    files["sdlc_workflow.md"] = "\n".join(wf_lines).encode("utf-8")

    # Master ZIP bundle
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    files["artefacts_bundle.zip"] = zip_buf.getvalue()
    return files
