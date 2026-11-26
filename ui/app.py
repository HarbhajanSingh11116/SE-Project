"""SecReqAgents — Multi-Agent Cybersecurity Requirements Engineering & SDLC Platform (Streamlit UI)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import pandas as pd
import streamlit as st

from artefacts import generate_artefacts
from config import CASE_STUDIES_DIR, DOMAIN_SCOPES, SDLC_JOINT_VOTE_ROLES, STAKEHOLDER_ROLES
from evaluation import evaluate_all_case_studies
from interview import AdaptiveInterviewEngine, import_unstructured_notes
from llm import LLMEngine
from orchestrator import MultiAgentOrchestrator, ProjectStore
from rag import KnowledgeBaseRetriever, extract_text_from_bytes
from security import AuthManager, verify_audit_chain
from security.audit import AuditLogger
from security.rbac import authorize_action

st.set_page_config(page_title="SecReqAgents | Agentic RE & SDLC", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_core_services(llm_mode: str, use_dense: bool):
    kb = KnowledgeBaseRetriever(use_dense_embeddings=use_dense)
    llm = LLMEngine(mode=llm_mode)
    store = ProjectStore()
    audit = AuditLogger()
    auth = AuthManager()
    orch = MultiAgentOrchestrator(kb=kb, llm=llm, store=store, audit=audit)
    return kb, llm, store, audit, auth, orch


if "user" not in st.session_state:
    st.session_state.user = {"username": "admin", "roles": ["admin", "analyst", "architect", "security_officer", "compliance_officer", "project_manager"]}
if "llm_mode" not in st.session_state:
    st.session_state.llm_mode = "deterministic"
if "use_dense" not in st.session_state:
    st.session_state.use_dense = False
if "interview_excerpts" not in st.session_state:
    st.session_state.interview_excerpts = []
if "active_run_id" not in st.session_state:
    st.session_state.active_run_id = None

kb, llm, store, audit, auth, orch = get_core_services(st.session_state.llm_mode, st.session_state.use_dense)

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.title("🛡️ SecReqAgents")
    st.caption("Cybersecurity & Common Criteria Multi-Agent RE + SDLC")

    st.subheader("Active Session (RBAC)")
    st.write(f"**User:** `{st.session_state.user['username']}`")
    st.write(f"**Roles:** `{', '.join(st.session_state.user['roles'])}`")

    with st.expander("Switch Role / Login"):
        demo_users = auth.list_users()
        uname = st.selectbox("Username", [u["username"] for u in demo_users])
        pwd = st.text_input("Password (default: demo1234)", value="demo1234", type="password")
        if st.button("Authenticate"):
            res = auth.authenticate(uname, pwd)
            if res:
                st.session_state.user = res
                audit.log("user_login", actor=res["username"], role=",".join(res["roles"]))
                st.success(f"Signed in as {res['username']}")
                st.rerun()
            else:
                st.error("Invalid credentials.")

    st.divider()
    st.subheader("AI Runtime Mode")
    gpu_ok, gpu_msg = llm.gpu_available()
    st.caption(f"Hardware: {gpu_msg}")
    chosen_mode = st.radio(
        "Execution Backend",
        ["deterministic", "local_gpu"],
        format_func=lambda x: "Fast Deterministic + Rules (Instant)" if x == "deterministic" else "Local GPU: Qwen2.5-3B + Your LoRA Adapters",
        index=0 if st.session_state.llm_mode == "deterministic" else 1,
    )
    if chosen_mode != st.session_state.llm_mode:
        st.session_state.llm_mode = chosen_mode
        st.rerun()
    if llm.load_error:
        st.warning(f"GPU fallback note: {llm.load_error}")

    st.divider()
    page = st.radio(
        "Workspace",
        [
            "1. Stakeholder Interview & Input",
            "2. Run Multi-Agent Pipeline",
            "3. HITL Review & SDLC Vote",
            "4. Results, Mermaid & Artefacts",
            "5. Knowledge Base & Colab Import",
            "6. Evaluation & Feedback",
            "7. Security & Audit Trail",
        ],
    )

user = st.session_state.user

# ---------------- PAGE 1: INTERVIEW ----------------
if page.startswith("1."):
    st.header("1. Adaptive Stakeholder Interview & Unstructured Input")
    col1, col2 = st.columns([2, 1])
    with col1:
        role = st.selectbox("Stakeholder Role Template", STAKEHOLDER_ROLES)
        if "interview_engine" not in st.session_state or st.session_state.get("interview_role") != role:
            if st.button("Start / Reset Adaptive Interview") or "interview_engine" not in st.session_state:
                st.session_state.interview_engine = AdaptiveInterviewEngine(role=role, kb=kb, llm_engine=llm)
                st.session_state.interview_role = role

        eng: AdaptiveInterviewEngine = st.session_state.interview_engine
        for msg in eng.transcript_history:
            with st.chat_message("assistant" if msg["speaker"] == "agent" else "user"):
                st.markdown(msg["text"])

        if not eng.is_complete():
            ans = st.chat_input("Answer the stakeholder question (or type 'skip')...")
            if ans:
                eng.submit_answer(ans)
                st.rerun()
        else:
            st.success("Interview completed!")

        if st.button("Attach Interview Transcripts to Pipeline"):
            st.session_state.interview_excerpts = eng.export_excerpts()
            st.success(f"Attached {len(st.session_state.interview_excerpts)} masked interview excerpts.")

    with col2:
        st.subheader("Import Emails / Notes / Questionnaires")
        note_role = st.selectbox("Source Role", STAKEHOLDER_ROLES, key="note_role")
        note_type = st.selectbox("Input Type", ["email", "meeting_notes", "questionnaire", "incident_report"])
        raw_notes = st.text_area("Paste raw notes (sensitive PII/keys will be auto-masked)", height=180)
        if st.button("Import & Mask Notes") and raw_notes.strip():
            imported = import_unstructured_notes(raw_notes, note_role, note_type)
            st.session_state.interview_excerpts.extend(imported)
            st.success(f"Imported {len(imported)} masked excerpts.")
        st.info(f"Currently queued interview/note excerpts: **{len(st.session_state.interview_excerpts)}**")
        if st.session_state.interview_excerpts and st.button("Clear Queued Excerpts"):
            st.session_state.interview_excerpts = []
            st.rerun()

# ---------------- PAGE 2: PIPELINE ----------------
elif page.startswith("2."):
    st.header("2. Multi-Agent Requirements & SDLC Pipeline")

    case_files = sorted(CASE_STUDIES_DIR.glob("*.json"))
    case_names = ["Custom Project"] + [p.stem for p in case_files]
    selected_case = st.selectbox("Load Representative Case Study (Optional)", case_names)

    default_proj = "Enterprise Boundary Firewall"
    default_domain = DOMAIN_SCOPES[0]
    default_func = "Firewall traffic filtering, interface-bound authentication, and access control enforcement"
    default_doc = (
        "The firewall shall enforce FDP_IFF.1.1 and FDP_ACC.2 across source IP, destination IP, "
        "and application protocols (HTTP, SSH, SQL). Interface identification (FIA_UAU.1.1) must occur "
        "before user authentication. All audit records must be retained for 365 days."
    )

    if selected_case != "Custom Project":
        with (CASE_STUDIES_DIR / f"{selected_case}.json").open("r", encoding="utf-8") as f:
            cdata = json.load(f)
        default_proj = cdata["project_name"]
        default_domain = cdata["domain"]
        default_func = cdata["functionality"]
        default_doc = cdata["document_text"]

    c1, c2 = st.columns(2)
    with c1:
        proj_name = st.text_input("Project Name", value=default_proj)
        domain = st.selectbox("Target Security Domain", DOMAIN_SCOPES, index=DOMAIN_SCOPES.index(default_domain) if default_domain in DOMAIN_SCOPES else 0)
        stakeholder = st.selectbox("Primary Stakeholder", STAKEHOLDER_ROLES, index=4)
    with c2:
        max_reqs = st.slider("Max Extracted Requirements", 3, 12, 6)
        stability = st.select_slider("Requirement Stability", ["Low", "Medium", "High"], value="Medium")
        change_freq = st.select_slider("Expected Change Frequency", ["Low", "Medium", "High"], value="High")

    functionality = st.text_input("System Functionality / Scope", value=default_func)
    spec_text = st.text_area("Specification / Legacy Doc / Policy Input (sensitive tokens auto-masked)", value=default_doc, height=150)
    uploaded_files = st.file_uploader("Upload Supporting Specs (TXT, MD, PDF, DOCX)", accept_multiple_files=True)

    if st.button("🚀 Run Multi-Agent Pipeline", type="primary"):
        raw_docs = []
        if spec_text.strip():
            raw_docs.append({"name": "PrimarySpecInput", "text": spec_text})
        for uf in uploaded_files or []:
            raw_docs.append({"name": uf.name, "text": extract_text_from_bytes(uf.name, uf.read())})

        with st.spinner("Running RAG -> Agent 1 (Extraction) -> Quality -> Compliance/Risk -> Agent 2 (SDLC) -> Workflow..."):
            state = orch.run_pipeline(
                project_name=proj_name,
                domain=domain,
                functionality=functionality,
                raw_documents=raw_docs,
                interview_excerpts=st.session_state.interview_excerpts,
                stakeholder_role=stakeholder,
                project_meta={"requirement_stability": stability, "change_frequency": change_freq},
                max_reqs=max_reqs,
                actor=user["username"],
                actor_roles=user["roles"],
                auto_approve=False,
            )
            st.session_state.active_run_id = state["run_id"]
        st.success(f"Run `{state['run_id']}` complete in {state['timings']['total']}s! Extracted {len(state['requirements'])} requirements. Go to **3. HITL Review** or **4. Results**.")
        if state["quarantined_excerpts"]:
            st.error(f"Quarantined {len(state['quarantined_excerpts'])} excerpt(s) due to prompt-injection patterns!")

# ---------------- PAGE 3: HITL REVIEW ----------------
elif page.startswith("3."):
    st.header("3. Human-in-the-Loop (HITL) Governance & SDLC Vote")
    runs = store.list_runs()
    if not runs:
        st.info("No runs yet. Execute the pipeline in Page 2 first.")
    else:
        run_ids = [r["run_id"] for r in runs]
        idx = run_ids.index(st.session_state.active_run_id) if st.session_state.active_run_id in run_ids else 0
        sel_run_id = st.selectbox("Select Pipeline Run", run_ids, index=idx)
        st.session_state.active_run_id = sel_run_id
        run = store.get_run(sel_run_id)

        st.subheader("A. Requirement Approvals (Accept / Edit / Reject)")
        for req in run["requirements"]:
            lock_badge = f"🔒 Mandatory Role: `{req['mandatory_approval_role']}`" if req.get("mandatory_approval_role") else "General Review"
            with st.expander(f"{req['req_id']} [{req['approval_status']}] — Conf: {req['confidence_score']} | {lock_badge}"):
                edited = st.text_area("Statement", value=req["statement"], key=f"stmt_{sel_run_id}_{req['req_id']}")
                comment = st.text_input("Reviewer Comment", value=req.get("reviewer_comment", ""), key=f"cmt_{sel_run_id}_{req['req_id']}")
                c1, c2, c3 = st.columns(3)
                if c1.button("✅ Approve", key=f"app_{sel_run_id}_{req['req_id']}"):
                    ok, msg = orch.decide_requirement(sel_run_id, req["req_id"], "Approved", user["username"], user["roles"], edited, comment)
                    st.toast(msg) if ok else st.error(msg)
                    if ok:
                        st.rerun()
                if c2.button("🔄 Needs Revision", key=f"rev_{sel_run_id}_{req['req_id']}"):
                    ok, msg = orch.decide_requirement(sel_run_id, req["req_id"], "Needs Revision", user["username"], user["roles"], edited, comment)
                    st.toast(msg) if ok else st.error(msg)
                    if ok:
                        st.rerun()
                if c3.button("❌ Reject", key=f"rej_{sel_run_id}_{req['req_id']}"):
                    ok, msg = orch.decide_requirement(sel_run_id, req["req_id"], "Rejected", user["username"], user["roles"], edited, comment)
                    st.toast(msg) if ok else st.error(msg)
                    if ok:
                        st.rerun()

        st.subheader("B. Joint 4-Role SDLC Selection Vote")
        sdlc = run["sdlc_recommendation"]
        st.write(f"**Current Top Recommendation:** `{sdlc['recommended_sdlc']}` | **Overall Status:** `{sdlc['approval_status']}`")
        st.write("**Votes:**", sdlc.get("votes", {}))
        vc1, vc2, vc3 = st.columns(3)
        vote_role = vc1.selectbox("Vote As Role", SDLC_JOINT_VOTE_ROLES)
        model_choices = [m["model_name"] for m in sdlc.get("ranked_models", [])] or [sdlc["recommended_sdlc"]]
        override = vc2.selectbox("SDLC Model", model_choices)
        if vc3.button("Cast Approving SDLC Vote"):
            ok, msg = orch.vote_sdlc(sel_run_id, vote_role, "Approved", user["username"], user["roles"], override_model=override)
            st.success(msg) if ok else st.error(msg)
            if ok:
                st.rerun()

        st.subheader("C. Lock Versioned Baseline & Change Requests")
        if st.button("🔐 Lock Approved Baseline"):
            ok, msg = orch.lock_run_baseline(sel_run_id, user["username"], user["roles"])
            st.success(msg) if ok else st.error(msg)

        baselines = store.list_baselines()
        if baselines:
            st.dataframe(pd.DataFrame(baselines), use_container_width=True)

# ---------------- PAGE 4: RESULTS & ARTEFACTS ----------------
elif page.startswith("4."):
    st.header("4. Analysis Results, Mermaid Workflow & Export Artefacts")
    runs = store.list_runs()
    if not runs:
        st.info("No runs available yet.")
    else:
        run_ids = [r["run_id"] for r in runs]
        idx = run_ids.index(st.session_state.active_run_id) if st.session_state.active_run_id in run_ids else 0
        sel_run_id = st.selectbox("Select Run", run_ids, index=idx)
        run = store.get_run(sel_run_id)

        t1, t2, t3, t4, t5 = st.tabs(["Requirements", "Quality & Conflicts", "Compliance & Risk", "SDLC & Workflow", "📦 Artefacts"])
        with t1:
            st.caption(f"Extractor Backend: `{run['agent_meta']['extractor'].get('adapter_used')}` | Total Time: `{run['timings'].get('total')}s`")
            st.dataframe(pd.DataFrame(run["requirements"])[["req_id", "kind", "categories", "statement", "priority", "confidence_score", "approval_status"]], use_container_width=True)
        with t2:
            if run["quality_issues"]:
                st.dataframe(pd.DataFrame(run["quality_issues"]), use_container_width=True)
            else:
                st.success("Zero quality or ambiguity defects detected.")
            if run["conflicts"]:
                st.warning(f"Conflicts detected: {run['conflicts']}")
        with t3:
            st.subheader("Compliance Control Matrix")
            st.dataframe(pd.DataFrame(run["compliance_mappings"]), use_container_width=True)
            st.subheader("Threat & Risk Register")
            st.dataframe(pd.DataFrame(run["risk_register"]), use_container_width=True)
        with t4:
            sdlc = run["sdlc_recommendation"]
            st.subheader(f"Recommended SDLC: {sdlc['recommended_sdlc']}")
            st.write(f"**Dominant Constraint:** {sdlc['dominant_constraint']}")
            st.write(f"**Justification:** {sdlc['justification']}")
            st.dataframe(pd.DataFrame(sdlc["ranked_models"]), use_container_width=True)
            st.subheader("Tailored SDLC Phases")
            st.dataframe(pd.DataFrame(run["sdlc_workflow"]), use_container_width=True)
        with t5:
            files = generate_artefacts(run)
            st.download_button("⬇️ Download All Artefacts (ZIP)", data=files["artefacts_bundle.zip"], file_name=f"{sel_run_id}_artefacts.zip", mime="application/zip")
            c1, c2, c3 = st.columns(3)
            c1.download_button("📄 SRS (.docx)", data=files["srs.docx"], file_name="srs.docx")
            c2.download_button("📊 Traceability Matrix (.xlsx)", data=files["traceability_matrix.xlsx"], file_name="traceability_matrix.xlsx")
            c3.download_button("⚠️ Risk Register (.xlsx)", data=files["risk_register.xlsx"], file_name="risk_register.xlsx")
            st.subheader("Process Workflow (Mermaid)")
            st.code(files["process_workflow.mmd"].decode("utf-8"), language="mermaid")

# ---------------- PAGE 5: KNOWLEDGE BASE ----------------
elif page.startswith("5."):
    st.header("5. Versioned Security Knowledge Base & Colab Dataset Importer")
    st.write(f"**KB Version:** `{kb.kb_version}` | **Digest:** `{kb.kb_digest()}` | **Items:** `{len(kb.items)}`")
    st.dataframe(pd.DataFrame([{"id": i["id"], "title": i["title"], "standard": i["standard"], "version": i["version"], "sfr_ids": ", ".join(i.get("sfr_ids", []))} for i in kb.items]), use_container_width=True)

    ok_kb, msg_kb = authorize_action(user["roles"], "manage_kb")
    if ok_kb:
        with st.expander("Import Colab `chunks.json` into Knowledge Base"):
            up_chunks = st.file_uploader("Upload chunks.json", type=["json"])
            if up_chunks and st.button("Index Colab Chunks"):
                n = kb.import_colab_chunks(up_chunks.read(), limit=200)
                st.success(f"Imported and indexed {n} chunks from Colab dataset!")
    else:
        st.info(msg_kb)

# ---------------- PAGE 6: EVALUATION ----------------
elif page.startswith("6."):
    st.header("6. System Evaluation & Stakeholder Satisfaction")
    if st.button("📊 Run Benchmark Evaluation (3 Cybersecurity Case Studies vs Baseline)", type="primary"):
        with st.spinner("Evaluating Multi-Agent RAG pipeline vs. Single-Prompt No-RAG baseline..."):
            st.session_state.eval_report = evaluate_all_case_studies(orch)

    if "eval_report" in st.session_state:
        rep = st.session_state.eval_report
        st.subheader("Summary: Multi-Agent System vs. Single-Prompt Baseline")
        comp_df = pd.DataFrame([
            {"System": "SecReqAgents (Multi-Agent + RAG + Rules)", **rep["summary"]["multi_agent_avg"]},
            {"System": "Single-Prompt Baseline (No RAG)", **rep["summary"]["baseline_avg"]},
        ])
        st.dataframe(comp_df, use_container_width=True)
        st.write(f"**Human Correction Rate:** `{rep['human_correction_rate']}` | **Avg Stakeholder Satisfaction:** `{rep['avg_stakeholder_satisfaction']}`")

    st.subheader("Submit Stakeholder Satisfaction Rating")
    runs = store.list_runs()
    if runs:
        fb_run = st.selectbox("Run ID", [r["run_id"] for r in runs], key="fb_run")
        rating = st.slider("Satisfaction (1 = Poor, 5 = Excellent)", 1, 5, 5)
        comment = st.text_input("Comments")
        if st.button("Submit Feedback"):
            store.add_feedback(fb_run, user["username"], rating, comment)
            st.success("Thank you! Feedback recorded.")

# ---------------- PAGE 7: SECURITY & AUDIT ----------------
elif page.startswith("7."):
    st.header("7. Platform Security & Tamper-Evident Audit Trail")
    valid, msg, cnt = verify_audit_chain()
    if valid:
        st.success(f"🔒 Audit Hash Chain Intact: {msg}")
    else:
        st.error(f"🚨 {msg}")

    ok_aud, msg_aud = authorize_action(user["roles"], "view_audit")
    if ok_aud:
        rows = audit.read_recent(50)
        if rows:
            st.dataframe(pd.DataFrame(rows)[["timestamp", "action", "actor", "role", "run_id", "mask_counts", "entry_hash"]], use_container_width=True)
    else:
        st.warning(msg_aud)
