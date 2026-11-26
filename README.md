# SecReqAgents — Multi-Agent Cybersecurity Requirements Engineering & Secure SDLC Platform

An original, **100% local-first** multi-agent platform for automated **requirements gathering, quality/conflict analysis, compliance & risk mapping, tailored SDLC recommendation, and artefact generation** in **Cybersecurity & Regulated IT Systems** (Common Criteria Protection Profiles, NIST SP 800-53, ISO/IEC 27001, OWASP ASVS, IEEE 29148).

Built around two custom fine-tuned **`Qwen2.5-3B-Instruct` PEFT LoRA adapters** (`qwen2.5-3b-cc-agent1` and `qwen2.5-3b-cc-agent2`), paired with hybrid RAG retrieval, deterministic validation rules, human-in-the-loop (HITL) governance, and a tamper-evident audit trail.

- **Local GPU + Deterministic Dual Mode:** Runs your fine-tuned 4-bit `Qwen2.5-3B` LoRA adapters locally on GPU (e.g. RTX 3050 6 GB) or switches to instant deterministic rule-backed execution for fast testing/demos.
- **Grounded & Accountable:** Every extracted requirement goes through citation verification, number grounding, claim-support scoring, confidence thresholding, and mandatory role-based human sign-off.
- **Security-First Design:** Sensitive identifiers (emails, IPs, API keys, passwords, cards/PAN) are masked before any model call; untrusted inputs are scanned for prompt injection; every action is logged in a SHA-256 hash-chained audit trail.

---

## Multi-Agent & Component Overview

| Component | File(s) | What It Does | Kind |
|---|---|---|---|
| **Stakeholder Interaction Agent** | `interview/` | Adaptive chat interview across 9 security stakeholder roles and 12 topics; probes vague, non-numeric, or contradictory answers; imports raw emails/notes. | Rules + KB hints |
| **Knowledge Base & Hybrid RAG** | `kb/`, `rag/` | Versioned YAML standards (Common Criteria SFRs, NIST, ISO 27001, OWASP, IEEE 29148) + document chunker + TF-IDF/MiniLM + SFR-ID retrieval + grounding verifier. | Deterministic + Embeddings |
| **Agent 1: Requirement Extractor** | `agents/extractor.py` | Powered by **`qwen2.5-3b-cc-agent1` LoRA**; extracts requirements with robust JSON repair, 13-class multi-label classification, Given/When/Then criteria, and confidence scores. | Fine-tuned LoRA + Rules |
| **Quality & Clarification Agent** | `agents/quality.py` | Detects all 10 defect types (ambiguity, incompleteness, numeric/policy conflicts, TF-IDF duplicates, missing citations/controls, undefined acronyms) and routes questions to stakeholders. | Rules + Base LLM |
| **Compliance & Risk Agent** | `agents/compliance_risk.py` | Maps requirements to KB standards/jurisdictions, flags gaps and mandatory Compliance Officer checkpoints, and builds the Likelihood × Impact Threat & Risk Register. | Rules + KB |
| **Agent 2: Hybrid SDLC Selector** | `agents/sdlc.py` | Powered by **`qwen2.5-3b-cc-agent2` LoRA** + deterministic MCDA across 13 decision factors and 6 SDLC models, producing ranked percentages and dominant constraint justification. | Fine-tuned LoRA + MCDA |
| **Workflow Generator** | `agents/workflow.py` | Customizes the winning SDLC template with phases, responsible roles, SAST/DAST/CC gates, entry/exit criteria, and requirement-to-phase traceability. | Template + Rules |
| **Human-in-the-Loop Governance** | `orchestrator/`, `security/rbac.py` | Accept / Edit / Needs Revision / Reject, mandatory role enforcement, 4-role joint SDLC vote, versioned baseline locking, and change-request tracking. | SQLite + RBAC |
| **Artefact Generator** | `artefacts/generator.py` | Exports IEEE 830 SRS (`MD` & `DOCX`), User Stories, Use Cases, Mermaid Flowchart, Risk Register, Compliance Matrix, RTM, Assumptions/Dependencies, Open Issues (`CSV` & `XLSX`), and ZIP bundle. | Deterministic |
| **Evaluation Suite** | `evaluation/evaluator.py` | Benchmarks Precision, Recall, F1, Citation Correctness, Hallucination Rate, Control Coverage, Ambiguity/Conflict Detection, and SDLC Accuracy across 3 case studies vs. single-prompt baseline. | Deterministic + LLM |

---

## Development Flow & File-by-File Sequence

Files are structured and committed in the exact dependency order of the architecture so you can walk through the codebase from initial model training to the full local application:

### Stage 0 — Model Training & Colab Prototyping (`notebooks/`)
0. **[`notebooks/01_rag_corpus_builder.ipynb`](notebooks/01_rag_corpus_builder.ipynb)** — Chunks Common Criteria Protection Profiles, extracts SFR IDs, and builds `all-MiniLM-L6-v2` embeddings.
   - **[`notebooks/02_train_agent1_requirements_lora.ipynb`](notebooks/02_train_agent1_requirements_lora.ipynb)** — Fine-tunes `qwen2.5-3b-cc-agent1` (4-bit QLoRA) for grounded security requirement extraction + v2 negative-abstention training.
   - **[`notebooks/03_train_agent2_sdlc_lora.ipynb`](notebooks/03_train_agent2_sdlc_lora.ipynb)** — Fine-tunes `qwen2.5-3b-cc-agent2` (4-bit QLoRA) for requirement weighting, dominant-constraint detection, and SDLC recommendation.
   - **[`notebooks/04_multi_agent_colab_prototype.ipynb`](notebooks/04_multi_agent_colab_prototype.ipynb)** — Clean 2-agent Gradio prototype connecting Agent 1 → Agent 2 before integrating into the full local platform below.

### Stage 1 — Configuration & Environment
1. **[`config.py`](config.py)** — Central configuration: paths, domain scopes, 13 requirement categories, 9 stakeholder roles, 6 RBAC roles, 4 joint SDLC vote roles, confidence review threshold (`0.72`), vague-term dictionary, and baseline security controls. Used across every module.
2. **[`requirements.txt`](requirements.txt)** & **[`pytest.ini`](pytest.ini)** — Python dependencies and pytest root/path configuration.
3. **[`.streamlit/config.toml`](.streamlit/config.toml)** — Disables telemetry prompts and sets headless/watcher options for smooth local Windows execution.

### Stage 2 — Versioned Knowledge Base (`kb/`)
4. **[`kb/cc_sfrs.yaml`](kb/cc_sfrs.yaml)** — Common Criteria v3.1 Protection Profile SFRs (`FDP_IFF.1.1`, `FDP_ACC.2`, `FDP_ACF.1.1`, `FIA_UAU.1.1`, `FPT_TUD_EXT.1`, `FAU_GEN.1.1`, `FPT_PHP.1`, `FPT_TST.1`, `FCS_COP.1`) with standard, jurisdiction, version, effective date, applicability tags, and retention duties.
5. **[`kb/standards.yaml`](kb/standards.yaml)** — NIST SP 800-53 Rev.5, ISO/IEC 27001:2022, OWASP ASVS v4.0.3, and ISO/IEC/IEEE 29148 requirement quality controls.
6. **[`kb/sdlc_policies.yaml`](kb/sdlc_policies.yaml)** — Weighted MCDA rules and phase templates for 6 SDLC models (`High-Assurance V-Model`, `DevSecOps (Continuous Agile)`, `Agile-DevSecOps Hybrid`, `Agile-V-Model Hybrid`, `Spiral`, `Waterfall`).

### Stage 3 — Platform Security Layer (`security/`)
7. **[`security/masking.py`](security/masking.py)** — `mask_text()` and `mask_payload()` redact secrets, Bearer tokens, API keys, emails, Luhn-checked cards, PAN, SSN, IPv4 addresses, phones, and labeled names before any LLM prompt or audit write.
8. **[`security/injection.py`](security/injection.py)** — `scan_and_quarantine()` flags adversarial override/exfiltration patterns; `frame_untrusted_text()` wraps stakeholder/document text in `<<<UNTRUSTED_DATA>>>` delimiters.
9. **[`security/rbac.py`](security/rbac.py)** — `AuthManager` (PBKDF2-HMAC-SHA256 password hashing), `authorize_action()` role enforcement, and `filter_state_for_agent()` implementing least-privilege state slicing per agent.
10. **[`security/audit.py`](security/audit.py)** — `AuditLogger` and `verify_audit_chain()` maintaining an append-only SHA-256 hash-chained `logs/audit_log.jsonl`.

### Stage 4 — Hybrid RAG & Grounding (`rag/`)
11. **[`rag/retriever.py`](rag/retriever.py)** — `KnowledgeBaseRetriever` (TF-IDF + optional `all-MiniLM-L6-v2` dense embeddings + regex SFR-ID boosting), `chunk_document()`, `extract_text_from_bytes()` (PDF/DOCX/TXT/MD), and `import_colab_chunks()`.
12. **[`rag/grounding.py`](rag/grounding.py)** — `verify_requirement_grounding()` computes `citation_score`, `number_score`, `support_score`, weighted `confidence`, and `needs_human_review`.

### Stage 5 — LLM Runtime & Trained LoRA Integration (`llm/`, `models/`)
13. **[`llm/json_utils.py`](llm/json_utils.py)** — `extract_json_payload()` strips prose prefixes (e.g., `"Based on the retrieved source material..."`) and markdown fences, then repairs malformed JSON using `json_repair`.
14. **[`llm/engine.py`](llm/engine.py)** — `LLMEngine` manages `deterministic` mode and `local_gpu` mode (loads 4-bit `unsloth/qwen2.5-3b-instruct-unsloth-bnb-4bit` once into VRAM and hot-swaps PEFT adapters `agent1` and `agent2`, or disables adapters for base model calls, with automatic `mask_payload()` guard).
15. **`models/`** — Holds your complete fine-tuned PEFT LoRA adapters (`qwen2.5-3b-cc-agent1`, `qwen2.5-3b-cc-agent2`), with `adapter_model.safetensors` stored directly in the repository via **Git LFS**.

### Stage 6 — Adaptive Stakeholder Elicitation (`interview/`)
16. **[`interview/templates.py`](interview/templates.py)** — 12 structured security engineering topics and role-specific focus mappings for 9 stakeholder roles.
17. **[`interview/engine.py`](interview/engine.py)** — `AdaptiveInterviewEngine` evaluates vagueness, missing quantitative thresholds, and numeric contradictions to trigger follow-up questions; `import_unstructured_notes()` ingests raw emails/meeting notes.

### Stage 7 — Specialized AI Agents (`agents/`)
18. **[`agents/schemas.py`](agents/schemas.py)** — Pydantic v2 data contracts (`RequirementItem`, `QualityIssue`, `ComplianceMapping`, `RiskEntry`, `SDLCRecommendation`, `WorkflowPhase`).
19. **[`agents/extractor.py`](agents/extractor.py)** — `RequirementExtractionAgent` invokes `cc-agent1` LoRA (or grounded fallback), runs 13-class multi-label classification, generates Given/When/Then criteria, and attaches grounding confidence.
20. **[`agents/quality.py`](agents/quality.py)** — `QualityClarificationAgent` checks ambiguity, incompleteness, missing citations, testability, undefined acronyms, TF-IDF duplicates, numeric/policy conflicts, and missing baseline controls.
21. **[`agents/compliance_risk.py`](agents/compliance_risk.py)** — `ComplianceRiskAgent` maps requirements to KB rules, identifies gaps/retention duties, and builds the Threat & Risk Register.
22. **[`agents/sdlc.py`](agents/sdlc.py)** — `SDLCSelectionAgent` derives the 13 SDLC factors, runs `cc-agent2` LoRA for requirement weighting/dominant constraint, and computes ranked MCDA percentages across all 6 SDLC models.
23. **[`agents/workflow.py`](agents/workflow.py)** — `WorkflowGeneratorAgent` binds extracted `REQ-xxx` IDs and mandatory approval gates into the selected SDLC's phase template.

### Stage 8 — Artefacts & Central Orchestration (`artefacts/`, `orchestrator/`)
24. **[`artefacts/generator.py`](artefacts/generator.py)** — `generate_artefacts()` builds all 11 outputs (`srs.md`, `srs.docx`, `user_stories.md`, `use_cases.md`, `process_workflow.mmd/.md`, `data_interface_requirements.md`, `risk_register`, `compliance_control_matrix`, `traceability_matrix`, `assumptions_dependencies`, `open_issues` in CSV/XLSX, `sdlc_workflow.md`) and packages `artefacts_bundle.zip`.
25. **[`orchestrator/store.py`](orchestrator/store.py)** — `ProjectStore` persists runs, versioned baselines, change requests, and stakeholder feedback in SQLite (`data/secreq.db`).
26. **[`orchestrator/pipeline.py`](orchestrator/pipeline.py)** — `MultiAgentOrchestrator` coordinates end-to-end execution, least-privilege state filtering, RBAC-enforced HITL requirement decisions, 4-role SDLC voting, baseline locking, and audit logging.

### Stage 9 — Evaluation, Case Studies, CLI & Web UI
27. **[`case_studies/`](case_studies/)** — Representative scenarios (`firewall_gateway.json`, `zero_trust_iam.json`, `trusted_firmware_tpm.json`) with gold requirements, expected standards, SDLC targets, and seeded defects.
28. **[`evaluation/evaluator.py`](evaluation/evaluator.py)** — `evaluate_all_case_studies()` compares the multi-agent RAG pipeline against a single-prompt no-RAG baseline.
29. **[`ui/app.py`](ui/app.py)** — 7-page Streamlit application (Interview, Pipeline, HITL Review & SDLC Vote, Results & Artefacts, KB & Colab Import, Evaluation & Feedback, Security & Audit).
30. **[`run_demo.py`](run_demo.py)** & **[`start_app.ps1`](start_app.ps1)** — CLI runner/benchmark and one-click Windows launcher.

### Stage 10 — Verification Suite (`tests/`)
31. **[`tests/test_suite.py`](tests/test_suite.py)** — Pytest suite verifying masking, prompt-injection quarantine, audit hash-chain tamper detection, Colab JSON repair, adaptive interviews, full E2E pipeline + HITL + artefacts + evaluation, and UI syntax.

---

## Setup & Running Locally (Windows)

1. **Clone with Git LFS (includes fine-tuned LoRA weights):**
   ```powershell
   git lfs install
   git clone https://github.com/HarbhajanSingh11116/SE-Project.git
   cd SE-Project
   git lfs pull
   ```
2. **Create virtual environment & install dependencies** (Python 3.12 recommended):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\pip install torch --index-url https://download.pytorch.org/whl/cu124
   .\.venv\Scripts\pip install -r requirements.txt
   ```
3. **Launch the Web UI:**
   ```powershell
   .\start_app.ps1
   ```
   Open **`http://localhost:8501`** in your browser.

### Demo Accounts (RBAC)
Default password for all seeded demo accounts: `demo1234` (change via `SECREQ_DEMO_PASS` env var):
- `admin` — Full administrative + all review roles
- `analyst` — Requirement review & pipeline runs
- `sec_officer` — High-risk security requirement approvals & SDLC vote
- `compliance` — Compliance mapping approvals & SDLC vote
- `architect` — Architecture-critical requirement approvals & SDLC vote
- `pm` — Conflict resolution, SDLC vote & baseline locking

---

## Testing & Benchmark Commands

```powershell
# Run automated test suite (6/6 tests)
.\.venv\Scripts\python.exe -m pytest tests\test_suite.py -v

# Run quantitative evaluation benchmark (Multi-Agent RAG vs. Single-Prompt Baseline)
.\.venv\Scripts\python.exe run_demo.py --eval

# Run end-to-end CLI demo and export artefacts
.\.venv\Scripts\python.exe run_demo.py --out demo_output
```

### Measured Benchmark Summary (Deterministic Mode across 3 Case Studies)
- **Requirement Extraction F1:** `0.939` (vs. `0.400` single-prompt baseline)
- **Citation Correctness:** `1.000` | **Hallucination Rate:** `0.000`
- **Regulatory Control Coverage:** `0.878`
- **Ambiguity Detection:** `1.000` | **Conflict Detection:** `1.000`
- **SDLC Top-3 Accuracy:** `1.000` | **Traceability Coverage:** `1.000`
