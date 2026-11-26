"""CLI runner for SecReqAgents end-to-end demo and quantitative evaluation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from artefacts import generate_artefacts
from evaluation import evaluate_all_case_studies
from llm import LLMEngine
from orchestrator import MultiAgentOrchestrator


def main() -> None:
    parser = argparse.ArgumentParser(description="SecReqAgents CLI Demo & Evaluator")
    parser.add_argument("--mode", choices=["deterministic", "local_gpu"], default="deterministic")
    parser.add_argument("--eval", action="store_true", help="Run evaluation suite across all case studies")
    parser.add_argument("--out", default="demo_output", help="Output folder for generated artefacts")
    args = parser.parse_args()

    llm = LLMEngine(mode=args.mode)
    orch = MultiAgentOrchestrator(llm=llm)

    if args.eval:
        report = evaluate_all_case_studies(orch)
        print(json.dumps(report["summary"], indent=2))
        return

    state = orch.run_pipeline(
        project_name="Enterprise Boundary Firewall",
        domain="Network & Boundary Protection (Firewalls / IDS / IPS / VPN)",
        functionality="Firewall traffic filtering, interface-bound authentication, and network access control",
        raw_documents=[
            {
                "name": "FirewallSpec.md",
                "text": (
                    "The interconnection firewall shall enforce FDP_IFF.1.1 and FDP_ACC.2 across source IP, "
                    "destination IP, and application protocols (HTTP, SSH, SQL). Interface identification "
                    "(FIA_UAU.1.1) must occur before authentication. Audit logs must be retained for 365 days."
                ),
            }
        ],
        max_reqs=6,
        actor="admin",
        actor_roles=["admin", "analyst", "architect", "security_officer", "compliance_officer", "project_manager"],
        auto_approve=True,
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = generate_artefacts(state)
    for fname, data in files.items():
        (out_dir / fname).write_bytes(data)

    print(f"Run {state['run_id']} finished in {state['timings']['total']}s")
    print(f"Requirements extracted: {len(state['requirements'])}")
    print(f"Recommended SDLC: {state['sdlc_recommendation']['recommended_sdlc']}")
    print(f"Artefacts saved to: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
