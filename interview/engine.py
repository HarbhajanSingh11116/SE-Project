"""Adaptive Stakeholder Interaction Agent + unstructured transcript/email/note importer."""
from __future__ import annotations

import re
from typing import Any

from config import VAGUE_TERMS
from interview.templates import INTERVIEW_TOPICS, ROLE_TEMPLATES
from rag.retriever import KnowledgeBaseRetriever
from security.masking import mask_text


def import_unstructured_notes(raw_text: str, stakeholder_role: str, source_type: str = "meeting_notes") -> list[dict[str, Any]]:
    """Convert raw emails, questionnaires, or meeting transcripts into structured masked excerpts."""
    masked, counts = mask_text(raw_text.strip())
    paragraphs = [p.strip() for p in re.split(r"\n{2,}", masked) if len(p.strip()) >= 20]
    if not paragraphs and masked:
        paragraphs = [masked]
    return [
        {
            "excerpt_id": f"INT-{idx}",
            "source": f"{source_type}:{stakeholder_role}",
            "stakeholder_role": stakeholder_role,
            "text": para,
            "mask_counts": counts,
        }
        for idx, para in enumerate(paragraphs, start=1)
    ]


class AdaptiveInterviewEngine:
    """Conducts role-tailored adaptive interviews with vagueness & contradiction probing."""

    def __init__(self, role: str, kb: KnowledgeBaseRetriever | None = None, llm_engine: Any = None) -> None:
        self.role = role
        self.kb = kb
        self.llm = llm_engine
        template = ROLE_TEMPLATES.get(role, {})
        focus_ids = template.get("focus_topics") or [t["id"] for t in INTERVIEW_TOPICS[:5]]
        topic_map = {t["id"]: t for t in INTERVIEW_TOPICS}
        self.topics = [topic_map[tid] for tid in focus_ids if tid in topic_map]
        self.current_idx = 0
        self.follow_up_used = False
        self.answers: list[dict[str, Any]] = []
        self.transcript_history: list[dict[str, str]] = []

        opening = template.get("opening", "")
        first_q = self.current_question()
        if first_q:
            self.transcript_history.append(
                {"speaker": "agent", "text": f"[{role} Interview] {opening}\n\n**Topic 1 ({first_q['title']}):** {first_q['prompt']}"}
            )

    def current_question(self) -> dict[str, Any] | None:
        if self.current_idx >= len(self.topics):
            return None
        return self.topics[self.current_idx]

    def is_complete(self) -> bool:
        return self.current_idx >= len(self.topics)

    def _assess_answer(self, topic: dict[str, Any], answer: str) -> tuple[bool, str | None]:
        cleaned = answer.strip()
        if len(cleaned) < 25:
            return False, f"Your answer on **{topic['title']}** is brief. Could you specify concrete actors, mechanisms, or failure behavior?"

        lower = cleaned.lower()
        found_vague = [v for v in VAGUE_TERMS if re.search(rf"\b{re.escape(v)}\b", lower)]
        has_number = bool(re.search(r"\d+", cleaned))

        if topic.get("requires_quant") and not has_number:
            return False, f"For **{topic['title']}**, please provide measurable thresholds (e.g., exact milliseconds, days, key bit-length, or percentage SLA)."

        if found_vague and not has_number:
            return False, f"Terms like `{', '.join(found_vague[:2])}` are ambiguous for engineering specs. What measurable target or standard defines this?"

        # Detect simple numeric contradiction against earlier answers on same topic keyword
        nums = re.findall(r"\b(\d+)\s*(days?|ms|seconds?|minutes?|bits?|%)\b", lower)
        for prev in self.answers:
            prev_nums = re.findall(r"\b(\d+)\s*(days?|ms|seconds?|minutes?|bits?|%)\b", prev["answer"].lower())
            for n1, u1 in nums:
                for n2, u2 in prev_nums:
                    if u1.rstrip("s") == u2.rstrip("s") and n1 != n2 and topic["id"] == prev["topic_id"]:
                        return False, f"I noticed conflicting numbers ({n2} {u2} vs {n1} {u1}). Which threshold should be enforced?"

        return True, None

    def submit_answer(self, raw_answer: str) -> dict[str, Any]:
        topic = self.current_question()
        if not topic:
            return {"complete": True, "reply": "All interview topics are complete."}

        masked_answer, counts = mask_text(raw_answer)
        self.transcript_history.append({"speaker": self.role, "text": masked_answer})

        # Skip command support
        if masked_answer.strip().lower() in {"skip", "n/a", "na"}:
            self.answers.append({"topic_id": topic["id"], "topic": topic["title"], "role": self.role, "answer": "Skipped by stakeholder.", "mask_counts": counts})
            self.current_idx += 1
            self.follow_up_used = False
        else:
            ok, follow_up = self._assess_answer(topic, masked_answer)
            if not ok and not self.follow_up_used and follow_up:
                self.follow_up_used = True
                kb_hint = ""
                if self.kb:
                    hits = self.kb.retrieve(masked_answer, top_k=1)
                    if hits:
                        kb_hint = f"\n*(Relevant standard hint: {hits[0]['id']} — {hits[0]['title']})*"
                reply = f"{follow_up}{kb_hint}"
                self.transcript_history.append({"speaker": "agent", "text": reply})
                return {"complete": False, "follow_up": True, "reply": reply}

            self.answers.append(
                {
                    "topic_id": topic["id"],
                    "topic": topic["title"],
                    "role": self.role,
                    "answer": masked_answer,
                    "mask_counts": counts,
                }
            )
            self.current_idx += 1
            self.follow_up_used = False

        next_q = self.current_question()
        if next_q:
            reply = f"Got it. **Topic {self.current_idx + 1} ({next_q['title']}):** {next_q['prompt']}"
            self.transcript_history.append({"speaker": "agent", "text": reply})
            return {"complete": False, "follow_up": False, "reply": reply}

        reply = f"Interview complete for **{self.role}** ({len(self.answers)} topics captured). You can now send these transcripts to the Multi-Agent Pipeline."
        self.transcript_history.append({"speaker": "agent", "text": reply})
        return {"complete": True, "follow_up": False, "reply": reply}

    def export_excerpts(self) -> list[dict[str, Any]]:
        return [
            {
                "excerpt_id": f"INT-{idx}",
                "source": f"interview:{item['role']}:{item['topic_id']}",
                "stakeholder_role": item["role"],
                "text": f"[{item['topic']}] {item['answer']}",
            }
            for idx, item in enumerate(self.answers, start=1)
        ]
