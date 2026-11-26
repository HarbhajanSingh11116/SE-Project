"""Hybrid Knowledge Base & Document RAG retriever (semantic + SFR-ID lexical)."""
from __future__ import annotations

import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from config import EMBEDDING_MODEL_ID, KB_DIR

SFR_PATTERN = re.compile(r"\b([A-Z]{3}_[A-Z]{2,5}(?:_[A-Z]{2,5})?\.\d+(?:\.\d+)?)\b")


def extract_text_from_bytes(filename: str, raw: bytes) -> str:
    """Extract plain text from .txt, .md, .json, .pdf, or .docx uploads."""
    lower = filename.lower()
    if lower.endswith((".txt", ".md", ".yaml", ".yml", ".csv", ".json")):
        return raw.decode("utf-8", errors="replace")
    if lower.endswith(".docx"):
        import docx

        document = docx.Document(io.BytesIO(raw))
        return "\n".join(p.text for p in document.paragraphs if p.text.strip())
    if lower.endswith(".pdf"):
        import fitz

        doc = fitz.open(stream=raw, filetype="pdf")
        pages = [page.get_text("text") for page in doc]
        return "\n".join(pages)
    return raw.decode("utf-8", errors="replace")


def chunk_document(text: str, source_name: str, chunk_size: int = 750, overlap: int = 120) -> list[dict[str, Any]]:
    """Split an input specification/transcript into indexed [DOC-n] excerpts."""
    cleaned = re.sub(r"\s+\n", "\n", text.strip())
    if not cleaned:
        return []
    chunks: list[dict[str, Any]] = []
    start = 0
    idx = 1
    while start < len(cleaned):
        piece = cleaned[start : start + chunk_size].strip()
        if len(piece) >= 40 or not chunks:
            chunks.append(
                {
                    "excerpt_id": f"DOC-{idx}",
                    "source": source_name,
                    "sfr_ids": sorted(set(SFR_PATTERN.findall(piece))),
                    "text": piece,
                }
            )
            idx += 1
        if start + chunk_size >= len(cleaned):
            break
        start += max(1, chunk_size - overlap)
    return chunks


class KnowledgeBaseRetriever:
    """Version-controlled, allowlisted Cybersecurity & Common Criteria Knowledge Base."""

    def __init__(self, kb_dir: Path | str = KB_DIR, use_dense_embeddings: bool = False) -> None:
        self.kb_dir = Path(kb_dir)
        self.items: list[dict[str, Any]] = []
        self.kb_version: str = "unknown"
        self.use_dense_embeddings = use_dense_embeddings
        self._embedder = None
        self._dense_matrix: np.ndarray | None = None
        self._tfidf = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        self._tfidf_matrix = None
        self.load_kb()

    def load_kb(self) -> None:
        self.items = []
        versions: list[str] = []
        for path in sorted(self.kb_dir.glob("*.yaml")):
            if path.name == "sdlc_policies.yaml":
                continue
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if "version" in data:
                versions.append(f"{path.stem}:{data['version']}")
            for item in data.get("items", []):
                entry = dict(item)
                entry.setdefault("sfr_ids", sorted(set(SFR_PATTERN.findall(entry.get("text", "")))))
                entry.setdefault("controls", [])
                entry.setdefault("retention_duty", "")
                self.items.append(entry)
        self.kb_version = "+".join(versions) if versions else "2026.1"
        self._reindex()

    def add_custom_item(self, item: dict[str, Any]) -> None:
        item = dict(item)
        item.setdefault("id", f"KB-CUSTOM-{len(self.items)+1:03d}")
        item.setdefault("type", "policy")
        item.setdefault("standard", "Custom Uploaded Policy")
        item.setdefault("jurisdiction", "Organisation-Specific")
        item.setdefault("effective_date", "2026-01-01")
        item.setdefault("version", "1.0")
        item.setdefault("applicability", ["custom"])
        item.setdefault("sfr_ids", sorted(set(SFR_PATTERN.findall(item.get("text", "")))))
        item.setdefault("controls", [])
        item.setdefault("retention_duty", "")
        self.items.append(item)
        self._reindex()

    def import_colab_chunks(self, chunks_json_bytes: bytes, limit: int = 200) -> int:
        """Import chunks.json built in the user's Colab notebook into the KB."""
        raw_chunks = json.loads(chunks_json_bytes.decode("utf-8"))
        added = 0
        for idx, ch in enumerate(raw_chunks[:limit], start=1):
            self.items.append(
                {
                    "id": f"KB-COLAB-{idx:03d}",
                    "title": ch.get("title", f"Imported CC Chunk {idx}"),
                    "type": "regulation",
                    "standard": ch.get("category", "Common Criteria Protection Profile"),
                    "jurisdiction": "International (Common Criteria)",
                    "effective_date": "2025-01-01",
                    "version": "1.0",
                    "applicability": [ch.get("category", "security").lower()],
                    "sfr_ids": ch.get("sfr_ids", []),
                    "controls": ch.get("sfr_ids", []),
                    "retention_duty": "Retain compliance evidence per Protection Profile.",
                    "text": ch.get("text", ""),
                }
            )
            added += 1
        self._reindex()
        return added

    def kb_digest(self) -> str:
        payload = json.dumps(self.items, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

    def _searchable_text(self, item: dict[str, Any]) -> str:
        parts = [
            item.get("id", ""),
            item.get("title", ""),
            item.get("standard", ""),
            " ".join(item.get("sfr_ids", [])),
            " ".join(item.get("applicability", [])),
            " ".join(item.get("controls", [])),
            item.get("text", ""),
        ]
        return " ".join(parts)

    def _reindex(self) -> None:
        if not self.items:
            self._tfidf_matrix = None
            self._dense_matrix = None
            return
        corpus = [self._searchable_text(item) for item in self.items]
        self._tfidf_matrix = self._tfidf.fit_transform(corpus)
        if self.use_dense_embeddings:
            try:
                from sentence_transformers import SentenceTransformer

                if self._embedder is None:
                    self._embedder = SentenceTransformer(EMBEDDING_MODEL_ID)
                self._dense_matrix = np.asarray(self._embedder.encode(corpus, show_progress_bar=False))
            except Exception:
                self._dense_matrix = None

    def retrieve(self, query: str, top_k: int = 4) -> list[dict[str, Any]]:
        if not self.items or not query.strip():
            return []

        q_vec = self._tfidf.transform([query])
        scores = cosine_similarity(q_vec, self._tfidf_matrix).ravel()

        if self._dense_matrix is not None and self._embedder is not None:
            q_emb = np.asarray(self._embedder.encode([query], show_progress_bar=False))[0]
            denom = np.linalg.norm(self._dense_matrix, axis=1) * (np.linalg.norm(q_emb) + 1e-8)
            dense_scores = (self._dense_matrix @ q_emb) / (denom + 1e-8)
            scores = 0.45 * scores + 0.55 * dense_scores

        # Boost exact SFR ID or keyword applicability matches
        query_lower = query.lower()
        query_sfrs = set(SFR_PATTERN.findall(query))
        boosted = scores.copy()
        for i, item in enumerate(self.items):
            item_sfrs = set(item.get("sfr_ids", []))
            if query_sfrs & item_sfrs:
                boosted[i] += 0.35
            app_hits = sum(1 for kw in item.get("applicability", []) if kw.lower() in query_lower)
            boosted[i] += min(0.25, 0.06 * app_hits)

        top_indices = np.argsort(-boosted)[:top_k]
        results: list[dict[str, Any]] = []
        for idx in top_indices:
            if boosted[idx] <= 0.01:
                continue
            item = dict(self.items[int(idx)])
            item["score"] = round(float(min(1.0, boosted[idx])), 3)
            results.append(item)

        if not results and self.items:
            fallback = dict(self.items[0])
            fallback["score"] = 0.25
            results.append(fallback)
        return results
