"""
AegisX In-Memory RAG Retriever
===============================

Retrieves top-k relevant knowledge chunks using CPU-safe BM25 scoring.
Designed for rapid, deterministic execution on local developer workstations.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ai.rag.embeddings import BaseScorer, BM25Scorer
from ai.rag.ingest import DocumentChunk

@dataclass
class RetrievalResult:
    """Ranked retrieval output containing matching chunk and similarity score."""
    chunk: DocumentChunk
    score: float
    rank: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rank": self.rank,
            "score": round(self.score, 4),
            "chunk_id": self.chunk.chunk_id,
            "document_id": self.chunk.document_id,
            "title": self.chunk.title,
            "content": self.chunk.content,
            "metadata": self.chunk.metadata,
        }

class RAGRetriever:
    """In-memory security knowledge chunk retriever."""

    def __init__(self, scorer: Optional[BaseScorer] = None):
        self.scorer: BaseScorer = scorer or BM25Scorer()
        self.chunks: List[DocumentChunk] = []

    def index(self, chunks: List[DocumentChunk]) -> None:
        """Index a list of document chunks and fit the scoring model."""
        self.chunks = list(chunks)
        corpus = [f"{c.title}\n{c.content}" for c in self.chunks]
        self.scorer.fit(corpus)

    def count(self) -> int:
        """Return total number of indexed chunks."""
        return len(self.chunks)

    def clear(self) -> None:
        """Reset the retriever index."""
        self.chunks = []
        self.scorer.fit([])

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        threshold: float = 0.0,
    ) -> List[RetrievalResult]:
        """
        Rank and retrieve the top_k most relevant document chunks for query.

        Args:
            query: Search string (indicator, technique, CVE, attack summary).
            top_k: Maximum number of ranked results to return.
            threshold: Minimum relevance score required to be included.

        Returns:
            List[RetrievalResult]: Ranked list of matching chunks with scores.
        """
        if not self.chunks or not query or not query.strip():
            return []

        scored_items = []
        for idx, chunk in enumerate(self.chunks):
            s = self.scorer.score(query, idx)
            if s > threshold:
                scored_items.append((chunk, s))

        # Sort descending by score
        scored_items.sort(key=lambda item: item[1], reverse=True)

        results = []
        for rank_idx, (chunk, score) in enumerate(scored_items[:top_k]):
            results.append(
                RetrievalResult(
                    chunk=chunk,
                    score=score,
                    rank=rank_idx + 1,
                )
            )

        return results
