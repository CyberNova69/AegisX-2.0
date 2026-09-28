"""AegisX RAG Service Interface.

Provides a clean application-level service interface for the RAG pipeline.
Enables runtime query enrichment for SOC workflows, alert triage,
investigation, and MITRE ATT&CK contextual grounding.

Zero GPU requirement, offline, CPU-safe BM25 indexing.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from ai.rag.pipeline import RAGPipeline, create_default_rag_pipeline
from ai.rag.retriever import RetrievalResult

logger = logging.getLogger("AegisX.RAGService")


class RAGService:
    """Singleton service wrapping the AegisX RAG pipeline.

    Provides high-level retrieval methods for SOC agents and workflows:
        - retrieve_context(query) -> formatted markdown context
        - retrieve_for_alert(title, technique_id) -> relevant document chunks
        - query(query, top_k) -> structured RetrievalResult list
    """

    _instance: Optional["RAGService"] = None
    _lock = threading.Lock()

    def __init__(self, pipeline: Optional[RAGPipeline] = None):
        self._pipeline = pipeline
        self._initialized = False

    @classmethod
    def get_instance(cls) -> "RAGService":
        """Get or create the singleton RAG service instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (for testing)."""
        with cls._lock:
            cls._instance = None

    def _ensure_initialized(self) -> None:
        """Lazily initialize the underlying RAG pipeline."""
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    if self._pipeline is None:
                        self._pipeline = create_default_rag_pipeline(auto_init=True)
                    elif not self._pipeline.is_initialized:
                        self._pipeline.initialize()
                    self._initialized = True
                    logger.info("RAGService initialized with default RAG pipeline.")

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        threshold: Optional[float] = None,
    ) -> List[RetrievalResult]:
        """Retrieve top-k relevant document chunks for a query string."""
        self._ensure_initialized()
        assert self._pipeline is not None
        return self._pipeline.query(query, top_k=top_k, threshold=threshold)

    def retrieve_context(
        self,
        query: str,
        top_k: int = 3,
        threshold: Optional[float] = None,
    ) -> str:
        """Retrieve relevant context and format as clean markdown for prompting."""
        self._ensure_initialized()
        assert self._pipeline is not None
        results = self._pipeline.query(query, top_k=top_k, threshold=threshold)
        return self._pipeline.format_context_for_prompt(results)

    def retrieve_for_alert(
        self,
        title: str,
        technique_id: Optional[str] = None,
        top_k: int = 3,
    ) -> Dict[str, Any]:
        """Retrieve security context specifically tailored to an alert."""
        self._ensure_initialized()
        assert self._pipeline is not None

        query_terms = [title]
        if technique_id:
            query_terms.append(technique_id)
        combined_query = " ".join(query_terms)

        results = self._pipeline.query(combined_query, top_k=top_k)
        formatted_context = self._pipeline.format_context_for_prompt(results)

        return {
            "query": combined_query,
            "results_count": len(results),
            "chunks": [r.to_dict() for r in results],
            "formatted_context": formatted_context,
        }

    def is_reranker_enabled(self) -> bool:
        """Check if the optional neural reranker is currently active."""
        self._ensure_initialized()
        assert self._pipeline is not None
        return bool(self._pipeline.reranker_config.enabled)

    def get_reranker_metrics(self) -> Dict[str, Any]:
        """Retrieve operational metrics from the reranker stage."""
        self._ensure_initialized()
        assert self._pipeline is not None
        return self._pipeline.reranker_stage.metrics.to_dict()
