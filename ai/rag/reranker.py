"""AegisX Production Conditional Reranker & Context Preservation Stage.
====================================================================

Optional Stage 2 neural cross-encoder reranking integrated cleanly into the
production AegisX RAG architecture.

Key Invariants:
1. Zero modifications to Stage 1 BM25Scorer.
2. Controlled behind a strict feature flag: `reranker.enabled = false` by default.
3. Conditional Router: exact IOCs (IP, Hash, MITRE ID) and high-confidence
   BM25 results bypass the cross-encoder, avoiding ~220ms CPU overhead.
4. Strategy C Context Preservation: prevents semantic crowding by guaranteeing
   multi-domain diversity (MITRE ATT&CK vs Threat Intel) in final context.
5. Circuit-Breaker Resilience: any model load failure, inference error, or
   timeout automatically falls back to native BM25 without breaking SOC workflows.
6. Thread-safe singleton model management with lazy deserialization.
7. CPU-safe: offline, zero background processes or dynamic code execution.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ai.rag.ingest import DocumentChunk
from ai.rag.retriever import RetrievalResult

logger = logging.getLogger("AegisX.RAG.Reranker")

# Deterministic Security Token Regexes
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
MITRE_TID_REGEX = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")


@dataclass
class RerankerConfig:
    """Configuration settings for the optional conditional reranker."""
    enabled: bool = False
    mode: str = "conditional"  # "off", "conditional", "always"
    model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    candidate_k: int = 10
    output_k: int = 3
    strategy: str = "domain_diversity"  # Strategy C
    fallback: str = "bm25"
    score_margin_threshold: float = 1.200
    high_margin_bypass: float = 5.000
    exact_margin_bypass: float = 1.200

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]] = None) -> "RerankerConfig":
        if not data:
            return cls()
        margin_thresh = float(data.get("score_margin_threshold", 1.200))
        return cls(
            enabled=bool(data.get("enabled", False)),
            mode=str(data.get("mode", "conditional")),
            model=str(data.get("model", "cross-encoder/ms-marco-MiniLM-L-6-v2")),
            candidate_k=int(data.get("candidate_k", 10)),
            output_k=int(data.get("output_k", 3)),
            strategy=str(data.get("strategy", "domain_diversity")),
            fallback=str(data.get("fallback", "bm25")),
            score_margin_threshold=margin_thresh,
            high_margin_bypass=float(data.get("high_margin_bypass", 5.000)),
            exact_margin_bypass=float(data.get("exact_margin_bypass", margin_thresh)),
        )


@dataclass
class RerankerMetrics:
    """In-memory thread-safe telemetry and latency counters."""
    bm25_latency_ms: float = 0.0
    router_latency_ms: float = 0.0
    reranker_latency_ms: float = 0.0
    total_retrieval_latency_ms: float = 0.0
    model_load_time_ms: float = 0.0
    invocation_count: int = 0
    bypass_count: int = 0
    fallback_count: int = 0
    model_loaded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bm25_latency_ms": round(self.bm25_latency_ms, 3),
            "router_latency_ms": round(self.router_latency_ms, 3),
            "reranker_latency_ms": round(self.reranker_latency_ms, 3),
            "total_retrieval_latency_ms": round(self.total_retrieval_latency_ms, 3),
            "model_load_time_ms": round(self.model_load_time_ms, 2),
            "invocation_count": self.invocation_count,
            "bypass_count": self.bypass_count,
            "fallback_count": self.fallback_count,
            "model_loaded": self.model_loaded,
        }


class RerankerModelManager:
    """Thread-safe singleton managing the lifecycle of the cross-encoder model."""

    _instance: Optional["RerankerModelManager"] = None
    _lock = threading.Lock()

    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        self.model_name = model_name
        self._ranker: Any = None
        self._load_error: Optional[str] = None
        self._load_time_ms: float = 0.0
        self._init_lock = threading.Lock()

    @classmethod
    def get_instance(cls, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2") -> "RerankerModelManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(model_name=model_name)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (useful for test tear-downs)."""
        with cls._lock:
            cls._instance = None

    def get_ranker(self) -> Any:
        """Lazily load and return the underlying cross-encoder instance."""
        if self._ranker is not None:
            return self._ranker

        with self._init_lock:
            if self._ranker is not None:
                return self._ranker

            t0 = time.perf_counter()
            try:
                from rerankers import Reranker
                logger.info("Deserializing cross-encoder weights: %s", self.model_name)
                self._ranker = Reranker(self.model_name, model_type="cross-encoder", verbose=0)
                self._load_time_ms = (time.perf_counter() - t0) * 1000.0
                logger.info("Cross-encoder successfully initialized in %.2f ms", self._load_time_ms)
                return self._ranker
            except Exception as exc:
                self._load_error = str(exc)
                logger.warning("Failed to initialize cross-encoder: %s", exc)
                return None

    @property
    def is_loaded(self) -> bool:
        return self._ranker is not None

    @property
    def load_time_ms(self) -> float:
        return self._load_time_ms


class ConditionalRouter:
    """Deterministic security router gating Stage 2 reranker execution.

    Reproduces the validated Phase 3/4 deterministic routing semantics:
    1. Zero/Empty BM25 results -> bypass ('empty_bm25_results' / 'zero_bm25_score' / 'no_bm25_matches')
    2. Exact IOC or MITRE TID with margin >= exact_margin_bypass -> bypass ('exact_identifier_high_margin_bypass')
    3. BM25 score margin >= high_margin_bypass (>= 5.0) -> bypass ('high_bm25_margin_bypass')
    4. Otherwise -> invoke reranker:
       - 'low_margin_ambiguity' if margin < score_margin_threshold
       - 'natural_language_complex_query' if margin >= score_margin_threshold
    """

    def __init__(
        self,
        score_margin_threshold: float = 1.200,
        high_margin_bypass: float = 5.000,
        exact_margin_bypass: Optional[float] = None,
    ):
        self.score_margin_threshold = score_margin_threshold
        self.high_margin_bypass = high_margin_bypass
        self.exact_margin_bypass = exact_margin_bypass if exact_margin_bypass is not None else score_margin_threshold

    @staticmethod
    def extract_signals(query: str) -> Tuple[bool, bool, int]:
        """Extract deterministic security entity signals from query string."""
        has_ipv4 = bool(IPV4_REGEX.search(query))
        has_ipv6 = bool(IPV6_REGEX.search(query))
        has_hash = bool(SHA256_REGEX.search(query) or SHA1_REGEX.search(query) or MD5_REGEX.search(query))
        has_ioc = has_ipv4 or has_ipv6 or has_hash
        has_mitre = bool(MITRE_TID_REGEX.search(query))
        word_count = len(query.strip().split())
        return has_ioc, has_mitre, word_count

    def should_rerank(
        self,
        query: str,
        bm25_results: List[RetrievalResult],
    ) -> Tuple[bool, str]:
        """
        Evaluate whether the reranker should be invoked or bypassed.
        Returns:
            (should_rerank: bool, reason: str)
        """
        if not bm25_results:
            return False, "empty_bm25_results"

        top_score = bm25_results[0].score if len(bm25_results) > 0 else 0.0
        if top_score == 0.0:
            return False, "zero_bm25_score"

        second_score = bm25_results[1].score if len(bm25_results) > 1 else 0.0
        score_margin = top_score - second_score

        has_ioc, has_mitre, _ = self.extract_signals(query)

        # Rule 1: Exact IOC / MITRE technique with solid margin -> bypass
        if (has_ioc or has_mitre) and score_margin >= self.exact_margin_bypass:
            return False, "exact_identifier_high_margin_bypass"

        # Rule 2: Decisive BM25 score margin -> bypass
        if score_margin >= self.high_margin_bypass:
            return False, "high_bm25_margin_bypass"

        # Rule 3: Narrow score margin or complex natural language query -> invoke
        if score_margin < self.score_margin_threshold:
            return True, "low_margin_ambiguity"
        return True, "natural_language_complex_query"


def classify_chunk_domain(chunk_id: str) -> str:
    """Classify knowledge chunk as MITRE ATT&CK, Threat Intel, or General."""
    if chunk_id.startswith("MITRE"):
        return "mitre"
    if chunk_id.startswith("TI"):
        return "threat_intel"
    return "general"


class StrategyCContextSelector:
    """
    Selects top-k chunks with Strategy C domain-diversity preservation.
    Guarantees that secondary facts from distinct security domains
    are not evicted by semantic crowding.
    """

    @staticmethod
    def select(
        ranked_chunks: List[DocumentChunk],
        top_k: int = 3,
    ) -> List[DocumentChunk]:
        if len(ranked_chunks) <= top_k:
            return ranked_chunks

        selected: List[DocumentChunk] = []
        selected_ids: Set[str] = set()
        seen_domains: Set[str] = set()

        # Step 1: Always preserve #1 top-ranked chunk
        top_1 = ranked_chunks[0]
        selected.append(top_1)
        selected_ids.add(top_1.chunk_id)
        seen_domains.add(classify_chunk_domain(top_1.chunk_id))

        # Step 2: Ensure representation from an unrepresented domain
        for c in ranked_chunks[1:]:
            domain = classify_chunk_domain(c.chunk_id)
            if domain not in seen_domains and len(selected) < top_k:
                selected.append(c)
                selected_ids.add(c.chunk_id)
                seen_domains.add(domain)

        # Step 3: Fill remaining slots by descending rank order
        for c in ranked_chunks[1:]:
            if len(selected) >= top_k:
                break
            if c.chunk_id not in selected_ids:
                selected.append(c)
                selected_ids.add(c.chunk_id)

        return selected


class ConditionalRerankerStage:
    """
    Production-grade Stage 2 conditional reranker orchestrator.
    Executes between Stage 1 BM25 retrieval and final context formatting.
    """

    def __init__(
        self,
        config: Optional[RerankerConfig] = None,
        model_manager: Optional[RerankerModelManager] = None,
    ):
        self.config = config or RerankerConfig()
        self.model_manager = model_manager or RerankerModelManager.get_instance(self.config.model)
        self.router = ConditionalRouter(
            score_margin_threshold=self.config.score_margin_threshold,
            high_margin_bypass=self.config.high_margin_bypass,
            exact_margin_bypass=self.config.exact_margin_bypass,
        )
        self.selector = StrategyCContextSelector()
        self.metrics = RerankerMetrics()

    def rerank(
        self,
        query: str,
        bm25_results: List[RetrievalResult],
        output_k: Optional[int] = None,
    ) -> List[RetrievalResult]:
        """
        Execute conditional reranking on BM25 candidate results.
        Guarantees safe fallback to native BM25 on any error or bypass.
        """
        t0_total = time.perf_counter()
        k = output_k or self.config.output_k

        # If disabled or mode is 'off', return existing BM25 results
        if not self.config.enabled or self.config.mode == "off":
            return bm25_results[:k]

        if not bm25_results or not query or not query.strip():
            return []

        # Step 1: Routing Check
        t0_router = time.perf_counter()
        should_rerank, route_reason = self.router.should_rerank(query, bm25_results)
        self.metrics.router_latency_ms = (time.perf_counter() - t0_router) * 1000.0

        if not should_rerank and self.config.mode != "always":
            self.metrics.bypass_count += 1
            logger.debug("Reranker bypassed: %s", route_reason)
            self.metrics.total_retrieval_latency_ms = (time.perf_counter() - t0_total) * 1000.0
            return bm25_results[:k]

        # Step 2: Cross-Encoder Inference with Circuit-Breaker Fallback
        t0_rerank = time.perf_counter()
        try:
            ranker = self.model_manager.get_ranker()
            if ranker is None:
                raise RuntimeError("Cross-encoder model instance unavailable")

            self.metrics.model_loaded = True
            self.metrics.model_load_time_ms = self.model_manager.load_time_ms

            # Format passages
            docs = [f"{r.chunk.title}\n{r.chunk.content}" for r in bm25_results]
            rerank_out = ranker.rank(query=query, docs=docs)

            # Sort candidate chunks by reranker score
            scored_candidates: List[Tuple[DocumentChunk, float]] = []
            for item in rerank_out.results:
                chunk = bm25_results[item.doc_id].chunk
                scored_candidates.append((chunk, float(item.score)))

            ranked_chunks = [c for c, _ in scored_candidates]

            # Step 3: Strategy C Context Selection
            if self.config.strategy == "domain_diversity":
                selected_chunks = self.selector.select(ranked_chunks, top_k=k)
            else:
                selected_chunks = ranked_chunks[:k]

            # Build final RetrievalResult objects preserving contract
            final_results: List[RetrievalResult] = []
            score_map = {c.chunk_id: s for c, s in scored_candidates}
            for idx, chunk in enumerate(selected_chunks, start=1):
                final_results.append(
                    RetrievalResult(
                        chunk=chunk,
                        score=score_map.get(chunk.chunk_id, 1.0),
                        rank=idx,
                    )
                )

            self.metrics.invocation_count += 1
            self.metrics.reranker_latency_ms = (time.perf_counter() - t0_rerank) * 1000.0
            self.metrics.total_retrieval_latency_ms = (time.perf_counter() - t0_total) * 1000.0
            logger.debug("Reranker executed successfully: %d chunks returned", len(final_results))
            return final_results

        except Exception as exc:
            # Mandatory Circuit Breaker: fallback to native BM25
            self.metrics.fallback_count += 1
            self.metrics.reranker_latency_ms = (time.perf_counter() - t0_rerank) * 1000.0
            self.metrics.total_retrieval_latency_ms = (time.perf_counter() - t0_total) * 1000.0
            logger.warning("Reranker failed (%s); falling back immediately to BM25", exc)
            return bm25_results[:k]
