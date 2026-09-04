"""
AegisX RAG Retrieval Evaluation Framework
==========================================

Evaluates the CPU-safe Okapi BM25 retriever and knowledge base independently
of LLM generation. Measures Hit@K, indicator recall, MITRE technique accuracy,
unknown indicator rejection, and retrieval latency statistics.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ai.evaluation.metrics import (
    compute_hit_at_k,
    compute_latency_stats,
)
from ai.rag import create_default_rag_pipeline, RAGPipeline

DEFAULT_BENCHMARK_QUERIES: List[Dict[str, Any]] = [
    {
        "query": "198.51.100.200",
        "category": "exact_ip",
        "expected_ids": ["TI-198_51_100_200-0"],
        "expect_hit": True,
    },
    {
        "query": "198.51.100.250",
        "category": "exact_ip",
        "expected_ids": ["TI-198_51_100_250-0"],
        "expect_hit": True,
    },
    {
        "query": "7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7",
        "category": "exact_hash",
        "expected_ids": ["TI-7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7-0"],
        "expect_hit": True,
    },
    {
        "query": "T1059.001 PowerShell execution script",
        "category": "mitre_technique",
        "expected_ids": ["MITRE-T1059.001-0"],
        "expect_hit": True,
    },
    {
        "query": "T1486 Data Encrypted for Impact Ransomware",
        "category": "mitre_technique",
        "expected_ids": ["MITRE-T1486-0"],
        "expect_hit": True,
    },
    {
        "query": "Cobalt Strike Command and Control FIN7",
        "category": "semantic_threat",
        "expected_ids": ["TI-198_51_100_200-0"],
        "expect_hit": True,
    },
    {
        "query": "SSH brute force dictionary spray port 22",
        "category": "semantic_threat",
        "expected_ids": ["TI-198_51_100_77-0"],
        "expect_hit": True,
    },
    {
        "query": "non_existent_supernova_quantum_ip_999",
        "category": "unknown_indicator",
        "expected_ids": [],
        "expect_hit": False,
    },
]

@dataclass
class RAGRetrievalMetrics:
    """Consolidated metrics for retrieval engine evaluation."""
    total_queries: int = 0
    hit_at_1: float = 0.0
    hit_at_3: float = 0.0
    hit_at_5: float = 0.0
    exact_indicator_hit_rate: float = 0.0
    mitre_technique_hit_rate: float = 0.0
    unknown_indicator_rejection_rate: float = 1.0
    latency_stats: Dict[str, float] = field(default_factory=dict)
    query_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "hit_at_1": round(self.hit_at_1, 4),
            "hit_at_3": round(self.hit_at_3, 4),
            "hit_at_5": round(self.hit_at_5, 4),
            "exact_indicator_hit_rate": round(self.exact_indicator_hit_rate, 4),
            "mitre_technique_hit_rate": round(self.mitre_technique_hit_rate, 4),
            "unknown_indicator_rejection_rate": round(self.unknown_indicator_rejection_rate, 4),
            "latency_stats": self.latency_stats,
            "query_results": self.query_results,
        }

def evaluate_rag_retrieval(
    pipeline: Optional[RAGPipeline] = None,
    benchmark_queries: Optional[List[Dict[str, Any]]] = None,
) -> RAGRetrievalMetrics:
    """
    Execute deterministic benchmark queries against RAG pipeline and compute retrieval metrics.
    """
    pipe = pipeline or create_default_rag_pipeline(auto_init=True)
    queries = benchmark_queries or DEFAULT_BENCHMARK_QUERIES

    retrieved_chunk_ids_list: List[List[str]] = []
    expected_chunk_ids_list: List[List[str]] = []
    latencies_ms: List[float] = []

    exact_ind_queries = 0
    exact_ind_hits = 0
    mitre_queries = 0
    mitre_hits = 0
    unknown_queries = 0
    unknown_rejections = 0
    query_records: List[Dict[str, Any]] = []

    for item in queries:
        q_text = item["query"]
        category = item.get("category", "general")
        expected_ids = item.get("expected_ids", [])
        expect_hit = item.get("expect_hit", True)

        start_t = time.perf_counter()
        results = pipe.query(q_text, top_k=5, threshold=0.0)
        dur_ms = (time.perf_counter() - start_t) * 1000.0
        latencies_ms.append(dur_ms)

        retrieved_ids = [r.chunk.chunk_id for r in results]
        retrieved_chunk_ids_list.append(retrieved_ids)
        expected_chunk_ids_list.append(expected_ids)

        is_hit = False
        if expect_hit:
            is_hit = bool(set(retrieved_ids) & set(expected_ids))
        else:
            # For unknown indicators, we expect 0 matches or below threshold
            is_hit = len(results) == 0 or (len(results) > 0 and results[0].score < 1.0)

        if category in {"exact_ip", "exact_hash"}:
            exact_ind_queries += 1
            if is_hit:
                exact_ind_hits += 1
        elif category == "mitre_technique":
            mitre_queries += 1
            if is_hit:
                mitre_hits += 1
        elif category == "unknown_indicator":
            unknown_queries += 1
            if is_hit:
                unknown_rejections += 1

        query_records.append({
            "query": q_text,
            "category": category,
            "latency_ms": round(dur_ms, 2),
            "retrieved_top_3": retrieved_ids[:3],
            "expected": expected_ids,
            "success": is_hit,
        })

    # Compute overall Hit@K for queries expecting hits
    hit_queries = [
        (ret, exp) for ret, exp, q in zip(retrieved_chunk_ids_list, expected_chunk_ids_list, queries)
        if q.get("expect_hit", True)
    ]
    hit_rets = [h[0] for h in hit_queries]
    hit_exps = [h[1] for h in hit_queries]

    hit_1 = compute_hit_at_k(hit_rets, hit_exps, k=1)
    hit_3 = compute_hit_at_k(hit_rets, hit_exps, k=3)
    hit_5 = compute_hit_at_k(hit_rets, hit_exps, k=5)

    exact_rate = exact_ind_hits / exact_ind_queries if exact_ind_queries > 0 else 1.0
    mitre_rate = mitre_hits / mitre_queries if mitre_queries > 0 else 1.0
    unknown_rate = unknown_rejections / unknown_queries if unknown_queries > 0 else 1.0

    return RAGRetrievalMetrics(
        total_queries=len(queries),
        hit_at_1=hit_1,
        hit_at_3=hit_3,
        hit_at_5=hit_5,
        exact_indicator_hit_rate=round(exact_rate, 4),
        mitre_technique_hit_rate=round(mitre_rate, 4),
        unknown_indicator_rejection_rate=round(unknown_rate, 4),
        latency_stats=compute_latency_stats(latencies_ms),
        query_results=query_records,
    )
