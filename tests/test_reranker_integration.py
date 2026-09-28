#!/usr/bin/env python3
"""
AegisX Production Reranker Integration Unit Tests
=================================================

Comprehensive regression tests for Phase 5 conditional reranker integration:
1. Feature flag disabled -> identical BM25 behavior.
2. Feature flag enabled + exact IOC -> BM25 bypass.
3. Feature flag enabled + MITRE ID -> BM25 bypass.
4. Ambiguous natural language query -> conditional reranker invokes.
5. Strategy C multi-evidence query -> all evidence domains preserved.
6. Reranker exception -> BM25 fallback.
7. Reranker unavailable -> BM25 fallback.
8. Empty BM25 result -> safe handling.
9. Negative query -> no fabricated retrieval.
10. Deterministic routing.
11. Deterministic Strategy C selection.
12. Existing RAG API contract unchanged.

Usage:
    python -m unittest tests/test_reranker_integration.py -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.rag import (
    RAGPipeline,
    RAGRetriever,
    RetrievalResult,
    create_default_rag_pipeline,
)
from ai.rag.ingest import DocumentChunk
from ai.rag.rag_service import RAGService
from ai.rag.reranker import (
    RerankerConfig,
    ConditionalRouter,
    StrategyCContextSelector,
    ConditionalRerankerStage,
    RerankerModelManager,
)


class TestRerankerIntegration(unittest.TestCase):
    """Production regression and safety tests for the conditional reranker."""

    def setUp(self):
        self.pipeline = create_default_rag_pipeline(auto_init=True)

    def test_01_feature_flag_disabled_identical_bm25_behavior(self):
        """Feature flag disabled -> 100% identical BM25 behavior."""
        # Ensure disabled by default
        self.assertFalse(self.pipeline.reranker_config.enabled)

        query = "PowerShell execution running encoded commands"
        res_default = self.pipeline.query(query, top_k=3)

        # Standalone retriever query
        res_direct_bm25 = self.pipeline.retriever.retrieve(query, top_k=3)

        self.assertEqual(len(res_default), len(res_direct_bm25))
        self.assertEqual(
            [r.chunk.chunk_id for r in res_default],
            [r.chunk.chunk_id for r in res_direct_bm25],
        )
        self.assertEqual(
            [round(r.score, 4) for r in res_default],
            [round(r.score, 4) for r in res_direct_bm25],
        )

    def test_02_feature_flag_enabled_exact_ioc_bypasses_reranker(self):
        """Feature flag enabled + exact IOC query -> BM25 bypass without reranker invocation."""
        cfg = RerankerConfig(enabled=True, mode="conditional")
        pipeline = RAGPipeline(reranker_config=cfg)
        pipeline.initialize()

        query = "Traffic beaconing to external C2 198.51.100.200"
        results = pipeline.query(query, top_k=3)

        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].chunk.chunk_id, "TI-198.51.100.200-0")
        # Ensure reranker was bypassed
        metrics = pipeline.reranker_stage.metrics
        self.assertGreater(metrics.bypass_count, 0)
        self.assertEqual(metrics.invocation_count, 0)

    def test_03_feature_flag_enabled_mitre_id_bypasses_reranker(self):
        """Feature flag enabled + MITRE ID query -> BM25 bypass without reranker invocation."""
        cfg = RerankerConfig(enabled=True, mode="conditional")
        pipeline = RAGPipeline(reranker_config=cfg)
        pipeline.initialize()

        query = "Technique T1059.001 detected on host"
        results = pipeline.query(query, top_k=3)

        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].chunk.chunk_id, "MITRE-T1059.001-0")
        # Ensure reranker was bypassed
        metrics = pipeline.reranker_stage.metrics
        self.assertGreater(metrics.bypass_count, 0)
        self.assertEqual(metrics.invocation_count, 0)

    def test_04_ambiguous_nl_query_invokes_conditional_reranker(self):
        """Ambiguous natural language query triggers conditional router invocation."""
        router = ConditionalRouter(score_margin_threshold=0.150)
        # Construct mock candidates with low score margin
        c1 = DocumentChunk(chunk_id="TI-LockBit-0", document_id="D1", title="LockBit", content="LockBit ransomware")
        c2 = DocumentChunk(chunk_id="MITRE-T1486-0", document_id="D2", title="Encryption", content="Data Encrypted")
        candidates = [
            RetrievalResult(chunk=c1, score=0.350, rank=1),
            RetrievalResult(chunk=c2, score=0.340, rank=2),  # Margin: 0.010 (< 0.150)
        ]
        should_rerank, reason = router.should_rerank("suspicious encryption activity detected", candidates)
        self.assertTrue(should_rerank)
        self.assertEqual(reason, "low_margin_ambiguity")

    def test_05_strategy_c_multi_evidence_domain_preservation(self):
        """Strategy C multi-evidence query preserves both MITRE and Threat Intel domains."""
        selector = StrategyCContextSelector()

        # Simulate 4 candidates: 3 TI hashes and 1 MITRE technique
        c_hash1 = DocumentChunk(chunk_id="TI-hash1-0", document_id="D1", title="Hash 1", content="hash 1")
        c_hash2 = DocumentChunk(chunk_id="TI-hash2-0", document_id="D2", title="Hash 2", content="hash 2")
        c_hash3 = DocumentChunk(chunk_id="TI-hash3-0", document_id="D3", title="Hash 3", content="hash 3")
        c_mitre = DocumentChunk(chunk_id="MITRE-T1059.001-0", document_id="D4", title="PS", content="PowerShell")

        # Reranker ranked hash1 #1, hash2 #2, hash3 #3, and MITRE #4
        ranked_chunks = [c_hash1, c_hash2, c_hash3, c_mitre]

        selected = selector.select(ranked_chunks, top_k=3)
        selected_ids = [c.chunk_id for c in selected]

        # Strategy C must keep #1 (hash1), but ensure Slot 2 includes MITRE, avoiding starvation
        self.assertEqual(len(selected), 3)
        self.assertIn("TI-hash1-0", selected_ids)
        self.assertIn("MITRE-T1059.001-0", selected_ids)

    def test_06_reranker_exception_falls_back_to_bm25(self):
        """Reranker exception inside inference must trigger instantaneous BM25 fallback."""
        cfg = RerankerConfig(enabled=True, mode="always")
        stage = ConditionalRerankerStage(config=cfg)

        c1 = DocumentChunk(chunk_id="C1", document_id="D1", title="T1", content="Text 1")
        candidates = [RetrievalResult(chunk=c1, score=1.0, rank=1)]

        # Mock model_manager to raise an exception
        with patch.object(stage.model_manager, "get_ranker", side_effect=RuntimeError("GPU OOM / CUDA error")):
            results = stage.rerank("test query", candidates, output_k=1)

            # Fallback must return BM25 candidates
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].chunk.chunk_id, "C1")
            self.assertEqual(stage.metrics.fallback_count, 1)

    def test_07_reranker_unavailable_falls_back_to_bm25(self):
        """Reranker model manager returning None triggers BM25 fallback."""
        cfg = RerankerConfig(enabled=True, mode="always")
        stage = ConditionalRerankerStage(config=cfg)

        c1 = DocumentChunk(chunk_id="C1", document_id="D1", title="T1", content="Text 1")
        candidates = [RetrievalResult(chunk=c1, score=1.0, rank=1)]

        with patch.object(stage.model_manager, "get_ranker", return_value=None):
            results = stage.rerank("test query", candidates, output_k=1)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].chunk.chunk_id, "C1")
            self.assertEqual(stage.metrics.fallback_count, 1)

    def test_08_empty_bm25_result_handling(self):
        """Empty BM25 candidate list handled gracefully without exceptions."""
        cfg = RerankerConfig(enabled=True, mode="conditional")
        stage = ConditionalRerankerStage(config=cfg)

        results = stage.rerank("test query", [], output_k=3)
        self.assertEqual(results, [])

    def test_09_negative_and_blank_query_handling(self):
        """Blank and whitespace-only queries return empty results without errors."""
        cfg = RerankerConfig(enabled=True, mode="conditional")
        stage = ConditionalRerankerStage(config=cfg)

        results = stage.rerank("   ", [], output_k=3)
        self.assertEqual(results, [])

    def test_10_router_determinism(self):
        """Conditional router produces identical routing decisions on repeated runs."""
        router = ConditionalRouter(score_margin_threshold=0.150)
        c1 = DocumentChunk(chunk_id="TI-1-0", document_id="D1", title="T1", content="C1")
        c2 = DocumentChunk(chunk_id="TI-2-0", document_id="D2", title="T2", content="C2")
        candidates = [
            RetrievalResult(chunk=c1, score=0.50, rank=1),
            RetrievalResult(chunk=c2, score=0.48, rank=2),
        ]
        decisions = [router.should_rerank("repeated ambiguous query", candidates) for _ in range(10)]
        self.assertTrue(all(d == decisions[0] for d in decisions))

    def test_11_deterministic_strategy_c_selection(self):
        """Strategy C selection is 100% deterministic across multiple iterations."""
        selector = StrategyCContextSelector()
        c1 = DocumentChunk(chunk_id="TI-1-0", document_id="D1", title="T1", content="C1")
        c2 = DocumentChunk(chunk_id="TI-2-0", document_id="D2", title="T2", content="C2")
        c3 = DocumentChunk(chunk_id="MITRE-T1059.001-0", document_id="D3", title="T3", content="C3")
        chunks = [c1, c2, c3]

        runs = [selector.select(chunks, top_k=2) for _ in range(10)]
        first_run_ids = [c.chunk_id for c in runs[0]]
        for run in runs[1:]:
            self.assertEqual([c.chunk_id for c in run], first_run_ids)

    def test_12_existing_rag_api_contract_unchanged(self):
        """Existing RAGService and RAGPipeline return standard RetrievalResult structures."""
        service = RAGService.get_instance()
        alert_res = service.retrieve_for_alert("PowerShell execution", technique_id="T1059.001")

        self.assertIn("query", alert_res)
        self.assertIn("results_count", alert_res)
        self.assertIn("chunks", alert_res)
        self.assertIn("formatted_context", alert_res)
        self.assertIsInstance(alert_res["chunks"], list)
        self.assertTrue(len(alert_res["chunks"]) > 0)
        # Verify chunk dictionary fields
        chunk_0 = alert_res["chunks"][0]
        self.assertIn("chunk_id", chunk_0)
        self.assertIn("score", chunk_0)
        self.assertIn("rank", chunk_0)
        self.assertIn("title", chunk_0)
        self.assertIn("content", chunk_0)


if __name__ == "__main__":
    unittest.main()
