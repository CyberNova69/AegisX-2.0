#!/usr/bin/env python3
"""
AegisX RAG Foundation & Threat Intelligence Unit Tests
======================================================

Tests document ingestion, chunking, BM25 scoring, in-memory retrieval,
and prompt context formatting. All tests are 100% CPU-safe and offline.

Usage:
    python -m unittest tests/test_rag.py -v
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.rag import (
    Document,
    DocumentChunk,
    DocumentIngester,
    BM25Scorer,
    RAGRetriever,
    RetrievalResult,
    RAGPipeline,
    create_default_rag_pipeline,
)
from ai.tools.synthetic_threat_intel import (
    get_threat_intel,
    list_all_threat_intel,
    search_threat_intel,
)

class TestSyntheticThreatIntel(unittest.TestCase):
    """Unit tests for the synthetic threat intelligence knowledge base."""

    def test_lookup_known_malicious_ip(self):
        """Lookup of known C2 IP returns malicious reputation and actor."""
        intel = get_threat_intel("198.51.100.200")
        self.assertIsNotNone(intel)
        self.assertEqual(intel["reputation"], "malicious")
        self.assertEqual(intel["threat_actor"], "FIN7")
        self.assertEqual(intel["malware_family"], "Cobalt Strike")
        self.assertIn("c2", intel["tags"])

    def test_lookup_known_malicious_hash(self):
        """Lookup of known malware dropper hash returns dropper profile."""
        hash_val = "7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7"
        intel = get_threat_intel(hash_val)
        self.assertIsNotNone(intel)
        self.assertEqual(intel["reputation"], "malicious")
        self.assertEqual(intel["indicator_type"], "hash")
        self.assertIn("dropper", intel["tags"])

    def test_lookup_benign_internal_ip(self):
        """Lookup of internal monitoring server returns benign reputation."""
        intel = get_threat_intel("10.0.10.2")
        self.assertIsNotNone(intel)
        self.assertEqual(intel["reputation"], "benign")
        self.assertIn("whitelisted", intel["tags"])

    def test_lookup_unknown_indicator(self):
        """Lookup of unrecorded indicator returns None."""
        intel = get_threat_intel("192.0.2.1")
        self.assertIsNone(intel)

    def test_search_threat_intel_by_keyword(self):
        """Keyword search across threat intelligence database returns matches."""
        matches = search_threat_intel("LockBit")
        self.assertTrue(len(matches) >= 2)  # IP and hash associated with LockBit
        for m in matches:
            self.assertIn("lockbit", str(m).lower())

class TestDocumentIngestion(unittest.TestCase):
    """Unit tests for document ingestion and chunking."""

    def setUp(self):
        self.ingester = DocumentIngester(chunk_size=300, chunk_overlap=50)

    def test_load_mitre_reference_all_records(self):
        """Ingester loads all 34 MITRE ATT&CK techniques."""
        docs = self.ingester.load_mitre_reference()
        self.assertEqual(len(docs), 34)
        first = docs[0]
        self.assertIsInstance(first, Document)
        self.assertEqual(first.source_type, "mitre_technique")
        self.assertTrue("T1059.001" in first.content or "PowerShell" in first.content)

    def test_load_synthetic_threat_intel_docs(self):
        """Ingester converts synthetic threat intelligence records into Documents."""
        docs = self.ingester.load_synthetic_threat_intel()
        self.assertTrue(len(docs) >= 10)
        for d in docs:
            self.assertEqual(d.source_type, "threat_intel_report")
            self.assertIn("Threat Intelligence Indicator", d.content)

    def test_chunk_small_document_no_split(self):
        """Document smaller than chunk_size produces exactly 1 chunk."""
        doc = Document(id="DOC-01", title="Short", content="Short alert description", source_type="test")
        chunks = self.ingester.chunk_document(doc)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].chunk_id, "DOC-01-0")
        self.assertEqual(chunks[0].content, "Short alert description")

    def test_chunk_large_document_with_overlap(self):
        """Long document produces multiple chunks with specified overlap."""
        long_content = " ".join([f"Word{i}" for i in range(200)])  # ~1400 chars
        doc = Document(id="DOC-02", title="Long Doc", content=long_content, source_type="test")
        chunks = self.ingester.chunk_document(doc)
        self.assertTrue(len(chunks) > 1)
        self.assertEqual(chunks[0].chunk_id, "DOC-02-0")
        self.assertEqual(chunks[1].chunk_id, "DOC-02-1")

class TestBM25Retriever(unittest.TestCase):
    """Unit tests for Okapi BM25 scoring and RAG retriever ranking."""

    def setUp(self):
        self.ingester = DocumentIngester(chunk_size=400, chunk_overlap=50)
        self.chunks = self.ingester.ingest_all()
        self.retriever = RAGRetriever(scorer=BM25Scorer())
        self.retriever.index(self.chunks)

    def test_retriever_indexed_count(self):
        """Retriever successfully indexes chunks from MITRE and threat intel."""
        self.assertTrue(self.retriever.count() >= 40)

    def test_retrieve_exact_ip_indicator(self):
        """Retrieval for known IP '198.51.100.200' ranks Cobalt Strike chunk first."""
        results = self.retriever.retrieve("198.51.100.200", top_k=3)
        self.assertTrue(len(results) > 0)
        top = results[0]
        self.assertEqual(top.rank, 1)
        self.assertIn("198.51.100.200", top.chunk.content)
        self.assertIn("Cobalt Strike", top.chunk.content)
        self.assertTrue(top.score > 2.0)

    def test_retrieve_mitre_powershell_technique(self):
        """Retrieval for 'PowerShell execution' ranks T1059.001 chunk high."""
        results = self.retriever.retrieve("PowerShell script execution", top_k=3)
        self.assertTrue(len(results) > 0)
        matched_content = " ".join([r.chunk.content for r in results])
        self.assertIn("T1059.001", matched_content)

    def test_retrieve_respects_top_k(self):
        """Retriever strictly limits returned chunks to top_k."""
        results = self.retriever.retrieve("Windows", top_k=2)
        self.assertLessEqual(len(results), 2)

    def test_retrieve_irrelevant_query_threshold(self):
        """Nonsense query with high threshold returns zero chunks."""
        results = self.retriever.retrieve("quantum_astrophysics_nebula", top_k=3, threshold=5.0)
        self.assertEqual(len(results), 0)

class TestRAGPipeline(unittest.TestCase):
    """Unit tests for the end-to-end RAGPipeline."""

    def setUp(self):
        self.pipeline = create_default_rag_pipeline(auto_init=True)

    def test_pipeline_initialization(self):
        """Pipeline initializes successfully from default configs and reference data."""
        self.assertTrue(self.pipeline.is_initialized)
        self.assertTrue(self.pipeline.retriever.count() >= 40)

    def test_pipeline_query_context_formatting(self):
        """Pipeline formats retrieved chunks into clean markdown block for prompts."""
        results = self.pipeline.query("LockBit ransomware encryption", top_k=2)
        self.assertTrue(len(results) > 0)

        context_str = self.pipeline.format_context_for_prompt(results)
        self.assertIn("=== RETRIEVED THREAT INTELLIGENCE & MITRE KNOWLEDGE ===", context_str)
        self.assertIn("LockBit", context_str)

    def test_pipeline_query_indicator_combined(self):
        """query_indicator returns both structured DB match and relevant RAG context."""
        res = self.pipeline.query_indicator("198.51.100.250")
        self.assertTrue(res["has_threat_intel"])
        self.assertEqual(res["reputation"], "malicious")
        self.assertEqual(res["direct_match"]["threat_actor"], "LockBit Gang")
        self.assertTrue(len(res["context_chunks"]) > 0)

    def test_pipeline_empty_query_formatting(self):
        """Pipeline handles empty result formatting gracefully."""
        context_str = self.pipeline.format_context_for_prompt([])
        self.assertIn("No relevant threat intelligence", context_str)

    def test_cpu_safety_and_no_prohibited_tokens_in_rag(self):
        """Verify ai/rag contains no subprocess, os.system, exec, or eval."""
        rag_dir = PROJECT_ROOT / "ai" / "rag"
        prohibited = ["subprocess", "os.system", "os.popen", "shell=True", "exec(", "eval("]
        for py_file in rag_dir.glob("*.py"):
            code = py_file.read_text(encoding="utf-8")
            for token in prohibited:
                self.assertNotIn(
                    token,
                    code,
                    f"Safety violation: Found prohibited token '{token}' in {py_file.name}",
                )

if __name__ == "__main__":
    unittest.main()
