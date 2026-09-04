"""
AegisX RAG Pipeline Orchestrator
=================================

High-level pipeline orchestrator connecting DocumentIngestion, BM25 Indexing,
RAG Retrieval, and Prompt Context Formatting.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from ai.rag.embeddings import BM25Scorer
from ai.rag.ingest import DocumentIngester, DocumentChunk
from ai.rag.retriever import RAGRetriever, RetrievalResult
from ai.tools.synthetic_threat_intel import get_threat_intel

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "rag.yaml"

class RAGPipeline:
    """
    Orchestrates ingestion, retrieval, and prompt context formatting
    for security threat intelligence and MITRE ATT&CK knowledge.
    """

    def __init__(
        self,
        top_k: int = 3,
        similarity_threshold: float = 0.05,
        chunk_size: int = 400,
        chunk_overlap: int = 50,
        retriever: Optional[RAGRetriever] = None,
    ):
        self.top_k = top_k
        self.similarity_threshold = similarity_threshold
        self.ingester = DocumentIngester(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self.retriever = retriever or RAGRetriever(scorer=BM25Scorer())
        self.is_initialized: bool = False

    @classmethod
    def from_config(cls, config_path: Optional[Path] = None) -> "RAGPipeline":
        """Factory initializing pipeline from configs/rag.yaml."""
        cfg_file = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        top_k = 3
        threshold = 0.05
        chunk_size = 400
        chunk_overlap = 50

        if cfg_file.exists():
            try:
                import yaml
                with open(cfg_file, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                ret_cfg = cfg.get("retrieval", {})
                top_k = ret_cfg.get("top_k", top_k)
                threshold = float(ret_cfg.get("similarity_threshold", threshold))
                chk_cfg = cfg.get("chunking", {})
                chunk_size = chk_cfg.get("chunk_size", chunk_size)
                chunk_overlap = chk_cfg.get("chunk_overlap", chunk_overlap)
            except Exception:
                pass

        return cls(
            top_k=top_k,
            similarity_threshold=threshold,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
        )

    def initialize(
        self,
        mitre_path: Optional[Path] = None,
        threat_intel_records: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """
        Ingest documents, chunk them, and build the retrieval index.
        Returns total number of chunks indexed.
        """
        chunks = self.ingester.ingest_all(
            mitre_path=mitre_path,
            threat_intel_records=threat_intel_records,
        )
        self.retriever.index(chunks)
        self.is_initialized = True
        return len(chunks)

    def query(
        self,
        query_text: str,
        top_k: Optional[int] = None,
        threshold: Optional[float] = None,
    ) -> List[RetrievalResult]:
        """
        Query indexed threat intelligence and MITRE documents.
        """
        if not self.is_initialized:
            self.initialize()

        k = top_k if top_k is not None else self.top_k
        thresh = threshold if threshold is not None else self.similarity_threshold
        return self.retriever.retrieve(query=query_text, top_k=k, threshold=thresh)

    def query_indicator(self, indicator: str) -> Dict[str, Any]:
        """
        Combined indicator lookup: checks direct synthetic threat intel DB
        plus performs RAG retrieval for relevant context.
        """
        direct_match = get_threat_intel(indicator)
        rag_matches = self.query(indicator, top_k=2)

        return {
            "indicator": indicator,
            "direct_match": direct_match,
            "has_threat_intel": direct_match is not None,
            "reputation": direct_match.get("reputation", "unknown") if direct_match else "unknown",
            "context_chunks": [r.to_dict() for r in rag_matches],
        }

    def format_context_for_prompt(self, results: List[RetrievalResult]) -> str:
        """
        Format retrieved document chunks into clean markdown for prompt injection.
        """
        if not results:
            return "No relevant threat intelligence or MITRE context found."

        context_blocks = [
            "=== RETRIEVED THREAT INTELLIGENCE & MITRE KNOWLEDGE ===",
        ]

        for r in results:
            context_blocks.append(
                f"\n[Source: {r.chunk.title} | Relevance Score: {r.score:.2f}]"
            )
            context_blocks.append(r.chunk.content)

        context_blocks.append("\n=======================================================")
        return "\n".join(context_blocks)

def create_default_rag_pipeline(auto_init: bool = True) -> RAGPipeline:
    """Convenience factory creating and optionally initializing the default RAG pipeline."""
    pipeline = RAGPipeline.from_config()
    if auto_init:
        pipeline.initialize()
    return pipeline
