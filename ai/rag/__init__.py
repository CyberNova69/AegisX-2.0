"""
AegisX RAG & Threat Intelligence Package
=========================================

Exports CPU-safe document ingestion, BM25 retrieval, and RAG pipeline orchestrators.
"""

from ai.rag.ingest import Document, DocumentChunk, DocumentIngester
from ai.rag.embeddings import BaseScorer, BM25Scorer
from ai.rag.retriever import RAGRetriever, RetrievalResult
from ai.rag.pipeline import RAGPipeline, create_default_rag_pipeline

__all__ = [
    "Document",
    "DocumentChunk",
    "DocumentIngester",
    "BaseScorer",
    "BM25Scorer",
    "RAGRetriever",
    "RetrievalResult",
    "RAGPipeline",
    "create_default_rag_pipeline",
]
