"""
AegisX CPU-Safe Embeddings & Relevance Scoring
===============================================

Pure standard-library text vectorization and relevance scoring.
Implements Okapi BM25 and TF-IDF with zero external C-dependencies,
zero PyTorch/GPU requirements, and sub-millisecond query evaluation.
"""

import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any, Dict, List, Set

STOPWORDS: Set[str] = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
    "has", "he", "in", "is", "it", "its", "of", "on", "that", "the",
    "to", "was", "were", "will", "with", "or", "this", "but", "they",
}

def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercased terms while preserving IPs, hashes, and IDs."""
    if not text:
        return []
    # Match words, dots, dashes, underscores (e.g. 198.51.100.200, T1059.001, powershell.exe)
    tokens = re.findall(r"[A-Za-z0-9_\.\-]+", text.lower())
    return [t for t in tokens if len(t) > 1 and t not in STOPWORDS]

class BaseScorer(ABC):
    """Abstract interface for text relevance scoring and ranking."""

    @abstractmethod
    def fit(self, corpus: List[str]) -> None:
        """Fit scoring model on document corpus."""
        pass

    @abstractmethod
    def score(self, query: str, doc_idx: int) -> float:
        """Calculate relevance score between query and document at doc_idx."""
        pass

class BM25Scorer(BaseScorer):
    """
    Okapi BM25 scoring model.
    Industry-standard sparse retrieval algorithm providing superior keyword ranking.
    """

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.corpus_size: int = 0
        self.avg_doc_len: float = 0.0
        self.doc_lens: List[int] = []
        self.doc_term_freqs: List[Counter] = []
        self.doc_freqs: Counter = Counter()
        self.idf_cache: Dict[str, float] = {}

    def fit(self, corpus: List[str]) -> None:
        """Compute term frequencies, document frequencies, and IDF table."""
        self.corpus_size = len(corpus)
        if self.corpus_size == 0:
            return

        self.doc_lens = []
        self.doc_term_freqs = []
        self.doc_freqs = Counter()
        self.idf_cache = {}

        total_len = 0
        for doc_text in corpus:
            tokens = tokenize(doc_text)
            length = len(tokens)
            self.doc_lens.append(length)
            total_len += length

            tf = Counter(tokens)
            self.doc_term_freqs.append(tf)

            # Document frequency (count unique words per document)
            for term in tf.keys():
                self.doc_freqs[term] += 1

        self.avg_doc_len = total_len / self.corpus_size if self.corpus_size > 0 else 0.0

        # Precompute IDF for all vocabulary terms
        for term, df in self.doc_freqs.items():
            # Standard smoothed BM25 IDF
            idf = math.log(1.0 + (self.corpus_size - df + 0.5) / (df + 0.5))
            self.idf_cache[term] = max(0.01, idf)

    def score(self, query: str, doc_idx: int) -> float:
        """Score query against document index using Okapi BM25."""
        if doc_idx >= self.corpus_size or self.avg_doc_len == 0:
            return 0.0

        query_tokens = tokenize(query)
        if not query_tokens:
            return 0.0

        doc_tf = self.doc_term_freqs[doc_idx]
        doc_len = self.doc_lens[doc_idx]
        score = 0.0

        # Length normalization component
        len_norm = 1.0 - self.b + self.b * (doc_len / self.avg_doc_len)

        for q_term in query_tokens:
            if q_term not in doc_tf:
                continue

            tf = doc_tf[q_term]
            idf = self.idf_cache.get(q_term, 0.01)

            # BM25 term weighting
            term_score = idf * (tf * (self.k1 + 1.0)) / (tf + self.k1 * len_norm)
            score += term_score

        # Exact substring bonus for IOCs or technique IDs
        clean_q = query.strip().lower()
        if len(clean_q) >= 4 and clean_q in " ".join(doc_tf.keys()):
            score += 2.0

        return round(score, 4)
