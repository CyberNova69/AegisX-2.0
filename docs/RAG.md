# AegisX 2.0 — Production Integration Guide: Conditional Neural Reranker

## 1. Architectural Overview

AegisX 2.0 implements a **two-stage retrieval pipeline** designed to combine the ultra-low latency (< 1 ms) and exact lexical precision of BM25 with the deep contextual ranking precision of a cross-encoder neural model (`cross-encoder/ms-marco-MiniLM-L-6-v2`).

```
                              [Incoming Query / Alert]
                                         │
                                         ▼
                            [Stage 1: In-Memory BM25]
                                         │
                        ┌────────────────┴────────────────┐
                        ▼                                 ▼
             [reranker.enabled = false]        [reranker.enabled = true]
                        │                                 │
                        ▼                                 ▼
               Return BM25 top-k                 [Conditional Router]
              (Production Default)                        │
                                        ┌─────────────────┴─────────────────┐
                                        ▼                                   ▼
                                 [Router Bypass]                     [Router Invoke]
                             (Exact IOC / High Margin)            (Low Margin / Ambiguous)
                                        │                                   │
                                        ▼                                   ▼
                                Return BM25 top-k               [Stage 2: Cross-Encoder]
                                                                            │
                                                        ┌───────────────────┴───────────────────┐
                                                        ▼                                       ▼
                                                   [Success]                                [Failure]
                                                        │                                       │
                                                        ▼                                       ▼
                                              [Strategy C Selection]                     [BM25 Fallback]
                                                        │                                       │
                                                        ▼                                       ▼
                                              Return Diverse top-k                      Return BM25 top-k
```

### Core Invariants
1. **BM25 Is Primary**: Native stdlib BM25 remains Stage 1 and default.
2. **Feature-Flag Gated**: `reranker.enabled: false` by default in `configs/rag.yaml`.
3. **Exact Token Protection**: Regex filters for IPv4, IPv6, SHA256, SHA1, MD5, and MITRE Technique IDs automatically bypass the neural model when BM25 certainty is established.
4. **Strategy C Context Preservation**: Eliminates semantic crowding by enforcing multi-domain coverage (MITRE ATT&CK techniques paired with Threat Intel indicators).
5. **Circuit Breaker Fallback**: Any cross-encoder failure, timeout, or missing weight file automatically falls back to native BM25 with zero service interruption.

---

## 2. Configuration Reference

All settings are managed via [`configs/rag.yaml`](file:///c:/Users/makwa/AegisX/configs/rag.yaml) under the `reranker` namespace:

```yaml
retrieval:
  top_k: 3
  similarity_threshold: 0.05
  algorithm: "bm25"

reranker:
  enabled: false                       # Feature flag: default MUST be false
  mode: "conditional"                  # Options: "off", "conditional", "always"
  model: "cross-encoder/ms-marco-MiniLM-L-6-v2"
  candidate_k: 10                      # Stage 1 candidate pool for reranking
  output_k: 3                          # Final top-k context count
  strategy: "domain_diversity"         # Strategy C: domain diversity preservation
  fallback: "bm25"                     # Automated fallback on exception/timeout
  score_margin_threshold: 0.150        # Low margin threshold triggering reranker
```

### Key Parameters:
- `enabled` (*bool*): Master feature flag. If `false`, Stage 2 is completely bypassed without importing neural models.
- `mode` (*str*):
  - `"off"`: Reranker disabled.
  - `"conditional"`: (Recommended) Routes through exact identifier filters and BM25 score margins.
  - `"always"`: Always reranks all non-empty candidate sets.
- `candidate_k` (*int*): Number of Stage 1 BM25 candidates fed into the cross-encoder (default: `10`).
- `output_k` (*int*): Final number of document chunks returned to LLM prompts (default: `3`).
- `strategy` (*str*): `"domain_diversity"` (Strategy C) preserves diverse evidence categories.

---

## 3. Conditional Routing & Identifier Protection

The conditional router (`ConditionalRouter` in `ai/rag/reranker.py`) uses deterministic token detection to avoid invoking the neural model on queries where BM25 already excels:

1. **Exact IOC Match**: Detects IPv4, IPv6, MD5, SHA1, SHA256. If BM25 score margin $\ge 0.100$, bypasses reranker (`exact_identifier_high_margin_bypass`).
2. **Exact MITRE Technique ID**: Detects `T1xxx` or `T1xxx.yyy`. If BM25 score margin $\ge 0.100$, bypasses reranker (`exact_identifier_high_margin_bypass`).
3. **Decisive BM25 Margin**: If difference between Rank 1 and Rank 2 score $\ge 0.150$, bypasses reranker (`high_bm25_margin_bypass`).
4. **Low Margin / Ambiguous**: If BM25 score margin $< 0.150$ or query contains ambiguous natural language, invokes the cross-encoder (`low_margin_ambiguity`).

---

## 4. Strategy C Context Selection Algorithm

Standard cross-encoders score each passage independently. For queries with long strings (e.g. file hashes), multiple related threat intel chunks often receive top scores, pushing distinct secondary evidence (such as MITRE execution techniques) outside top-3.

Strategy C resolves this via **Domain Diversity Enforcement**:
- **Slot 1**: Reserved for the absolute highest-scoring cross-encoder candidate (focal target).
- **Slot 2**: Allocated to the highest-scoring candidate from an *unrepresented domain* (`mitre` vs `threat_intel`).
- **Slot 3**: Filled with the remaining candidate having the highest cross-encoder score.

---

## 5. Resilience & Circuit-Breaker Fallback

If any exception occurs during neural inference:
```python
try:
    # Cross-encoder inference + Strategy C
    return self._execute_rerank(query, bm25_results, output_k)
except Exception as exc:
    # Circuit-breaker fallback
    self.metrics.fallback_count += 1
    logger.warning("Reranker failed (%s); falling back immediately to BM25", exc)
    return bm25_results[:output_k]
```
The alert investigation proceeds without delay, preserving uninterrupted SOC operations.

---

## 6. Computational Resource Profile

| Metric | BM25 Baseline | Conditional Reranker (Invoked) | Router Bypass |
| :--- | :---: | :---: | :---: |
| **Mean Latency** | **0.153 ms** | **~219.24 ms** | **~0.098 ms** |
| **Resident RAM** | ~13 MB | **~495 MB – 727 MB** | N/A |
| **Cold-Start Load Time** | 0 ms | **~4.8 s – 15.6 s** | N/A |
| **Dependencies** | Python stdlib | PyTorch + Transformers | Python stdlib |

---

## 7. Operational Runbook

### How to Enable the Reranker
In [`configs/rag.yaml`](file:///c:/Users/makwa/AegisX/configs/rag.yaml):
```yaml
reranker:
  enabled: true
  mode: "conditional"
```
Restart the AegisX daemon or worker process.

### How to Inspect Operational Telemetry
Via python:
```python
from ai.rag.rag_service import RAGService
metrics = RAGService.get_instance().get_reranker_metrics()
print(metrics)
# Output:
# {
#   'bm25_latency_ms': 0.15,
#   'router_latency_ms': 0.01,
#   'reranker_latency_ms': 219.2,
#   'invocation_count': 14,
#   'bypass_count': 32,
#   'fallback_count': 0,
#   'model_loaded': True
# }
```

### Rollback Procedure
To rollback to BM25-only retrieval with zero code deployment:
1. In [`configs/rag.yaml`](file:///c:/Users/makwa/AegisX/configs/rag.yaml), set:
   ```yaml
   reranker:
     enabled: false
   ```
2. Restart the AegisX service or reload the configuration. The retrieval pipeline immediately reverts to 100% native BM25.
