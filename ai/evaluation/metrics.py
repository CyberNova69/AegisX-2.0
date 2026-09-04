"""
AegisX Evaluation Metrics & Statistics Engine
=============================================

Computes standard ML classification, retrieval, safety, and operational metrics
for SOC AI evaluation without external heavy dependencies (pure standard library).
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

class FailureType(str, Enum):
    """Categorized failure types for transparent evaluation diagnostics."""
    MODEL_ERROR = "model_error"
    MALFORMED_OUTPUT = "malformed_output"
    GROUNDING_FAILURE = "evidence_grounding_failure"
    TOOL_FAILURE = "tool_failure"
    API_FAILURE = "api_network_failure"
    DATASET_ERROR = "dataset_error"
    EVALUATOR_ERROR = "evaluator_error"

# ---------------------------------------------------------------------------
# Classification & Tabular Metrics
# ---------------------------------------------------------------------------

def compute_accuracy(predictions: List[str], targets: List[str]) -> float:
    """Compute exact match ratio."""
    if not targets or len(predictions) != len(targets):
        return 0.0
    correct = sum(1 for p, t in zip(predictions, targets) if p == t)
    return round(correct / len(targets), 4)

def compute_confusion_matrix(
    predictions: List[str],
    targets: List[str],
    labels: Optional[List[str]] = None,
) -> Dict[str, Dict[str, int]]:
    """
    Build 2D confusion matrix: matrix[actual_label][predicted_label] = count.
    """
    all_labels = labels or sorted(list(set(targets) | set(predictions)))
    matrix: Dict[str, Dict[str, int]] = {
        actual: {pred: 0 for pred in all_labels} for actual in all_labels
    }

    for p, t in zip(predictions, targets):
        if t in matrix and p in matrix[t]:
            matrix[t][p] += 1
        elif t in matrix:
            matrix[t][p] = 1

    return matrix

def compute_per_class_metrics(
    predictions: List[str],
    targets: List[str],
    labels: Optional[List[str]] = None,
) -> Dict[str, Dict[str, float]]:
    """
    Compute Precision, Recall, and F1 score per unique class label.
    """
    all_labels = labels or sorted(list(set(targets) | set(predictions)))
    results: Dict[str, Dict[str, float]] = {}

    for label in all_labels:
        tp = sum(1 for p, t in zip(predictions, targets) if p == label and t == label)
        fp = sum(1 for p, t in zip(predictions, targets) if p == label and t != label)
        fn = sum(1 for p, t in zip(predictions, targets) if p != label and t == label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        results[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(1 for t in targets if t == label),
        }

    return results

def compute_macro_metrics(per_class_metrics: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    """
    Compute unweighted macro average of precision, recall, and F1 across all classes.
    """
    if not per_class_metrics:
        return {"macro_precision": 0.0, "macro_recall": 0.0, "macro_f1": 0.0}

    precisions = [m["precision"] for m in per_class_metrics.values()]
    recalls = [m["recall"] for m in per_class_metrics.values()]
    f1s = [m["f1"] for m in per_class_metrics.values()]

    k = len(per_class_metrics)
    return {
        "macro_precision": round(sum(precisions) / k, 4),
        "macro_recall": round(sum(recalls) / k, 4),
        "macro_f1": round(sum(f1s) / k, 4),
    }

# ---------------------------------------------------------------------------
# Retrieval & RAG Metrics
# ---------------------------------------------------------------------------

def compute_hit_at_k(
    retrieved_ids_list: List[List[str]],
    expected_ids_list: List[List[str]],
    k: int,
) -> float:
    """
    Compute Hit@K: fraction of queries where at least one expected ID appears in top-K retrieved.
    """
    if not retrieved_ids_list or len(retrieved_ids_list) != len(expected_ids_list):
        return 0.0

    hits = 0
    total = len(retrieved_ids_list)

    for retrieved, expected in zip(retrieved_ids_list, expected_ids_list):
        top_k_set = set(retrieved[:k])
        expected_set = set(expected)
        if bool(top_k_set & expected_set):
            hits += 1

    return round(hits / total, 4) if total > 0 else 0.0

# ---------------------------------------------------------------------------
# Latency & Distribution Statistics
# ---------------------------------------------------------------------------

def compute_latency_stats(latencies_ms: List[float]) -> Dict[str, float]:
    """
    Compute mean, median, p95, min, and max latency in milliseconds.
    """
    if not latencies_ms:
        return {"count": 0, "avg_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0}

    sorted_vals = sorted(latencies_ms)
    n = len(sorted_vals)
    avg_val = sum(sorted_vals) / n
    median_val = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0

    # 95th percentile index
    p95_idx = int(0.95 * n)
    p95_val = sorted_vals[min(p95_idx, n - 1)]

    return {
        "count": n,
        "avg_ms": round(avg_val, 2),
        "median_ms": round(median_val, 2),
        "p95_ms": round(p95_val, 2),
        "min_ms": round(sorted_vals[0], 2),
        "max_ms": round(sorted_vals[-1], 2),
    }

# ---------------------------------------------------------------------------
# Evidence Grounding Statistics
# ---------------------------------------------------------------------------

def compute_evidence_grounding_stats(
    findings: List[Dict[str, Any]],
    valid_evidence_ids: Set[str],
) -> Dict[str, Any]:
    """
    Evaluate grounding compliance of findings against valid evidence pool.
    """
    total_findings = len(findings)
    if total_findings == 0:
        return {
            "total_findings": 0,
            "grounded_findings": 0,
            "evidence_grounding_rate": 1.0,
            "total_hallucination_attempts": 0,
            "hallucinated_evidence_rate": 0.0,
            "hallucinated_ids": [],
        }

    grounded_count = 0
    hallucinated_ids = []

    for f in findings:
        eids = f.get("evidence_ids", [])
        if eids:
            all_valid = True
            for eid in eids:
                if eid in valid_evidence_ids:
                    pass
                else:
                    all_valid = False
                    hallucinated_ids.append(eid)
            if all_valid and len(eids) > 0:
                grounded_count += 1

    return {
        "total_findings": total_findings,
        "grounded_findings": grounded_count,
        "evidence_grounding_rate": round(grounded_count / total_findings, 4),
        "total_hallucination_attempts": len(hallucinated_ids),
        "hallucinated_evidence_rate": round(len(hallucinated_ids) / total_findings, 4),
        "hallucinated_ids": hallucinated_ids,
    }
