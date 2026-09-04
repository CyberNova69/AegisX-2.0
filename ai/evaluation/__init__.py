"""
AegisX Evaluation Framework Package
====================================

Exports evaluation metrics, test set firewall, loaders, and benchmark reporting tools.
"""

from ai.evaluation.test_set_firewall import (
    TestSetFirewall,
    FirewallViolationError,
    EXPECTED_TEST_SET_SHA256,
    EXPECTED_TEST_SET_COUNT,
)
from ai.evaluation.loader import (
    load_test_records,
    DatasetValidationError,
)
from ai.evaluation.metrics import (
    compute_accuracy,
    compute_confusion_matrix,
    compute_per_class_metrics,
    compute_macro_metrics,
    compute_hit_at_k,
    compute_latency_stats,
    compute_evidence_grounding_stats,
    FailureType,
)
from ai.evaluation.triage_eval import (
    TriageEvalMetrics,
    evaluate_triage_predictions,
)
from ai.evaluation.investigation_eval import (
    InvestigationEvalMetrics,
    evaluate_investigation_scenarios,
)
from ai.evaluation.threat_intel_eval import (
    ThreatIntelEvalMetrics,
    evaluate_threat_intel_results,
)
from ai.evaluation.rag_eval import (
    RAGRetrievalMetrics,
    evaluate_rag_retrieval,
)
from ai.evaluation.safety_eval import (
    SafetyEvaluationMetrics,
    evaluate_safety_invariants,
)
from ai.evaluation.benchmark import (
    BenchmarkReport,
    generate_comparison_schema,
)

__all__ = [
    "TestSetFirewall",
    "FirewallViolationError",
    "EXPECTED_TEST_SET_SHA256",
    "EXPECTED_TEST_SET_COUNT",
    "load_test_records",
    "DatasetValidationError",
    "compute_accuracy",
    "compute_confusion_matrix",
    "compute_per_class_metrics",
    "compute_macro_metrics",
    "compute_hit_at_k",
    "compute_latency_stats",
    "compute_evidence_grounding_stats",
    "FailureType",
    "TriageEvalMetrics",
    "evaluate_triage_predictions",
    "InvestigationEvalMetrics",
    "evaluate_investigation_scenarios",
    "ThreatIntelEvalMetrics",
    "evaluate_threat_intel_results",
    "RAGRetrievalMetrics",
    "evaluate_rag_retrieval",
    "SafetyEvaluationMetrics",
    "evaluate_safety_invariants",
    "BenchmarkReport",
    "generate_comparison_schema",
]
