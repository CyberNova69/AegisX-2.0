"""
AegisX Investigation Evaluation Framework
===========================================

Computes evaluation metrics for InvestigationAgent performance across synthetic scenarios.
Clearly labeled as: SYNTHETIC EVALUATION (does NOT represent real-world SOC accuracy).
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ai.agents.investigation_schemas import InvestigationResult

@dataclass
class InvestigationEvalMetrics:
    """Consolidated metrics for synthetic investigation evaluation."""
    evaluation_type: str = "SYNTHETIC EVALUATION"
    disclaimer: str = "Evaluated on deterministic synthetic telemetry. Does NOT represent real-world SOC accuracy."
    total_scenarios: int = 0
    completed_count: int = 0
    completion_rate: float = 0.0
    correct_conclusions: int = 0
    conclusion_accuracy: float = 0.0
    total_findings: int = 0
    grounded_findings: int = 0
    evidence_grounding_rate: float = 0.0
    total_hallucination_attempts: int = 0
    hallucinated_evidence_rate: float = 0.0
    max_step_violations: int = 0
    structured_output_valid_count: int = 0
    structured_output_validity_rate: float = 0.0
    avg_steps_per_investigation: float = 0.0
    conclusions_distribution: Dict[str, int] = field(default_factory=Counter)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_type": self.evaluation_type,
            "disclaimer": self.disclaimer,
            "total_scenarios": self.total_scenarios,
            "completed_count": self.completed_count,
            "completion_rate": round(self.completion_rate, 4),
            "correct_conclusions": self.correct_conclusions,
            "conclusion_accuracy": round(self.conclusion_accuracy, 4),
            "total_findings": self.total_findings,
            "grounded_findings": self.grounded_findings,
            "evidence_grounding_rate": round(self.evidence_grounding_rate, 4),
            "total_hallucination_attempts": self.total_hallucination_attempts,
            "hallucinated_evidence_rate": round(self.hallucinated_evidence_rate, 4),
            "max_step_violations": self.max_step_violations,
            "structured_output_validity_rate": round(self.structured_output_validity_rate, 4),
            "avg_steps_per_investigation": round(self.avg_steps_per_investigation, 2),
            "conclusions_distribution": dict(self.conclusions_distribution),
        }

def evaluate_investigation_scenarios(
    results: List[Dict[str, Any]],
    expected_scenarios: List[Dict[str, Any]],
) -> InvestigationEvalMetrics:
    """
    Evaluate a batch of investigation outputs against expected scenario outcomes.

    Args:
        results: List of InvestigationResult objects or serialized dicts.
        expected_scenarios: List of scenario dictionaries containing 'expected_conclusion' and 'expected_severity'.

    Returns:
        InvestigationEvalMetrics: Full structured synthetic evaluation report.
    """
    metrics = InvestigationEvalMetrics(total_scenarios=len(results))
    if not results:
        return metrics

    total_steps = 0

    for res, expected in zip(results, expected_scenarios):
        if hasattr(res, "to_dict"):
            r_dict = res.to_dict()
        else:
            r_dict = res

        # Completion
        if r_dict.get("status") == "completed":
            metrics.completed_count += 1

        # Structured output validity
        if "conclusion" in r_dict and "findings" in r_dict and "evidence" in r_dict:
            metrics.structured_output_valid_count += 1

        # Conclusion accuracy
        pred_conc = r_dict.get("conclusion")
        metrics.conclusions_distribution[pred_conc] += 1
        exp_conc = expected.get("expected_conclusion")
        if pred_conc == exp_conc:
            metrics.correct_conclusions += 1

        # Steps
        steps = r_dict.get("investigation_steps", [])
        total_steps += len(steps)
        if len(steps) > 5:
            metrics.max_step_violations += 1

        # Findings & Evidence Grounding
        meta = r_dict.get("metadata", {})
        hallucinated = meta.get("hallucinated_evidence_attempts", [])
        metrics.total_hallucination_attempts += len(hallucinated)

        findings = r_dict.get("findings", [])
        for f in findings:
            metrics.total_findings += 1
            if f.get("evidence_ids") and len(f.get("evidence_ids")) > 0:
                metrics.grounded_findings += 1

    # Ratios
    n = metrics.total_scenarios
    metrics.completion_rate = metrics.completed_count / n if n > 0 else 0.0
    metrics.conclusion_accuracy = metrics.correct_conclusions / n if n > 0 else 0.0
    metrics.structured_output_validity_rate = metrics.structured_output_valid_count / n if n > 0 else 0.0
    metrics.avg_steps_per_investigation = total_steps / n if n > 0 else 0.0

    if metrics.total_findings > 0:
        metrics.evidence_grounding_rate = metrics.grounded_findings / metrics.total_findings
        metrics.hallucinated_evidence_rate = metrics.total_hallucination_attempts / metrics.total_findings
    else:
        metrics.evidence_grounding_rate = 1.0
        metrics.hallucinated_evidence_rate = 0.0

    return metrics
