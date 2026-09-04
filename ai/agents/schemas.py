"""
AegisX AI Agents Data Schemas
==============================

Data structures for agent inputs, outputs, findings, and triage results.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

VALID_CLASSIFICATIONS = {
    "benign",
    "suspicious",
    "likely_malicious",
    "confirmed_malicious",
    "insufficient_evidence",
}

VALID_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}

VALID_ACTION_PRIORITIES = {
    "immediate",
    "high",
    "medium",
    "low",
}

@dataclass
class FindingItem:
    """Individual evidence-grounded finding."""
    finding: str
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding,
            "evidence_ids": self.evidence_ids,
        }

@dataclass
class RecommendedAction:
    """Recommended SOC containment or investigation action."""
    action: str
    priority: str = "medium"
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "priority": self.priority,
            "rationale": self.rationale,
        }

@dataclass
class AlertInput:
    """Normalized security alert input passed to TriageAgent."""
    alert: Dict[str, Any]
    context: Dict[str, Any]
    evidence: List[Dict[str, Any]]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertInput":
        if "alert" not in data or not isinstance(data["alert"], dict):
            raise ValueError("Input data must contain an 'alert' object.")
        if "context" not in data or not isinstance(data["context"], dict):
            raise ValueError("Input data must contain a 'context' object.")
        if "evidence" not in data or not isinstance(data["evidence"], list):
            raise ValueError("Input data must contain an 'evidence' list.")
        if len(data["evidence"]) == 0:
            raise ValueError("Evidence array must not be empty.")
        return cls(
            alert=data["alert"],
            context=data["context"],
            evidence=data["evidence"],
        )

    def get_valid_evidence_ids(self) -> set[str]:
        ids = set()
        for evt in self.evidence:
            if isinstance(evt, dict) and "id" in evt:
                ids.add(evt["id"])
        return ids

@dataclass
class TriageResult:
    """Structured result produced by TriageAgent."""
    classification: str
    severity: str
    confidence: float
    investigation_required: bool
    summary: str
    findings: List[FindingItem] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    recommended_actions: List[RecommendedAction] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification,
            "severity": self.severity,
            "confidence": self.confidence,
            "investigation_required": self.investigation_required,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "evidence_ids": self.evidence_ids,
            "recommended_actions": [a.to_dict() for a in self.recommended_actions],
            "metadata": self.metadata,
        }
