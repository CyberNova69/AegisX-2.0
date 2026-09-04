"""
AegisX SOC Investigation Agent Schemas
========================================

Data structures for investigation requests, steps, findings, tool decisions,
and final investigation results.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    VALID_ACTION_PRIORITIES,
    FindingItem,
    RecommendedAction,
    TriageResult,
)

VALID_INVESTIGATION_STATUSES = {
    "completed",
    "incomplete",
    "failed",
    "insufficient_evidence",
}

VALID_INVESTIGATION_ACTIONS = {
    "investigate",
    "finish",
}

@dataclass
class InvestigationFinding:
    """Individual evidence-grounded finding discovered during investigation."""
    finding_id: str
    title: str
    description: str
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5

    def __post_init__(self):
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence {self.confidence} must be between 0.0 and 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "evidence_ids": self.evidence_ids,
            "confidence": round(float(self.confidence), 4),
        }

@dataclass
class InvestigationStep:
    """Record of a single investigation tool execution step."""
    step_number: int
    tool_name: str
    tool_input: Dict[str, Any]
    purpose: str
    result: Dict[str, Any]
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "purpose": self.purpose,
            "result": self.result,
            "evidence_ids": self.evidence_ids,
        }

@dataclass
class InvestigationDecision:
    """Structured decision produced by the LLM during an investigation turn."""
    action: str
    tool_name: Optional[str] = None
    tool_input: Dict[str, Any] = field(default_factory=dict)
    purpose: str = ""
    stop_reason: Optional[str] = None

    def __post_init__(self):
        if self.action not in VALID_INVESTIGATION_ACTIONS:
            raise ValueError(
                f"Invalid action '{self.action}'. Must be one of: {sorted(VALID_INVESTIGATION_ACTIONS)}"
            )
        if self.action == "investigate" and not self.tool_name:
            raise ValueError("tool_name is required when action is 'investigate'.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "purpose": self.purpose,
            "stop_reason": self.stop_reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationDecision":
        action = data.get("action", "")
        tool_name = data.get("tool_name")
        tool_input = data.get("tool_input") or {}
        purpose = data.get("purpose", "")
        stop_reason = data.get("stop_reason")
        return cls(
            action=action,
            tool_name=tool_name,
            tool_input=tool_input,
            purpose=purpose,
            stop_reason=stop_reason,
        )

@dataclass
class InvestigationRequest:
    """Input request passed to the InvestigationAgent."""
    investigation_id: str
    alert: Dict[str, Any]
    triage_result: Union[TriageResult, Dict[str, Any]]
    initial_evidence: List[Dict[str, Any]]
    context: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationRequest":
        if "alert" not in data or not isinstance(data["alert"], dict):
            raise ValueError("InvestigationRequest requires an 'alert' dictionary.")
        if "context" not in data or not isinstance(data["context"], dict):
            raise ValueError("InvestigationRequest requires a 'context' dictionary.")
        if "initial_evidence" not in data or not isinstance(data["initial_evidence"], list):
            raise ValueError("InvestigationRequest requires an 'initial_evidence' list.")
        
        triage_res = data.get("triage_result", {})
        if isinstance(triage_res, dict) and "classification" in triage_res and "severity" in triage_res:
            triage_obj = triage_res
        elif isinstance(triage_res, TriageResult):
            triage_obj = triage_res
        else:
            triage_obj = triage_res

        return cls(
            investigation_id=data.get("investigation_id", f"INV-{data.get('alert', {}).get('id', '001')}"),
            alert=data["alert"],
            triage_result=triage_obj,
            initial_evidence=data["initial_evidence"],
            context=data["context"],
        )

    def get_valid_evidence_ids(self) -> set:
        """Extract all evidence IDs present in initial evidence."""
        ids = set()
        for evt in self.initial_evidence:
            if isinstance(evt, dict) and "id" in evt:
                ids.add(evt["id"])
        return ids

    def to_dict(self) -> Dict[str, Any]:
        triage_dict = (
            self.triage_result.to_dict()
            if hasattr(self.triage_result, "to_dict")
            else self.triage_result
        )
        return {
            "investigation_id": self.investigation_id,
            "alert": self.alert,
            "triage_result": triage_dict,
            "initial_evidence": self.initial_evidence,
            "context": self.context,
        }

@dataclass
class InvestigationResult:
    """Final comprehensive investigation report produced by the InvestigationAgent."""
    investigation_id: str
    alert_id: str
    status: str
    conclusion: str
    severity: str
    confidence: float
    findings: List[InvestigationFinding] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    investigation_steps: List[InvestigationStep] = field(default_factory=list)
    recommended_actions: List[Dict[str, Any]] = field(default_factory=list)
    limitations: str = "Read-only synthetic investigation. No endpoint remediation performed."
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.status not in VALID_INVESTIGATION_STATUSES:
            raise ValueError(
                f"Invalid status '{self.status}'. Must be one of: {sorted(VALID_INVESTIGATION_STATUSES)}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence {self.confidence} must be between 0.0 and 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "alert_id": self.alert_id,
            "status": self.status,
            "conclusion": self.conclusion,
            "severity": self.severity,
            "confidence": round(float(self.confidence), 4),
            "findings": [f.to_dict() for f in self.findings],
            "evidence": self.evidence,
            "investigation_steps": [s.to_dict() for s in self.investigation_steps],
            "recommended_actions": self.recommended_actions,
            "limitations": self.limitations,
            "metadata": self.metadata,
        }
