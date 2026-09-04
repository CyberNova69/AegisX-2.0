"""
AegisX Threat Intelligence Agent Schemas
=========================================

Data structures for autonomous threat intelligence enrichment requests,
multi-step intelligence decisions, findings, and final results.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

VALID_THREAT_INTEL_STATUSES: Set[str] = {
    "completed",
    "insufficient_evidence",
    "failed",
    "inconclusive",
}

VALID_THREAT_INTEL_ACTIONS: Set[str] = {
    "query_threat_intel",
    "query_mitre",
    "finish",
    "insufficient_evidence",
}

VALID_INDICATOR_TYPES: Set[str] = {
    "ip",
    "domain",
    "hash",
    "unknown",
}

@dataclass
class ThreatIntelDecision:
    """Structured decision produced by LLM during an enrichment step."""
    action: str
    indicator: Optional[str] = None
    indicator_type: Optional[str] = None
    technique_id: Optional[str] = None
    query: Optional[str] = None
    reason: str = ""
    stop_reason: Optional[str] = None

    def __post_init__(self):
        if self.action not in VALID_THREAT_INTEL_ACTIONS:
            raise ValueError(
                f"Invalid threat intelligence action '{self.action}'. "
                f"Must be one of: {sorted(VALID_THREAT_INTEL_ACTIONS)}"
            )
        if self.action == "query_threat_intel" and not self.indicator:
            raise ValueError("Action 'query_threat_intel' requires an 'indicator'.")
        if self.action == "query_mitre" and not self.technique_id and not self.query:
            raise ValueError("Action 'query_mitre' requires 'technique_id' or 'query'.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "technique_id": self.technique_id,
            "query": self.query,
            "reason": self.reason,
            "stop_reason": self.stop_reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatIntelDecision":
        return cls(
            action=data.get("action", ""),
            indicator=data.get("indicator"),
            indicator_type=data.get("indicator_type"),
            technique_id=data.get("technique_id"),
            query=data.get("query"),
            reason=data.get("reason", ""),
            stop_reason=data.get("stop_reason"),
        )

@dataclass
class ThreatIntelFinding:
    """Evidence-grounded intelligence finding correlating telemetry with threat context."""
    finding_id: str
    title: str
    description: str
    category: str  # "reputation", "threat_actor", "malware_family", "mitre_mapping", "infrastructure"
    evidence_ids: List[str] = field(default_factory=list)
    indicator: Optional[str] = None
    confidence: float = 0.5

    def __post_init__(self):
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence {self.confidence} must be between 0.0 and 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "evidence_ids": self.evidence_ids,
            "indicator": self.indicator,
            "confidence": round(float(self.confidence), 4),
        }

@dataclass
class ThreatIntelStep:
    """Audit record of a single intelligence query execution step."""
    step_number: int
    action: str
    tool_name: str
    query_params: Dict[str, Any]
    purpose: str
    result: Dict[str, Any]
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "action": self.action,
            "tool_name": self.tool_name,
            "query_params": self.query_params,
            "purpose": self.purpose,
            "result": self.result,
            "evidence_ids": self.evidence_ids,
        }

@dataclass
class ThreatIntelRequest:
    """Normalized security context passed to ThreatIntelAgent for enrichment."""
    request_id: str
    alert: Dict[str, Any] = field(default_factory=dict)
    initial_evidence: List[Dict[str, Any]] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    triage_result: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatIntelRequest":
        if not isinstance(data, dict):
            raise ValueError("ThreatIntelRequest input must be a dictionary.")

        req_id = data.get("request_id") or data.get("investigation_id") or f"TI-REQ-{data.get('alert', {}).get('id', '001')}"
        return cls(
            request_id=str(req_id),
            alert=data.get("alert") or {},
            initial_evidence=data.get("initial_evidence") or data.get("evidence") or [],
            context=data.get("context") or {},
            findings=data.get("findings") or [],
            indicators=data.get("indicators") or [],
            triage_result=data.get("triage_result"),
        )

    def get_valid_evidence_ids(self) -> Set[str]:
        """Extract all evidence IDs present in initial evidence."""
        ids: Set[str] = set()
        for evt in self.initial_evidence:
            if isinstance(evt, dict) and "id" in evt:
                ids.add(str(evt["id"]))
        return ids

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "alert": self.alert,
            "initial_evidence": self.initial_evidence,
            "context": self.context,
            "findings": self.findings,
            "indicators": self.indicators,
            "triage_result": self.triage_result,
        }

@dataclass
class ThreatIntelResult:
    """Comprehensive, evidence-grounded threat intelligence report."""
    request_id: str
    status: str
    confidence: float
    summary: str
    findings: List[ThreatIntelFinding] = field(default_factory=list)
    indicators_analyzed: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    enrichment_steps: List[ThreatIntelStep] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    limitations: str = (
        "Synthetic threat-intelligence record. Attribution is repository-record inference, "
        "not verified real-world actor."
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.status not in VALID_THREAT_INTEL_STATUSES:
            raise ValueError(
                f"Invalid status '{self.status}'. Must be one of: {sorted(VALID_THREAT_INTEL_STATUSES)}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence {self.confidence} must be between 0.0 and 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "confidence": round(float(self.confidence), 4),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "indicators_analyzed": self.indicators_analyzed,
            "mitre_techniques": self.mitre_techniques,
            "evidence_ids": self.evidence_ids,
            "enrichment_steps": [s.to_dict() for s in self.enrichment_steps],
            "recommendations": self.recommendations,
            "limitations": self.limitations,
            "metadata": self.metadata,
        }
