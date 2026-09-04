"""
AegisX AI Agents Package
=========================

Exports AegisX SOC agents and schemas:
  - TriageAgent & TriageResult
  - InvestigationAgent & InvestigationResult
  - ThreatIntelAgent & ThreatIntelResult
"""

from ai.agents.triage_agent import TriageAgent
from ai.agents.schemas import (
    AlertInput,
    FindingItem,
    RecommendedAction,
    TriageResult,
)
from ai.agents.investigation_agent import InvestigationAgent
from ai.agents.investigation_schemas import (
    InvestigationRequest,
    InvestigationStep,
    InvestigationFinding,
    InvestigationDecision,
    InvestigationResult,
    VALID_INVESTIGATION_STATUSES,
    VALID_INVESTIGATION_ACTIONS,
)
from ai.agents.threat_intel_agent import ThreatIntelAgent
from ai.agents.threat_intel_schemas import (
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatIntelFinding,
    ThreatIntelStep,
    ThreatIntelDecision,
    VALID_THREAT_INTEL_STATUSES,
    VALID_THREAT_INTEL_ACTIONS,
)

__all__ = [
    "TriageAgent",
    "AlertInput",
    "FindingItem",
    "RecommendedAction",
    "TriageResult",
    "InvestigationAgent",
    "InvestigationRequest",
    "InvestigationStep",
    "InvestigationFinding",
    "InvestigationDecision",
    "InvestigationResult",
    "VALID_INVESTIGATION_STATUSES",
    "VALID_INVESTIGATION_ACTIONS",
    "ThreatIntelAgent",
    "ThreatIntelRequest",
    "ThreatIntelResult",
    "ThreatIntelFinding",
    "ThreatIntelStep",
    "ThreatIntelDecision",
    "VALID_THREAT_INTEL_STATUSES",
    "VALID_THREAT_INTEL_ACTIONS",
]
