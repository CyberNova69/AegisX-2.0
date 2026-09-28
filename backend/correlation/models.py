"""Correlation engine data models.

Defines Incident and related types for the AegisX SOC correlation layer.
Incidents are created by grouping related Alerts within time windows and
by shared entities (host, user, IP).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IncidentSeverity(str, Enum):
    """Incident severity — escalated from constituent alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """Incident lifecycle status."""
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    RESOLVED = "resolved"
    CLOSED = "closed"


class AttackStage(str, Enum):
    """Kill-chain stage derived from MITRE tactic correlation."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


# Map MITRE tactics to kill-chain stages
TACTIC_TO_STAGE: Dict[str, AttackStage] = {
    "reconnaissance": AttackStage.RECONNAISSANCE,
    "initial_access": AttackStage.INITIAL_ACCESS,
    "execution": AttackStage.EXECUTION,
    "persistence": AttackStage.PERSISTENCE,
    "privilege_escalation": AttackStage.PRIVILEGE_ESCALATION,
    "defense_evasion": AttackStage.DEFENSE_EVASION,
    "credential_access": AttackStage.CREDENTIAL_ACCESS,
    "discovery": AttackStage.DISCOVERY,
    "lateral_movement": AttackStage.LATERAL_MOVEMENT,
    "collection": AttackStage.COLLECTION,
    "command_and_control": AttackStage.COMMAND_AND_CONTROL,
    "exfiltration": AttackStage.EXFILTRATION,
    "impact": AttackStage.IMPACT,
}

# Kill-chain ordering for severity escalation
KILL_CHAIN_ORDER = [
    AttackStage.RECONNAISSANCE,
    AttackStage.INITIAL_ACCESS,
    AttackStage.EXECUTION,
    AttackStage.PERSISTENCE,
    AttackStage.PRIVILEGE_ESCALATION,
    AttackStage.DEFENSE_EVASION,
    AttackStage.CREDENTIAL_ACCESS,
    AttackStage.DISCOVERY,
    AttackStage.LATERAL_MOVEMENT,
    AttackStage.COLLECTION,
    AttackStage.COMMAND_AND_CONTROL,
    AttackStage.EXFILTRATION,
    AttackStage.IMPACT,
]


@dataclass
class CorrelatedAlert:
    """An alert that has been correlated into an incident, with its contribution."""
    alert_id: str
    title: str
    severity: str
    rule_id: Optional[str] = None
    source_event_id: str = ""
    timestamp: str = ""
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    attack_stage: AttackStage = AttackStage.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "source_event_id": self.source_event_id,
            "timestamp": self.timestamp,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_tactic": self.mitre_tactic,
            "attack_stage": self.attack_stage.value,
        }


@dataclass
class Incident:
    """A correlated security incident composed of related alerts.

    Incidents are produced by the correlation engine grouping alerts
    that share entities (host, user, IP) within a time window.
    """
    incident_id: str = field(
        default_factory=lambda: f"INC-{uuid.uuid4().hex[:12].upper()}"
    )
    title: str = ""
    description: str = ""
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Correlated alerts
    alert_ids: List[str] = field(default_factory=list)
    alerts: List[CorrelatedAlert] = field(default_factory=list)
    alert_count: int = 0

    # Affected entities (correlation keys)
    affected_hosts: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    affected_ips: List[str] = field(default_factory=list)

    # Attack progression
    attack_stages: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    is_multi_stage: bool = False

    # Timeline
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    # Correlation metadata
    correlation_method: str = ""
    correlation_window_minutes: int = 30

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "alert_ids": self.alert_ids,
            "alerts": [a.to_dict() for a in self.alerts],
            "alert_count": self.alert_count,
            "affected_hosts": self.affected_hosts,
            "affected_users": self.affected_users,
            "affected_ips": self.affected_ips,
            "attack_stages": self.attack_stages,
            "mitre_techniques": self.mitre_techniques,
            "is_multi_stage": self.is_multi_stage,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "correlation_method": self.correlation_method,
            "correlation_window_minutes": self.correlation_window_minutes,
        }

    def to_triage_input(self) -> Dict[str, Any]:
        """Bridge to TriageAgent for incident-level triage.

        Creates an AlertInput-compatible structure from the incident
        with all correlated evidence.
        """
        # Build evidence list from correlated alerts
        evidence = []
        for i, alert in enumerate(self.alerts):
            evidence.append({
                "id": f"EVT-{i + 1:06d}",
                "type": "correlated_alert",
                "description": (
                    f"[{alert.severity}] {alert.title} "
                    f"(rule={alert.rule_id}, MITRE={alert.mitre_technique_id or 'N/A'})"
                ),
            })

        if not evidence:
            evidence = [{"id": "EVT-000001", "type": "incident", "description": self.description}]

        return {
            "alert": {
                "title": self.title,
                "severity": self.severity.value,
                "source": "correlation_engine",
                "timestamp": self.created_at,
            },
            "context": {
                "hostname": self.affected_hosts[0] if self.affected_hosts else "unknown",
                "username": self.affected_users[0] if self.affected_users else "unknown",
                "ip_address": self.affected_ips[0] if self.affected_ips else "0.0.0.0",
                "os": "unknown",
                "environment": "unknown",
                "asset_criticality": "unknown",
                "department": "unknown",
            },
            "evidence": evidence,
        }
