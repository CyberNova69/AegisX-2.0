"""Detection engine data models.

Defines Alert, DetectionRule, and related types for the AegisX SOC detection
layer. These are the core data structures for the NormalizedEvent → Alert
pathway. They are deliberately independent of the LLM/AI layer — detection
is deterministic.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AlertSeverity(str, Enum):
    """Alert severity levels, consistent with ai/ingestion/types.py SEVERITIES."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionType(str, Enum):
    """Categories of detection methods."""
    RULE = "rule"
    IOC = "ioc"
    BEHAVIORAL = "behavioral"
    ANOMALY = "anomaly"


class AlertStatus(str, Enum):
    """Alert lifecycle status."""
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


@dataclass
class DetectionRule:
    """A single detection rule definition.

    Rules are deterministic pattern matchers that produce alerts from
    normalized security events. Each rule has:
      - A unique ID (e.g. "AX-RULE-001")
      - A condition function that returns True if the event matches
      - Associated MITRE ATT&CK mapping
      - Severity and metadata
    """
    rule_id: str
    name: str
    description: str
    severity: AlertSeverity
    detection_type: DetectionType = DetectionType.RULE
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    # Hard-negative exclusion patterns: if any returns True, suppress the alert
    # even if the main condition matches. This prevents false positives from
    # known benign activity (e.g., authorized scanners, IT deployments).
    # Exclusions are checked BEFORE the rule fires, not after.
    exclude_tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "detection_type": self.detection_type.value,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "enabled": self.enabled,
            "tags": self.tags,
            "exclude_tags": self.exclude_tags,
        }


@dataclass
class Alert:
    """A security alert produced by the detection engine.

    Alerts are the output of deterministic detection rules applied to
    NormalizedEvents. They are NOT the same as triage results — triage
    is performed by the AI layer downstream.

    Each alert retains full provenance: which rule fired, which event
    triggered it, and why.
    """
    alert_id: str = field(default_factory=lambda: f"ALERT-{uuid.uuid4().hex[:12].upper()}")
    title: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    detection_type: DetectionType = DetectionType.RULE
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None

    # Source event provenance
    source_event_id: str = ""
    source_name: str = ""
    event_type: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Entity context (from the triggering event)
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None

    # MITRE ATT&CK mapping
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None

    # Evidence — what matched and why
    evidence: Dict[str, Any] = field(default_factory=dict)
    match_details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "detection_type": self.detection_type.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "source_event_id": self.source_event_id,
            "source_name": self.source_name,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "username": self.username,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "file_path": self.file_path,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "evidence": self.evidence,
            "match_details": self.match_details,
        }

    def to_triage_input(self) -> Dict[str, Any]:
        """Bridge to the TriageAgent AlertInput contract.

        This creates the alert/context/evidence structure that the
        existing TriageAgent expects, enabling the detection→triage
        pipeline integration.
        """
        return {
            "alert": {
                "title": self.title,
                "severity": self.severity.value,
                "source": self.source_name or "detection_engine",
                "timestamp": self.timestamp,
            },
            "context": {
                "hostname": self.hostname or "unknown",
                "username": self.username or "unknown",
                "ip_address": self.source_ip or self.dest_ip or "0.0.0.0",
                "os": "unknown",
                "environment": "unknown",
                "asset_criticality": "unknown",
                "department": "unknown",
            },
            "evidence": [
                {
                    "id": f"EVT-{self.source_event_id[-6:]}" if self.source_event_id else "EVT-000001",
                    "type": self.event_type or "process_creation",
                    "description": self.match_details or self.description,
                }
            ],
        }
