"""AegisX Alert Correlation Engine.

Implements the core SOC correlation contract:

    correlate(alerts: list[Alert], window_minutes=30) -> list[Incident]

Groups related alerts into incidents using:
  1. Time-window grouping (alerts within N minutes of each other)
  2. Entity-based correlation (same host, user, or IP)
  3. MITRE kill-chain ordering (detect multi-stage attack chains)

This is deterministic — no LLM involvement.

Architecture position:
    Alert(s) → [Correlation Engine] → Incident(s) → AI Triage → Investigation
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.detection.models import Alert, AlertSeverity

from .models import (
    AttackStage,
    CorrelatedAlert,
    Incident,
    IncidentSeverity,
    KILL_CHAIN_ORDER,
    TACTIC_TO_STAGE,
)

logger = logging.getLogger("AegisX.CorrelationEngine")


# Severity escalation mapping: Alert → Incident
_SEVERITY_ESCALATION: Dict[str, IncidentSeverity] = {
    "informational": IncidentSeverity.LOW,
    "low": IncidentSeverity.LOW,
    "medium": IncidentSeverity.MEDIUM,
    "high": IncidentSeverity.HIGH,
    "critical": IncidentSeverity.CRITICAL,
}


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO-8601 timestamp, tolerant of common variations."""
    if not ts:
        return None
    try:
        # Handle 'Z' suffix
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _max_severity(severities: List[str]) -> IncidentSeverity:
    """Return the highest severity from a list of alert severity strings."""
    order = ["informational", "low", "medium", "high", "critical"]
    max_idx = -1
    for sev in severities:
        try:
            idx = order.index(sev)
            max_idx = max(max_idx, idx)
        except ValueError:
            continue
    if max_idx < 0:
        return IncidentSeverity.MEDIUM
    return _SEVERITY_ESCALATION.get(order[max_idx], IncidentSeverity.MEDIUM)


class CorrelationEngine:
    """Entity-and-time-based alert correlation engine.

    Groups alerts into incidents by:
      1. Extracting entity keys (hostname, username, IP addresses)
      2. Grouping alerts that share at least one entity
      3. Filtering groups by time window
      4. Detecting multi-stage attack chains via MITRE tactic ordering

    Usage:
        engine = CorrelationEngine()
        incidents = engine.correlate(alerts, window_minutes=30)
    """

    def __init__(self, window_minutes: int = 30):
        self._default_window = window_minutes
        self._stats = CorrelationStats()

    @property
    def stats(self) -> "CorrelationStats":
        return self._stats

    def correlate(
        self,
        alerts: List[Alert],
        window_minutes: Optional[int] = None,
    ) -> List[Incident]:
        """Correlate alerts into incidents.

        This is the primary contract:
            correlate(alerts, window_minutes=30) -> list[Incident]

        Args:
            alerts: List of Alert objects from the detection engine.
            window_minutes: Time window in minutes for correlation.

        Returns:
            List of Incident objects, each containing related alerts.
        """
        window = window_minutes or self._default_window
        self._stats.alerts_processed += len(alerts)

        if not alerts:
            return []

        # Step 1: Extract entity keys for each alert
        alert_entities = self._extract_entities(alerts)

        # Step 2: Group alerts by shared entities (union-find style)
        groups = self._group_by_entities(alerts, alert_entities)

        # Step 3: Apply time-window filtering within each group
        time_filtered = self._apply_time_window(groups, alerts, window)

        # Step 4: Build incidents from groups
        incidents = []
        for group_alerts in time_filtered:
            if len(group_alerts) < 1:
                continue

            incident = self._build_incident(group_alerts, window)
            incidents.append(incident)
            self._stats.incidents_created += 1

            logger.info(
                "Incident created: %s (%d alerts, severity=%s, multi_stage=%s)",
                incident.incident_id, incident.alert_count,
                incident.severity.value, incident.is_multi_stage,
            )

        self._stats.uncorrelated_alerts += sum(
            1 for group in time_filtered if len(group) == 1
        )

        return incidents

    def _extract_entities(self, alerts: List[Alert]) -> Dict[int, Set[str]]:
        """Extract correlation entity keys from each alert."""
        entities: Dict[int, Set[str]] = {}

        for i, alert in enumerate(alerts):
            keys: Set[str] = set()
            if alert.hostname:
                keys.add(f"host:{alert.hostname.lower()}")
            if alert.username:
                keys.add(f"user:{alert.username.lower()}")
            if alert.source_ip:
                keys.add(f"ip:{alert.source_ip}")
            if alert.dest_ip:
                keys.add(f"ip:{alert.dest_ip}")
            entities[i] = keys

        return entities

    def _group_by_entities(
        self,
        alerts: List[Alert],
        alert_entities: Dict[int, Set[str]],
    ) -> List[List[Alert]]:
        """Group alerts that share at least one entity key.

        Uses union-find to merge alerts sharing entities.
        """
        n = len(alerts)
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int):
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        # Build entity → alert-index mapping
        entity_to_alerts: Dict[str, List[int]] = defaultdict(list)
        for idx, keys in alert_entities.items():
            for key in keys:
                entity_to_alerts[key].append(idx)

        # Union alerts sharing the same entity
        for entity_key, indices in entity_to_alerts.items():
            for i in range(1, len(indices)):
                union(indices[0], indices[i])

        # Collect groups
        groups: Dict[int, List[int]] = defaultdict(list)
        for i in range(n):
            groups[find(i)].append(i)

        return [[alerts[i] for i in group] for group in groups.values()]

    def _apply_time_window(
        self,
        groups: List[List[Alert]],
        alerts: List[Alert],
        window_minutes: int,
    ) -> List[List[Alert]]:
        """Filter groups by time window.

        Alerts without timestamps are included (they cannot be excluded
        on temporal grounds). Within a group, if the time span exceeds
        the window, split into sub-groups.
        """
        result: List[List[Alert]] = []

        for group in groups:
            if len(group) <= 1:
                result.append(group)
                continue

            # Parse timestamps
            timed: List[Tuple[Optional[datetime], Alert]] = []
            for alert in group:
                ts = _parse_timestamp(alert.timestamp)
                timed.append((ts, alert))

            # Sort by timestamp (None sorts first)
            timed.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc))

            # Group within window
            current_group: List[Alert] = [timed[0][1]]
            current_start = timed[0][0]

            for ts, alert in timed[1:]:
                if ts is None or current_start is None:
                    current_group.append(alert)
                    continue

                delta = (ts - current_start).total_seconds() / 60.0
                if delta <= window_minutes:
                    current_group.append(alert)
                else:
                    result.append(current_group)
                    current_group = [alert]
                    current_start = ts

            if current_group:
                result.append(current_group)

        return result

    def _build_incident(
        self,
        alerts: List[Alert],
        window_minutes: int,
    ) -> Incident:
        """Build an Incident from a group of correlated alerts."""
        # Collect entities
        hosts: Set[str] = set()
        users: Set[str] = set()
        ips: Set[str] = set()
        stages: Set[AttackStage] = set()
        techniques: Set[str] = set()
        severities: List[str] = []
        timestamps: List[str] = []
        correlated_alerts: List[CorrelatedAlert] = []

        for alert in alerts:
            if alert.hostname:
                hosts.add(alert.hostname)
            if alert.username:
                users.add(alert.username)
            if alert.source_ip:
                ips.add(alert.source_ip)
            if alert.dest_ip:
                ips.add(alert.dest_ip)
            if alert.mitre_technique_id:
                techniques.add(alert.mitre_technique_id)

            # Map MITRE tactic to kill-chain stage
            stage = AttackStage.UNKNOWN
            if alert.mitre_tactic:
                stage = TACTIC_TO_STAGE.get(alert.mitre_tactic, AttackStage.UNKNOWN)
            stages.add(stage)

            severities.append(alert.severity.value)
            if alert.timestamp:
                timestamps.append(alert.timestamp)

            correlated_alerts.append(CorrelatedAlert(
                alert_id=alert.alert_id,
                title=alert.title,
                severity=alert.severity.value,
                rule_id=alert.rule_id,
                source_event_id=alert.source_event_id,
                timestamp=alert.timestamp,
                mitre_technique_id=alert.mitre_technique_id,
                mitre_tactic=alert.mitre_tactic,
                attack_stage=stage,
            ))

        # Determine if multi-stage
        meaningful_stages = stages - {AttackStage.UNKNOWN}
        is_multi_stage = len(meaningful_stages) >= 2

        # Order stages by kill-chain
        ordered_stages = sorted(
            meaningful_stages,
            key=lambda s: KILL_CHAIN_ORDER.index(s) if s in KILL_CHAIN_ORDER else 999,
        )

        # Compute severity (max of constituent alerts, escalate if multi-stage)
        incident_severity = _max_severity(severities)
        if is_multi_stage and incident_severity != IncidentSeverity.CRITICAL:
            # Escalate by one level for multi-stage attacks
            sev_order = [IncidentSeverity.LOW, IncidentSeverity.MEDIUM,
                         IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
            idx = sev_order.index(incident_severity)
            incident_severity = sev_order[min(idx + 1, len(sev_order) - 1)]

        # Build title
        if is_multi_stage:
            title = f"Multi-stage attack: {' → '.join(s.value for s in ordered_stages)}"
        elif len(alerts) == 1:
            title = alerts[0].title
        else:
            title = f"Correlated alerts ({len(alerts)}) on {', '.join(sorted(hosts) or ['unknown'])}"

        # Timeline
        sorted_ts = sorted(timestamps) if timestamps else []
        first_seen = sorted_ts[0] if sorted_ts else None
        last_seen = sorted_ts[-1] if sorted_ts else None

        # Description
        description_parts = [
            f"{len(alerts)} correlated alert(s)",
            f"affecting {len(hosts)} host(s)" if hosts else "",
            f"and {len(users)} user(s)" if users else "",
        ]
        if is_multi_stage:
            description_parts.append(
                f"spanning {len(meaningful_stages)} kill-chain stages"
            )
        description = " ".join(p for p in description_parts if p)

        return Incident(
            title=title,
            description=description,
            severity=incident_severity,
            alert_ids=[a.alert_id for a in alerts],
            alerts=correlated_alerts,
            alert_count=len(alerts),
            affected_hosts=sorted(hosts),
            affected_users=sorted(users),
            affected_ips=sorted(ips),
            attack_stages=[s.value for s in ordered_stages],
            mitre_techniques=sorted(techniques),
            is_multi_stage=is_multi_stage,
            first_seen=first_seen,
            last_seen=last_seen,
            correlation_method="entity_time_window",
            correlation_window_minutes=window_minutes,
        )


class CorrelationStats:
    """Counters for correlation engine performance tracking."""

    def __init__(self):
        self.alerts_processed: int = 0
        self.incidents_created: int = 0
        self.uncorrelated_alerts: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "alerts_processed": self.alerts_processed,
            "incidents_created": self.incidents_created,
            "uncorrelated_alerts": self.uncorrelated_alerts,
        }

    def reset(self):
        self.alerts_processed = 0
        self.incidents_created = 0
        self.uncorrelated_alerts = 0
