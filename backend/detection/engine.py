"""AegisX Security Detection Engine.

Implements the core SOC detection contract:

    evaluate(event: NormalizedEvent) -> list[Alert]

The detection engine applies all enabled rules to each normalized event,
checks hard-negative exclusions, and produces zero or more alerts per event.
This is purely deterministic — no LLM involvement.

Architecture position:
    NormalizedEvent → [Detection Engine] → Alert(s) → Correlation → Incident
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ai.ingestion.processing import NormalizedEvent

from .models import Alert, AlertSeverity, DetectionType
from .rules import (
    DETECTION_RULES,
    RuleCondition,
    get_all_rules,
    get_exclusion_fn,
)
from .models import DetectionRule

logger = logging.getLogger("AegisX.DetectionEngine")


class DetectionEngine:
    """Deterministic, rule-based security event detection engine.

    Evaluates NormalizedEvents against registered detection rules,
    applies hard-negative exclusions, and produces Alert objects.

    Usage:
        engine = DetectionEngine()
        alerts = engine.evaluate(normalized_event)
    """

    def __init__(
        self,
        rules: Optional[List[tuple]] = None,
        enabled_only: bool = True,
    ):
        """Initialize the detection engine.

        Args:
            rules: List of (DetectionRule, RuleCondition) tuples. If None,
                   uses the built-in rule set.
            enabled_only: If True, skip disabled rules.
        """
        self._rules = rules or get_all_rules()
        self._enabled_only = enabled_only
        self._stats = DetectionStats()

    @property
    def stats(self) -> "DetectionStats":
        return self._stats

    @property
    def rule_count(self) -> int:
        """Number of active rules."""
        if self._enabled_only:
            return sum(1 for rule, _ in self._rules if rule.enabled)
        return len(self._rules)

    def evaluate(self, event: NormalizedEvent) -> List[Alert]:
        """Evaluate a single NormalizedEvent against all detection rules.

        This is the primary contract:
            evaluate(event: NormalizedEvent) -> list[Alert]

        Returns zero or more Alert objects. Each alert retains full
        provenance (which rule, which event, what matched).

        Args:
            event: A NormalizedEvent from the ingestion processing pipeline.

        Returns:
            List of Alert objects. Empty list means no detection.
        """
        self._stats.events_evaluated += 1
        alerts: List[Alert] = []

        # Convert event to dict for rule condition evaluation
        event_dict = event.event.to_dict()

        for rule, condition_fn in self._rules:
            if self._enabled_only and not rule.enabled:
                continue

            self._stats.rules_evaluated += 1

            try:
                matched, details, evidence = condition_fn(event_dict)
            except Exception as exc:
                logger.warning(
                    "Rule %s raised exception on event %s: %s",
                    rule.rule_id, event.event_id, exc,
                )
                self._stats.rule_errors += 1
                continue

            if not matched:
                continue

            # Check hard-negative exclusions before firing
            excluded = False
            for exclude_tag in rule.exclude_tags:
                exclusion_fn = get_exclusion_fn(exclude_tag)
                if exclusion_fn and exclusion_fn(event_dict):
                    logger.debug(
                        "Rule %s suppressed by exclusion '%s' on event %s",
                        rule.rule_id, exclude_tag, event.event_id,
                    )
                    self._stats.alerts_suppressed += 1
                    excluded = True
                    break

            if excluded:
                continue

            # Build the alert
            alert = Alert(
                title=rule.name,
                description=f"{rule.description}: {details}",
                severity=rule.severity,
                detection_type=rule.detection_type,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                source_event_id=event.event_id,
                source_name=event.event.source_name,
                event_type=event.event.event_type,
                timestamp=event.event.timestamp or "",
                hostname=event.event.hostname,
                username=event.event.username,
                source_ip=event.event.source_ip,
                dest_ip=event.event.dest_ip,
                process_name=event.event.process_name,
                command_line=event.event.command_line,
                file_path=event.event.file_path,
                mitre_technique_id=rule.mitre_technique_id,
                mitre_technique_name=rule.mitre_technique_name,
                mitre_tactic=rule.mitre_tactic,
                evidence=evidence,
                match_details=details,
            )

            alerts.append(alert)
            self._stats.alerts_generated += 1

            logger.info(
                "Alert generated: [%s] %s on event %s (host=%s, user=%s)",
                rule.rule_id, rule.name, event.event_id,
                event.event.hostname, event.event.username,
            )

        return alerts

    def evaluate_batch(self, events: List[NormalizedEvent]) -> List[Alert]:
        """Evaluate a batch of events and return all generated alerts.

        Args:
            events: List of NormalizedEvents.

        Returns:
            Flat list of all alerts from all events.
        """
        all_alerts: List[Alert] = []
        for event in events:
            all_alerts.extend(self.evaluate(event))
        return all_alerts

    def get_rules_summary(self) -> List[Dict[str, Any]]:
        """Return summary of all registered rules."""
        return [
            {
                **rule.to_dict(),
                "active": rule.enabled and (not self._enabled_only or rule.enabled),
            }
            for rule, _ in self._rules
        ]


class DetectionStats:
    """Counters for detection engine performance tracking."""

    def __init__(self):
        self.events_evaluated: int = 0
        self.rules_evaluated: int = 0
        self.alerts_generated: int = 0
        self.alerts_suppressed: int = 0
        self.rule_errors: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "events_evaluated": self.events_evaluated,
            "rules_evaluated": self.rules_evaluated,
            "alerts_generated": self.alerts_generated,
            "alerts_suppressed": self.alerts_suppressed,
            "rule_errors": self.rule_errors,
        }

    def reset(self):
        self.events_evaluated = 0
        self.rules_evaluated = 0
        self.alerts_generated = 0
        self.alerts_suppressed = 0
        self.rule_errors = 0
