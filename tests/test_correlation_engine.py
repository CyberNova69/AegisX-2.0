"""Tests for the AegisX Alert Correlation Engine.

Verifies the correlation contract:
    correlate(alerts, window_minutes=30) -> list[Incident]

Covers time-window grouping, entity-based correlation, multi-stage
attack chain detection, and severity escalation.
"""

import unittest
from datetime import datetime, timezone, timedelta

from backend.detection.models import Alert, AlertSeverity, DetectionType
from backend.correlation.engine import CorrelationEngine
from backend.correlation.models import (
    Incident,
    IncidentSeverity,
    AttackStage,
)


def _make_alert(
    alert_id="ALERT-001",
    title="Test Alert",
    severity=AlertSeverity.MEDIUM,
    rule_id="AX-RULE-001",
    hostname="WS-001",
    username="jdoe",
    source_ip="10.0.0.5",
    dest_ip=None,
    mitre_technique_id=None,
    mitre_tactic=None,
    timestamp=None,
    source_event_id="ev-001",
) -> Alert:
    """Helper to create test alerts."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return Alert(
        alert_id=alert_id,
        title=title,
        severity=severity,
        rule_id=rule_id,
        hostname=hostname,
        username=username,
        source_ip=source_ip,
        dest_ip=dest_ip,
        mitre_technique_id=mitre_technique_id,
        mitre_tactic=mitre_tactic,
        timestamp=timestamp,
        source_event_id=source_event_id,
    )


class TestCorrelationContract(unittest.TestCase):
    """Verify the correlation engine API contract."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_correlate_returns_list(self):
        """correlate() must return a list of Incident objects."""
        result = self.engine.correlate([])
        self.assertIsInstance(result, list)

    def test_empty_alerts_returns_empty(self):
        incidents = self.engine.correlate([])
        self.assertEqual(len(incidents), 0)

    def test_single_alert_creates_incident(self):
        alerts = [_make_alert()]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_count, 1)

    def test_incident_has_required_fields(self):
        alerts = [_make_alert()]
        incidents = self.engine.correlate(alerts)
        incident = incidents[0]
        self.assertIsNotNone(incident.incident_id)
        self.assertIsNotNone(incident.title)
        self.assertIsNotNone(incident.severity)
        self.assertIsNotNone(incident.status)


class TestEntityCorrelation(unittest.TestCase):
    """Verify entity-based alert grouping."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_same_host_correlated(self):
        """Alerts on the same host should be grouped."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(alert_id="A1", hostname="WS-001",
                        timestamp=now.isoformat()),
            _make_alert(alert_id="A2", hostname="WS-001",
                        timestamp=(now + timedelta(minutes=5)).isoformat()),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_count, 2)
        self.assertIn("WS-001", incidents[0].affected_hosts)

    def test_same_user_correlated(self):
        """Alerts for the same user on different hosts should be grouped."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(alert_id="A1", hostname="WS-001", username="admin",
                        timestamp=now.isoformat()),
            _make_alert(alert_id="A2", hostname="WS-002", username="admin",
                        timestamp=(now + timedelta(minutes=5)).isoformat()),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertIn("admin", incidents[0].affected_users)

    def test_same_ip_correlated(self):
        """Alerts sharing an IP address should be grouped."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(alert_id="A1", hostname="WS-001",
                        source_ip="10.0.0.5",
                        timestamp=now.isoformat()),
            _make_alert(alert_id="A2", hostname="WS-002",
                        source_ip="10.0.0.5", username="other",
                        timestamp=(now + timedelta(minutes=5)).isoformat()),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)

    def test_different_entities_separate_incidents(self):
        """Alerts with no shared entities should be separate incidents."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(alert_id="A1", hostname="WS-001", username="user1",
                        source_ip="10.0.0.1",
                        timestamp=now.isoformat()),
            _make_alert(alert_id="A2", hostname="WS-099", username="user99",
                        source_ip="10.0.0.99",
                        timestamp=(now + timedelta(minutes=5)).isoformat()),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 2)


class TestTimeWindowCorrelation(unittest.TestCase):
    """Verify time-window filtering."""

    def setUp(self):
        self.engine = CorrelationEngine(window_minutes=30)

    def test_within_window_correlated(self):
        """Alerts within the window should be in the same incident."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(alert_id="A1", hostname="WS-001",
                        timestamp=now.isoformat()),
            _make_alert(alert_id="A2", hostname="WS-001",
                        timestamp=(now + timedelta(minutes=15)).isoformat()),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_count, 2)

    def test_outside_window_separated(self):
        """Alerts outside the window should be split."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(alert_id="A1", hostname="WS-001",
                        timestamp=now.isoformat()),
            _make_alert(alert_id="A2", hostname="WS-001",
                        timestamp=(now + timedelta(hours=2)).isoformat()),
        ]
        incidents = self.engine.correlate(alerts, window_minutes=30)
        self.assertEqual(len(incidents), 2)


class TestMultiStageDetection(unittest.TestCase):
    """Verify multi-stage attack chain detection."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_multi_stage_detected(self):
        """Alerts spanning multiple MITRE tactics should be flagged multi-stage."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(
                alert_id="A1", hostname="WS-001",
                mitre_technique_id="T1566", mitre_tactic="initial_access",
                timestamp=now.isoformat(),
            ),
            _make_alert(
                alert_id="A2", hostname="WS-001",
                mitre_technique_id="T1059.001", mitre_tactic="execution",
                timestamp=(now + timedelta(minutes=5)).isoformat(),
            ),
            _make_alert(
                alert_id="A3", hostname="WS-001",
                mitre_technique_id="T1053.005", mitre_tactic="persistence",
                timestamp=(now + timedelta(minutes=10)).isoformat(),
            ),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertTrue(incident.is_multi_stage)
        self.assertGreaterEqual(len(incident.attack_stages), 2)
        self.assertIn("initial_access", incident.attack_stages)
        self.assertIn("execution", incident.attack_stages)

    def test_single_tactic_not_multi_stage(self):
        """Alerts from the same MITRE tactic should NOT be multi-stage."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(
                alert_id="A1", hostname="WS-001",
                mitre_tactic="execution",
                timestamp=now.isoformat(),
            ),
            _make_alert(
                alert_id="A2", hostname="WS-001",
                mitre_tactic="execution",
                timestamp=(now + timedelta(minutes=5)).isoformat(),
            ),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertFalse(incidents[0].is_multi_stage)


class TestSeverityEscalation(unittest.TestCase):
    """Verify severity escalation for multi-stage attacks."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_multi_stage_escalates_severity(self):
        """Multi-stage incidents should have escalated severity."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(
                alert_id="A1", hostname="WS-001",
                severity=AlertSeverity.MEDIUM,
                mitre_tactic="initial_access",
                timestamp=now.isoformat(),
            ),
            _make_alert(
                alert_id="A2", hostname="WS-001",
                severity=AlertSeverity.MEDIUM,
                mitre_tactic="execution",
                timestamp=(now + timedelta(minutes=5)).isoformat(),
            ),
        ]
        incidents = self.engine.correlate(alerts)
        # MEDIUM base + multi-stage escalation = HIGH
        self.assertEqual(incidents[0].severity, IncidentSeverity.HIGH)

    def test_critical_not_escalated_beyond_critical(self):
        """Critical severity should not escalate beyond critical."""
        now = datetime.now(timezone.utc)
        alerts = [
            _make_alert(
                alert_id="A1", hostname="WS-001",
                severity=AlertSeverity.CRITICAL,
                mitre_tactic="execution",
                timestamp=now.isoformat(),
            ),
            _make_alert(
                alert_id="A2", hostname="WS-001",
                severity=AlertSeverity.CRITICAL,
                mitre_tactic="impact",
                timestamp=(now + timedelta(minutes=5)).isoformat(),
            ),
        ]
        incidents = self.engine.correlate(alerts)
        self.assertEqual(incidents[0].severity, IncidentSeverity.CRITICAL)


class TestIncidentToTriageBridge(unittest.TestCase):
    """Verify Incident.to_triage_input() produces valid TriageAgent input."""

    def test_triage_input_structure(self):
        now = datetime.now(timezone.utc)
        engine = CorrelationEngine()
        alerts = [
            _make_alert(
                alert_id="A1", hostname="WS-001", username="jdoe",
                source_ip="10.0.0.5",
                timestamp=now.isoformat(),
            ),
        ]
        incidents = engine.correlate(alerts)
        triage_input = incidents[0].to_triage_input()

        self.assertIn("alert", triage_input)
        self.assertIn("context", triage_input)
        self.assertIn("evidence", triage_input)
        self.assertEqual(triage_input["context"]["hostname"], "WS-001")
        self.assertEqual(triage_input["context"]["username"], "jdoe")
        self.assertIsInstance(triage_input["evidence"], list)
        self.assertGreater(len(triage_input["evidence"]), 0)


class TestCorrelationStats(unittest.TestCase):
    """Verify correlation engine statistics."""

    def test_stats_tracking(self):
        engine = CorrelationEngine()
        alerts = [_make_alert(alert_id="A1"), _make_alert(alert_id="A2")]
        engine.correlate(alerts)
        self.assertEqual(engine.stats.alerts_processed, 2)
        self.assertGreater(engine.stats.incidents_created, 0)


class TestFullMultiStageChain(unittest.TestCase):
    """Scenario 12: Full multi-stage attack chain."""

    def test_full_chain(self):
        """Simulate a complete multi-stage attack from initial access to impact."""
        now = datetime.now(timezone.utc)
        engine = CorrelationEngine(window_minutes=60)

        alerts = [
            _make_alert(
                alert_id="A1", title="Phishing email opened",
                hostname="WS-001", username="jdoe",
                severity=AlertSeverity.MEDIUM,
                mitre_technique_id="T1566.001", mitre_tactic="initial_access",
                timestamp=now.isoformat(),
            ),
            _make_alert(
                alert_id="A2", title="Office spawns PowerShell",
                hostname="WS-001", username="jdoe",
                severity=AlertSeverity.CRITICAL,
                mitre_technique_id="T1204.002", mitre_tactic="execution",
                timestamp=(now + timedelta(minutes=2)).isoformat(),
            ),
            _make_alert(
                alert_id="A3", title="Scheduled task created",
                hostname="WS-001", username="jdoe",
                severity=AlertSeverity.HIGH,
                mitre_technique_id="T1053.005", mitre_tactic="persistence",
                timestamp=(now + timedelta(minutes=5)).isoformat(),
            ),
            _make_alert(
                alert_id="A4", title="C2 connection on port 4444",
                hostname="WS-001", username="jdoe",
                severity=AlertSeverity.HIGH,
                mitre_technique_id="T1571", mitre_tactic="command_and_control",
                timestamp=(now + timedelta(minutes=10)).isoformat(),
            ),
            _make_alert(
                alert_id="A5", title="Files encrypted",
                hostname="WS-001", username="jdoe",
                severity=AlertSeverity.CRITICAL,
                mitre_technique_id="T1486", mitre_tactic="impact",
                timestamp=(now + timedelta(minutes=15)).isoformat(),
            ),
        ]

        incidents = engine.correlate(alerts)
        self.assertEqual(len(incidents), 1)

        incident = incidents[0]
        self.assertTrue(incident.is_multi_stage)
        self.assertEqual(incident.alert_count, 5)
        self.assertGreaterEqual(len(incident.attack_stages), 4)
        self.assertEqual(incident.severity, IncidentSeverity.CRITICAL)
        self.assertIn("WS-001", incident.affected_hosts)
        self.assertIn("jdoe", incident.affected_users)
        self.assertIn("Multi-stage", incident.title)


if __name__ == "__main__":
    unittest.main()
