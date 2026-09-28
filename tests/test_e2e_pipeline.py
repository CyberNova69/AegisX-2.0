"""AegisX Full End-to-End Pipeline Integration Test Suite.

Traces complete flow:
    Synthetic controlled telemetry
        ↓
    REST API (/api/v1/telemetry/ingest)
        ↓
    Canonicalization (CanonicalEvent)
        ↓
    Normalization & Validation (EventProcessor -> NormalizedEvent)
        ↓
    Detection Engine (rules AX-RULE-001 to AX-RULE-010)
        ↓
    Alert Generation & Provenance
        ↓
    Correlation Engine (temporal + entity grouping)
        ↓
    Incident Creation & Stage Progression
        ↓
    AI Triage (TriageAgent advisory assessment)
        ↓
    AI Investigation (InvestigationAgent bounded loop)
        ↓
    Threat Intelligence & MITRE Context (ThreatIntelAgent + RAGService)
        ↓
    Response Recommendations (Advisory only)
        ↓
    Human Approval Required (requires_human_approval = True)

Scenarios Tested:
    SC-001: Encoded PowerShell execution (T1059.001)
    SC-002: Brute-force authentication (T1110)
    SC-003: Login anomaly / impossible travel (T1078)
    SC-004: Scheduled task persistence (T1053.005)
    SC-005: Office to shell execution (T1204.002)
    SC-006: Suspicious outbound communication (T1571 / C2)
    SC-007: Ransomware file modification fixture (T1486)
    SC-008: Authorized vulnerability scanner hard negative (no alert)
    SC-009: Approved deployment hard negative (no alert)
    SC-010: Multi-stage attack chain (multi-stage correlation + escalation)
"""

import os
import json
import unittest
from starlette.testclient import TestClient

from backend.api.app import create_app
from backend.api.auth import reset_auth_config
from backend.api.services import reset_services, get_services
from ai.orchestration.workflow import SOCWorkflow
from ai.llm import LLMClient


class TestE2EPipeline(unittest.TestCase):
    """End-to-end integration tests for all 10 controlled SOC scenarios."""

    def setUp(self):
        os.environ["AEGISX_AUTH_ENABLED"] = "true"
        os.environ["AEGISX_API_KEY"] = "test-e2e-api-key"
        os.environ["AEGISX_API_KEY_ROLE"] = "admin"
        reset_auth_config()
        reset_services()

        self.app = create_app()
        self.client = TestClient(self.app)
        self.headers = {"X-API-Key": "test-e2e-api-key"}
        self.workflow = SOCWorkflow(llm_client=LLMClient.from_mock(), enable_rag=True)

    def tearDown(self):
        reset_auth_config()
        reset_services()

    # -------------------------------------------------------------------------
    # SC-001: Encoded PowerShell Execution (T1059.001)
    # -------------------------------------------------------------------------
    def test_sc001_powershell_execution(self):
        """SC-001: Encoded PowerShell execution detected with MITRE T1059.001."""
        payload = {
            "endpoint_id": "WS-FIN-01",
            "events": [{
                "event_type": "process_creation",
                "hostname": "WS-FIN-01",
                "username": "fin_user",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["accepted"], 1)
        self.assertEqual(data["alerts_generated"], 1)

        services = get_services()
        alert = services.alert_store.list_recent()[0]
        self.assertEqual(alert.mitre_technique_id, "T1059.001")
        self.assertEqual(alert.rule_id, "AX-RULE-001")

        # Trace through workflow
        incident = services.incident_store.list_all()[0][0]
        wf_result = self.workflow.run(incident)
        self.assertEqual(wf_result.status, "completed")
        self.assertTrue(wf_result.requires_human_approval)
        self.assertIsNotNone(wf_result.rag_context)

    # -------------------------------------------------------------------------
    # SC-002: Brute-Force Authentication (T1110)
    # -------------------------------------------------------------------------
    def test_sc002_brute_force_authentication(self):
        """SC-002: Brute-force auth failures detected with MITRE T1110."""
        payload = {
            "endpoint_id": "AUTH-SRV-01",
            "events": [{
                "event_type": "authentication",
                "hostname": "AUTH-SRV-01",
                "username": "administrator",
                "source_ip": "198.51.100.25",
                "attributes": {"status": "failure", "failure_count": 12, "reason": "bad_password"},
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["alerts_generated"], 1)

        services = get_services()
        alert = services.alert_store.list_recent()[0]
        self.assertEqual(alert.mitre_technique_id, "T1110")
        self.assertEqual(alert.rule_id, "AX-RULE-002")

    # -------------------------------------------------------------------------
    # SC-003: Login Anomaly / Impossible Travel (T1078)
    # -------------------------------------------------------------------------
    def test_sc003_login_anomaly(self):
        """SC-003: Impossible travel anomaly detected with MITRE T1078."""
        payload = {
            "endpoint_id": "VPN-GW-01",
            "events": [{
                "event_type": "authentication",
                "hostname": "VPN-GW-01",
                "username": "executive_user",
                "source_ip": "203.0.113.88",
                "attributes": {"impossible_travel": True, "city_a": "New York", "city_b": "London", "time_delta_min": 15},
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["alerts_generated"], 1)

        services = get_services()
        alert = services.alert_store.list_recent()[0]
        self.assertEqual(alert.mitre_technique_id, "T1078")
        self.assertEqual(alert.rule_id, "AX-RULE-003")

    # -------------------------------------------------------------------------
    # SC-004: Scheduled Task Persistence (T1053.005)
    # -------------------------------------------------------------------------
    def test_sc004_scheduled_task_persistence(self):
        """SC-004: Persistence creation via schtasks detected with MITRE T1053.005."""
        payload = {
            "endpoint_id": "WS-ENG-03",
            "events": [{
                "event_type": "process_creation",
                "hostname": "WS-ENG-03",
                "username": "system",
                "process_name": "schtasks.exe",
                "command_line": "schtasks /create /tn Updates /tr C:\\Users\\Public\\updater.exe /sc onlogon",
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["alerts_generated"], 1)

        services = get_services()
        alert = services.alert_store.list_recent()[0]
        self.assertEqual(alert.mitre_technique_id, "T1053.005")
        self.assertEqual(alert.rule_id, "AX-RULE-004")

    # -------------------------------------------------------------------------
    # SC-005: Office to Shell Execution (T1204.002)
    # -------------------------------------------------------------------------
    def test_sc005_office_shell_chain(self):
        """SC-005: Word spawning cmd/powershell detected with MITRE T1204.002."""
        payload = {
            "endpoint_id": "WS-EXEC-01",
            "events": [{
                "event_type": "process_creation",
                "hostname": "WS-EXEC-01",
                "username": "executive",
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c whoami",
                "attributes": {"parent_process_name": "winword.exe"},
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["alerts_generated"], 1)

        services = get_services()
        alert = services.alert_store.list_recent()[0]
        self.assertEqual(alert.mitre_technique_id, "T1204.002")
        self.assertEqual(alert.rule_id, "AX-RULE-005")

    # -------------------------------------------------------------------------
    # SC-006: Suspicious Outbound C2 (T1571)
    # -------------------------------------------------------------------------
    def test_sc006_suspicious_outbound_c2(self):
        """SC-006: Outbound connection to C2 port detected with MITRE T1571."""
        payload = {
            "endpoint_id": "WS-HR-02",
            "events": [{
                "event_type": "network_connection",
                "hostname": "WS-HR-02",
                "dest_ip": "198.51.100.99",
                "dest_port": 4444,
                "protocol": "tcp",
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["alerts_generated"], 1)

        services = get_services()
        alert = services.alert_store.list_recent()[0]
        self.assertEqual(alert.mitre_technique_id, "T1571")
        self.assertEqual(alert.rule_id, "AX-RULE-006")

    # -------------------------------------------------------------------------
    # SC-007: Ransomware File Modification (T1486)
    # -------------------------------------------------------------------------
    def test_sc007_ransomware_activity(self):
        """SC-007: Bulk encrypted extensions or ransom note detected with MITRE T1486."""
        payload = {
            "endpoint_id": "FILE-SRV-01",
            "events": [{
                "event_type": "file_modification",
                "hostname": "FILE-SRV-01",
                "file_path": "D:\\Shares\\Finance\\Q3_Report.xlsx.locked",
                "attributes": {"extension": ".locked", "modification_type": "rename"},
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["alerts_generated"], 1)

        services = get_services()
        alert = services.alert_store.list_recent()[0]
        self.assertEqual(alert.mitre_technique_id, "T1486")
        self.assertEqual(alert.rule_id, "AX-RULE-007")

    # -------------------------------------------------------------------------
    # SC-008: Authorized Vulnerability Scanner (Hard Negative)
    # -------------------------------------------------------------------------
    def test_sc008_authorized_scanner_hard_negative(self):
        """SC-008: Authorized security scanner traffic produces no alerts."""
        payload = {
            "endpoint_id": "SEC-SCAN-01",
            "events": [{
                "event_type": "network_connection",
                "hostname": "SEC-SCAN-01",
                "dest_ip": "10.0.0.50",
                "dest_port": 4444,
                "protocol": "tcp",
                "attributes": {"authorized_scanner": True, "scanner_id": "qualys-internal"},
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["accepted"], 1)
        self.assertEqual(res.json()["alerts_generated"], 0)

    # -------------------------------------------------------------------------
    # SC-009: Approved Deployment (Hard Negative)
    # -------------------------------------------------------------------------
    def test_sc009_approved_deployment_hard_negative(self):
        """SC-009: Approved administrative PowerShell cmdlets produce no false positive alerts."""
        payload = {
            "endpoint_id": "OPS-MGMT-01",
            "events": [{
                "event_type": "process_creation",
                "hostname": "OPS-MGMT-01",
                "username": "svc_ansible",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -Command Get-Service -Name W3SVC | Restart-Service",
                "attributes": {"approved_deployment": True, "change_ticket": "CHG-10492"},
            }],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["accepted"], 1)
        self.assertEqual(res.json()["alerts_generated"], 0)

    # -------------------------------------------------------------------------
    # SC-010: Multi-Stage Attack Chain (Correlation & Escalation)
    # -------------------------------------------------------------------------
    def test_sc010_multistage_attack_chain(self):
        """SC-010: Multi-stage attack chain correlates alerts and detects stage progression."""
        # Multi-stage sequence on target host TARGET-SRV:
        # Stage 1: Brute force login
        # Stage 2: Suspicious PowerShell execution
        # Stage 3: Persistence via scheduled task
        payload = {
            "endpoint_id": "TARGET-SRV",
            "events": [
                {
                    "event_type": "authentication",
                    "hostname": "TARGET-SRV",
                    "username": "victim_user",
                    "source_ip": "198.51.100.77",
                    "attributes": {"status": "failure", "failure_count": 8},
                },
                {
                    "event_type": "process_creation",
                    "hostname": "TARGET-SRV",
                    "username": "victim_user",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -enc ZABpAHIAIABDADoAXA==",
                },
                {
                    "event_type": "process_creation",
                    "hostname": "TARGET-SRV",
                    "username": "victim_user",
                    "process_name": "schtasks.exe",
                    "command_line": "schtasks /create /tn Backdoor /tr cmd.exe /sc minute",
                },
            ],
        }
        res = self.client.post("/api/v1/telemetry/ingest", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["accepted"], 3)
        self.assertGreaterEqual(data["alerts_generated"], 2)
        self.assertGreaterEqual(data["incidents_created"], 1)

        # Inspect correlated incident
        services = get_services()
        incidents, _ = services.incident_store.list_all()
        target_incident = [i for i in incidents if any(h.lower() == "target-srv" for h in i.affected_hosts)][0]

        # Multi-stage progression verification
        self.assertTrue(target_incident.is_multi_stage)
        self.assertGreaterEqual(len(target_incident.attack_stages), 2)
        self.assertIn(target_incident.severity.value, ("high", "critical"))

        # Run multi-stage incident through full SOCWorkflow
        wf_result = self.workflow.run(target_incident)
        self.assertEqual(wf_result.status, "completed")
        self.assertTrue(wf_result.requires_human_approval)
        self.assertGreaterEqual(len(wf_result.steps), 3)
        self.assertIsNotNone(wf_result.triage_result)
        self.assertIsNotNone(wf_result.investigation_result)
        self.assertIsNotNone(wf_result.threat_intel_result)


if __name__ == "__main__":
    unittest.main()
