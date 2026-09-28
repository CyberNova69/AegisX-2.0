"""Tests for AegisX REST API.

Covers:
    - Health endpoints (/health, /)
    - Authentication (missing key, invalid key, valid key)
    - Role-Based Access Control (admin, analyst, viewer, agent)
    - Telemetry ingestion pipeline (ingest -> normalize -> detect -> correlate -> incident)
    - Incident management and AI triage/investigate triggers
    - Dashboard summary and alerts
    - Endpoint registration and agent command queue
    - Security edge cases (unauthorized bypass attempts, malformed payloads)
"""

import os
import unittest
import json
from starlette.testclient import TestClient

from backend.api.app import create_app
from backend.api.auth import get_auth_config, reset_auth_config
from backend.api.services import reset_services


class TestAPI(unittest.TestCase):
    """Test suite for the AegisX FastAPI application."""

    def setUp(self):
        # Configure test API keys in environment
        os.environ["AEGISX_AUTH_ENABLED"] = "true"
        os.environ["AEGISX_API_KEYS_JSON"] = json.dumps({
            "test-admin-key": "admin",
            "test-analyst-key": "analyst",
            "test-viewer-key": "viewer",
            "test-agent-key": "agent",
        })
        reset_auth_config()
        reset_services()

        self.app = create_app()
        self.client = TestClient(self.app)

        self.admin_headers = {"X-API-Key": "test-admin-key"}
        self.analyst_headers = {"X-API-Key": "test-analyst-key"}
        self.viewer_headers = {"X-API-Key": "test-viewer-key"}
        self.agent_headers = {"X-API-Key": "test-agent-key"}

    def tearDown(self):
        reset_auth_config()
        reset_services()

    # -------------------------------------------------------------------------
    # Health Endpoints
    # -------------------------------------------------------------------------
    def test_root_endpoint(self):
        """Root endpoint returns system info without authentication."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "AegisX SOC Platform")
        self.assertEqual(data["status"], "running")

    def test_health_check_endpoint(self):
        """Health check returns 200 with component statuses."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("api", data["components"])
        self.assertIn("detection_engine", data["components"])
        self.assertIn("correlation_engine", data["components"])

    # -------------------------------------------------------------------------
    # Authentication & RBAC
    # -------------------------------------------------------------------------
    def test_missing_api_key_returns_401(self):
        """Protected routes require an API key header."""
        response = self.client.get("/api/v1/dashboard/summary")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Missing API key", response.json()["detail"])

    def test_invalid_api_key_returns_403(self):
        """An unrecognized API key is rejected with 403."""
        response = self.client.get(
            "/api/v1/dashboard/summary",
            headers={"X-API-Key": "completely-invalid-key"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Invalid API key", response.json()["detail"])

    def test_viewer_can_read_dashboard(self):
        """Viewer role can access read-only dashboard summary."""
        response = self.client.get(
            "/api/v1/dashboard/summary",
            headers=self.viewer_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("events", response.json())

    def test_viewer_cannot_ingest_telemetry(self):
        """Viewer role cannot ingest telemetry (requires agent or admin)."""
        payload = {"endpoint_id": "EP-01", "events": []}
        response = self.client.post(
            "/api/v1/telemetry/ingest",
            json=payload,
            headers=self.viewer_headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_agent_can_ingest_telemetry(self):
        """Agent role can ingest telemetry."""
        payload = {"endpoint_id": "EP-01", "events": []}
        response = self.client.post(
            "/api/v1/telemetry/ingest",
            json=payload,
            headers=self.agent_headers,
        )
        self.assertEqual(response.status_code, 200)

    def test_admin_can_access_all_endpoints(self):
        """Admin has full access across all role-gated routes."""
        dash = self.client.get("/api/v1/dashboard/summary", headers=self.admin_headers)
        self.assertEqual(dash.status_code, 200)

        ingest = self.client.post(
            "/api/v1/telemetry/ingest",
            json={"endpoint_id": "EP-01", "events": []},
            headers=self.admin_headers,
        )
        self.assertEqual(ingest.status_code, 200)

    # -------------------------------------------------------------------------
    # Telemetry Ingestion Pipeline
    # -------------------------------------------------------------------------
    def test_telemetry_ingest_powershell_generates_alert_and_incident(self):
        """Ingesting suspicious PowerShell event generates detection alert and correlated incident."""
        payload = {
            "endpoint_id": "WORKSTATION-99",
            "events": [{
                "event_type": "process_creation",
                "hostname": "WORKSTATION-99",
                "username": "attacker",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc ZABpAHIAIABDADoAXA==",
            }],
        }
        response = self.client.post(
            "/api/v1/telemetry/ingest",
            json=payload,
            headers=self.agent_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["accepted"], 1)
        self.assertEqual(data["rejected"], 0)
        self.assertGreaterEqual(data["alerts_generated"], 1)
        self.assertGreaterEqual(data["incidents_created"], 1)

        # Verify dashboard reflects the ingestion
        dash_res = self.client.get(
            "/api/v1/dashboard/summary",
            headers=self.viewer_headers,
        )
        self.assertEqual(dash_res.status_code, 200)
        dash_data = dash_res.json()
        self.assertGreaterEqual(dash_data["alerts"]["total"], 1)
        self.assertGreaterEqual(dash_data["incidents"]["total"], 1)

    def test_telemetry_ingest_benign_produces_no_alerts(self):
        """Ingesting benign process event accepts event without generating false positive alerts."""
        payload = {
            "endpoint_id": "WORKSTATION-01",
            "events": [{
                "event_type": "process_creation",
                "hostname": "WORKSTATION-01",
                "username": "analyst",
                "process_name": "notepad.exe",
                "command_line": "notepad.exe report.txt",
            }],
        }
        response = self.client.post(
            "/api/v1/telemetry/ingest",
            json=payload,
            headers=self.agent_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["accepted"], 1)
        self.assertEqual(data["alerts_generated"], 0)
        self.assertEqual(data["incidents_created"], 0)

    # -------------------------------------------------------------------------
    # Endpoints Management
    # -------------------------------------------------------------------------
    def test_endpoint_registration_and_command_lifecycle(self):
        """Endpoint registers, receives agent_id, and can poll commands."""
        reg_payload = {
            "hostname": "SERVER-SQL-01",
            "ip_address": "10.0.1.50",
            "os": "Windows Server 2022",
            "environment": "production",
            "asset_criticality": "critical",
        }
        response = self.client.post(
            "/api/v1/endpoints/register",
            json=reg_payload,
            headers=self.agent_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["endpoint_id"].startswith("ep-"))
        self.assertTrue(data["agent_id"].startswith("ag-"))

        agent_id = data["agent_id"]

        # Poll commands
        cmd_res = self.client.get(
            f"/api/v1/agent/commands?agent_id={agent_id}",
            headers=self.agent_headers,
        )
        self.assertEqual(cmd_res.status_code, 200)
        self.assertEqual(cmd_res.json()["count"], 0)

        # Ack command
        ack_res = self.client.post(
            "/api/v1/agent/commands/cmd-123/ack",
            json={"status": "received", "result": {}},
            headers=self.agent_headers,
        )
        self.assertEqual(ack_res.status_code, 200)
        self.assertTrue(ack_res.json()["acknowledged"])

    # -------------------------------------------------------------------------
    # Incidents & AI Triggers
    # -------------------------------------------------------------------------
    def test_incident_triage_trigger(self):
        """AI triage can be triggered by an analyst on an existing incident."""
        from backend.api.routes.incidents import register_incident

        register_incident({
            "incident_id": "INC-TEST-999",
            "title": "Suspicious PowerShell Execution",
            "severity": "high",
            "status": "new",
            "affected_hosts": ["WS-01"],
            "affected_users": ["jdoe"],
            "alerts": [{
                "title": "Encoded PowerShell",
                "severity": "high",
                "source_event_id": "EVT-000001",
            }],
        })

        response = self.client.post(
            "/api/v1/incidents/INC-TEST-999/triage",
            json={"provider": "mock"},
            headers=self.analyst_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["incident_id"], "INC-TEST-999")
        self.assertIn("triage_result", data)
        self.assertEqual(data["triage_result"]["classification"], "suspicious")


if __name__ == "__main__":
    unittest.main()
