"""Tests for Phase 2 Productization: JWT Authentication, Dynamic Dashboard, and Audit/Trace Stores.

Covers:
    - Zero-dependency RFC 7519 HMAC-SHA256 JWT encoding and decoding
    - Expiration and tamper-resistance verification
    - Dual-mode authentication (Bearer JWT and X-API-Key)
    - Auth endpoints (POST /api/v1/auth/login, GET /api/v1/auth/me)
    - Dynamic dashboard statistics and database health status
    - Dashboard traces and audit log endpoints
    - Automated audit and trace persistence during SOC workflow and incident actions
"""

import os
import time
import unittest
from unittest.mock import MagicMock

try:
    from fastapi.testclient import TestClient
    from backend.api.app import create_app

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from backend.api.auth import (
    Role,
    create_access_token,
    decode_access_token,
    get_auth_config,
    reset_auth_config,
    authenticate_user,
)
from backend.api.services import (
    get_services,
    reset_services,
    InMemoryAuditStore,
    PostgresAuditStore,
    InMemoryTraceStore,
    PostgresTraceStore,
)


class TestJWTMechanisms(unittest.TestCase):
    """Test standard library RFC 7519 HMAC-SHA256 JWT implementation."""

    def setUp(self):
        reset_auth_config()
        os.environ["AEGISX_JWT_SECRET"] = "test-jwt-secret-key-12345"
        os.environ["AEGISX_JWT_EXPIRY_SECONDS"] = "3600"

    def tearDown(self):
        reset_auth_config()

    def test_jwt_create_and_decode_valid_token(self):
        """Token can be created and successfully decoded."""
        payload = {"sub": "usr-test-001", "role": "analyst", "username": "analyst_bob"}
        token = create_access_token(payload)

        self.assertIsInstance(token, str)
        self.assertEqual(len(token.split(".")), 3)

        decoded = decode_access_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["sub"], "usr-test-001")
        self.assertEqual(decoded["role"], "analyst")
        self.assertEqual(decoded["username"], "analyst_bob")
        self.assertIn("exp", decoded)
        self.assertIn("iat", decoded)

    def test_jwt_tampered_payload_rejected(self):
        """Tampered payload fails HMAC signature verification."""
        token = create_access_token({"sub": "usr-01", "role": "viewer"})
        parts = token.split(".")

        # Tamper payload part
        tampered_token = f"{parts[0]}.eyJyZXBsYWNlZCI6ICJ0cnVlIn0.{parts[2]}"
        decoded = decode_access_token(tampered_token)
        self.assertIsNone(decoded)

    def test_jwt_tampered_signature_rejected(self):
        """Tampered signature fails verification."""
        token = create_access_token({"sub": "usr-01", "role": "viewer"})
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}.badsignature=="
        decoded = decode_access_token(tampered_token)
        self.assertIsNone(decoded)

    def test_jwt_expired_token_rejected(self):
        """Expired token returns None on decode."""
        payload = {"sub": "usr-01", "role": "viewer"}
        token = create_access_token(payload, expires_in_seconds=-10)
        decoded = decode_access_token(token)
        self.assertIsNone(decoded)

    def test_jwt_different_secret_rejected(self):
        """Token encoded with different secret is rejected."""
        token = create_access_token({"sub": "usr-01"}, secret="secret-A")
        decoded = decode_access_token(token, secret="secret-B")
        self.assertIsNone(decoded)

    def test_user_authentication_helper(self):
        """Default user directory authenticates known test users."""
        admin_rec = authenticate_user("admin", "adminpassword")
        self.assertIsNotNone(admin_rec)
        self.assertEqual(admin_rec["role"], Role.ADMIN)

        bad_rec = authenticate_user("admin", "wrongpassword")
        self.assertIsNone(bad_rec)

        unknown_rec = authenticate_user("nonexistent", "pwd")
        self.assertIsNone(unknown_rec)


class TestDualAuthAndRoutes(unittest.TestCase):
    """Test API authentication via Bearer tokens and API keys."""

    @classmethod
    def setUpClass(cls):
        if not HAS_FASTAPI:
            raise unittest.SkipTest("FastAPI not installed")

        os.environ["AEGISX_AUTH_ENABLED"] = "true"
        os.environ["AEGISX_API_KEYS_JSON"] = (
            '{"key-admin": "admin", "key-analyst": "analyst", "key-viewer": "viewer"}'
        )
        os.environ["AEGISX_JWT_SECRET"] = "soc-integration-test-secret"
        reset_auth_config()
        reset_services()

        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        reset_auth_config()
        reset_services()

    def test_login_with_valid_credentials(self):
        """POST /auth/login returns JWT bearer token for valid user."""
        res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analystpassword"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["role"], "analyst")
        self.assertEqual(data["user"]["username"], "analyst")

    def test_login_with_invalid_credentials(self):
        """POST /auth/login rejects invalid credentials with 401."""
        res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "wrong"})
        self.assertEqual(res.status_code, 401)

    def test_login_with_api_key_exchange(self):
        """POST /auth/login exchanges valid API key for session token."""
        res = self.client.post("/api/v1/auth/login", json={"api_key": "key-admin"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["role"], "admin")
        self.assertIn("access_token", data)

    def test_bearer_token_accesses_protected_route(self):
        """Requests with Authorization: Bearer <token> succeed and pass RBAC."""
        # 1. Obtain token
        login_res = self.client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewerpassword"})
        token = login_res.json()["access_token"]

        # 2. Access dashboard with Bearer token
        headers = {"Authorization": f"Bearer {token}"}
        dash_res = self.client.get("/api/v1/dashboard/summary", headers=headers)
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn("events", dash_res.json())

        # 3. Check /auth/me
        me_res = self.client.get("/api/v1/auth/me", headers=headers)
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["user"]["role"], "viewer")

    def test_bearer_token_insufficient_role_forbidden(self):
        """Viewer Bearer token cannot access analyst-only endpoints."""
        login_res = self.client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewerpassword"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Attempt to trigger triage with viewer token
        res = self.client.post("/api/v1/incidents/INC-001/triage", json={}, headers=headers)
        self.assertEqual(res.status_code, 403)

    def test_invalid_bearer_token_returns_401(self):
        """Tampered or invalid Bearer token returns 401."""
        res = self.client.get(
            "/api/v1/dashboard/summary",
            headers={"Authorization": "Bearer not.a.real.token"},
        )
        self.assertEqual(res.status_code, 401)


class TestDashboardAndAuditPersistence(unittest.TestCase):
    """Test dynamic dashboard status, trace recording, and audit log persistence."""

    @classmethod
    def setUpClass(cls):
        if not HAS_FASTAPI:
            raise unittest.SkipTest("FastAPI not installed")

        os.environ["AEGISX_AUTH_ENABLED"] = "true"
        os.environ["AEGISX_API_KEYS_JSON"] = '{"key-admin": "admin", "key-viewer": "viewer"}'
        reset_auth_config()
        reset_services()

        cls.app = create_app()
        cls.client = TestClient(cls.app)
        cls.admin_headers = {"X-API-Key": "key-admin"}

    def test_health_check_dynamic_database_status(self):
        """Health check returns database component status."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["components"]["database"], "not_configured")

    def test_dashboard_summary_dynamic_system_status(self):
        """Dashboard summary dynamically evaluates database connectivity and store stats."""
        res = self.client.get("/api/v1/dashboard/summary", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["system"]["database"], "not_connected")
        self.assertIn("audit_logs_recorded", data["system"])
        self.assertIn("agent_traces_recorded", data["system"])

    def test_dashboard_traces_and_audit_endpoints(self):
        """GET /dashboard/traces and GET /dashboard/audit-logs return structured records."""
        services = get_services()
        # Seed test audit log and trace
        services.audit_store.add(
            action="test_action",
            user_id="usr-test",
            resource_type="endpoint",
            resource_id="ep-123",
            details={"foo": "bar"},
        )
        services.trace_store.add(
            agent_type="TriageAgent",
            incident_id="INC-TEST",
            model="mock",
            provider="mock",
            latency_ms=12.5,
            structured_output={"verdict": "benign"},
        )

        trace_res = self.client.get("/api/v1/dashboard/traces", headers=self.admin_headers)
        self.assertEqual(trace_res.status_code, 200)
        trace_data = trace_res.json()
        self.assertGreaterEqual(trace_data["total"], 1)
        self.assertEqual(trace_data["traces"][0]["agent_type"], "TriageAgent")

        audit_res = self.client.get("/api/v1/dashboard/audit-logs", headers=self.admin_headers)
        self.assertEqual(audit_res.status_code, 200)
        audit_data = audit_res.json()
        self.assertGreaterEqual(audit_data["total"], 1)
        self.assertEqual(audit_data["audit_logs"][0]["action"], "test_action")

    def test_soc_workflow_records_automated_traces_and_audit(self):
        """Executing SOCWorkflow automatically records step traces and audit logs."""
        from ai.orchestration.workflow import SOCWorkflow
        from tests.test_orchestration import _make_mock_client, _sample_incident

        services = get_services()
        initial_trace_count = services.trace_store.count
        initial_audit_count = services.audit_store.count

        workflow = SOCWorkflow(
            llm_client=_make_mock_client(),
            max_investigation_steps=2,
            enable_threat_intel=False,
        )

        incident_data = _sample_incident()
        incident_data["incident_id"] = "INC-TRACE-TEST-001"

        result = workflow.run(incident_data)
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.requires_human_approval)

        # Traces recorded for triage and investigation
        self.assertGreater(services.trace_store.count, initial_trace_count)
        # Workflow execution audit log recorded
        self.assertGreater(services.audit_store.count, initial_audit_count)


class TestDualModeStores(unittest.TestCase):
    """Test InMemory and PostgreSQL store implementations."""

    def test_in_memory_audit_and_trace_stores(self):
        """In-memory audit and trace stores support bounded FIFO collection and filtering."""
        audit_store = InMemoryAuditStore()
        log1 = audit_store.add("login", user_id="usr-1", resource_type="auth")
        log2 = audit_store.add("isolate_host", user_id="usr-1", resource_type="endpoint")

        self.assertEqual(audit_store.count, 2)
        logs, total = audit_store.list_logs(action="login")
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["log_id"], log1["log_id"])

        trace_store = InMemoryTraceStore()
        t1 = trace_store.add("TriageAgent", incident_id="INC-1")
        t2 = trace_store.add("InvestigationAgent", incident_id="INC-1")

        self.assertEqual(trace_store.count, 2)
        traces, total = trace_store.list_traces(agent_type="InvestigationAgent")
        self.assertEqual(total, 1)
        self.assertEqual(traces[0]["trace_id"], t2["trace_id"])

    def test_postgres_audit_and_trace_stores_with_mock_pool(self):
        """Postgres audit and trace stores execute parameterized SQL queries when initialized."""
        mock_pool = MagicMock()
        mock_pool.is_initialized = True
        mock_pool.execute_sync = MagicMock(return_value="")

        pg_audit = PostgresAuditStore(mock_pool)
        pg_audit.add("block_ip", user_id="usr-2", resource_type="firewall", resource_id="fw-01")
        mock_pool.execute_sync.assert_called_once()
        self.assertIn("INSERT INTO audit_logs", mock_pool.execute_sync.call_args[0][0])

        mock_pool.reset_mock()
        pg_trace = PostgresTraceStore(mock_pool)
        pg_trace.add("ThreatIntelAgent", incident_id="INC-2", model="mock", latency_ms=45.0)
        mock_pool.execute_sync.assert_called_once()
        self.assertIn("INSERT INTO agent_traces", mock_pool.execute_sync.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
