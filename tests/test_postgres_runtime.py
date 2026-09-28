"""AegisX PostgreSQL Runtime & Dual-Mode Persistence Tests.

Verifies:
    1. DatabaseConfig environment parsing, DSN format, and credential security.
    2. DatabasePool connection management, query execution (async & sync), and graceful fallback.
    3. MigrationRunner 25 core schema table verification, schema_migrations tracking, and seeders.
    4. Dual-mode event, alert, and incident stores (in-memory + PostgreSQL).
    5. DB-backed investigation tools with active database execution and seamless synthetic fallback.
    6. DatabaseThreatIntelProvider lookup, search, and fallback to synthetic provider.
    7. Telemetry ingestion event persistence into event_store.
"""

import os
import json
import pytest
from unittest.mock import MagicMock, AsyncMock

from backend.database.connection import DatabaseConfig, DatabasePool, get_db_pool, reset_db_pool
from backend.database.migrations import MigrationRunner, CORE_SCHEMA_TABLES
from backend.api.services import (
    AppServices,
    InMemoryEventStore,
    PostgresEventStore,
    InMemoryAlertStore,
    PostgresAlertStore,
    InMemoryIncidentStore,
    PostgresIncidentStore,
    get_services,
    reset_services,
)
from backend.detection.models import Alert, AlertSeverity
from backend.correlation.models import Incident, IncidentSeverity
from ai.tools.db_tools import (
    DBProcessActivityTool,
    DBNetworkActivityTool,
    DBAuthenticationTool,
    DBFileActivityTool,
    DBRelatedAlertsTool,
)
from ai.tools.ti_providers import (
    DatabaseThreatIntelProvider,
    SyntheticThreatIntelProvider,
    get_threat_intel_provider,
    reset_threat_intel_provider,
)


class TestDatabaseConfig:
    """Test connection configuration logic."""

    def test_default_config(self):
        cfg = DatabaseConfig()
        assert cfg.port == 5432
        assert cfg.database == "aegisx"
        assert cfg.ssl_mode == "prefer"
        assert cfg.statement_timeout_ms == 30000
        assert not cfg.is_configured

    def test_from_env_configured(self, monkeypatch):
        monkeypatch.setenv("AEGISX_DB_HOST", "db.example.com")
        monkeypatch.setenv("AEGISX_DB_PORT", "5433")
        monkeypatch.setenv("AEGISX_DB_NAME", "aegisx_prod")
        monkeypatch.setenv("AEGISX_DB_USER", "aegis_admin")
        monkeypatch.setenv("AEGISX_DB_PASSWORD", "supersecret123")

        cfg = DatabaseConfig.from_env()
        assert cfg.host == "db.example.com"
        assert cfg.port == 5433
        assert cfg.database == "aegisx_prod"
        assert cfg.user == "aegis_admin"
        assert cfg.is_configured
        assert "supersecret123" in cfg.dsn
        assert "supersecret123" not in str(cfg.to_dict())  # No secrets leaked in dictionary


class TestDatabasePool:
    """Test DatabasePool initialization, query dispatch, and graceful fallback."""

    def setup_method(self):
        reset_db_pool()

    def teardown_method(self):
        reset_db_pool()

    def test_offline_initialization_graceful_degradation(self):
        import asyncio

        async def _run():
            cfg = DatabaseConfig(host="", user="")  # Unconfigured
            pool = DatabasePool(cfg)
            assert not pool.is_initialized
            success = await pool.initialize()
            assert not success
            assert not pool.is_initialized

            # Health check reflects disconnected state
            health = await pool.health_check()
            assert health["status"] == "disconnected"
            assert not health["configured"]

        asyncio.run(_run())

    def test_mock_pool_async_and_sync_queries(self):
        import asyncio

        async def _run():
            # Create a mock asyncpg pool
            mock_raw_pool = MagicMock()
            mock_conn = AsyncMock()
            mock_conn.fetch.return_value = [{"id": 1, "val": "test"}]
            mock_conn.fetchrow.return_value = {"id": 1, "val": "test"}
            mock_conn.fetchval.return_value = 42
            mock_conn.execute.return_value = "INSERT 0 1"

            # Context manager on mock_raw_pool.acquire()
            mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
            mock_raw_pool.acquire.return_value.__aexit__.return_value = None

            pool = DatabasePool(pool_instance=mock_raw_pool)
            assert pool.is_initialized

            # Async query methods
            rows = await pool.fetch("SELECT * FROM test")
            assert len(rows) == 1
            assert rows[0]["val"] == "test"

            row = await pool.fetchrow("SELECT * FROM test WHERE id = $1", 1)
            assert row["id"] == 1

            val = await pool.fetchval("SELECT COUNT(*) FROM test")
            assert val == 42

            res = await pool.execute("INSERT INTO test VALUES ($1)", 2)
            assert res == "INSERT 0 1"

            # Synchronous query methods
            rows_sync = pool.fetch_sync("SELECT * FROM test")
            assert len(rows_sync) == 1

            row_sync = pool.fetchrow_sync("SELECT * FROM test WHERE id = $1", 1)
            assert row_sync["id"] == 1

            val_sync = pool.fetchval_sync("SELECT COUNT(*) FROM test")
            assert val_sync == 42

            res_sync = pool.execute_sync("INSERT INTO test VALUES ($1)", 2)
            assert res_sync == "INSERT 0 1"

        asyncio.run(_run())

    def test_singleton_management(self):
        p1 = get_db_pool()
        p2 = get_db_pool()
        assert p1 is p2
        reset_db_pool()
        p3 = get_db_pool()
        assert p1 is not p3


class TestMigrationRunner:
    """Test database schema verification and migration runner."""

    def test_core_tables_authoritative_count(self):
        runner = MigrationRunner()
        assert len(runner.get_core_tables()) == 25
        assert set(runner.get_core_tables()) == set(CORE_SCHEMA_TABLES)

    def test_schema_sql_verification(self):
        runner = MigrationRunner()
        verification = runner.verify_table_count()
        assert verification["verified"] is True
        assert verification["table_count"] == 25
        assert verification["expected"] == 25

    def test_in_memory_migration_execution(self):
        runner = MigrationRunner()
        res = runner.apply_migrations_sync(pool=None)
        assert res["success"] is True
        assert res["mode"] == "in_memory"
        assert "001_initial_schema" in res["applied"]

        status = runner.status()
        assert status["schema_tables_verified"] is True
        assert status["applied_count"] == 1
        assert status["applied_migrations"][0]["version"] == "001_initial_schema"

    def test_mock_postgresql_migration_and_seed(self):
        import asyncio

        async def _run():
            mock_raw_pool = MagicMock()
            mock_conn = AsyncMock()
            # First check returns None (migration not applied yet)
            mock_conn.fetchrow.return_value = None
            mock_conn.execute.return_value = "CREATE TABLE"

            mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
            mock_raw_pool.acquire.return_value.__aexit__.return_value = None

            pool = DatabasePool(pool_instance=mock_raw_pool)
            runner = MigrationRunner()

            res = await runner.apply_migrations(pool=pool)
            assert res["success"] is True
            assert res["mode"] == "postgresql"
            assert "001_initial_schema" in res["applied"]
            assert res["seeded"]["users"] >= 3
            assert res["seeded"]["tactics"] >= 10
            assert res["seeded"]["threat_intel"] >= 5

        asyncio.run(_run())


class TestDualModeStores:
    """Test in-memory and PostgreSQL dual-mode stores."""

    def setup_method(self):
        reset_services()

    def teardown_method(self):
        reset_services()

    def test_in_memory_event_store(self):
        store = InMemoryEventStore()
        event = {"event_id": "tel-12345", "event_type": "process_creation", "hostname": "HOST-01"}
        store.add(event)
        assert store.count == 1
        assert store.get("tel-12345")["hostname"] == "HOST-01"
        assert len(store.list_recent()) == 1

    def test_in_memory_alert_and_incident_stores(self):
        services = get_services()
        assert not services.is_db_available

        alert = Alert(
            alert_id="ALT-TEST-001",
            title="Suspicious PowerShell Command",
            severity=AlertSeverity.HIGH,
            rule_id="RULE-001",
            rule_name="PowerShell Obfuscation",
            hostname="HOST-01",
            username="SYSTEM",
            source_ip="10.0.0.5",
        )
        services.alert_store.add(alert)
        assert services.alert_store.count == 1
        assert services.alert_store.get("ALT-TEST-001").title == "Suspicious PowerShell Command"

        incident = Incident(
            incident_id="INC-TEST-001",
            title="Credential Dumping Attack",
            severity=IncidentSeverity.HIGH,
            status="new",
            alert_ids=["ALT-TEST-001"],
            affected_hosts=["HOST-01"],
            affected_users=["SYSTEM"],
        )
        services.incident_store.add(incident)
        assert services.incident_store.count == 1
        assert services.incident_store.active_count == 1
        assert services.incident_store.get("INC-TEST-001").title == "Credential Dumping Attack"

    def test_postgres_stores_with_mock_pool(self):
        mock_raw_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.execute.return_value = "INSERT 0 1"
        mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None

        pool = DatabasePool(pool_instance=mock_raw_pool)

        # Alert store
        alert_store = PostgresAlertStore(pool)
        alert = Alert(
            alert_id="ALT-PG-001",
            title="Mimikatz Execution",
            severity=AlertSeverity.CRITICAL,
            rule_id="RULE-002",
            rule_name="Mimikatz",
            hostname="DC-01",
            username="Administrator",
            source_ip="10.0.0.1",
        )
        alert_store.add(alert)
        assert alert_store.count == 1
        assert alert_store.get("ALT-PG-001").title == "Mimikatz Execution"

        # Incident store
        incident_store = PostgresIncidentStore(pool)
        incident = Incident(
            incident_id="INC-PG-001",
            title="Domain Compromise",
            severity=IncidentSeverity.CRITICAL,
            status="new",
            alert_ids=["ALT-PG-001"],
            affected_hosts=["DC-01"],
            affected_users=["Administrator"],
        )
        incident_store.add(incident)
        assert incident_store.count == 1
        assert incident_store.get("INC-PG-001").title == "Domain Compromise"

        # Event store
        event_store = PostgresEventStore(pool)
        event_store.add({
            "event_id": "tel-pg-001",
            "event_type": "process_creation",
            "hostname": "DC-01",
            "username": "Administrator",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            "file_path": "C:\\mimikatz.exe",
            "file_hash": "a" * 64,
        })
        assert event_store.count == 1
        assert event_store.get("tel-pg-001")["process_name"] == "mimikatz.exe"

    def test_app_services_runtime_db_configuration(self):
        services = get_services()
        assert not services.is_db_available
        assert isinstance(services.alert_store, InMemoryAlertStore)

        mock_raw_pool = MagicMock()
        mock_raw_pool.acquire.return_value.__aenter__.return_value = AsyncMock()
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None
        pool = DatabasePool(pool_instance=mock_raw_pool)

        services.configure_db(pool)
        assert services.is_db_available
        assert isinstance(services.alert_store, PostgresAlertStore)
        assert isinstance(services.incident_store, PostgresIncidentStore)
        assert isinstance(services.event_store, PostgresEventStore)


class TestInvestigationDBTools:
    """Test database investigation tools with both database execution and synthetic fallback."""

    def test_process_activity_synthetic_fallback(self):
        tool = DBProcessActivityTool()
        res = tool.execute({"hostname": "SRV-OPS-01", "limit": 5})
        assert res.success
        assert res.data["source"] == "synthetic_fallback"
        assert res.data["count"] > 0
        assert len(res.evidence) > 0

    def test_process_activity_database_execution(self):
        mock_raw_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch.return_value = [{
            "process_id": "proc-uuid-1",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "file_path": "C:\\powershell.exe",
            "file_hash": "b" * 64,
            "username": "johndoe",
            "hostname": "WORKSTATION-01",
            "pid": 1234,
            "parent_pid": 5678,
            "start_time": "2026-09-18T10:00:00Z",
        }]
        mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None

        pool = DatabasePool(pool_instance=mock_raw_pool)
        tool = DBProcessActivityTool(db_pool=pool)

        res = tool.execute({"hostname": "WORKSTATION-01", "limit": 10})
        assert res.success
        assert res.data["source"] == "postgresql_runtime"
        assert res.data["count"] == 1
        assert res.evidence[0]["process_name"] == "powershell.exe"
        assert res.evidence[0]["evidence_id"].startswith("PROC-")

    def test_network_activity_database_execution(self):
        mock_raw_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch.return_value = [{
            "network_event_id": "net-uuid-1",
            "source_ip": "10.0.0.15",
            "dest_ip": "198.51.100.200",
            "source_port": 49152,
            "dest_port": 4444,
            "protocol": "tcp",
            "hostname": "WORKSTATION-01",
            "timestamp": "2026-09-18T10:00:05Z",
        }]
        mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None

        pool = DatabasePool(pool_instance=mock_raw_pool)
        tool = DBNetworkActivityTool(db_pool=pool)

        res = tool.execute({"hostname": "WORKSTATION-01", "dest_ip": "198.51.100.200"})
        assert res.success
        assert res.data["source"] == "postgresql_runtime"
        assert res.data["count"] == 1
        assert res.evidence[0]["dest_ip"] == "198.51.100.200"
        assert res.evidence[0]["evidence_id"].startswith("NET-")

    def test_authentication_tool_database_execution(self):
        mock_raw_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch.return_value = [{
            "event_id": "auth-uuid-1",
            "event_type": "authentication",
            "hostname": "DC-01",
            "username": "Administrator",
            "source_ip": "192.168.1.100",
            "severity": "high",
            "timestamp": "2026-09-18T10:01:00Z",
            "raw": {"status": "failure"},
            "attributes": {"status": "failure"},
        }]
        mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None

        pool = DatabasePool(pool_instance=mock_raw_pool)
        tool = DBAuthenticationTool(db_pool=pool)

        res = tool.execute({"username": "Administrator", "status": "failure"})
        assert res.success
        assert res.data["source"] == "postgresql_runtime"
        assert res.data["count"] == 1
        assert res.evidence[0]["status"] == "failure"
        assert res.evidence[0]["evidence_id"].startswith("AUTH-")

    def test_file_activity_tool_database_execution(self):
        mock_raw_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch.return_value = [{
            "event_id": "file-uuid-1",
            "event_type": "file_modification",
            "file_path": "C:\\Users\\admin\\malware.exe",
            "file_hash": "c" * 64,
            "hostname": "HOST-02",
            "username": "admin",
            "timestamp": "2026-09-18T10:02:00Z",
        }]
        mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None

        pool = DatabasePool(pool_instance=mock_raw_pool)
        tool = DBFileActivityTool(db_pool=pool)

        res = tool.execute({"hostname": "HOST-02", "file_path": "malware.exe"})
        assert res.success
        assert res.data["source"] == "postgresql_runtime"
        assert res.data["count"] == 1
        assert res.evidence[0]["file_path"] == "C:\\Users\\admin\\malware.exe"
        assert res.evidence[0]["evidence_id"].startswith("FILE-")

    def test_related_alerts_tool_database_execution(self):
        mock_raw_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch.return_value = [{
            "alert_id": "alt-uuid-1",
            "title": "Suspicious Service Creation",
            "severity": "high",
            "rule_id": "RULE-005",
            "rule_name": "Service Creation",
            "hostname": "HOST-01",
            "username": "SYSTEM",
            "mitre_technique_id": "T1543.003",
            "mitre_technique_name": "Windows Service",
            "created_at": "2026-09-18T10:03:00Z",
        }]
        mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None

        pool = DatabasePool(pool_instance=mock_raw_pool)
        tool = DBRelatedAlertsTool(db_pool=pool)

        res = tool.execute({"hostname": "HOST-01"})
        assert res.success
        assert res.data["source"] == "postgresql_runtime"
        assert res.data["count"] == 1
        assert res.evidence[0]["mitre_technique_id"] == "T1543.003"
        assert res.evidence[0]["evidence_id"].startswith("ALT-")


class TestThreatIntelProvider:
    """Test DatabaseThreatIntelProvider lookup, search, and fallback."""

    def setup_method(self):
        reset_threat_intel_provider()

    def teardown_method(self):
        reset_threat_intel_provider()

    def test_synthetic_lookup(self):
        provider = SyntheticThreatIntelProvider()
        res = provider.lookup("198.51.100.200")
        assert res is not None
        assert res["indicator"] == "198.51.100.200"
        assert res["reputation"] == "malicious"
        assert res["threat_actor"] == "FIN7"

    def test_database_provider_fallback_to_synthetic(self):
        provider = DatabaseThreatIntelProvider(db_pool=None, fallback_to_synthetic=True)
        res = provider.lookup("198.51.100.200")
        assert res is not None
        assert res["indicator"] == "198.51.100.200"
        assert res["reputation"] == "malicious"

    def test_database_provider_direct_query(self):
        mock_raw_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow.return_value = {
            "indicator_value": "198.51.100.99",
            "indicator_type": "ip",
            "threat_type": "Mirai Variant",
            "reputation": "malicious",
            "confidence": 0.95,
            "source": "PostgreSQL DB",
            "first_seen": "2026-09-01T00:00:00Z",
            "last_seen": "2026-09-18T00:00:00Z",
            "description": "Botnet C2 IP",
            "tags": ["botnet", "c2"],
            "metadata": json.dumps({"threat_actor": "LNX-Botnet-Group", "malware_family": "Mirai"}),
        }
        mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_raw_pool.acquire.return_value.__aexit__.return_value = None

        pool = DatabasePool(pool_instance=mock_raw_pool)
        provider = DatabaseThreatIntelProvider(db_pool=pool)

        res = provider.lookup("198.51.100.99")
        assert res is not None
        assert res["indicator"] == "198.51.100.99"
        assert res["threat_actor"] == "LNX-Botnet-Group"
        assert res["malware_family"] == "Mirai"
        assert res["provider"] == "database"


class TestTelemetryIngestionPersistence:
    """Verify that incoming telemetry is saved into event_store."""

    def setup_method(self):
        reset_services()

    def teardown_method(self):
        reset_services()

    def test_ingested_events_persisted_in_event_store(self):
        from starlette.testclient import TestClient
        from backend.api.app import create_app
        from backend.api.auth import reset_auth_config

        os.environ["AEGISX_API_KEYS_JSON"] = json.dumps({"test-agent-key": "agent"})
        reset_auth_config()

        services = get_services()
        initial_event_count = services.event_store.count

        app = create_app()
        client = TestClient(app)
        payload = {
            "endpoint_id": "ep-test-persist-01",
            "events": [
                {
                    "event_type": "process_creation",
                    "hostname": "PERSIST-HOST-01",
                    "username": "analyst",
                    "process_name": "curl.exe",
                    "command_line": "curl.exe http://example.com",
                    "timestamp": "2026-09-18T12:00:00Z",
                },
                {
                    "event_type": "network_connection",
                    "hostname": "PERSIST-HOST-01",
                    "dest_ip": "93.184.216.34",
                    "dest_port": 80,
                    "protocol": "tcp",
                    "timestamp": "2026-09-18T12:00:01Z",
                },
            ],
        }

        resp = client.post(
            "/api/v1/telemetry/ingest",
            json=payload,
            headers={"X-API-Key": "test-agent-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 2

        # Verify event store now contains the events
        assert services.event_store.count == initial_event_count + 2
        recent = services.event_store.list_recent(limit=5)
        from backend.api.services import _extract_event_field
        hostnames = [_extract_event_field(e, "hostname") for e in recent]
        assert "persist-host-01" in hostnames


class TestD01DashboardAlertStoreListAll:
    """Regression tests for defect D-01: missing list_all() on InMemoryAlertStore.

    Verifies that:
        1. list_all() method exists on InMemoryAlertStore and PostgresAlertStore.
        2. Empty store returns empty list.
        3. Single alert is returned correctly.
        4. Multiple alerts are returned in timestamp-descending order.
        5. Dashboard /summary does not crash when alerts exist but dashboard cache is empty.
    """

    def setup_method(self):
        reset_services()

    def teardown_method(self):
        reset_services()

    def test_list_all_method_exists(self):
        store = InMemoryAlertStore()
        assert hasattr(store, "list_all"), "InMemoryAlertStore must have list_all()"
        assert callable(store.list_all)
        # PostgresAlertStore inherits it
        assert hasattr(PostgresAlertStore, "list_all"), "PostgresAlertStore must have list_all()"

    def test_list_all_empty_store(self):
        store = InMemoryAlertStore()
        result = store.list_all()
        assert isinstance(result, list)
        assert len(result) == 0

    def test_list_all_single_alert(self):
        store = InMemoryAlertStore()
        alert = Alert(
            alert_id="ALT-D01-001",
            title="Test Alert D01 Single",
            severity=AlertSeverity.MEDIUM,
            rule_id="RULE-D01",
            rule_name="D01 Test Rule",
            hostname="HOST-D01",
            username="testuser",
            source_ip="10.0.0.99",
            timestamp="2026-09-19T10:00:00Z",
        )
        store.add(alert)
        result = store.list_all()
        assert len(result) == 1
        assert result[0].alert_id == "ALT-D01-001"
        assert result[0].title == "Test Alert D01 Single"

    def test_list_all_multiple_alerts_sorted(self):
        store = InMemoryAlertStore()
        alert_early = Alert(
            alert_id="ALT-D01-EARLY",
            title="Early Alert",
            severity=AlertSeverity.LOW,
            rule_id="RULE-D01",
            rule_name="D01 Test Rule",
            hostname="HOST-D01",
            username="testuser",
            source_ip="10.0.0.1",
            timestamp="2026-09-19T08:00:00Z",
        )
        alert_late = Alert(
            alert_id="ALT-D01-LATE",
            title="Late Alert",
            severity=AlertSeverity.HIGH,
            rule_id="RULE-D01",
            rule_name="D01 Test Rule",
            hostname="HOST-D01",
            username="testuser",
            source_ip="10.0.0.2",
            timestamp="2026-09-19T12:00:00Z",
        )
        store.add(alert_early)
        store.add(alert_late)
        result = store.list_all()
        assert len(result) == 2
        # Most recent first
        assert result[0].alert_id == "ALT-D01-LATE"
        assert result[1].alert_id == "ALT-D01-EARLY"

    def test_dashboard_summary_with_alerts_no_crash(self):
        """D-01 regression: dashboard /summary must not raise AttributeError."""
        from starlette.testclient import TestClient
        from backend.api.app import create_app
        from backend.api.auth import reset_auth_config

        os.environ["AEGISX_API_KEYS_JSON"] = json.dumps({"test-key": "admin"})
        reset_auth_config()

        services = get_services()
        # Seed alerts directly into store (bypassing dashboard cache)
        for i in range(3):
            services.alert_store.add(Alert(
                alert_id=f"ALT-D01-DASH-{i:03d}",
                title=f"D01 Dashboard Test Alert {i}",
                severity=AlertSeverity.HIGH if i % 2 == 0 else AlertSeverity.MEDIUM,
                rule_id=f"RULE-D01-{i}",
                rule_name=f"D01 Rule {i}",
                hostname="HOST-D01",
                username="testuser",
                source_ip="10.0.0.1",
                timestamp=f"2026-09-19T{10+i:02d}:00:00Z",
            ))
        assert services.alert_store.count == 3

        app = create_app()
        client = TestClient(app)
        resp = client.get(
            "/api/v1/dashboard/summary",
            headers={"X-API-Key": "test-key"},
        )
        # Before fix: AttributeError. After fix: 200 with severity/rule breakdown.
        assert resp.status_code == 200
        data = resp.json()
        assert data["alerts"]["total"] >= 3
        assert len(data["alerts"]["by_severity"]) > 0
        assert len(data["alerts"]["by_rule"]) > 0

    def test_dashboard_summary_empty_alerts_no_crash(self):
        """Dashboard /summary must not crash when zero alerts exist."""
        from starlette.testclient import TestClient
        from backend.api.app import create_app
        from backend.api.auth import reset_auth_config

        os.environ["AEGISX_API_KEYS_JSON"] = json.dumps({"test-key": "admin"})
        reset_auth_config()

        app = create_app()
        client = TestClient(app)
        resp = client.get(
            "/api/v1/dashboard/summary",
            headers={"X-API-Key": "test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Core D-01 validation: endpoint responds without AttributeError
        assert "alerts" in data
        assert "total" in data["alerts"]
        assert isinstance(data["alerts"]["total"], int)
        assert isinstance(data["alerts"]["by_severity"], dict)
        assert isinstance(data["alerts"]["by_rule"], dict)
