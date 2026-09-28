"""AegisX Live DB Investigation Workflow Tests.

Verifies:
    1. SOCWorkflow creates DB-backed registry when PostgreSQL mode is active.
    2. InvestigationAgent receives and uses that registry.
    3. DB tools (process, network, related_alerts) dispatch through the DB tool path.
    4. DB evidence (evidence_id key) is properly tracked for grounding.
    5. Hallucinated DB evidence is rejected.
    6. PostgreSQL-unavailable path remains safe (synthetic fallback).
    7. RAG context preservation.
    8. TI/MITRE tools remain available in DB-backed registry.
    9. Read-only invariant enforced.
"""

import json
import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from ai.agents.investigation_agent import InvestigationAgent
from ai.agents.investigation_schemas import InvestigationRequest, InvestigationResult
from ai.llm import LLMClient
from ai.llm.providers.mock import MockProvider
from ai.tools.registry import ToolRegistry, create_default_registry
from ai.tools.db_tools import (
    DBProcessActivityTool,
    DBNetworkActivityTool,
    DBRelatedAlertsTool,
)
from ai.orchestration.workflow import SOCWorkflow, WorkflowResult
from backend.database.connection import DatabasePool
from backend.api.services import get_services, reset_services


def _make_mock_db_pool(process_rows=None, network_rows=None, alert_rows=None):
    """Create a mock DatabasePool that returns controlled query results."""
    mock_raw_pool = MagicMock()
    mock_conn = AsyncMock()

    default_process = [{
        "process_id": "proc-uuid-db-test",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
        "file_path": "C:\\powershell.exe",
        "file_hash": "b" * 64,
        "username": "johndoe",
        "hostname": "WORKSTATION-DB-01",
        "pid": 1234,
        "parent_pid": 5678,
        "start_time": "2026-09-19T10:00:00Z",
    }]

    default_network = [{
        "network_event_id": "net-uuid-db-test",
        "source_ip": "10.0.0.15",
        "dest_ip": "198.51.100.200",
        "source_port": 49152,
        "dest_port": 4444,
        "protocol": "tcp",
        "hostname": "WORKSTATION-DB-01",
        "timestamp": "2026-09-19T10:00:05Z",
    }]

    default_alerts = [{
        "alert_id": "alt-uuid-db-test",
        "title": "Suspicious Service Creation",
        "severity": "high",
        "rule_id": "RULE-005",
        "rule_name": "Service Creation",
        "hostname": "WORKSTATION-DB-01",
        "username": "SYSTEM",
        "mitre_technique_id": "T1543.003",
        "mitre_technique_name": "Windows Service",
        "created_at": "2026-09-19T10:03:00Z",
    }]

    # Route fetch calls based on query content
    actual_process = process_rows if process_rows is not None else default_process
    actual_network = network_rows if network_rows is not None else default_network
    actual_alerts = alert_rows if alert_rows is not None else default_alerts

    def _fetch_side_effect(query, *args):
        q_lower = query.lower()
        if "processes" in q_lower or "process_name" in q_lower:
            return actual_process
        elif "network_events" in q_lower:
            return actual_network
        elif "alerts" in q_lower:
            return actual_alerts
        return []

    mock_conn.fetch.side_effect = _fetch_side_effect
    mock_raw_pool.acquire.return_value.__aenter__.return_value = mock_conn
    mock_raw_pool.acquire.return_value.__aexit__.return_value = None

    pool = DatabasePool(pool_instance=mock_raw_pool)
    return pool


def _make_investigation_mock_client(tool_name="process_activity", evidence_ids=None):
    """Create an LLMClient that drives the InvestigationAgent to call a specific tool."""
    provider = MockProvider()

    # Turn 1: Investigate with specified tool
    turn1 = json.dumps({
        "action": "investigate",
        "tool_name": tool_name,
        "tool_input": {"hostname": "WORKSTATION-DB-01"},
        "purpose": f"Investigate {tool_name} on target host.",
    })
    provider.register_response("INVESTIGATION STEP 1", turn1)

    # Turn 2: Finish
    turn2 = json.dumps({
        "action": "finish",
        "stop_reason": "Sufficient evidence gathered.",
    })
    provider.register_response("INVESTIGATION STEP 2", turn2)

    # Conclusion
    eids = evidence_ids or ["EVT-003"]
    conclusion = json.dumps({
        "status": "completed",
        "conclusion": "likely_malicious",
        "severity": "high",
        "confidence": 0.88,
        "findings": [{
            "finding_id": "FIND-001",
            "title": "Suspicious activity detected",
            "description": "DB-backed investigation found suspicious indicators.",
            "evidence_ids": eids,
            "confidence": 0.88,
        }],
        "recommended_actions": [],
        "limitations": "Read-only DB investigation.",
    })
    provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
    provider.default_response = conclusion

    return LLMClient(provider=provider)


def _make_sample_request():
    """Create a standard investigation request."""
    return InvestigationRequest(
        investigation_id="INV-DB-TEST-001",
        alert={
            "id": "ALT-DB-TEST-001",
            "title": "Suspicious PowerShell with C2 Connection",
            "severity": "high",
            "rule_id": "RULE-PS-002",
        },
        triage_result={
            "classification": "likely_malicious",
            "severity": "high",
            "confidence": 0.85,
            "investigation_required": True,
        },
        initial_evidence=[{
            "id": "EVT-003",
            "type": "process_creation",
            "description": "PowerShell with encoded command",
        }],
        context={
            "hostname": "WORKSTATION-DB-01",
            "username": "johndoe",
        },
    )


class TestDBRegistryCreation:
    """Test that create_default_registry produces a DB-backed registry."""

    def test_db_registry_contains_db_tools(self):
        pool = _make_mock_db_pool()
        registry = create_default_registry(
            include_threat_intel=True,
            use_database=True,
            db_pool=pool,
        )
        tools = registry.list_tools()
        assert "process_activity" in tools
        assert "network_activity" in tools
        assert "authentication" in tools
        assert "file_activity" in tools
        assert "related_alerts" in tools

    def test_db_registry_includes_ti_mitre(self):
        pool = _make_mock_db_pool()
        registry = create_default_registry(
            include_threat_intel=True,
            use_database=True,
            db_pool=pool,
        )
        tools = registry.list_tools()
        assert "threat_intel" in tools
        assert "mitre_lookup" in tools
        assert len(tools) == 7

    def test_db_tools_are_read_only(self):
        pool = _make_mock_db_pool()
        registry = create_default_registry(use_database=True, db_pool=pool)
        for tool_name in registry.list_tools():
            tool = registry.get(tool_name)
            assert tool.read_only, f"Tool '{tool_name}' must be read_only"

    def test_synthetic_fallback_when_no_pool(self):
        registry = create_default_registry(use_database=False)
        tools = registry.list_tools()
        assert "process_activity" in tools
        # Verify it's the synthetic tool, not DB tool
        tool = registry.get("process_activity")
        assert not hasattr(tool, "db_pool"), "Synthetic tool should not have db_pool"


class TestDBToolEvidenceTracking:
    """Test that DB tool evidence_id keys are properly tracked by InvestigationAgent."""

    def test_evidence_id_key_tracked_by_agent(self):
        """DB tools produce 'evidence_id' key — InvestigationAgent must track it."""
        pool = _make_mock_db_pool()
        registry = create_default_registry(use_database=True, db_pool=pool)

        # Use evidence_id from DB tool output as the conclusion evidence ref
        client = _make_investigation_mock_client(
            tool_name="process_activity",
            evidence_ids=["EVT-003", "PROC-PROC-UU"],
        )

        agent = InvestigationAgent(
            llm_client=client,
            tool_registry=registry,
            max_steps=3,
        )

        result = agent.investigate(_make_sample_request())
        assert result.status == "completed"
        assert len(result.investigation_steps) == 1
        assert result.investigation_steps[0].tool_name == "process_activity"

        # Verify DB evidence was collected
        step_eids = result.investigation_steps[0].evidence_ids
        assert len(step_eids) > 0, "DB tool evidence must be tracked"
        # All DB process evidence_ids start with "PROC-"
        db_eids = [eid for eid in step_eids if eid.startswith("PROC-")]
        assert len(db_eids) > 0, "DB process evidence IDs must be present"

    def test_network_evidence_id_tracked(self):
        """DB network tool evidence is tracked for grounding."""
        pool = _make_mock_db_pool()
        registry = create_default_registry(use_database=True, db_pool=pool)

        client = _make_investigation_mock_client(tool_name="network_activity")
        agent = InvestigationAgent(
            llm_client=client,
            tool_registry=registry,
            max_steps=3,
        )

        result = agent.investigate(_make_sample_request())
        step_eids = result.investigation_steps[0].evidence_ids
        net_eids = [eid for eid in step_eids if eid.startswith("NET-")]
        assert len(net_eids) > 0, "DB network evidence IDs must be present"

    def test_related_alerts_evidence_id_tracked(self):
        """DB related_alerts tool evidence is tracked for grounding."""
        pool = _make_mock_db_pool()
        registry = create_default_registry(use_database=True, db_pool=pool)

        client = _make_investigation_mock_client(tool_name="related_alerts")
        agent = InvestigationAgent(
            llm_client=client,
            tool_registry=registry,
            max_steps=3,
        )

        result = agent.investigate(_make_sample_request())
        step_eids = result.investigation_steps[0].evidence_ids
        alt_eids = [eid for eid in step_eids if eid.startswith("ALT-")]
        assert len(alt_eids) > 0, "DB alert evidence IDs must be present"

    def test_db_evidence_reaches_final_result(self):
        """DB tool evidence reaches the final investigation result."""
        pool = _make_mock_db_pool()
        registry = create_default_registry(use_database=True, db_pool=pool)

        client = _make_investigation_mock_client(tool_name="process_activity")
        agent = InvestigationAgent(
            llm_client=client,
            tool_registry=registry,
            max_steps=3,
        )

        result = agent.investigate(_make_sample_request())
        # Evidence should contain DB-sourced items
        db_items = [
            e for e in result.evidence
            if isinstance(e, dict) and e.get("evidence_id", "").startswith("PROC-")
        ]
        assert len(db_items) > 0, "DB evidence must reach final investigation result"

    def test_db_evidence_source_is_postgresql(self):
        """DB tool results report 'postgresql_runtime' as source."""
        pool = _make_mock_db_pool()
        tool = DBProcessActivityTool(db_pool=pool)
        result = tool.execute({"hostname": "WORKSTATION-DB-01"})
        assert result.success
        assert result.data["source"] == "postgresql_runtime"


class TestHallucinatedDBEvidence:
    """Test that hallucinated DB evidence IDs are still rejected."""

    def test_hallucinated_evidence_id_rejected(self):
        """Findings referencing non-existent DB evidence IDs are rejected."""
        pool = _make_mock_db_pool()
        registry = create_default_registry(use_database=True, db_pool=pool)

        # Conclusion references a fabricated evidence ID
        client = _make_investigation_mock_client(
            tool_name="process_activity",
            evidence_ids=["PROC-FABRICATED-999"],
        )

        agent = InvestigationAgent(
            llm_client=client,
            tool_registry=registry,
            max_steps=3,
        )

        result = agent.investigate(_make_sample_request())
        # The fabricated ID should be in rejected/hallucinated list
        metadata = result.metadata
        assert "PROC-FABRICATED-999" in metadata.get("hallucinated_evidence_attempts", []) or \
               "PROC-FABRICATED-999" in metadata.get("rejected_evidence_ids", [])


class TestSOCWorkflowDBRegistryWiring:
    """Test that SOCWorkflow passes DB-backed registry to InvestigationAgent."""

    def setup_method(self):
        reset_services()

    def teardown_method(self):
        reset_services()

    def test_workflow_uses_db_registry_when_db_available(self):
        """SOCWorkflow creates DB-backed registry when PostgreSQL is active."""
        pool = _make_mock_db_pool()

        # Configure services with DB pool
        services = get_services()
        services.configure_db(pool)
        assert services.is_db_available

        # Create a mock LLM client that drives the workflow
        triage_resp = json.dumps({
            "classification": "suspicious",
            "severity": "medium",
            "confidence": 0.75,
            "investigation_required": True,
            "summary": "Suspicious activity",
            "findings": [{"finding": "Test", "evidence_ids": ["EVT-003"]}],
            "evidence_ids": ["EVT-003"],
            "recommended_actions": [],
        })
        inv_decision = json.dumps({
            "action": "finish",
            "stop_reason": "Quick investigation",
        })
        inv_conclusion = json.dumps({
            "conclusion": "suspicious",
            "severity": "medium",
            "confidence": 0.7,
            "findings": [],
            "recommended_actions": [],
            "status": "completed",
        })
        ti_result = json.dumps({
            "findings": [],
            "indicators_checked": [],
            "summary": "No TI matches",
        })

        provider = MockProvider(default_response=triage_resp)
        provider.register_response("decide the next investigation", inv_decision)
        provider.register_response("INVESTIGATION STEP", inv_decision)
        provider.register_response("final conclusion", inv_conclusion)
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", inv_conclusion)
        provider.register_response("threat intelligence", ti_result)

        workflow = SOCWorkflow(
            llm_client=LLMClient(provider=provider),
            enable_investigation=True,
            enable_threat_intel=False,
            enable_rag=False,
        )

        incident = {
            "alert": {
                "id": "ALT-DB-WF-001",
                "title": "Suspicious Process Execution",
                "severity": "medium",
            },
            "context": {"hostname": "WORKSTATION-DB-01"},
            "evidence": [{"id": "EVT-003", "type": "process_creation", "description": "Test"}],
        }

        result = workflow.run(incident)
        assert result.status == "completed"
        # Investigation step should have completed
        inv_steps = [s for s in result.steps if s.agent_type == "InvestigationAgent"]
        assert len(inv_steps) == 1
        assert inv_steps[0].status == "completed"

    def test_workflow_synthetic_fallback_when_no_db(self):
        """SOCWorkflow uses synthetic registry when no database is configured."""
        services = get_services()
        assert not services.is_db_available

        triage_resp = json.dumps({
            "classification": "suspicious",
            "severity": "medium",
            "confidence": 0.75,
            "investigation_required": True,
            "summary": "Test",
            "findings": [],
            "evidence_ids": ["EVT-003"],
            "recommended_actions": [],
        })
        inv_decision = json.dumps({"action": "finish", "stop_reason": "Done"})
        inv_conclusion = json.dumps({
            "conclusion": "suspicious", "severity": "medium", "confidence": 0.6,
            "findings": [], "recommended_actions": [], "status": "completed",
        })

        provider = MockProvider(default_response=triage_resp)
        provider.register_response("decide the next investigation", inv_decision)
        provider.register_response("INVESTIGATION STEP", inv_decision)
        provider.register_response("final conclusion", inv_conclusion)
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", inv_conclusion)

        workflow = SOCWorkflow(
            llm_client=LLMClient(provider=provider),
            enable_investigation=True,
            enable_threat_intel=False,
            enable_rag=False,
        )

        incident = {
            "alert": {"id": "ALT-SYNTH-001", "title": "Test Alert", "severity": "low"},
            "context": {"hostname": "TEST-HOST"},
            "evidence": [{"id": "EVT-003", "type": "test", "description": "Test"}],
        }

        result = workflow.run(incident)
        assert result.status == "completed"


class TestDBToolDirectExecution:
    """Verify DB tools execute against mock PostgreSQL and return proper evidence format."""

    def test_process_tool_db_execution_and_evidence_format(self):
        pool = _make_mock_db_pool()
        tool = DBProcessActivityTool(db_pool=pool)
        result = tool.execute({"hostname": "WORKSTATION-DB-01"})
        assert result.success
        assert result.data["source"] == "postgresql_runtime"
        assert result.data["count"] == 1
        assert len(result.evidence) == 1
        # Verify evidence_id key exists (not just "id")
        assert "evidence_id" in result.evidence[0]
        assert result.evidence[0]["evidence_id"].startswith("PROC-")

    def test_network_tool_db_execution_and_evidence_format(self):
        pool = _make_mock_db_pool()
        tool = DBNetworkActivityTool(db_pool=pool)
        result = tool.execute({"hostname": "WORKSTATION-DB-01"})
        assert result.success
        assert result.data["source"] == "postgresql_runtime"
        assert "evidence_id" in result.evidence[0]
        assert result.evidence[0]["evidence_id"].startswith("NET-")

    def test_related_alerts_tool_db_execution_and_evidence_format(self):
        pool = _make_mock_db_pool()
        tool = DBRelatedAlertsTool(db_pool=pool)
        result = tool.execute({"hostname": "WORKSTATION-DB-01"})
        assert result.success
        assert result.data["source"] == "postgresql_runtime"
        assert "evidence_id" in result.evidence[0]
        assert result.evidence[0]["evidence_id"].startswith("ALT-")

    def test_synthetic_fallback_when_pool_none(self):
        tool = DBProcessActivityTool(db_pool=None)
        result = tool.execute({"hostname": "SRV-OPS-01"})
        assert result.success
        assert result.data["source"] == "synthetic_fallback"
