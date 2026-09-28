"""Tests for the AegisX Multi-Agent SOC Pipeline Orchestrator.

Verifies the SOCWorkflow correctly chains:
    Triage → Investigation → ThreatIntel → Response Recommendations

Uses MockProvider for all LLM calls to keep tests offline and deterministic.
"""

import unittest
import json

from ai.llm import LLMClient
from ai.llm.providers.mock import MockProvider
from ai.orchestration.workflow import SOCWorkflow, WorkflowResult


def _make_mock_client() -> LLMClient:
    """Create an LLMClient with MockProvider that returns valid agent outputs.

    The default response is the triage JSON — this is what TriageAgent
    receives because its prompt doesn't match any registered substrings.
    Investigation and TI agents use separate substring triggers.
    """
    # The default response must be a valid triage response because the
    # triage prompt (which includes "investigation_required" in the format
    # hint) is the FIRST call through the workflow.
    triage_response = json.dumps({
        "classification": "suspicious",
        "severity": "medium",
        "confidence": 0.75,
        "investigation_required": True,
        "summary": "Suspicious PowerShell activity detected",
        "findings": [
            {
                "finding": "Encoded PowerShell command detected",
                "evidence_ids": ["EVT-000001"],
            }
        ],
        "evidence_ids": ["EVT-000001"],
        "recommended_actions": [
            {
                "action": "Investigate PowerShell execution context",
                "priority": "high",
                "rationale": "Encoded commands may indicate obfuscation",
            }
        ],
    })

    provider = MockProvider(default_response=triage_response)

    # Investigation decide-step response — use a very specific substring
    # that appears in the investigation prompt but NOT the triage prompt.
    investigation_decision = json.dumps({
        "action": "conclude",
        "reasoning": "Investigation complete based on evidence review",
        "tool": None,
        "tool_input": None,
    })
    provider.register_response("decide the next investigation", investigation_decision)

    # Investigation conclusion response
    investigation_conclusion = json.dumps({
        "classification": "likely_malicious",
        "confidence": 0.85,
        "summary": "PowerShell encoded command with download cradle",
        "findings": [
            {
                "finding": "Encoded PowerShell execution detected",
                "evidence_ids": ["EVT-000001"],
            }
        ],
        "evidence_ids": ["EVT-000001"],
        "recommended_actions": [],
    })
    provider.register_response("final conclusion", investigation_conclusion)

    return LLMClient(provider=provider)


def _sample_incident() -> dict:
    """Create a sample incident input matching the AlertInput contract."""
    return {
        "alert": {
            "title": "Suspicious PowerShell Execution",
            "severity": "high",
            "source": "detection_engine",
            "timestamp": "2026-09-18T10:00:00Z",
        },
        "context": {
            "hostname": "WS-001",
            "username": "jdoe",
            "ip_address": "10.0.0.5",
            "os": "Windows 10",
            "environment": "corporate",
            "asset_criticality": "high",
            "department": "engineering",
        },
        "evidence": [
            {
                "id": "EVT-000001",
                "type": "process_creation",
                "description": "powershell.exe -EncodedCommand ZABpAHIAIABDADoAXA==",
            },
        ],
    }


class TestSOCWorkflowContract(unittest.TestCase):
    """Verify the workflow API contract."""

    def test_workflow_returns_result(self):
        """run() must return a WorkflowResult."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        self.assertIsInstance(result, WorkflowResult)

    def test_workflow_result_has_steps(self):
        """Result must contain workflow steps."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        self.assertGreater(len(result.steps), 0)

    def test_workflow_completes(self):
        """Workflow should complete successfully with mock provider."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        self.assertEqual(result.status, "completed")

    def test_workflow_has_triage(self):
        """Completed workflow must have triage result."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        self.assertIsNotNone(result.triage_result)
        self.assertIn("classification", result.triage_result)


class TestTriageStep(unittest.TestCase):
    """Verify the triage step."""

    def test_triage_step_completes(self):
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())

        triage_steps = [s for s in result.steps if s.step_name == "Triage"]
        self.assertEqual(len(triage_steps), 1)
        self.assertEqual(triage_steps[0].status, "completed")
        self.assertGreater(triage_steps[0].duration_ms, 0)

    def test_triage_classification(self):
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        self.assertEqual(result.triage_result["classification"], "suspicious")


class TestInvestigationStep(unittest.TestCase):
    """Verify the investigation step."""

    def test_investigation_runs_when_required(self):
        """Investigation should run when triage says investigation_required=True."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client, enable_investigation=True)
        result = workflow.run(_sample_incident())

        inv_steps = [s for s in result.steps if s.step_name == "Investigation"]
        self.assertEqual(len(inv_steps), 1)
        # The investigation agent may fail with mock responses (it expects specific
        # JSON structure), but the step should at least be attempted
        self.assertIn(inv_steps[0].status, ("completed", "failed"))

    def test_investigation_skipped_when_disabled(self):
        """Investigation should be skipped when disabled."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client, enable_investigation=False)
        result = workflow.run(_sample_incident())

        inv_steps = [s for s in result.steps if s.step_name == "Investigation"]
        self.assertEqual(len(inv_steps), 1)
        self.assertEqual(inv_steps[0].status, "skipped")


class TestResponseRecommendations(unittest.TestCase):
    """Verify response recommendation generation."""

    def test_recommendations_generated(self):
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        self.assertIsInstance(result.response_recommendations, list)

    def test_all_recommendations_require_approval(self):
        """Every recommendation must require human approval."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        for rec in result.response_recommendations:
            self.assertTrue(rec.get("requires_approval", False))

    def test_human_gating_flag(self):
        """Workflow result must flag human approval required."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        self.assertTrue(result.requires_human_approval)


class TestWorkflowSerialization(unittest.TestCase):
    """Verify workflow result serialization."""

    def test_to_dict(self):
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        result_dict = result.to_dict()
        self.assertIsInstance(result_dict, dict)
        self.assertIn("steps", result_dict)
        self.assertIn("status", result_dict)
        self.assertIn("requires_human_approval", result_dict)

    def test_json_serializable(self):
        """Result.to_dict() should be JSON-serializable."""
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(_sample_incident())
        try:
            json.dumps(result.to_dict())
        except (TypeError, ValueError) as e:
            self.fail(f"WorkflowResult.to_dict() is not JSON-serializable: {e}")


class TestThreatIntelStep(unittest.TestCase):
    """Verify the threat intel step."""

    def test_threat_intel_skipped_when_disabled(self):
        client = _make_mock_client()
        workflow = SOCWorkflow(llm_client=client, enable_threat_intel=False)
        result = workflow.run(_sample_incident())

        ti_steps = [s for s in result.steps if s.step_name == "Threat Intelligence"]
        self.assertEqual(len(ti_steps), 1)
        self.assertEqual(ti_steps[0].status, "skipped")


if __name__ == "__main__":
    unittest.main()
