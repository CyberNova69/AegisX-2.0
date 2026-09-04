#!/usr/bin/env python3
"""
AegisX Investigation Agent Unit & Integration Tests
===================================================

Tests InvestigationAgent multi-turn reasoning, schema validation,
loop bounding, tool allowlisting, evidence grounding, and MockProvider integration.

Usage:
    python -m unittest tests/test_investigation_agent.py -v
"""

import json
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.investigation_agent import InvestigationAgent
from ai.agents.investigation_schemas import (
    InvestigationDecision,
    InvestigationFinding,
    InvestigationRequest,
    InvestigationResult,
    InvestigationStep,
    VALID_INVESTIGATION_ACTIONS,
    VALID_INVESTIGATION_STATUSES,
)
from ai.evaluation.investigation_eval import evaluate_investigation_scenarios
from ai.llm import LLMClient, LLMResponseError
from ai.llm.providers.mock import MockProvider
from ai.tools.registry import create_default_registry
from ai.tools.synthetic_data import get_scenario

class TestInvestigationAgent(unittest.TestCase):
    """Unit and integration test suite for InvestigationAgent."""

    def setUp(self):
        self.scenario = get_scenario("malicious_powershell")
        self.sample_request = InvestigationRequest(
            investigation_id="INV-TEST-001",
            alert=self.scenario["alert"],
            triage_result={
                "classification": "confirmed_malicious",
                "severity": "critical",
                "confidence": 0.90,
                "investigation_required": True,
            },
            initial_evidence=self.scenario["initial_evidence"],
            context=self.scenario["context"],
        )

    # -------------------------------------------------------------------------
    # Schemas Validation Tests
    # -------------------------------------------------------------------------
    def test_schema_investigation_finding_valid(self):
        """InvestigationFinding stores verified evidence and rounds confidence."""
        f = InvestigationFinding(
            finding_id="FIND-001",
            title="Macro spawn",
            description="Word spawned PowerShell",
            evidence_ids=["EVT-003", "PROC-003"],
            confidence=0.95,
        )
        d = f.to_dict()
        self.assertEqual(d["finding_id"], "FIND-001")
        self.assertEqual(d["confidence"], 0.95)
        self.assertEqual(len(d["evidence_ids"]), 2)

    def test_schema_investigation_finding_invalid_confidence(self):
        """InvestigationFinding rejects confidence outside [0.0, 1.0]."""
        with self.assertRaises(ValueError):
            InvestigationFinding(
                finding_id="FIND-001",
                title="Bad",
                description="Bad",
                confidence=1.5,
            )

    def test_schema_investigation_decision_actions(self):
        """InvestigationDecision validates allowed actions."""
        d1 = InvestigationDecision(action="investigate", tool_name="process_activity")
        self.assertEqual(d1.action, "investigate")
        self.assertEqual(d1.tool_name, "process_activity")

        d2 = InvestigationDecision(action="finish", stop_reason="done")
        self.assertEqual(d2.action, "finish")

        with self.assertRaises(ValueError):
            InvestigationDecision(action="unauthorized_action")

        with self.assertRaises(ValueError):
            InvestigationDecision(action="investigate", tool_name=None)

    def test_schema_investigation_result_status_validation(self):
        """InvestigationResult validates status enums."""
        res = InvestigationResult(
            investigation_id="INV-01",
            alert_id="ALT-01",
            status="completed",
            conclusion="confirmed_malicious",
            severity="critical",
            confidence=0.95,
        )
        self.assertEqual(res.status, "completed")

        with self.assertRaises(ValueError):
            InvestigationResult(
                investigation_id="INV-01",
                alert_id="ALT-01",
                status="invalid_status",
                conclusion="confirmed_malicious",
                severity="critical",
                confidence=0.95,
            )

    # -------------------------------------------------------------------------
    # Multi-turn Investigation Loop with MockProvider
    # -------------------------------------------------------------------------
    def test_multi_turn_investigation_flow(self):
        """InvestigationAgent executes multi-turn loop, gathers evidence, and produces report."""
        provider = MockProvider()

        # Turn 1: Investigate process activity
        turn1 = json.dumps({
            "action": "investigate",
            "tool_name": "process_activity",
            "tool_input": {"scenario": "malicious_powershell"},
            "purpose": "Find parent process of PowerShell.",
        })
        provider.register_response("INVESTIGATION STEP 1", turn1)

        # Turn 2: Finish
        turn2 = json.dumps({
            "action": "finish",
            "stop_reason": "Found WINWORD parent process.",
        })
        provider.register_response("INVESTIGATION STEP 2", turn2)

        # Conclusion Synthesis
        conclusion = json.dumps({
            "status": "completed",
            "conclusion": "confirmed_malicious",
            "severity": "critical",
            "confidence": 0.94,
            "findings": [
                {
                    "finding_id": "FIND-001",
                    "title": "Word spawned PowerShell",
                    "description": "Macro document launched PowerShell with hidden window flag.",
                    "evidence_ids": ["EVT-003", "PROC-003"],
                    "confidence": 0.95,
                }
            ],
            "recommended_actions": [
                {"action": "Isolate host FIN-W10-04", "priority": "immediate", "rationale": "Active C2"}
            ],
            "limitations": "Synthetic read-only investigation.",
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(
            llm_client=LLMClient(provider=provider),
            max_steps=5,
        )

        result = agent.investigate(self.sample_request)

        self.assertIsInstance(result, InvestigationResult)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.conclusion, "confirmed_malicious")
        self.assertEqual(result.severity, "critical")
        self.assertAlmostEqual(result.confidence, 0.94)
        self.assertEqual(len(result.investigation_steps), 1)
        self.assertEqual(result.investigation_steps[0].tool_name, "process_activity")
        self.assertIn("PROC-003", result.investigation_steps[0].evidence_ids)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].evidence_ids, ["EVT-003", "PROC-003"])

    # -------------------------------------------------------------------------
    # max_steps Enforcement Tests
    # -------------------------------------------------------------------------
    def test_max_steps_boundary_enforcement(self):
        """InvestigationAgent terminates when max_steps is reached without infinite loop."""
        provider = MockProvider()

        # Model keeps requesting tools endlessly
        endless_tool = json.dumps({
            "action": "investigate",
            "tool_name": "process_activity",
            "tool_input": {"scenario": "malicious_powershell"},
            "purpose": "Continuous check.",
        })
        provider.default_response = endless_tool

        # Set max_steps to 2
        agent = InvestigationAgent(
            llm_client=LLMClient(provider=provider),
            max_steps=2,
        )

        result = agent.investigate(self.sample_request)

        # Must execute exactly 2 steps, then exit loop and synthesize
        self.assertEqual(len(result.investigation_steps), 2)
        self.assertLessEqual(len(result.investigation_steps), 2)

    # -------------------------------------------------------------------------
    # Rejection & Safety Tests
    # -------------------------------------------------------------------------
    def test_rejection_of_unregistered_tool(self):
        """InvestigationAgent raises LLMResponseError when model requests unapproved tool."""
        provider = MockProvider(
            default_response=json.dumps({
                "action": "investigate",
                "tool_name": "bash_terminal",
                "purpose": "Unauthorized command execution attempt.",
            })
        )
        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError) as ctx:
            agent.investigate(self.sample_request)
        self.assertIn("Hallucinated or unapproved tool", str(ctx.exception))

    def test_rejection_of_invalid_action(self):
        """InvestigationAgent raises LLMResponseError on unrecognized action."""
        provider = MockProvider(
            default_response=json.dumps({
                "action": "terminate_process",
                "purpose": "Prohibited action.",
            })
        )
        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError) as ctx:
            agent.investigate(self.sample_request)
        self.assertIn("Invalid investigation action", str(ctx.exception))

    def test_rejection_of_malformed_json_response(self):
        """InvestigationAgent raises LLMResponseError on non-JSON model output."""
        provider = MockProvider(default_response="Not a JSON string at all.")
        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError):
            agent.investigate(self.sample_request)

    # -------------------------------------------------------------------------
    # Evidence Grounding & Hallucination Tests
    # -------------------------------------------------------------------------
    def test_hallucinated_evidence_rejection(self):
        """InvestigationAgent detects and strips hallucinated evidence IDs from findings."""
        provider = MockProvider()

        # Step 1: finish immediately
        provider.register_response("INVESTIGATION STEP 1", json.dumps({"action": "finish", "stop_reason": "done"}))

        # Model claims non-existent evidence IDs EVT-999 and PROC-FAKE
        conclusion = json.dumps({
            "status": "completed",
            "conclusion": "confirmed_malicious",
            "severity": "high",
            "confidence": 0.85,
            "findings": [
                {
                    "finding_id": "FIND-001",
                    "title": "Hallucinated claim",
                    "description": "Claims ungrounded evidence",
                    "evidence_ids": ["EVT-003", "EVT-999", "PROC-FAKE"],
                    "confidence": 0.85,
                }
            ],
            "recommended_actions": [],
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))
        result = agent.investigate(self.sample_request)

        # Only EVT-003 is valid (from initial evidence); EVT-999 and PROC-FAKE should be rejected
        self.assertEqual(result.findings[0].evidence_ids, ["EVT-003"])
        self.assertIn("EVT-999", result.metadata["hallucinated_evidence_attempts"])
        self.assertIn("PROC-FAKE", result.metadata["hallucinated_evidence_attempts"])
        self.assertEqual(len(result.metadata["rejected_evidence_ids"]), 2)

    # -------------------------------------------------------------------------
    # Evaluation Framework Integration Test
    # -------------------------------------------------------------------------
    def test_investigation_evaluation_metrics(self):
        """Investigation evaluation correctly computes accuracy and grounding rates."""
        mock_result = InvestigationResult(
            investigation_id="INV-01",
            alert_id="ALT-01",
            status="completed",
            conclusion="confirmed_malicious",
            severity="critical",
            confidence=0.90,
            findings=[
                InvestigationFinding("F1", "Title", "Desc", ["EVT-01"], 0.9)
            ],
            investigation_steps=[
                InvestigationStep(1, "process_activity", {}, "check", {}, ["PROC-01"])
            ],
        )

        expected = [{"expected_conclusion": "confirmed_malicious", "expected_severity": "critical"}]
        metrics = evaluate_investigation_scenarios([mock_result], expected)

        d = metrics.to_dict()
        self.assertEqual(d["evaluation_type"], "SYNTHETIC EVALUATION")
        self.assertEqual(d["total_scenarios"], 1)
        self.assertEqual(d["completion_rate"], 1.0)
        self.assertEqual(d["conclusion_accuracy"], 1.0)
        self.assertEqual(d["evidence_grounding_rate"], 1.0)
        self.assertEqual(d["max_step_violations"], 0)

    # -------------------------------------------------------------------------
    # Finish & Tool Failure & Insufficient Evidence Tests
    # -------------------------------------------------------------------------
    def test_immediate_finish_decision(self):
        """InvestigationAgent cleanly handles immediate finish decision on step 1."""
        provider = MockProvider()
        finish_decision = json.dumps({
            "action": "finish",
            "stop_reason": "Alert is already self-contained.",
        })
        provider.register_response("INVESTIGATION STEP 1", finish_decision)

        conclusion = json.dumps({
            "status": "completed",
            "conclusion": "benign",
            "severity": "low",
            "confidence": 0.95,
            "findings": [
                {"finding_id": "FIND-01", "title": "Normal", "description": "No threat", "evidence_ids": ["EVT-003"]}
            ],
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))
        result = agent.investigate(self.sample_request)

        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.investigation_steps), 0)
        self.assertEqual(result.conclusion, "benign")

    def test_missing_tool_name_when_action_is_investigate(self):
        """InvestigationAgent raises LLMResponseError when action is investigate but tool_name is missing."""
        provider = MockProvider(
            default_response=json.dumps({
                "action": "investigate",
                "purpose": "Forgot tool_name",
            })
        )
        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))
        with self.assertRaises(LLMResponseError) as ctx:
            agent.investigate(self.sample_request)
        self.assertIn("requires a valid non-empty 'tool_name'", str(ctx.exception))

    def test_tool_failure_recorded_in_step(self):
        """InvestigationAgent records failed tool executions without crashing."""
        provider = MockProvider()

        # Step 1: execute tool with invalid input that returns tool error
        step1 = json.dumps({
            "action": "investigate",
            "tool_name": "process_activity",
            "tool_input": "invalid_non_dict_input",
            "purpose": "Testing failure recording",
        })
        provider.register_response("INVESTIGATION STEP 1", step1)

        step2 = json.dumps({"action": "finish", "stop_reason": "Tool failed, stopping"})
        provider.register_response("INVESTIGATION STEP 2", step2)

        conclusion = json.dumps({
            "status": "completed",
            "conclusion": "suspicious",
            "severity": "medium",
            "confidence": 0.5,
            "findings": [],
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))
        result = agent.investigate(self.sample_request)

        self.assertEqual(len(result.investigation_steps), 1)
        self.assertFalse(result.investigation_steps[0].result["success"])
        self.assertIn("Invalid tool input", result.investigation_steps[0].result["error"])

    def test_insufficient_evidence_investigation(self):
        """InvestigationAgent correctly processes insufficient_evidence scenario."""
        scn = get_scenario("insufficient_evidence")
        req = InvestigationRequest(
            investigation_id="INV-INSUFF-01",
            alert=scn["alert"],
            triage_result={"classification": "insufficient_evidence", "severity": "low", "confidence": 0.3},
            initial_evidence=scn["initial_evidence"],
            context=scn["context"],
        )

        provider = MockProvider()
        provider.register_response("INVESTIGATION STEP 1", json.dumps({
            "action": "finish",
            "stop_reason": "No corroborating telemetry available",
        }))

        conclusion = json.dumps({
            "status": "insufficient_evidence",
            "conclusion": "insufficient_evidence",
            "severity": "low",
            "confidence": 0.25,
            "findings": [
                {"finding_id": "FIND-01", "title": "Inconclusive", "description": "Minimal log fragment", "evidence_ids": ["EVT-010"]}
            ],
            "recommended_actions": [
                {"action": "Enable process command-line audit logging", "priority": "medium", "rationale": "Collect telemetry"}
            ],
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))
        result = agent.investigate(req)

        self.assertEqual(result.status, "insufficient_evidence")
        self.assertEqual(result.conclusion, "insufficient_evidence")
        self.assertAlmostEqual(result.confidence, 0.25)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].evidence_ids, ["EVT-010"])

    # -------------------------------------------------------------------------
    # Provider SDK Isolation Test
    # -------------------------------------------------------------------------
    def test_provider_sdk_isolation(self):
        """InvestigationAgent does NOT import vendor SDKs directly."""
        import ai.agents.investigation_agent as mod
        source_text = Path(mod.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import openai", source_text)
        self.assertNotIn("import google", source_text)
        self.assertNotIn("import anthropic", source_text)
        self.assertIn("from ai.llm import LLMClient", source_text)

if __name__ == "__main__":
    unittest.main()
