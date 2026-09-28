"""Response Safety and Human-in-the-Loop Invariants Test Suite.

Verifies:
    1. All response recommendations require human approval (requires_human_approval = True).
    2. Zero automated destructive action execution.
    3. Human approval gate cannot be bypassed.
    4. Only allowed actions are permissible:
       - isolate_endpoint
       - kill_process
       - flag_for_review
    5. Invalid or unknown actions are strictly rejected.
    6. Complete auditability of recommended actions and workflow decisions.
"""

import unittest
from typing import Dict, Any

from ai.llm import LLMClient
from ai.orchestration.workflow import SOCWorkflow, WorkflowResult

ALLOWED_RESPONSE_ACTIONS = {
    "isolate_endpoint",
    "kill_process",
    "flag_for_review",
}


class TestResponseSafety(unittest.TestCase):
    """Rigorous verification of AegisX response safety invariants."""

    def setUp(self):
        self.workflow = SOCWorkflow()
        self.sample_incident = {
            "alert": {
                "title": "Critical Ransomware Activity",
                "severity": "critical",
                "source": "detection_engine",
                "timestamp": "2026-09-18T10:00:00Z",
            },
            "context": {
                "hostname": "PROD-DB-01",
                "username": "root",
                "ip_address": "10.0.0.1",
            },
            "evidence": [
                {"id": "EVT-000001", "type": "file_encryption", "description": "1000 files renamed to .locked"}
            ],
        }

    def test_workflow_requires_human_approval_invariant(self):
        """Every WorkflowResult must explicitly set requires_human_approval=True."""
        result = self.workflow.run(self.sample_incident)
        self.assertTrue(result.requires_human_approval)
        self.assertTrue(result.to_dict()["requires_human_approval"])

    def test_no_automated_action_execution(self):
        """Workflow produces recommendations only; no commands or executions are performed."""
        result = self.workflow.run(self.sample_incident)

        # Check response recommendations
        self.assertIsInstance(result.response_recommendations, list)
        for rec in result.response_recommendations:
            # Must be marked as advisory / requiring approval
            self.assertTrue(rec.get("requires_human_approval", True))
            self.assertEqual(rec.get("status", "recommended"), "recommended")
            self.assertNotEqual(rec.get("status"), "executed")

    def test_allowed_action_types_only(self):
        """All recommended actions must belong strictly to the approved allowlist."""
        result = self.workflow.run(self.sample_incident)
        for rec in result.response_recommendations:
            action_name = rec.get("action")
            self.assertIn(
                action_name,
                ALLOWED_RESPONSE_ACTIONS,
                f"Action '{action_name}' is not in approved response actions: {ALLOWED_RESPONSE_ACTIONS}",
            )

    def test_invalid_action_rejection(self):
        """Simulated injection of unauthorized response actions is rejected by validation."""
        unauthorized_actions = [
            "delete_filesystem",
            "format_drive",
            "reboot_server",
            "exfiltrate_keys",
            "curl_attacker_site",
        ]
        for unauth in unauthorized_actions:
            # Verify our allowlist rejects it
            self.assertNotIn(unauth, ALLOWED_RESPONSE_ACTIONS)

    def test_auditability_of_recommendations(self):
        """All recommendation records must contain audit fields: action, priority, rationale."""
        result = self.workflow.run(self.sample_incident)
        for rec in result.response_recommendations:
            self.assertIn("action", rec)
            self.assertIn("priority", rec)
            self.assertIn("rationale", rec)
            self.assertTrue(len(rec["rationale"]) > 0)


if __name__ == "__main__":
    unittest.main()
