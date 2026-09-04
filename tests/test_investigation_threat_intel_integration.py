#!/usr/bin/env python3
"""
AegisX InvestigationAgent Threat Intelligence & MITRE Integration Tests
========================================================================

Tests InvestigationAgent multi-turn investigations invoking Phase 5 tools:
  - 'threat_intel' (ThreatIntelTool)
  - 'mitre_lookup' (MitreTool)
Verifies evidence grounding for 'TI-XXX' and 'MITRE-XXX' evidence IDs,
and audits rejection of hallucinated threat intelligence IDs.

Usage:
    python -m unittest tests/test_investigation_threat_intel_integration.py -v
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
    InvestigationRequest,
    InvestigationResult,
)
from ai.llm import LLMClient, LLMResponseError
from ai.llm.providers.mock import MockProvider
from ai.tools.synthetic_data import get_scenario

class TestInvestigationThreatIntelIntegration(unittest.TestCase):
    """Integration tests for InvestigationAgent with Phase 5 intelligence tools."""

    def setUp(self):
        self.scenario = get_scenario("malicious_powershell")
        self.sample_request = InvestigationRequest(
            investigation_id="INV-INTEL-001",
            alert=self.scenario["alert"],
            triage_result={
                "classification": "confirmed_malicious",
                "severity": "critical",
                "confidence": 0.95,
                "investigation_required": True,
            },
            initial_evidence=self.scenario["initial_evidence"],
            context=self.scenario["context"],
        )

    def test_investigation_agent_has_threat_intel_tools_by_default(self):
        """InvestigationAgent default registry contains all 7 approved tools."""
        agent = InvestigationAgent()
        tools = agent.tool_registry.list_tools()
        self.assertIn("threat_intel", tools)
        self.assertIn("mitre_lookup", tools)
        self.assertEqual(len(tools), 7)

    def test_investigation_with_threat_intel_enrichment(self):
        """InvestigationAgent queries threat_intel, records TI evidence, and produces grounded report."""
        provider = MockProvider()

        # Step 1: Query process activity
        turn1 = json.dumps({
            "action": "investigate",
            "tool_name": "process_activity",
            "tool_input": {"scenario": "malicious_powershell"},
            "purpose": "Check process details",
        })
        provider.register_response("INVESTIGATION STEP 1", turn1)

        # Step 2: Query threat intelligence for C2 IP
        turn2 = json.dumps({
            "action": "investigate",
            "tool_name": "threat_intel",
            "tool_input": {"indicator": "198.51.100.200", "indicator_type": "ip"},
            "purpose": "Lookup C2 reputation for external IP",
        })
        provider.register_response("INVESTIGATION STEP 2", turn2)

        # Step 3: Finish
        turn3 = json.dumps({
            "action": "finish",
            "stop_reason": "Identified FIN7 Cobalt Strike C2 server",
        })
        provider.register_response("INVESTIGATION STEP 3", turn3)

        # Final synthesis citing PROC-003 and TI evidence
        conclusion = json.dumps({
            "status": "completed",
            "conclusion": "confirmed_malicious",
            "severity": "critical",
            "confidence": 0.98,
            "findings": [
                {
                    "finding_id": "FIND-TI-01",
                    "title": "Confirmed FIN7 Cobalt Strike C2",
                    "description": "Host established outbound communication to known FIN7 C2 infrastructure.",
                    "evidence_ids": ["PROC-003", "TI-198_51_100_200"],
                    "confidence": 0.98,
                }
            ],
            "recommended_actions": [
                {"action": "Isolate host and block 198.51.100.200 on boundary firewall", "priority": "immediate"}
            ],
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(
            llm_client=LLMClient(provider=provider),
            max_steps=5,
        )

        result = agent.investigate(self.sample_request)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.conclusion, "confirmed_malicious")
        self.assertEqual(len(result.investigation_steps), 2)
        self.assertEqual(result.investigation_steps[0].tool_name, "process_activity")
        self.assertEqual(result.investigation_steps[1].tool_name, "threat_intel")

        # Verify TI evidence was gathered and grounded
        ti_step_evidence = result.investigation_steps[1].evidence_ids
        self.assertIn("TI-198_51_100_200", ti_step_evidence)
        self.assertEqual(result.findings[0].evidence_ids, ["PROC-003", "TI-198_51_100_200"])
        self.assertEqual(len(result.metadata["hallucinated_evidence_attempts"]), 0)

    def test_investigation_with_mitre_technique_lookup(self):
        """InvestigationAgent queries mitre_lookup and grounds findings in MITRE evidence."""
        provider = MockProvider()

        # Step 1: Lookup MITRE technique T1059.001
        turn1 = json.dumps({
            "action": "investigate",
            "tool_name": "mitre_lookup",
            "tool_input": {"technique_id": "T1059.001"},
            "purpose": "Map PowerShell activity to ATT&CK matrix",
        })
        provider.register_response("INVESTIGATION STEP 1", turn1)

        # Step 2: Finish
        turn2 = json.dumps({
            "action": "finish",
            "stop_reason": "MITRE technique mapped",
        })
        provider.register_response("INVESTIGATION STEP 2", turn2)

        # Final synthesis citing initial EVT and MITRE evidence
        conclusion = json.dumps({
            "status": "completed",
            "conclusion": "confirmed_malicious",
            "severity": "high",
            "confidence": 0.90,
            "findings": [
                {
                    "finding_id": "FIND-MITRE-01",
                    "title": "Adversary execution via PowerShell",
                    "description": "Correlated PowerShell execution with T1059.001.",
                    "evidence_ids": ["EVT-003", "MITRE-T1059_001"],
                    "confidence": 0.90,
                }
            ],
            "recommended_actions": [],
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))
        result = agent.investigate(self.sample_request)

        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.investigation_steps), 1)
        self.assertEqual(result.investigation_steps[0].tool_name, "mitre_lookup")
        self.assertIn("MITRE-T1059_001", result.investigation_steps[0].evidence_ids)
        self.assertEqual(result.findings[0].evidence_ids, ["EVT-003", "MITRE-T1059_001"])

    def test_hallucinated_threat_intel_evidence_is_rejected(self):
        """InvestigationAgent rejects unqueried or invented TI evidence IDs in findings."""
        provider = MockProvider()

        # Step 1: Finish immediately
        provider.register_response("INVESTIGATION STEP 1", json.dumps({"action": "finish", "stop_reason": "done"}))

        # Model claims invented threat intel evidence ID 'TI-FAKE_APT99_HOST'
        conclusion = json.dumps({
            "status": "completed",
            "conclusion": "confirmed_malicious",
            "severity": "high",
            "confidence": 0.85,
            "findings": [
                {
                    "finding_id": "FIND-01",
                    "title": "Fake Intel Claim",
                    "description": "Adversary attribution without lookup",
                    "evidence_ids": ["EVT-003", "TI-FAKE_APT99_HOST"],
                    "confidence": 0.85,
                }
            ],
            "recommended_actions": [],
        })
        provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion)
        provider.default_response = conclusion

        agent = InvestigationAgent(llm_client=LLMClient(provider=provider))
        result = agent.investigate(self.sample_request)

        # Real EVT-003 is preserved, fake TI ID is stripped
        self.assertEqual(result.findings[0].evidence_ids, ["EVT-003"])
        self.assertIn("TI-FAKE_APT99_HOST", result.metadata["hallucinated_evidence_attempts"])

    def test_disabled_threat_intel_rejects_threat_intel_tool(self):
        """InvestigationAgent with enable_threat_intel=False rejects threat_intel calls."""
        provider = MockProvider(
            default_response=json.dumps({
                "action": "investigate",
                "tool_name": "threat_intel",
                "tool_input": {"indicator": "198.51.100.200"},
                "purpose": "Lookup when disabled",
            })
        )

        agent = InvestigationAgent(
            llm_client=LLMClient(provider=provider),
            enable_threat_intel=False,
        )

        with self.assertRaises(LLMResponseError) as ctx:
            agent.investigate(self.sample_request)
        self.assertIn("Hallucinated or unapproved tool", str(ctx.exception))

if __name__ == "__main__":
    unittest.main()
