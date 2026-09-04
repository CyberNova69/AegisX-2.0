#!/usr/bin/env python3
"""
AegisX TriageAgent Unit Tests
==============================

Comprehensive test suite for TriageAgent using MockProvider.
All tests run 100% offline without API key or internet dependencies.

Usage:
    python -m unittest tests/test_triage_agent.py -v
"""

import json
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.triage_agent import TriageAgent
from ai.agents.schemas import AlertInput, TriageResult
from ai.llm import LLMClient, LLMResponseError, LLMRateLimitError
from ai.llm.providers.mock import MockProvider

class TestTriageAgent(unittest.TestCase):
    """Unit test suite for TriageAgent."""

    def setUp(self):
        self.sample_alert = {
            "alert": {
                "title": "WINWORD spawning PowerShell with Encoded Command",
                "severity": "high",
                "source": "EDR",
                "rule_id": "RULE-5264",
            },
            "context": {
                "hostname": "PC-042",
                "username": "employee01",
                "department": "Finance",
                "os": "Windows 10 Enterprise",
            },
            "evidence": [
                {
                    "id": "EVT-001",
                    "type": "process_creation",
                    "description": "WINWORD.EXE spawned powershell.exe with -Enc parameter",
                    "timestamp": "2026-01-15T10:00:00+00:00",
                },
                {
                    "id": "EVT-002",
                    "type": "network_connection",
                    "description": "powershell.exe connected to 198.51.100.42:443",
                    "timestamp": "2026-01-15T10:00:15+00:00",
                },
            ],
        }

    def test_valid_malicious_triage(self):
        """TriageAgent correctly processes a valid malicious alert."""
        mock_response = json.dumps({
            "classification": "confirmed_malicious",
            "severity": "high",
            "confidence": 0.95,
            "investigation_required": True,
            "summary": "Macro document spawned obfuscated PowerShell establishing C2 connection.",
            "findings": [
                {"finding": "WINWORD launched encoded PowerShell", "evidence_ids": ["EVT-001"]},
                {"finding": "PowerShell established outbound C2 connection", "evidence_ids": ["EVT-002"]},
            ],
            "evidence_ids": ["EVT-001", "EVT-002"],
            "recommended_actions": [
                {"action": "Isolate host PC-042", "priority": "immediate", "rationale": "Prevent lateral movement"}
            ],
        })

        provider = MockProvider(default_response=mock_response)
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        result = agent.triage(self.sample_alert)

        self.assertIsInstance(result, TriageResult)
        self.assertEqual(result.classification, "confirmed_malicious")
        self.assertEqual(result.severity, "high")
        self.assertEqual(result.confidence, 0.95)
        self.assertTrue(result.investigation_required)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.evidence_ids, ["EVT-001", "EVT-002"])
        self.assertEqual(result.recommended_actions[0].priority, "immediate")

    def test_valid_benign_triage(self):
        """TriageAgent correctly processes a valid benign alert."""
        mock_response = json.dumps({
            "classification": "benign",
            "severity": "low",
            "confidence": 0.90,
            "investigation_required": False,
            "summary": "Legitimate admin script execution.",
            "findings": [
                {"finding": "Authorized maintenance script executed by admin01", "evidence_ids": ["EVT-001"]}
            ],
            "evidence_ids": ["EVT-001"],
            "recommended_actions": [
                {"action": "No containment required", "priority": "low", "rationale": "Normal IT activity"}
            ],
        })

        provider = MockProvider(default_response=mock_response)
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        result = agent.triage(self.sample_alert)
        self.assertEqual(result.classification, "benign")
        self.assertFalse(result.investigation_required)

    def test_insufficient_evidence_triage(self):
        """TriageAgent correctly handles insufficient_evidence triage decision."""
        mock_response = json.dumps({
            "classification": "insufficient_evidence",
            "severity": "medium",
            "confidence": 0.30,
            "investigation_required": True,
            "summary": "certutil execution observed without full parameters.",
            "findings": [
                {"finding": "certutil process created", "evidence_ids": ["EVT-001"]}
            ],
            "evidence_ids": ["EVT-001"],
            "recommended_actions": [
                {"action": "Collect command line telemetry", "priority": "medium", "rationale": "Incomplete data"}
            ],
        })

        provider = MockProvider(default_response=mock_response)
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        result = agent.triage(self.sample_alert)
        self.assertEqual(result.classification, "insufficient_evidence")
        self.assertTrue(result.investigation_required)

    def test_broken_evidence_reference_rejection(self):
        """TriageAgent rejects findings that reference non-existent evidence IDs."""
        mock_response = json.dumps({
            "classification": "likely_malicious",
            "severity": "high",
            "confidence": 0.80,
            "investigation_required": True,
            "summary": "Unsupported claim.",
            "findings": [
                {"finding": "Stole credentials", "evidence_ids": ["EVT-999"]}  # EVT-999 does not exist!
            ],
        })

        provider = MockProvider(default_response=mock_response)
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError) as ctx:
            agent.triage(self.sample_alert)
        self.assertIn("EVT-999", str(ctx.exception))

    def test_invalid_classification_enum_rejection(self):
        """TriageAgent rejects invalid classification enum values."""
        mock_response = json.dumps({
            "classification": "super_evil_malware",
            "severity": "high",
            "confidence": 0.80,
            "findings": [],
        })

        provider = MockProvider(default_response=mock_response)
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError):
            agent.triage(self.sample_alert)

    def test_invalid_severity_enum_rejection(self):
        """TriageAgent rejects invalid severity enum values."""
        mock_response = json.dumps({
            "classification": "suspicious",
            "severity": "catastrophic",
            "confidence": 0.50,
            "findings": [],
        })

        provider = MockProvider(default_response=mock_response)
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError):
            agent.triage(self.sample_alert)

    def test_invalid_confidence_out_of_bounds_rejection(self):
        """TriageAgent rejects confidence values outside [0.0, 1.0]."""
        mock_response = json.dumps({
            "classification": "suspicious",
            "severity": "medium",
            "confidence": 1.5,
            "findings": [],
        })

        provider = MockProvider(default_response=mock_response)
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError):
            agent.triage(self.sample_alert)

    def test_missing_alert_input_validation(self):
        """AlertInput rejects invalid alert dictionaries."""
        with self.assertRaises(ValueError):
            AlertInput.from_dict({"context": {}, "evidence": []})

        with self.assertRaises(ValueError):
            AlertInput.from_dict({"alert": {}, "context": {}, "evidence": []})  # empty evidence array

    def test_malformed_json_handling(self):
        """TriageAgent raises LLMResponseError on malformed LLM JSON response."""
        provider = MockProvider(default_response="Not a JSON string")
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMResponseError):
            agent.triage(self.sample_alert)

    def test_llm_exception_propagation(self):
        """TriageAgent propagates underlying provider errors cleanly."""
        provider = MockProvider(error_to_raise=LLMRateLimitError("Rate limit hit", provider="mock"))
        agent = TriageAgent(llm_client=LLMClient(provider=provider))

        with self.assertRaises(LLMRateLimitError):
            agent.triage(self.sample_alert)

    def test_provider_sdk_isolation(self):
        """Verify TriageAgent does NOT import vendor SDKs directly."""
        import ai.agents.triage_agent as mod
        source_text = Path(mod.__file__).read_text(encoding="utf-8")

        self.assertNotIn("import openai", source_text)
        self.assertNotIn("import google", source_text)
        self.assertNotIn("import anthropic", source_text)
        self.assertIn("from ai.llm import LLMClient", source_text)

if __name__ == "__main__":
    unittest.main()
