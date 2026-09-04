#!/usr/bin/env python3
"""
AegisX Threat Intelligence & MITRE Tools Unit Tests
===================================================

Tests ThreatIntelTool and MitreTool execution, structured evidence generation,
ToolRegistry integration, and read-only safety invariants.

Usage:
    python -m unittest tests/test_threat_intel_tools.py -v
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.registry import (
    ToolRegistry,
    create_default_registry,
    create_threat_intel_registry,
)
from ai.tools.threat_intel_tool import ThreatIntelTool
from ai.tools.mitre_tool import MitreTool

class TestThreatIntelTool(unittest.TestCase):
    """Unit tests for ThreatIntelTool."""

    def setUp(self):
        self.tool = ThreatIntelTool()

    def test_tool_metadata_and_readonly(self):
        """Tool attributes adhere to BaseInvestigationTool invariants."""
        self.assertEqual(self.tool.name, "threat_intel")
        self.assertTrue(self.tool.read_only)
        self.assertIn("indicator", self.tool.input_schema.get("required", []))

    def test_query_known_malicious_ip(self):
        """ThreatIntelTool returns structured reputation and evidence for known C2 IP."""
        res = self.tool.execute({"indicator": "198.51.100.200", "indicator_type": "ip"})
        self.assertTrue(res.success)
        self.assertTrue(res.data["found"])
        self.assertEqual(res.data["reputation"], "malicious")
        self.assertEqual(res.data["threat_actor"], "FIN7")
        self.assertEqual(res.data["malware_family"], "Cobalt Strike")

        # Verify evidence item
        self.assertEqual(len(res.evidence), 1)
        evt = res.evidence[0]
        self.assertEqual(evt["id"], "TI-198_51_100_200")
        self.assertEqual(evt["type"], "threat_intel_match")
        self.assertIn("Cobalt Strike", evt["description"])

    def test_query_known_malicious_hash(self):
        """ThreatIntelTool returns malware profile and evidence for known payload hash."""
        hash_val = "7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7"
        res = self.tool.execute({"indicator": hash_val})
        self.assertTrue(res.success)
        self.assertTrue(res.data["found"])
        self.assertEqual(res.data["reputation"], "malicious")
        self.assertEqual(len(res.evidence), 1)
        self.assertTrue(res.evidence[0]["id"].startswith("TI-7a35e729"))

    def test_query_benign_internal_ip(self):
        """ThreatIntelTool returns benign reputation without generating alerts."""
        res = self.tool.execute({"indicator": "10.0.10.2"})
        self.assertTrue(res.success)
        self.assertTrue(res.data["found"])
        self.assertEqual(res.data["reputation"], "benign")
        self.assertEqual(len(res.evidence), 1)

    def test_query_unknown_indicator(self):
        """ThreatIntelTool returns found=False with empty evidence for unknown indicator."""
        res = self.tool.execute({"indicator": "192.0.2.254"})
        self.assertTrue(res.success)
        self.assertFalse(res.data["found"])
        self.assertEqual(res.data["reputation"], "unknown")
        self.assertEqual(len(res.evidence), 0)

    def test_invalid_input_handling(self):
        """ThreatIntelTool returns error when indicator is missing or input is not a dict."""
        res1 = self.tool.execute("not_a_dictionary")
        self.assertFalse(res1.success)
        self.assertIn("Invalid tool input", res1.error)

        res2 = self.tool.execute({"not_an_indicator": "test"})
        self.assertFalse(res2.success)
        self.assertIn("indicator", res2.error)

class TestMitreTool(unittest.TestCase):
    """Unit tests for MitreTool."""

    def setUp(self):
        self.tool = MitreTool()

    def test_tool_metadata_and_readonly(self):
        """Tool attributes adhere to BaseInvestigationTool invariants."""
        self.assertEqual(self.tool.name, "mitre_lookup")
        self.assertTrue(self.tool.read_only)
        self.assertIn("technique_id", self.tool.input_schema.get("properties", {}))

    def test_lookup_by_technique_id(self):
        """MitreTool returns technique details and structured evidence for T1059.001."""
        res = self.tool.execute({"technique_id": "T1059.001"})
        self.assertTrue(res.success)
        self.assertTrue(res.data["found"])
        self.assertTrue(res.data["count"] >= 1)
        t = res.data["techniques"][0]
        self.assertEqual(t["technique_id"], "T1059.001")
        self.assertEqual(t["technique_name"], "PowerShell")
        self.assertEqual(t["tactic"], "Execution")

        # Verify evidence item
        self.assertTrue(len(res.evidence) >= 1)
        evt = res.evidence[0]
        self.assertEqual(evt["id"], "MITRE-T1059_001")
        self.assertEqual(evt["type"], "other")
        self.assertIn("PowerShell", evt["description"])

    def test_lookup_by_keyword_query(self):
        """MitreTool returns matching techniques for keyword search."""
        res = self.tool.execute({"query": "phishing"})
        self.assertTrue(res.success)
        self.assertTrue(res.data["found"])
        self.assertTrue(res.data["count"] >= 1)
        names = [t["technique_name"] for t in res.data["techniques"]]
        self.assertTrue(any("phishing" in n.lower() for n in names))

    def test_lookup_unknown_technique(self):
        """MitreTool returns found=False for non-existent technique."""
        res = self.tool.execute({"technique_id": "T9999.999"})
        self.assertTrue(res.success)
        self.assertFalse(res.data["found"])
        self.assertEqual(res.data["count"], 0)
        self.assertEqual(len(res.evidence), 0)

    def test_invalid_input_handling(self):
        """MitreTool returns error when neither technique_id nor query is provided."""
        res1 = self.tool.execute({})
        self.assertFalse(res1.success)
        self.assertIn("requires either", res1.error)

        res2 = self.tool.execute("not_a_dictionary")
        self.assertFalse(res2.success)

class TestToolRegistryIntegration(unittest.TestCase):
    """Unit tests for ToolRegistry with threat intel tools."""

    def test_default_registry_backward_compatibility(self):
        """create_default_registry() without flags still returns exact 5 core tools."""
        reg = create_default_registry()
        expected = [
            "authentication",
            "file_activity",
            "network_activity",
            "process_activity",
            "related_alerts",
        ]
        self.assertEqual(reg.list_tools(), expected)

    def test_threat_intel_registry_has_all_seven_tools(self):
        """create_threat_intel_registry() registers all 7 investigation and intelligence tools."""
        reg = create_threat_intel_registry()
        expected = [
            "authentication",
            "file_activity",
            "mitre_lookup",
            "network_activity",
            "process_activity",
            "related_alerts",
            "threat_intel",
        ]
        self.assertEqual(reg.list_tools(), expected)
        self.assertIsInstance(reg.get("threat_intel"), ThreatIntelTool)
        self.assertIsInstance(reg.get("mitre_lookup"), MitreTool)

    def test_manual_registration_of_threat_tools(self):
        """Threat tools can be registered into any custom ToolRegistry instance."""
        reg = ToolRegistry()
        reg.register(ThreatIntelTool())
        reg.register(MitreTool())
        self.assertTrue(reg.has("threat_intel"))
        self.assertTrue(reg.has("mitre_lookup"))

    def test_safety_and_prohibited_tokens(self):
        """Verify threat_intel_tool and mitre_tool contain no subprocess or OS command execution."""
        tools_dir = PROJECT_ROOT / "ai" / "tools"
        prohibited = ["subprocess", "os.system", "os.popen", "shell=True", "exec(", "eval("]
        for fname in ("threat_intel_tool.py", "mitre_tool.py"):
            py_file = tools_dir / fname
            code = py_file.read_text(encoding="utf-8")
            for token in prohibited:
                self.assertNotIn(
                    token,
                    code,
                    f"Safety violation: Found prohibited token '{token}' in {fname}",
                )

if __name__ == "__main__":
    unittest.main()
