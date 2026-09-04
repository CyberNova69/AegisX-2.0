#!/usr/bin/env python3
"""
AegisX Investigation Tools Unit & Safety Tests
==============================================

Tests read-only investigation tool abstraction, registry, mock tools,
and verifies strict safety invariants (no subprocess, no shell, no file deletion).

Usage:
    python -m unittest tests/test_investigation_tools.py -v
"""

import inspect
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.registry import ToolRegistry, create_default_registry
from ai.tools.process_tool import ProcessActivityTool
from ai.tools.network_tool import NetworkActivityTool
from ai.tools.auth_tool import AuthenticationTool
from ai.tools.file_tool import FileActivityTool
from ai.tools.alerts_tool import RelatedAlertsTool
from ai.tools.synthetic_data import (
    SYNTHETIC_SCENARIOS,
    get_scenario,
    list_scenarios,
    query_synthetic_telemetry,
)

class TestInvestigationTools(unittest.TestCase):
    """Unit test suite for investigation tools and registry."""

    def setUp(self):
        self.registry = create_default_registry()

    # -------------------------------------------------------------------------
    # Registry Tests
    # -------------------------------------------------------------------------
    def test_default_registry_has_exact_five_tools(self):
        """Default registry must contain exactly the 5 approved investigation tools."""
        expected = [
            "authentication",
            "file_activity",
            "network_activity",
            "process_activity",
            "related_alerts",
        ]
        self.assertEqual(self.registry.list_tools(), expected)

    def test_registry_get_valid_tool(self):
        """Registry successfully retrieves registered tools."""
        tool = self.registry.get("process_activity")
        self.assertIsInstance(tool, ProcessActivityTool)
        self.assertTrue(self.registry.has("process_activity"))

    def test_registry_rejects_unknown_tool(self):
        """Registry raises KeyError for unknown tools."""
        self.assertFalse(self.registry.has("shell_exec"))
        with self.assertRaises(KeyError) as ctx:
            self.registry.get("shell_exec")
        self.assertIn("not registered", str(ctx.exception))

    def test_registry_rejects_invalid_type(self):
        """Registry rejects tools not inheriting from BaseInvestigationTool."""
        with self.assertRaises(TypeError):
            self.registry.register("not_a_tool")

    def test_registry_rejects_non_readonly_tool(self):
        """Registry rejects any tool attempting to set read_only to False."""
        class DangerousTool(BaseInvestigationTool):
            @property
            def name(self): return "dangerous"
            @property
            def description(self): return "destructive"
            @property
            def input_schema(self): return {}
            @property
            def output_schema(self): return {}
            @property
            def read_only(self): return False
            def execute(self, tool_input): return ToolResult(True, self.name)

        reg = ToolRegistry()
        with self.assertRaises(ValueError):
            reg.register(DangerousTool())

    def test_registry_tool_descriptions(self):
        """Registry returns dictionary of tool descriptions for prompting."""
        descs = self.registry.get_tool_descriptions()
        self.assertIn("process_activity", descs)
        self.assertIn("network_activity", descs)
        self.assertTrue(len(descs["process_activity"]) > 10)

    # -------------------------------------------------------------------------
    # Tool Result Tests
    # -------------------------------------------------------------------------
    def test_tool_result_structure_and_to_dict(self):
        """ToolResult correctly formats into normalized dictionary."""
        tr = ToolResult(
            success=True,
            tool_name="process_activity",
            data={"test": 123},
            evidence=[{"id": "EVT-01"}],
            metadata={"source": "unit_test"},
        )
        d = tr.to_dict()
        self.assertTrue(d["success"])
        self.assertEqual(d["tool_name"], "process_activity")
        self.assertEqual(d["data"], {"test": 123})
        self.assertEqual(d["evidence"], [{"id": "EVT-01"}])
        self.assertIsNone(d["error"])

    # -------------------------------------------------------------------------
    # Individual Tool Executions
    # -------------------------------------------------------------------------
    def test_process_activity_tool_execution(self):
        """ProcessActivityTool returns process execution telemetry."""
        tool = self.registry.get("process_activity")
        res = tool.execute({"scenario": "malicious_powershell"})
        self.assertTrue(res.success)
        self.assertEqual(res.tool_name, "process_activity")
        procs = res.data.get("processes", [])
        self.assertTrue(len(procs) > 0)
        self.assertIn("powershell.exe", procs[0]["process_name"])
        self.assertTrue(len(res.evidence) > 0)
        self.assertEqual(res.evidence[0]["id"], "PROC-003")

    def test_network_activity_tool_execution(self):
        """NetworkActivityTool returns network connection telemetry."""
        tool = self.registry.get("network_activity")
        res = tool.execute({"scenario": "malicious_powershell"})
        self.assertTrue(res.success)
        self.assertEqual(res.tool_name, "network_activity")
        conns = res.data.get("connections", [])
        self.assertTrue(len(conns) > 0)
        self.assertEqual(conns[0]["destination_port"], 4444)
        self.assertEqual(res.evidence[0]["id"], "NET-003")

    def test_authentication_tool_execution(self):
        """AuthenticationTool returns authentication events."""
        tool = self.registry.get("authentication")
        res = tool.execute({"scenario": "brute_force_authentication"})
        self.assertTrue(res.success)
        self.assertEqual(res.tool_name, "authentication")
        auths = res.data.get("auth_events", [])
        self.assertTrue(len(auths) > 0)
        self.assertEqual(auths[0]["failure_count"], 52)
        self.assertEqual(res.evidence[0]["id"], "AUTH-005")

    def test_file_activity_tool_execution(self):
        """FileActivityTool returns file system telemetry."""
        tool = self.registry.get("file_activity")
        res = tool.execute({"scenario": "multi_stage_attack"})
        self.assertTrue(res.success)
        self.assertEqual(res.tool_name, "file_activity")
        files = res.data.get("file_events", [])
        self.assertTrue(len(files) > 0)
        self.assertIn("HOW_TO_DECRYPT", files[0]["path"])
        self.assertEqual(res.evidence[0]["id"], "FILE-009")

    def test_related_alerts_tool_execution(self):
        """RelatedAlertsTool returns correlated alerts."""
        tool = self.registry.get("related_alerts")
        res = tool.execute({"scenario": "multi_stage_attack"})
        self.assertTrue(res.success)
        self.assertEqual(res.tool_name, "related_alerts")
        alts = res.data.get("related_alerts", [])
        self.assertTrue(len(alts) > 0)
        self.assertEqual(alts[0]["correlation_id"], "CORR-VSS-DEL")
        self.assertEqual(res.evidence[0]["id"], "ALT-CORR-009")

    def test_invalid_tool_input_handling(self):
        """Tools handle non-dictionary inputs gracefully without crashing."""
        for tool_name in self.registry.list_tools():
            tool = self.registry.get(tool_name)
            res = tool.execute("not_a_dictionary")
            self.assertFalse(res.success)
            self.assertIn("Invalid tool input", res.error)

    # -------------------------------------------------------------------------
    # Synthetic Telemetry Store Tests
    # -------------------------------------------------------------------------
    def test_synthetic_scenarios_coverage(self):
        """All 10 required synthetic scenarios are defined."""
        scenarios = list_scenarios()
        self.assertEqual(len(scenarios), 10)
        expected_keys = [
            "benign_powershell",
            "suspicious_powershell",
            "malicious_powershell",
            "suspicious_login",
            "brute_force_authentication",
            "suspicious_process_chain",
            "suspicious_outbound_connection",
            "suspicious_file_activity",
            "multi_stage_attack",
            "insufficient_evidence",
        ]
        actual_keys = [s["key"] for s in scenarios]
        for key in expected_keys:
            self.assertIn(key, actual_keys)

    def test_insufficient_evidence_scenario_returns_empty_telemetry(self):
        """insufficient_evidence scenario has minimal/empty telemetry."""
        scn = get_scenario("insufficient_evidence")
        self.assertIsNotNone(scn)
        self.assertEqual(scn["expected_conclusion"], "insufficient_evidence")
        self.assertEqual(len(scn["telemetry"]["process"]), 0)
        self.assertEqual(len(scn["telemetry"]["network"]), 0)

    # -------------------------------------------------------------------------
    # SAFETY TESTS (Step 14 Verification)
    # -------------------------------------------------------------------------
    def test_safety_all_tools_are_strictly_read_only(self):
        """Every registered tool has read_only = True."""
        for name in self.registry.list_tools():
            tool = self.registry.get(name)
            self.assertTrue(tool.read_only, f"Tool {name} must have read_only=True")

    def test_safety_no_prohibited_os_execution_in_tools(self):
        """Verify tool modules contain no subprocess, shell=True, exec, eval, or os.system."""
        tools_dir = PROJECT_ROOT / "ai" / "tools"
        prohibited_tokens = [
            "subprocess",
            "os.system",
            "os.popen",
            "shell=True",
            "exec(",
            "eval(",
            "shutil.rmtree",
            "os.remove",
            "os.unlink",
            "os.kill",
        ]

        for py_file in tools_dir.glob("*.py"):
            code = py_file.read_text(encoding="utf-8")
            for token in prohibited_tokens:
                self.assertNotIn(
                    token,
                    code,
                    f"Safety violation: Found prohibited token '{token}' in {py_file.name}",
                )

    def test_safety_no_destructive_methods_on_tools(self):
        """Verify tools expose no deletion, killing, or containment methods."""
        destructive_names = ["delete", "kill", "terminate", "block", "contain", "modify", "drop_table"]
        for tool_name in self.registry.list_tools():
            tool = self.registry.get(tool_name)
            methods = [m[0] for m in inspect.getmembers(tool, predicate=inspect.ismethod)]
            for d in destructive_names:
                for m in methods:
                    self.assertNotIn(d, m.lower(), f"Tool {tool_name} exposes dangerous method '{m}'")

if __name__ == "__main__":
    unittest.main()
