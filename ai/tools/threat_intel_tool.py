"""
AegisX Threat Intelligence Investigation Tool
==============================================

Read-only investigation tool for querying synthetic threat intelligence
for indicator reputation (IP, domain, hash), malware family, threat actor, and tags.
Produces structured evidence items of type 'threat_intel_match'.
"""

import re
from typing import Any, Dict, Optional

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.synthetic_threat_intel import get_threat_intel

class ThreatIntelTool(BaseInvestigationTool):
    """Safe read-only tool querying synthetic threat intelligence database."""

    @property
    def name(self) -> str:
        return "threat_intel"

    @property
    def description(self) -> str:
        return (
            "Query threat intelligence for indicator reputation (IP, domain, hash), "
            "associated threat actors, malware families, and MITRE techniques."
        )

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "required": ["indicator"],
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "IP address, file hash, or domain to investigate",
                },
                "indicator_type": {
                    "type": "string",
                    "enum": ["ip", "hash", "domain"],
                    "description": "Optional type of the indicator",
                },
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "found": {"type": "boolean"},
                "indicator": {"type": "string"},
                "reputation": {"type": "string"},
                "intel": {"type": "object"},
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="Invalid tool input: expected dictionary.",
            )

        indicator = tool_input.get("indicator")
        if not indicator or not isinstance(indicator, str) or not indicator.strip():
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="Tool input requires a non-empty 'indicator' string.",
            )

        indicator = indicator.strip()
        indicator_type = tool_input.get("indicator_type")
        intel = get_threat_intel(indicator, indicator_type)

        if intel:
            clean_suffix = re.sub(r"[^A-Za-z0-9]", "_", indicator)[:32]
            evidence_id = f"TI-{clean_suffix}"
            
            evidence_item = {
                "id": evidence_id,
                "type": "threat_intel_match",
                "description": (
                    f"Threat intelligence match for {indicator}: {intel['reputation'].upper()} "
                    f"({intel.get('malware_family', 'Unknown')} attributed to {intel.get('threat_actor', 'Unknown')})"
                ),
                "timestamp": "2026-02-20T00:00:00Z",
                "raw_data": intel,
            }

            return ToolResult(
                success=True,
                tool_name=self.name,
                data={
                    "found": True,
                    "indicator": indicator,
                    "reputation": intel.get("reputation", "unknown"),
                    "threat_actor": intel.get("threat_actor", "Unknown"),
                    "malware_family": intel.get("malware_family", "None"),
                    "intel": intel,
                },
                evidence=[evidence_item],
                metadata={"indicator": indicator, "query_params": tool_input},
            )

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={
                "found": False,
                "indicator": indicator,
                "reputation": "unknown",
                "message": f"No threat intelligence found for indicator '{indicator}'.",
            },
            evidence=[],
            metadata={"indicator": indicator, "query_params": tool_input},
        )
