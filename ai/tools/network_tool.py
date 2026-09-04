"""
AegisX Network Activity Tool
==============================

Read-only investigation tool for inspecting synthetic network telemetry,
connections, ports, protocols, and states.
"""

from typing import Any, Dict

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.synthetic_data import query_synthetic_telemetry

class NetworkActivityTool(BaseInvestigationTool):
    """Safe read-only tool querying synthetic network connection telemetry."""

    @property
    def name(self) -> str:
        return "network_activity"

    @property
    def description(self) -> str:
        return "Inspect outbound and inbound network connections, destinations, ports, and protocols."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "destination_ip": {"type": "string", "description": "Destination IP address filter"},
                "destination_port": {"type": "integer", "description": "Destination port filter"},
                "scenario": {"type": "string", "description": "Synthetic scenario filter (optional)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "connections": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "source_endpoint": {"type": "string"},
                            "destination_ip": {"type": "string"},
                            "destination_port": {"type": "integer"},
                            "protocol": {"type": "string"},
                            "timestamp": {"type": "string"},
                            "process": {"type": "string"},
                            "connection_status": {"type": "string"},
                            "description": {"type": "string"},
                        },
                    },
                }
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="Invalid tool input: expected dictionary.",
            )

        events = query_synthetic_telemetry("network", tool_input)

        dest_ip = tool_input.get("destination_ip")
        if dest_ip:
            events = [e for e in events if dest_ip in e.get("destination_ip", "")]

        dest_port = tool_input.get("destination_port")
        if dest_port is not None:
            events = [e for e in events if e.get("destination_port") == dest_port]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"connections": events, "count": len(events)},
            evidence=events,
            metadata={"query_params": tool_input},
        )
