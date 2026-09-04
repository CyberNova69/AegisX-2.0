"""
AegisX Authentication Tool
===========================

Read-only investigation tool for inspecting synthetic authentication events,
logon types, source IPs, and failure counts.
"""

from typing import Any, Dict

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.synthetic_data import query_synthetic_telemetry

class AuthenticationTool(BaseInvestigationTool):
    """Safe read-only tool querying synthetic authentication and logon events."""

    @property
    def name(self) -> str:
        return "authentication"

    @property
    def description(self) -> str:
        return "Inspect authentication events, logon types, source IPs, and failure counts."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "username": {"type": "string", "description": "User account filter"},
                "event_type": {"type": "string", "description": "Authentication event type filter"},
                "scenario": {"type": "string", "description": "Synthetic scenario filter (optional)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "auth_events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "username": {"type": "string"},
                            "source_ip": {"type": "string"},
                            "destination_endpoint": {"type": "string"},
                            "event_type": {"type": "string"},
                            "success": {"type": "boolean"},
                            "timestamp": {"type": "string"},
                            "failure_count": {"type": "integer"},
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

        events = query_synthetic_telemetry("auth", tool_input)

        username = tool_input.get("username")
        if username:
            events = [e for e in events if username.lower() in e.get("username", "").lower()]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"auth_events": events, "count": len(events)},
            evidence=events,
            metadata={"query_params": tool_input},
        )
