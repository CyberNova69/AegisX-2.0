"""
AegisX Related Alerts Tool
===========================

Read-only investigation tool for finding correlated and historical alerts
linked by endpoint, user, or correlation identifier.
"""

from typing import Any, Dict

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.synthetic_data import query_synthetic_telemetry

class RelatedAlertsTool(BaseInvestigationTool):
    """Safe read-only tool querying correlated synthetic alerts."""

    @property
    def name(self) -> str:
        return "related_alerts"

    @property
    def description(self) -> str:
        return "Retrieve related or correlated alerts for the same endpoint, user, or correlation ID."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "user": {"type": "string", "description": "User identifier filter"},
                "correlation_id": {"type": "string", "description": "Correlation identifier filter"},
                "scenario": {"type": "string", "description": "Synthetic scenario filter (optional)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "related_alerts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "severity": {"type": "string"},
                            "endpoint": {"type": "string"},
                            "user": {"type": "string"},
                            "timestamp": {"type": "string"},
                            "correlation_id": {"type": "string"},
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

        events = query_synthetic_telemetry("alerts", tool_input)

        corr_id = tool_input.get("correlation_id")
        if corr_id:
            events = [e for e in events if corr_id in e.get("correlation_id", "")]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"related_alerts": events, "count": len(events)},
            evidence=events,
            metadata={"query_params": tool_input},
        )
