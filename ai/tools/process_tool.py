"""
AegisX Process Activity Tool
==============================

Read-only investigation tool for inspecting synthetic process telemetry,
parent/child relationships, command-line arguments, and hashes.
"""

from typing import Any, Dict

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.synthetic_data import query_synthetic_telemetry

class ProcessActivityTool(BaseInvestigationTool):
    """Safe read-only tool querying synthetic process creation and execution events."""

    @property
    def name(self) -> str:
        return "process_activity"

    @property
    def description(self) -> str:
        return "Inspect process execution telemetry, parent/child relationships, command lines, and hashes."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "username": {"type": "string", "description": "User context to query"},
                "process_name": {"type": "string", "description": "Process executable name filter"},
                "scenario": {"type": "string", "description": "Synthetic scenario filter (optional)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "processes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "process_id": {"type": "integer"},
                            "process_name": {"type": "string"},
                            "parent_process": {"type": "string"},
                            "command_line": {"type": "string"},
                            "user": {"type": "string"},
                            "timestamp": {"type": "string"},
                            "hash": {"type": "string"},
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

        events = query_synthetic_telemetry("process", tool_input)

        # Filter by process_name if provided
        proc_filter = tool_input.get("process_name")
        if proc_filter:
            events = [e for e in events if proc_filter.lower() in e.get("process_name", "").lower()]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"processes": events, "count": len(events)},
            evidence=events,
            metadata={"query_params": tool_input},
        )
