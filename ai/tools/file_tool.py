"""
AegisX File Activity Tool
==========================

Read-only investigation tool for inspecting synthetic file creation,
modification, and write events. Strictly query-only; never deletes or mutates files.
"""

from typing import Any, Dict

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.synthetic_data import query_synthetic_telemetry

class FileActivityTool(BaseInvestigationTool):
    """Safe read-only tool querying synthetic file system telemetry."""

    @property
    def name(self) -> str:
        return "file_activity"

    @property
    def description(self) -> str:
        return "Inspect file operations (creation, modification), file paths, hashes, and associated processes."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "path": {"type": "string", "description": "File path filter"},
                "operation": {"type": "string", "description": "Operation type (file_created, file_modified)"},
                "scenario": {"type": "string", "description": "Synthetic scenario filter (optional)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "file_events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "path": {"type": "string"},
                            "operation": {"type": "string"},
                            "process": {"type": "string"},
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

        events = query_synthetic_telemetry("file", tool_input)

        path_filter = tool_input.get("path")
        if path_filter:
            events = [e for e in events if path_filter.lower() in e.get("path", "").lower()]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"file_events": events, "count": len(events)},
            evidence=events,
            metadata={"query_params": tool_input},
        )
