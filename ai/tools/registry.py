"""
AegisX Tool Registry
====================

Central registry and allowlist mechanism for all read-only investigation tools.
Ensures the LLM cannot execute arbitrary or unapproved tools.
"""

from typing import Dict, List, Optional

from ai.tools.base import BaseInvestigationTool

class ToolRegistry:
    """
    Registry for approved, read-only investigation tools.
    Rejects unknown or unauthorized tools with controlled errors.
    """

    def __init__(self):
        self._tools: Dict[str, BaseInvestigationTool] = {}

    def register(self, tool: BaseInvestigationTool) -> None:
        """Register an approved read-only tool."""
        if not isinstance(tool, BaseInvestigationTool):
            raise TypeError("Tool must inherit from BaseInvestigationTool.")
        if not tool.read_only:
            raise ValueError(f"Refusing to register non-read-only tool: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseInvestigationTool:
        """Retrieve tool by name, or raise KeyError for unknown tools."""
        if name not in self._tools:
            available = sorted(list(self._tools.keys()))
            raise KeyError(f"Tool '{name}' is not registered. Available tools: {available}")
        return self._tools[name]

    def has(self, name: str) -> bool:
        """Check whether tool is registered."""
        return name in self._tools

    def list_tools(self) -> List[str]:
        """Return list of all registered tool names."""
        return sorted(list(self._tools.keys()))

    def get_tool_descriptions(self) -> Dict[str, str]:
        """Return mapping of tool name to purpose description for prompting."""
        return {name: tool.description for name, tool in self._tools.items()}

def create_default_registry(include_threat_intel: bool = False) -> ToolRegistry:
    """
    Factory creating a ToolRegistry populated with the approved read-only tools:
      - process_activity
      - network_activity
      - authentication
      - file_activity
      - related_alerts
    Optionally includes (Phase 5):
      - threat_intel
      - mitre_lookup
    """
    from ai.tools.process_tool import ProcessActivityTool
    from ai.tools.network_tool import NetworkActivityTool
    from ai.tools.auth_tool import AuthenticationTool
    from ai.tools.file_tool import FileActivityTool
    from ai.tools.alerts_tool import RelatedAlertsTool

    registry = ToolRegistry()
    registry.register(ProcessActivityTool())
    registry.register(NetworkActivityTool())
    registry.register(AuthenticationTool())
    registry.register(FileActivityTool())
    registry.register(RelatedAlertsTool())

    if include_threat_intel:
        from ai.tools.threat_intel_tool import ThreatIntelTool
        from ai.tools.mitre_tool import MitreTool
        registry.register(ThreatIntelTool())
        registry.register(MitreTool())

    return registry

def create_threat_intel_registry() -> ToolRegistry:
    """Convenience factory creating a ToolRegistry with all 7 investigation and intelligence tools."""
    return create_default_registry(include_threat_intel=True)

