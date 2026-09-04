"""
AegisX Investigation & Threat Intelligence Tools Package
=========================================================

Exports read-only investigation tools, intelligence lookup tools,
base interfaces, and the central tool registry.
"""

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.registry import (
    ToolRegistry,
    create_default_registry,
    create_threat_intel_registry,
)
from ai.tools.process_tool import ProcessActivityTool
from ai.tools.network_tool import NetworkActivityTool
from ai.tools.auth_tool import AuthenticationTool
from ai.tools.file_tool import FileActivityTool
from ai.tools.alerts_tool import RelatedAlertsTool
from ai.tools.threat_intel_tool import ThreatIntelTool
from ai.tools.mitre_tool import MitreTool

__all__ = [
    "BaseInvestigationTool",
    "ToolResult",
    "ToolRegistry",
    "create_default_registry",
    "create_threat_intel_registry",
    "ProcessActivityTool",
    "NetworkActivityTool",
    "AuthenticationTool",
    "FileActivityTool",
    "RelatedAlertsTool",
    "ThreatIntelTool",
    "MitreTool",
]
