"""
AegisX Base Investigation Tool Interface
=========================================

Abstract interface defining safe, read-only security investigation tools.
Zero execution of external commands, zero shell access, zero filesystem modification.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class ToolResult:
    """Standard normalized result returned by all investigation tools."""
    success: bool
    tool_name: str
    data: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "data": self.data,
            "evidence": self.evidence,
            "error": self.error,
            "metadata": self.metadata,
        }

class BaseInvestigationTool(ABC):
    """
    Abstract base class for all AegisX read-only investigation tools.
    Strictly query-only. Prohibits any endpoint modification or OS command execution.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the tool."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Analyst-facing description of the tool's investigation purpose."""
        pass

    @property
    @abstractmethod
    def input_schema(self) -> Dict[str, Any]:
        """JSON Schema specification for tool input parameters."""
        pass

    @property
    @abstractmethod
    def output_schema(self) -> Dict[str, Any]:
        """JSON Schema specification for tool output data."""
        pass

    @property
    def read_only(self) -> bool:
        """Safety invariant: All investigation tools are strictly read-only."""
        return True

    @abstractmethod
    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        """
        Execute safe read-only investigation query on synthetic telemetry.

        Args:
            tool_input: Dictionary of query parameters matching input_schema.

        Returns:
            ToolResult: Normalized execution result with structured evidence.
        """
        pass
