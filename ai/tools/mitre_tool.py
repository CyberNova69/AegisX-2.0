"""
AegisX MITRE ATT&CK Knowledge Tool
===================================

Read-only investigation tool for looking up MITRE ATT&CK techniques, tactics,
and descriptions from datasets/metadata/mitre_reference.json.
Generates structured evidence items for grounded adversary behavior mappings.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai.tools.base import BaseInvestigationTool, ToolResult

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MITRE_REFERENCE_FILE = PROJECT_ROOT / "datasets" / "metadata" / "mitre_reference.json"

class MitreTool(BaseInvestigationTool):
    """Safe read-only tool querying MITRE ATT&CK reference data."""

    def __init__(self, reference_path: Optional[Path] = None):
        self.reference_path = Path(reference_path) if reference_path else MITRE_REFERENCE_FILE
        self._cache: Optional[List[Dict[str, Any]]] = None

    def _load_reference(self) -> List[Dict[str, Any]]:
        """Load and cache MITRE reference data."""
        if self._cache is None:
            if self.reference_path.exists():
                with open(self.reference_path, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            else:
                self._cache = []
        return self._cache

    @property
    def name(self) -> str:
        return "mitre_lookup"

    @property
    def description(self) -> str:
        return (
            "Look up MITRE ATT&CK techniques by technique ID (e.g., T1059.001) "
            "or keyword query to map observed behaviors to tactics."
        )

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "Specific MITRE ATT&CK technique ID (e.g., 'T1059.001')",
                },
                "query": {
                    "type": "string",
                    "description": "Keyword search across technique names, tactics, and descriptions",
                },
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "found": {"type": "boolean"},
                "count": {"type": "integer"},
                "techniques": {"type": "array"},
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="Invalid tool input: expected dictionary.",
            )

        tid = tool_input.get("technique_id")
        query = tool_input.get("query")

        if not tid and not query:
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="Tool input requires either 'technique_id' or 'query'.",
            )

        all_techniques = self._load_reference()
        matches: List[Dict[str, Any]] = []

        if tid:
            clean_tid = tid.strip().upper()
            for item in all_techniques:
                if clean_tid in item.get("technique_id", "").upper():
                    matches.append(item)

        elif query:
            q_clean = query.strip().lower()
            for item in all_techniques:
                haystack = " ".join([
                    item.get("technique_id", ""),
                    item.get("technique_name", ""),
                    item.get("tactic", ""),
                    item.get("description", ""),
                ]).lower()
                if q_clean in haystack:
                    matches.append(item)

        if matches:
            evidence_items = []
            for m in matches[:3]:  # Limit top 3 matches for evidence
                t_id = m.get("technique_id", "UNKNOWN")
                clean_id = t_id.replace(".", "_")
                evidence_items.append({
                    "id": f"MITRE-{clean_id}",
                    "type": "other",
                    "description": (
                        f"MITRE ATT&CK {t_id} ({m.get('technique_name', 'Unknown')}) "
                        f"- Tactic: {m.get('tactic', 'Unknown')} - {m.get('description', '')[:100]}..."
                    ),
                    "timestamp": "2026-02-20T00:00:00Z",
                    "raw_data": m,
                })

            return ToolResult(
                success=True,
                tool_name=self.name,
                data={
                    "found": True,
                    "count": len(matches),
                    "techniques": matches,
                },
                evidence=evidence_items,
                metadata={"query_params": tool_input},
            )

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={
                "found": False,
                "count": 0,
                "techniques": [],
                "message": f"No MITRE techniques matched query '{tid or query}'.",
            },
            evidence=[],
            metadata={"query_params": tool_input},
        )
