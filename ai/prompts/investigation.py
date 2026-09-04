"""
AegisX Investigation Prompt Manager
====================================

Loads system prompts and formats structured user prompts for the InvestigationAgent.
Follows existing AegisX prompt formatting patterns.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from ai.agents.investigation_schemas import (
    InvestigationRequest,
    InvestigationStep,
)

PROMPTS_DIR = Path(__file__).resolve().parent / "investigation"

def get_investigation_system_prompt() -> str:
    """Load the system prompt for investigation analysis from disk."""
    sys_path = PROMPTS_DIR / "system.txt"
    if sys_path.exists():
        with open(sys_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content:
                return content
    return (
        "You are a Senior Security Operations Center (SOC) Investigation Analyst for AegisX. "
        "Perform evidence-grounded investigation using read-only tools and return structured JSON."
    )

def format_investigation_decision_prompt(
    request: InvestigationRequest,
    steps: List[InvestigationStep],
    available_tools: Dict[str, str],
    max_steps: int,
) -> str:
    """
    Format user prompt for the next investigation decision (tool selection or finish).
    """
    current_step = len(steps) + 1
    alert = request.alert
    context = request.context

    prompt_lines = [
        f"=== INVESTIGATION STEP {current_step} OF {max_steps} ===",
        f"Investigation ID: {request.investigation_id}",
        "",
        "=== INITIAL ALERT ===",
        f"Title: {alert.get('title', 'N/A')}",
        f"Severity: {alert.get('severity', 'N/A')}",
        f"Source: {alert.get('source', 'N/A')}",
        f"Rule ID: {alert.get('rule_id', 'N/A')}",
        "",
        "=== HOST & USER CONTEXT ===",
        f"Hostname: {context.get('hostname', 'N/A')}",
        f"Username: {context.get('username', 'N/A')}",
        f"Department: {context.get('department', 'N/A')}",
        f"OS: {context.get('os', 'N/A')}",
        f"IP: {context.get('ip_address', 'N/A')}",
        f"Environment: {context.get('environment', 'N/A')}",
        "",
        "=== INITIAL EVIDENCE ===",
    ]

    for evt in request.initial_evidence:
        prompt_lines.append(f"[{evt.get('id', 'EVT')}] {evt.get('description', '')}")

    # Add history of investigation steps taken so far
    if steps:
        prompt_lines.extend(["", "=== COMPLETED INVESTIGATION STEPS ==="])
        for s in steps:
            prompt_lines.append(
                f"Step {s.step_number}: Tool '{s.tool_name}' executed. Purpose: {s.purpose}"
            )
            data_summary = json.dumps(s.result.get("data", {}))
            prompt_lines.append(f"  Result Data: {data_summary}")
            if s.evidence_ids:
                prompt_lines.append(f"  Discovered Evidence IDs: {', '.join(s.evidence_ids)}")

    # Add available tools
    prompt_lines.extend([
        "",
        "=== AVAILABLE READ-ONLY TOOLS ===",
    ])
    for tool_name, desc in available_tools.items():
        prompt_lines.append(f"- {tool_name}: {desc}")

    prompt_lines.extend([
        "",
        "=== REQUIRED DECISION JSON FORMAT ===",
        "If further investigation is needed:",
        "{",
        '  "action": "investigate",',
        '  "tool_name": "<one of available tools>",',
        '  "tool_input": {"hostname": "<endpoint>", "scenario": "<scenario_name if known>"},',
        '  "purpose": "Explain why this tool is needed"',
        "}",
        "",
        "If sufficient evidence gathered or no further queries needed:",
        "{",
        '  "action": "finish",',
        '  "stop_reason": "Explanation of why investigation is concluded"',
        "}",
    ])

    return "\n".join(prompt_lines)

def format_investigation_conclusion_prompt(
    request: InvestigationRequest,
    steps: List[InvestigationStep],
    accumulated_evidence: List[Dict[str, Any]],
) -> str:
    """
    Format prompt asking the model to synthesize all gathered evidence into a final report.
    """
    alert = request.alert
    context = request.context

    prompt_lines = [
        "=== FINAL INVESTIGATION SYNTHESIS ===",
        f"Investigation ID: {request.investigation_id}",
        f"Alert: {alert.get('title', 'N/A')} on {context.get('hostname', 'N/A')}",
        "",
        "=== ACCUMULATED EVIDENCE POOL ===",
    ]

    valid_ids = []
    for evt in accumulated_evidence:
        eid = evt.get("id", "UNKNOWN")
        valid_ids.append(eid)
        desc = evt.get("description", "")
        prompt_lines.append(f"[{eid}] {desc}")

    prompt_lines.extend([
        "",
        f"VALID EVIDENCE IDS YOU MAY CITE: {', '.join(valid_ids)}",
        "CRITICAL: You must cite ONLY the valid evidence IDs above. Citing any other ID is a violation.",
        "",
        "=== REQUIRED FINAL REPORT JSON FORMAT ===",
        "{",
        '  "status": "completed" | "insufficient_evidence",',
        '  "conclusion": "benign" | "suspicious" | "likely_malicious" | "confirmed_malicious" | "insufficient_evidence",',
        '  "severity": "informational" | "low" | "medium" | "high" | "critical",',
        '  "confidence": 0.0 to 1.0,',
        '  "findings": [',
        '    {"finding_id": "FIND-001", "title": "Summary", "description": "Details", "evidence_ids": ["EVT-001"], "confidence": 0.9}',
        '  ],',
        '  "recommended_actions": [',
        '    {"action": "Specific analyst recommendation", "priority": "immediate"|"high"|"medium"|"low", "rationale": "Reason"}',
        '  ],',
        '  "limitations": "Statement of investigation constraints and synthetic boundaries"',
        "}",
    ])

    return "\n".join(prompt_lines)
