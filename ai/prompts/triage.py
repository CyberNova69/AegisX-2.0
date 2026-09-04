"""
AegisX Triage Prompt Template Manager
======================================

Loads system prompt templates and formats user input prompts for the TriageAgent.
"""

import json
from pathlib import Path
from typing import Any, Dict

PROMPTS_DIR = Path(__file__).resolve().parent / "triage"

def get_triage_system_prompt() -> str:
    """Load the system prompt for triage analysis."""
    sys_path = PROMPTS_DIR / "system.txt"
    if sys_path.exists():
        with open(sys_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return (
        "You are a Senior Security Operations Center (SOC) Alert Triage Analyst. "
        "Analyze the provided security alert and return a structured JSON triage assessment."
    )

def format_triage_user_prompt(alert_data: Dict[str, Any]) -> str:
    """Format input alert data into a structured user prompt for the LLM."""
    alert = alert_data.get("alert", {})
    context = alert_data.get("context", {})
    evidence = alert_data.get("evidence", [])

    prompt_lines = [
        "Please analyze the following security alert and provide your triage decision in JSON format.",
        "",
        "=== ALERT DETAILS ===",
        f"Title: {alert.get('title', 'N/A')}",
        f"Severity: {alert.get('severity', 'N/A')}",
        f"Source: {alert.get('source', 'N/A')}",
        f"Rule ID: {alert.get('rule_id', 'N/A')}",
        f"Rule Name: {alert.get('rule_name', 'N/A')}",
        f"Timestamp: {alert.get('timestamp', 'N/A')}",
        "",
        "=== HOST & USER CONTEXT ===",
        f"Hostname: {context.get('hostname', 'N/A')}",
        f"Username: {context.get('username', 'N/A')}",
        f"Department: {context.get('department', 'N/A')}",
        f"OS: {context.get('os', 'N/A')}",
        f"Environment: {context.get('environment', 'N/A')}",
        f"Asset Criticality: {context.get('asset_criticality', 'N/A')}",
        f"IP Address: {context.get('ip_address', 'N/A')}",
        "",
        "=== EVIDENCE ITEMS ===",
    ]

    for evt in evidence:
        evt_id = evt.get("id", "UNKNOWN")
        evt_type = evt.get("type", "unknown")
        desc = evt.get("description", "")
        ts = evt.get("timestamp", "")
        raw = json.dumps(evt.get("raw_data", {}))
        prompt_lines.append(f"[{evt_id}] Type: {evt_type} | Time: {ts} | Description: {desc} | Raw: {raw}")

    prompt_lines.extend([
        "",
        "=== REQUIRED OUTPUT JSON FORMAT ===",
        "{",
        '  "classification": "benign" | "suspicious" | "likely_malicious" | "confirmed_malicious" | "insufficient_evidence",',
        '  "severity": "informational" | "low" | "medium" | "high" | "critical",',
        '  "confidence": 0.0 to 1.0,',
        '  "investigation_required": true | false,',
        '  "summary": "Executive summary of triage decision",',
        '  "findings": [',
        '    {"finding": "Description of finding grounded in evidence", "evidence_ids": ["EVT-001"]}',
        '  ],',
        '  "evidence_ids": ["EVT-001"],',
        '  "recommended_actions": [',
        '    {"action": "Action description", "priority": "immediate"|"high"|"medium"|"low", "rationale": "Why action is needed"}',
        '  ]',
        "}"
    ])

    return "\n".join(prompt_lines)
