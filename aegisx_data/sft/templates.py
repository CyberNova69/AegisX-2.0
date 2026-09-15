"""Prompt templates for SFT dataset generation.

Provides system prompts and user prompt formatters for different
training tasks: triage, investigation, threat intelligence.
Compatible with the existing finetuning/prepare_sft_dataset.py format.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..core.types import DatasetRecord, Severity


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

TRIAGE_SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst performing alert triage.

Your task is to analyze the provided security alert and supporting evidence, then produce a structured triage decision.

You MUST respond with valid JSON containing:
- "classification": one of "benign", "suspicious", "likely_malicious", "confirmed_malicious", or "insufficient_evidence"
- "severity": one of "informational", "low", "medium", "high", or "critical"
- "confidence": a float between 0.0 and 1.0
- "investigation_required": boolean
- "summary": a concise explanation of your decision
- "findings": list of findings with evidence references
- "recommended_actions": list of recommended next steps

Base your analysis ONLY on the provided evidence. Do not hallucinate or invent evidence that is not present in the input."""


INVESTIGATION_SYSTEM_PROMPT = """You are an expert SOC analyst conducting a deep investigation of a security incident.

Analyze the provided evidence and produce a detailed investigation report with:
- Root cause analysis
- Attack timeline reconstruction
- Affected assets and scope
- MITRE ATT&CK technique mapping
- Recommended containment and remediation actions

Base your analysis ONLY on the provided evidence."""


THREAT_INTEL_SYSTEM_PROMPT = """You are a threat intelligence analyst. Analyze the provided indicators and context to produce a threat assessment.

Your response must include:
- Threat actor attribution (if possible)
- Campaign identification
- IOC classification and confidence
- Related MITRE ATT&CK techniques
- Recommended defensive actions"""


# ---------------------------------------------------------------------------
# User prompt formatters
# ---------------------------------------------------------------------------

def format_triage_user_prompt(record: DatasetRecord) -> str:
    """Format a DatasetRecord as a triage alert for the user prompt.

    Produces a format compatible with the existing ai/prompts/triage.py
    format_triage_user_prompt() function.
    """
    lines = ["## Security Alert for Triage", ""]

    # Alert header
    title = _derive_alert_title(record)
    severity = record.severity.value if record.severity else "medium"
    lines.append(f"**Alert**: {title}")
    lines.append(f"**Severity**: {severity}")
    source_name = record.source.value if hasattr(record.source, 'value') else str(record.source)
    lines.append(f"**Source**: {source_name}")
    if record.timestamp:
        lines.append(f"**Timestamp**: {record.timestamp}")
    lines.append("")

    # Context
    lines.append("### Context")
    if record.hostname:
        lines.append(f"- **Hostname**: {record.hostname}")
    if record.username:
        lines.append(f"- **Username**: {record.username}")
    if record.src_ip:
        lines.append(f"- **Source IP**: {record.src_ip}")
    if record.dst_ip:
        lines.append(f"- **Destination IP**: {record.dst_ip}")
    lines.append("")

    # Evidence
    lines.append("### Evidence")
    evidence_id = f"EVT-{record.record_index + 1:06d}"
    lines.append(f"**[{evidence_id}]** Network flow record:")

    evidence_parts = []
    if record.src_ip:
        evidence_parts.append(f"  Source: {record.src_ip}")
        if record.src_port:
            evidence_parts[-1] += f":{record.src_port}"
    if record.dst_ip:
        evidence_parts.append(f"  Destination: {record.dst_ip}")
        if record.dst_port:
            evidence_parts[-1] += f":{record.dst_port}"
    if record.protocol:
        evidence_parts.append(f"  Protocol: {record.protocol}")
    if record.duration is not None:
        evidence_parts.append(f"  Duration: {record.duration}s")
    if record.bytes_sent is not None:
        evidence_parts.append(f"  Bytes sent: {record.bytes_sent}")
    if record.bytes_recv is not None:
        evidence_parts.append(f"  Bytes received: {record.bytes_recv}")
    if record.process_name:
        evidence_parts.append(f"  Process: {record.process_name}")
    if record.command_line:
        evidence_parts.append(f"  Command: {record.command_line}")
    if record.file_path:
        evidence_parts.append(f"  File: {record.file_path}")
    if record.file_hash:
        evidence_parts.append(f"  Hash: {record.file_hash}")

    lines.extend(evidence_parts)

    # MITRE mapping if available
    if record.mitre_technique_id:
        lines.append("")
        lines.append(f"**MITRE ATT&CK**: {record.mitre_technique_id}")
        if record.mitre_technique_name:
            lines.append(f"  Technique: {record.mitre_technique_name}")
        if record.mitre_tactic:
            lines.append(f"  Tactic: {record.mitre_tactic}")

    return "\n".join(lines)


def format_assistant_response(record: DatasetRecord) -> Dict[str, Any]:
    """Format the expected assistant response (ground truth) for training."""
    evidence_id = f"EVT-{record.record_index + 1:06d}"

    classification = record.classification.value if record.classification else "suspicious"
    severity = record.severity.value if record.severity else "medium"
    confidence = record.confidence

    # Determine investigation_required
    if classification == "benign" and confidence >= 0.75:
        investigation_required = False
    else:
        investigation_required = True

    # Build summary
    if record.attack_category and record.attack_category.value != "none":
        summary = (
            f"Classified as {classification} — {record.attack_category.value} "
            f"activity detected from source {record.source.value if hasattr(record.source, 'value') else record.source}."
        )
    else:
        summary = f"Classified as {classification} based on network flow analysis."

    # Build findings
    findings = [{
        "finding": _derive_finding(record),
        "evidence_ids": [evidence_id],
    }]

    # Build recommended actions
    actions = _derive_actions(record)

    return {
        "classification": classification,
        "severity": severity,
        "confidence": round(confidence, 2),
        "investigation_required": investigation_required,
        "summary": summary,
        "findings": findings,
        "evidence_ids": [evidence_id],
        "recommended_actions": actions,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _derive_alert_title(record: DatasetRecord) -> str:
    """Derive an alert title from record data."""
    if record.attack_category and record.attack_category.value != "none":
        cat = record.attack_category.value.replace("_", " ").title()
        return f"{cat} Activity Detected"
    if record.process_name:
        return f"Suspicious Process: {record.process_name}"
    if record.src_ip and record.dst_ip:
        return f"Network Activity: {record.src_ip} → {record.dst_ip}"
    return "Security Event Detected"


def _derive_finding(record: DatasetRecord) -> str:
    """Derive a finding description from record data."""
    parts = []

    if record.attack_category and record.attack_category.value != "none":
        parts.append(
            f"{record.attack_category.value.replace('_', ' ').title()} activity observed"
        )

    if record.src_ip and record.dst_ip:
        flow = f"from {record.src_ip}"
        if record.src_port:
            flow += f":{record.src_port}"
        flow += f" to {record.dst_ip}"
        if record.dst_port:
            flow += f":{record.dst_port}"
        parts.append(f"Network flow {flow}")

    if record.protocol:
        parts.append(f"Protocol: {record.protocol.upper()}")

    if not parts:
        parts.append("Security event requiring analysis")

    return ". ".join(parts) + "."


def _derive_actions(record: DatasetRecord) -> list:
    """Derive recommended actions based on classification."""
    actions = []
    classification = record.classification.value if record.classification else "suspicious"

    if classification == "malicious":
        actions.append({"action": "Block source IP if external", "priority": "high"})
        actions.append({"action": "Isolate affected endpoint", "priority": "high"})
        actions.append({"action": "Conduct full investigation", "priority": "high"})
    elif classification == "suspicious":
        actions.append({"action": "Monitor for additional indicators", "priority": "medium"})
        actions.append({"action": "Review historical activity", "priority": "medium"})
    elif classification == "benign":
        actions.append({"action": "No action required", "priority": "low"})
    else:
        actions.append({"action": "Gather additional evidence", "priority": "medium"})

    return actions
