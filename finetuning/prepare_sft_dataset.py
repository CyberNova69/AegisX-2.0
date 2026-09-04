#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX SFT Dataset Preparation (v0.1)
=======================================

Converts AegisX v0.4 JSONL records into model-agnostic supervised fine-tuning
(SFT) chat format for instruction tuning.

Each v0.4 record is converted into:
    {
      "messages": [
        {"role": "system",    "content": "<SOC triage system prompt>"},
        {"role": "user",      "content": "<formatted security alert>"},
        {"role": "assistant", "content": "<structured TriageResult JSON>"}
      ]
    }

The tokenizer's apply_chat_template() is applied at TRAINING TIME, not here.
This keeps the dataset model-agnostic.

Usage:
    python -m finetuning.prepare_sft_dataset
    python -m finetuning.prepare_sft_dataset --source-dir datasets/finetuning/v0.4
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.prompts.triage import get_triage_system_prompt, format_triage_user_prompt
from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    VALID_ACTION_PRIORITIES,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CONVERSION_VERSION = "0.1.0"
SCHEMA_VERSION = "sft-chat-v1"

# ---------------------------------------------------------------------------
# Core conversion
# ---------------------------------------------------------------------------

def load_jsonl(filepath: Path) -> List[Dict[str, Any]]:
    """Load a JSONL file into a list of dicts."""
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"  [WARN] Skipping malformed JSON at line {line_num}: {e}")
    return records


def build_assistant_response(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a v0.4 output block into a TriageResult-compatible JSON structure.
    
    This maps the dataset's output format to the exact schema that
    ai/agents/schemas.py TriageResult expects.
    """
    output = record["output"]
    
    # Map findings: dataset uses "description" + "evidence_refs",
    # TriageResult uses "finding" + "evidence_ids"
    findings = []
    for f in output.get("findings", []):
        findings.append({
            "finding": f.get("description", f.get("finding", "")),
            "evidence_ids": f.get("evidence_refs", f.get("evidence_ids", [])),
        })
    
    # Build the TriageResult-compatible JSON
    classification = output["classification"]
    confidence = output.get("confidence", 0.5)
    
    # Determine investigation_required from classification + confidence
    if classification == "benign" and confidence >= 0.75:
        investigation_required = False
    else:
        investigation_required = True
    
    # Determine severity from findings or alert
    severity = None
    if findings:
        # Use the highest severity from findings
        sev_order = ["informational", "low", "medium", "high", "critical"]
        for f_item in output.get("findings", []):
            f_sev = f_item.get("severity")
            if f_sev and f_sev in VALID_SEVERITIES:
                if severity is None or sev_order.index(f_sev) > sev_order.index(severity):
                    severity = f_sev
    if severity is None:
        severity = record["input"]["alert"].get("severity", "medium")
    
    result = {
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "investigation_required": investigation_required,
        "summary": output.get("rationale", f"Triage decision: {classification}"),
        "findings": findings,
        "evidence_ids": sorted(list({
            eid
            for f in findings
            for eid in f.get("evidence_ids", [])
        })),
        "recommended_actions": output.get("recommended_actions", []),
    }
    return result


def validate_sft_example(
    messages: List[Dict[str, str]],
    record_id: str,
    valid_evidence_ids: set,
) -> Tuple[bool, Optional[str]]:
    """
    Validate a converted SFT example.
    
    Returns (is_valid, error_reason).
    """
    # Check message structure
    if len(messages) != 3:
        return False, f"Expected 3 messages, got {len(messages)}"
    
    roles = [m.get("role") for m in messages]
    if roles != ["system", "user", "assistant"]:
        return False, f"Invalid roles: {roles}"
    
    for m in messages:
        if not m.get("content") or not m["content"].strip():
            return False, f"Empty content in {m.get('role')} message"
    
    # Validate assistant output is valid JSON
    try:
        assistant_data = json.loads(messages[2]["content"])
    except json.JSONDecodeError as e:
        return False, f"Assistant content is not valid JSON: {e}"
    
    # Check required TriageResult fields
    required_fields = ["classification", "severity", "confidence", "investigation_required", "summary"]
    for field in required_fields:
        if field not in assistant_data:
            return False, f"Missing required field: {field}"
    
    # Validate classification enum
    if assistant_data["classification"] not in VALID_CLASSIFICATIONS:
        return False, f"Invalid classification: {assistant_data['classification']}"
    
    # Validate severity enum
    if assistant_data["severity"] not in VALID_SEVERITIES:
        return False, f"Invalid severity: {assistant_data['severity']}"
    
    # Validate confidence range
    conf = assistant_data["confidence"]
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        return False, f"Invalid confidence: {conf}"
    
    # Validate investigation_required is bool
    if not isinstance(assistant_data["investigation_required"], bool):
        return False, f"investigation_required must be boolean"
    
    # Validate findings have valid evidence refs
    for idx, finding in enumerate(assistant_data.get("findings", [])):
        if not isinstance(finding, dict):
            return False, f"Finding[{idx}] is not a dict"
        if "finding" not in finding:
            return False, f"Finding[{idx}] missing 'finding' field"
        for ref in finding.get("evidence_ids", []):
            if ref not in valid_evidence_ids:
                return False, f"Finding[{idx}] references invalid evidence ID '{ref}'"
    
    # Validate recommended_actions structure
    for idx, action in enumerate(assistant_data.get("recommended_actions", [])):
        if not isinstance(action, dict):
            return False, f"Action[{idx}] is not a dict"
        if "action" not in action:
            return False, f"Action[{idx}] missing 'action' field"
        priority = action.get("priority", "medium")
        if priority not in VALID_ACTION_PRIORITIES:
            return False, f"Action[{idx}] invalid priority: {priority}"
    
    return True, None


def convert_record(record: Dict[str, Any], system_prompt: str) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Convert a single v0.4 record into an SFT chat example.
    
    Returns (sft_example, error_reason).
    """
    try:
        record_id = record.get("id", "UNKNOWN")
        
        # Build user prompt from input block using the existing formatter
        input_data = record.get("input")
        if not input_data:
            return None, "Missing 'input' block"
        
        user_prompt = format_triage_user_prompt(input_data)
        
        # Build assistant response from output block
        assistant_response = build_assistant_response(record)
        assistant_json = json.dumps(assistant_response, indent=2)
        
        # Collect valid evidence IDs from input
        valid_evidence_ids = set()
        for evt in input_data.get("evidence", []):
            if isinstance(evt, dict) and "id" in evt:
                valid_evidence_ids.add(evt["id"])
        
        # Assemble messages
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_json},
        ]
        
        # Validate
        is_valid, error = validate_sft_example(messages, record_id, valid_evidence_ids)
        if not is_valid:
            return None, f"Validation failed for {record_id}: {error}"
        
        return {"messages": messages}, None
    
    except Exception as e:
        return None, f"Conversion error: {e}"


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def convert_split(
    source_path: Path,
    output_path: Path,
    system_prompt: str,
    split_name: str,
) -> Dict[str, Any]:
    """Convert one dataset split and write SFT output."""
    print(f"\n  Converting {split_name} split: {source_path.name}")
    
    records = load_jsonl(source_path)
    print(f"    Source records loaded: {len(records)}")
    
    converted = []
    rejected = []
    
    for record in records:
        sft_example, error = convert_record(record, system_prompt)
        if sft_example:
            converted.append(sft_example)
        else:
            rejected.append({
                "id": record.get("id", "UNKNOWN"),
                "error": error,
            })
    
    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for example in converted:
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
    
    print(f"    Converted:  {len(converted)}")
    print(f"    Rejected:   {len(rejected)}")
    if rejected:
        for r in rejected[:5]:
            print(f"      - {r['id']}: {r['error']}")
        if len(rejected) > 5:
            print(f"      ... and {len(rejected) - 5} more")
    
    output_hash = compute_file_hash(output_path)
    print(f"    Output:     {output_path.name} (SHA-256: {output_hash[:16]}...)")
    
    return {
        "split": split_name,
        "source_file": str(source_path.name),
        "output_file": str(output_path.name),
        "source_count": len(records),
        "converted_count": len(converted),
        "rejected_count": len(rejected),
        "rejected_records": rejected,
        "output_sha256": output_hash,
    }


def prepare_sft_dataset(source_dir: Path, output_dir: Optional[Path] = None):
    """
    Main conversion pipeline.
    
    Loads train.jsonl and validation.jsonl from source_dir,
    converts them to SFT chat format, writes to output_dir.
    
    NEVER loads test.jsonl.
    """
    print("=" * 60)
    print("  AegisX SFT Dataset Preparation (v0.1)")
    print("=" * 60)
    
    if output_dir is None:
        output_dir = source_dir / "sft"
    
    train_source = source_dir / "train.jsonl"
    val_source = source_dir / "validation.jsonl"
    test_path = source_dir / "test.jsonl"
    
    # Verify source files exist
    for p in [train_source, val_source]:
        if not p.exists():
            print(f"  [ERROR] Source file not found: {p}")
            sys.exit(1)
    
    # Confirm test.jsonl is NOT being loaded
    print(f"\n  Source directory: {source_dir}")
    print(f"  Output directory: {output_dir}")
    print(f"  Test set ({test_path.name}): EXCLUDED (never loaded for SFT preparation)")
    
    # Load system prompt
    system_prompt = get_triage_system_prompt()
    print(f"\n  System prompt loaded ({len(system_prompt)} chars)")
    
    # Convert splits
    train_report = convert_split(
        train_source,
        output_dir / "train.jsonl",
        system_prompt,
        "train",
    )
    
    val_report = convert_split(
        val_source,
        output_dir / "validation.jsonl",
        system_prompt,
        "validation",
    )
    
    # Compute source file hashes for provenance
    source_hashes = {
        "train_source_sha256": compute_file_hash(train_source),
        "validation_source_sha256": compute_file_hash(val_source),
    }
    
    # Write conversion metadata
    metadata = {
        "conversion_version": CONVERSION_VERSION,
        "schema_version": SCHEMA_VERSION,
        "converted_at": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(source_dir),
        "output_directory": str(output_dir),
        "test_set_excluded": True,
        "system_prompt_length": len(system_prompt),
        "splits": {
            "train": train_report,
            "validation": val_report,
        },
        "source_file_hashes": source_hashes,
        "totals": {
            "source_records": train_report["source_count"] + val_report["source_count"],
            "converted_records": train_report["converted_count"] + val_report["converted_count"],
            "rejected_records": train_report["rejected_count"] + val_report["rejected_count"],
        },
    }
    
    metadata_path = output_dir / "conversion_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    
    # Summary
    total_converted = metadata["totals"]["converted_records"]
    total_rejected = metadata["totals"]["rejected_records"]
    total_source = metadata["totals"]["source_records"]
    
    print(f"\n{'=' * 60}")
    print(f"  SFT CONVERSION SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Source records:    {total_source}")
    print(f"  Converted:        {total_converted}")
    print(f"  Rejected:         {total_rejected}")
    print(f"  Test set:         EXCLUDED")
    print(f"  Metadata:         {metadata_path.name}")
    
    if total_rejected > 0:
        print(f"\n  [WARNING] {total_rejected} records were rejected during conversion.")
        print(f"  Review conversion_metadata.json for details.")
    
    if total_converted == total_source:
        print(f"\n  RESULT: SUCCESS — {total_converted} SFT examples ready for fine-tuning.")
    else:
        print(f"\n  RESULT: PARTIAL — {total_converted}/{total_source} converted.")
    
    print(f"{'=' * 60}\n")
    
    return metadata


def main():
    parser = argparse.ArgumentParser(
        description="AegisX SFT Dataset Preparation — Convert v0.4 to chat format"
    )
    parser.add_argument(
        "--source-dir",
        type=str,
        default="datasets/finetuning/v0.4",
        help="Source dataset directory (default: datasets/finetuning/v0.4)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory (default: <source-dir>/sft)",
    )
    args = parser.parse_args()
    
    source_dir = Path(args.source_dir)
    if not source_dir.is_absolute():
        source_dir = PROJECT_ROOT / source_dir
    
    output_dir = None
    if args.output_dir:
        output_dir = Path(args.output_dir)
        if not output_dir.is_absolute():
            output_dir = PROJECT_ROOT / output_dir
    
    prepare_sft_dataset(source_dir, output_dir)


if __name__ == "__main__":
    main()
