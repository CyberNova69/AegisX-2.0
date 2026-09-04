#!/usr/bin/env python3
"""
AegisX Dataset Validator (v0.2)
================================

Validates JSONL dataset files against the AegisX SOC dataset schema.
Performs both structural integrity verification and deep semantic quality checks
including timestamp ordering, entity consistency, MITRE cross-referencing,
confidence coherence, and automated quality thresholding.

Usage:
    python scripts/validate_dataset.py datasets/generated/soc_examples.jsonl
    python scripts/validate_dataset.py datasets/generated/soc_examples.jsonl --strict
    python scripts/validate_dataset.py datasets/generated/soc_examples.jsonl \
      --output-validated datasets/validated/soc_examples_validated.jsonl \
      --output-rejected datasets/validated/soc_examples_rejected.jsonl
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants & Enums (Matches Schema v0.2)
# ---------------------------------------------------------------------------

VALID_TASKS = {
    "alert_triage",
    "investigation_planning",
    "evidence_analysis",
    "mitre_mapping",
    "incident_summarization",
    "threat_intelligence",
    "response_recommendation",
}

VALID_CLASSIFICATIONS = {
    "benign",
    "suspicious",
    "likely_malicious",
    "confirmed_malicious",
    "insufficient_evidence",
}

VALID_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}

VALID_REVIEW_STATUSES = {
    "pending",
    "approved",
    "rejected",
    "needs_revision",
}

VALID_EVIDENCE_TYPES = {
    "process_creation",
    "network_connection",
    "file_modification",
    "registry_modification",
    "authentication",
    "dns_query",
    "email",
    "firewall_log",
    "proxy_log",
    "scheduled_task",
    "service_creation",
    "wmi_activity",
    "powershell_log",
    "sysmon_event",
    "threat_intel_match",
    "vulnerability_scan",
    "user_report",
    "other",
}

ID_PATTERN = re.compile(r"^SOC-\d{6}$")
EVT_PATTERN = re.compile(r"^EVT-\d{3,6}$")
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# ---------------------------------------------------------------------------
# MITRE Reference Loader
# ---------------------------------------------------------------------------

def load_mitre_reference(project_root: Path) -> set[str]:
    ref_path = project_root / "datasets" / "metadata" / "mitre_reference.json"
    if not ref_path.exists():
        return set()
    try:
        with open(ref_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {item["technique_id"] for item in data if isinstance(item, dict) and "technique_id" in item}
    except Exception:
        return set()

# ---------------------------------------------------------------------------
# Validation Result
# ---------------------------------------------------------------------------

class ValidationResult:
    """Collects errors and warnings during validation."""

    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, record_id: str, message: str):
        self.errors.append(f"{record_id}: {message}")

    def warning(self, record_id: str, message: str):
        self.warnings.append(f"{record_id}: {message}")

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

# ---------------------------------------------------------------------------
# Record Validator
# ---------------------------------------------------------------------------

def validate_record(record: dict, result: ValidationResult, known_mitre_ids: set[str]) -> str | None:
    """Validate a single record structurally and semantically."""
    record_id = record.get("id", "UNKNOWN")
    if not isinstance(record_id, str):
        result.error("UNKNOWN", "id must be a string")
        record_id = "UNKNOWN"
    elif not ID_PATTERN.match(record_id):
        result.error(record_id, f"id '{record_id}' does not match pattern SOC-XXXXXX")

    for field in ["id", "task", "input", "output", "metadata"]:
        if field not in record:
            result.error(record_id, f"missing required top-level field: {field}")

    task = record.get("task")
    if task is not None and task not in VALID_TASKS:
        result.error(record_id, f"invalid task: '{task}'. Must be one of: {sorted(VALID_TASKS)}")

    inp = record.get("input")
    evidence_ids = set()
    if isinstance(inp, dict):
        _validate_input(record_id, inp, result)
        for evt in inp.get("evidence", []):
            if isinstance(evt, dict) and "id" in evt:
                evidence_ids.add(evt["id"])
    elif inp is not None:
        result.error(record_id, "input must be an object")

    out = record.get("output")
    if isinstance(out, dict):
        _validate_output(record_id, out, evidence_ids, result, known_mitre_ids)
    elif out is not None:
        result.error(record_id, "output must be an object")

    meta = record.get("metadata")
    if isinstance(meta, dict):
        _validate_metadata(record_id, meta, result)
    elif meta is not None:
        result.error(record_id, "metadata must be an object")

    # Semantic Validation Checks
    if isinstance(inp, dict) and isinstance(out, dict):
        _validate_semantics(record_id, inp, out, meta or {}, result)

    return record_id

def _validate_input(record_id: str, inp: dict, result: ValidationResult):
    for field in ["alert", "context", "evidence"]:
        if field not in inp:
            result.error(record_id, f"missing required input field: {field}")

    alert = inp.get("alert")
    if isinstance(alert, dict):
        for field in ["title", "severity", "source"]:
            if field not in alert:
                result.error(record_id, f"missing required alert field: {field}")
            elif isinstance(alert.get(field), str) and not alert[field].strip():
                result.error(record_id, f"alert.{field} must not be empty")

        if "severity" in alert and alert["severity"] not in VALID_SEVERITIES:
            result.error(record_id, f"invalid alert severity: '{alert['severity']}'")

    evidence = inp.get("evidence")
    if isinstance(evidence, list):
        if len(evidence) == 0:
            result.error(record_id, "evidence array must not be empty")

        seen_evt_ids = set()
        for i, evt in enumerate(evidence):
            if not isinstance(evt, dict):
                result.error(record_id, f"evidence[{i}] must be an object")
                continue

            for field in ["id", "type", "description"]:
                if field not in evt:
                    result.error(record_id, f"evidence[{i}] missing required field: {field}")

            evt_id = evt.get("id", "")
            if evt_id and not EVT_PATTERN.match(evt_id):
                result.error(record_id, f"evidence id '{evt_id}' does not match pattern EVT-XXX to EVT-XXXXXX")

            if evt_id in seen_evt_ids:
                result.error(record_id, f"duplicate evidence id: {evt_id}")
            seen_evt_ids.add(evt_id)

            evt_type = evt.get("type")
            if evt_type is not None and evt_type not in VALID_EVIDENCE_TYPES:
                result.error(record_id, f"invalid evidence type: '{evt_type}'")

def _validate_output(record_id: str, out: dict, evidence_ids: set, result: ValidationResult, known_mitre_ids: set[str]):
    for field in ["classification", "confidence", "findings"]:
        if field not in out:
            result.error(record_id, f"missing required output field: {field}")

    cls = out.get("classification")
    if cls is not None and cls not in VALID_CLASSIFICATIONS:
        result.error(record_id, f"invalid classification: '{cls}'")

    conf = out.get("confidence")
    if conf is not None:
        if not isinstance(conf, (int, float)):
            result.error(record_id, f"confidence must be a number, got {type(conf).__name__}")
        elif conf < 0.0 or conf > 1.0:
            result.error(record_id, f"confidence {conf} out of range [0.0, 1.0]")

    findings = out.get("findings")
    if isinstance(findings, list):
        if len(findings) == 0:
            result.error(record_id, "findings array must not be empty")

        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                result.error(record_id, f"findings[{i}] must be an object")
                continue

            if "description" not in finding:
                result.error(record_id, f"findings[{i}] missing required field: description")
            if "evidence_refs" not in finding:
                result.error(record_id, f"findings[{i}] missing required field: evidence_refs")
            elif isinstance(finding["evidence_refs"], list):
                if len(finding["evidence_refs"]) == 0:
                    result.error(record_id, f"findings[{i}].evidence_refs must not be empty")
                for ref in finding["evidence_refs"]:
                    if ref not in evidence_ids:
                        result.error(record_id, f"findings[{i}] references non-existent evidence '{ref}'")

    mitre = out.get("mitre_techniques")
    if isinstance(mitre, list):
        for i, tech in enumerate(mitre):
            if not isinstance(tech, dict):
                continue
            tid = tech.get("technique_id", "")
            if tid and not MITRE_PATTERN.match(tid):
                result.error(record_id, f"mitre_techniques[{i}] invalid technique_id pattern: '{tid}'")

            if tid and known_mitre_ids and tid not in known_mitre_ids:
                result.warning(record_id, f"mitre_techniques[{i}] technique_id '{tid}' not found in mitre_reference.json")

            if "evidence_refs" in tech and isinstance(tech["evidence_refs"], list):
                for ref in tech["evidence_refs"]:
                    if ref not in evidence_ids:
                        result.error(record_id, f"mitre_techniques[{i}] references non-existent evidence '{ref}'")

def _validate_metadata(record_id: str, meta: dict, result: ValidationResult):
    for field in ["source", "generator", "review_status", "dataset_version"]:
        if field not in meta:
            result.error(record_id, f"missing required metadata field: {field}")

    if meta.get("source") not in (None, "synthetic"):
        result.error(record_id, f"metadata.source must be 'synthetic', got '{meta.get('source')}'")

    if "review_status" in meta and meta["review_status"] not in VALID_REVIEW_STATUSES:
        result.error(record_id, f"invalid review_status: '{meta['review_status']}'")

def _validate_semantics(record_id: str, inp: dict, out: dict, meta: dict, result: ValidationResult):
    """Deep semantic coherence checks."""
    # 1. Temporal ordering of evidence
    evidences = inp.get("evidence", [])
    timestamps = []
    for evt in evidences:
        if isinstance(evt, dict) and "timestamp" in evt:
            try:
                dt = datetime.fromisoformat(evt["timestamp"])
                timestamps.append(dt)
            except ValueError:
                pass
    if timestamps and timestamps != sorted(timestamps):
        result.warning(record_id, "evidence timestamps are not in chronological order")

    # 2. Classification vs Confidence Coherence
    cls = out.get("classification")
    conf = out.get("confidence")
    if cls and isinstance(conf, (int, float)):
        if cls == "confirmed_malicious" and conf < 0.70:
            result.warning(record_id, f"classification 'confirmed_malicious' has low confidence ({conf})")
        elif cls == "benign" and conf < 0.60:
            result.warning(record_id, f"classification 'benign' has unusually low confidence ({conf})")

    # 3. Severity vs Classification Coherence
    sev = inp.get("alert", {}).get("severity")
    if cls == "benign" and sev == "critical":
        result.warning(record_id, "alert severity is 'critical' but output classification is 'benign'")

    # 4. Automated Quality Score Check
    qs = meta.get("quality_score")
    if isinstance(qs, int) and qs < 70:
        result.warning(record_id, f"quality_score {qs} is below recommended threshold of 70")

# ---------------------------------------------------------------------------
# Main Validation Execution
# ---------------------------------------------------------------------------

def validate_file(filepath: Path, project_root: Path) -> tuple[ValidationResult, list[dict]]:
    result = ValidationResult()
    known_mitre_ids = load_mitre_reference(project_root)

    if not filepath.exists():
        result.error("FILE", f"File not found: {filepath}")
        return result, []

    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                result.error(f"LINE-{line_num}", f"invalid JSON: {e}")
                continue

            if not isinstance(record, dict):
                result.error(f"LINE-{line_num}", "each line must be a JSON object")
                continue

            validate_record(record, result, known_mitre_ids)
            records.append(record)

    # Dataset-level checks
    id_counts = Counter(r.get("id", "UNKNOWN") for r in records)
    for rid, count in id_counts.items():
        if count > 1:
            result.error(rid, f"duplicate ID found ({count} occurrences)")

    return result, records

def print_report(filepath: Path, result: ValidationResult, records: list[dict]):
    print("\n============================================================")
    print("  AegisX Dataset Validation Report (v0.2)")
    print("============================================================")
    print(f"  File:    {filepath}")
    print(f"  Records: {len(records)}\n")

    if result.errors:
        print(f"  [FAIL] {len(result.errors)} error(s) found:\n")
        for err in result.errors[:15]:
            print(f"    - {err}")
        if len(result.errors) > 15:
            print(f"    ... and {len(result.errors) - 15} more errors")
        print()
    else:
        print(f"  [PASS] All {len(records)} records passed structural validation\n")

    if result.warnings:
        print(f"  [WARN] {len(result.warnings)} warning(s):\n")
        for warn in result.warnings[:15]:
            print(f"    - {warn}")
        if len(result.warnings) > 15:
            print(f"    ... and {len(result.warnings) - 15} more warnings")
        print()

    if records:
        quality_scores = [r.get("metadata", {}).get("quality_score") for r in records if isinstance(r.get("metadata", {}).get("quality_score"), int)]
        if quality_scores:
            avg_score = sum(quality_scores) / len(quality_scores)
            print(f"  Average Automated Quality Score: {avg_score:.1f} / 100\n")

    if result.is_valid:
        print("  =========================================")
        print(f"  RESULT: VALID ({len(records)} records, {len(result.warnings)} warnings)")
        print("  =========================================\n")
    else:
        print("  =========================================")
        print(f"  RESULT: INVALID ({len(result.errors)} errors, {len(result.warnings)} warnings)")
        print("  =========================================\n")

def main():
    parser = argparse.ArgumentParser(description="AegisX Dataset Validator v0.2")
    parser.add_argument("file", type=str, help="Path to JSONL dataset file")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    parser.add_argument("--output-validated", type=str, default=None, help="Output path for validated records")
    parser.add_argument("--output-rejected", type=str, default=None, help="Output path for rejected records")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    filepath = Path(args.file)
    if not filepath.is_absolute():
        filepath = project_root / filepath

    result, records = validate_file(filepath, project_root)

    if args.strict and result.warnings:
        for warn in result.warnings:
            result.errors.append(f"[strict] {warn}")

    print_report(filepath, result, records)

    # Handle output splitting if requested
    if args.output_validated or args.output_rejected:
        val_path = Path(args.output_validated) if args.output_validated else None
        rej_path = Path(args.output_rejected) if args.output_rejected else None

        if val_path and not val_path.is_absolute():
            val_path = project_root / val_path
        if rej_path and not rej_path.is_absolute():
            rej_path = project_root / rej_path

        error_ids = {e.split(":")[0] for e in result.errors}

        val_records = []
        rej_records = []
        for r in records:
            rid = r.get("id")
            qs = r.get("metadata", {}).get("quality_score", 100)
            if rid in error_ids or qs < 70:
                rej_records.append(r)
            else:
                val_records.append(r)

        if val_path:
            val_path.parent.mkdir(parents=True, exist_ok=True)
            with open(val_path, "w", encoding="utf-8") as f:
                for r in val_records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            print(f"Wrote {len(val_records)} validated records to {val_path}")

        if rej_path:
            rej_path.parent.mkdir(parents=True, exist_ok=True)
            with open(rej_path, "w", encoding="utf-8") as f:
                for r in rej_records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            print(f"Wrote {len(rej_records)} rejected records to {rej_path}")

    return 0 if result.is_valid else 1

if __name__ == "__main__":
    sys.exit(main())
