#!/usr/bin/env python3

"""
Controlled prompt experiment for AegisX TriageAgent.
Runs baseline and experimental prompts against the same 20 validation records.
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple
import hashlib

# Ensure we can import from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai.agents.triage_agent import TriageAgent
from ai.agents.schemas import TriageResult, VALID_CLASSIFICATIONS, VALID_SEVERITIES
from ai.prompts.triage import get_triage_system_prompt, format_triage_user_prompt
from ai.evaluation.triage_eval import evaluate_triage_predictions, TriageEvalMetrics
from ai.llm import LLMClient, LLMError, LLMResponseError
# Paths
BASELINE_PROMPT_PATH = "reports/phase3/baseline_prompt.txt"
EXPERIMENTAL_PROMPT_PATH = "reports/phase3/experimental_prompt.txt"
MANIFEST_PATH = "reports/phase3/controlled_prompt_experiment_manifest.json"
VALIDATION_DATASET_PATH = "datasets/finetuning/v0.4/validation.jsonl"
BASELINE_RESULTS_PATH = "reports/phase3/controlled_baseline_results.json"
EXPERIMENTAL_RESULTS_PATH = "reports/phase3/controlled_experimental_results.json"
FINAL_REPORT_PATH = "reports/phase3/PHASE_3_CONTROLLED_PROMPT_EXPERIMENT.md"

# Load prompts
def load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

BASELINE_PROMPT = load_prompt(BASELINE_PROMPT_PATH)
EXPERIMENTAL_PROMPT = load_prompt(EXPERIMENTAL_PROMPT_PATH)

print("Baseline prompt length: " + str(len(BASELINE_PROMPT)) + " chars")
print("Experimental prompt length: " + str(len(EXPERIMENTAL_PROMPT)) + " chars")

# Load manifest
def load_manifest(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)

manifest = load_manifest(MANIFEST_PATH)
print("Manifest dataset: " + manifest["dataset"])
print("Manifest split: " + manifest["split"])
print("Manifest sample size: " + str(manifest["sample_size"]))
print("Manifest model: " + manifest["model"])
print("Manifest provider: " + manifest["provider"])
print("Manifest generation settings: " + str(manifest["generation_settings"]))

# Load validation dataset and index by ID
def load_validation_records(dataset_path: str) -> Dict[str, Dict[str, Any]]:
    records = {}
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                rid = record.get("id")
                if rid:
                    records[rid] = record
            except json.JSONDecodeError:
                pass
    return records

validation_records = load_validation_records(VALIDATION_DATASET_PATH)
print("Loaded " + str(len(validation_records)) + " validation records total")

# Get the exact records from manifest in order
manifest_ids = manifest["record_ids"]
manifest_hashes = manifest["record_hashes"]

# Verify we have all records
missing = [rid for rid in manifest_ids if rid not in validation_records]
if missing:
    print("ERROR: Missing records: " + str(missing))
    sys.exit(1)

# Verify hashes (optional, but let's do it)
def compute_hash(record: Dict[str, Any]) -> str:
    # Canonical JSON: sort keys, no whitespace
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest().upper()

hash_mismatches = []
for rid in manifest_ids:
    record = validation_records[rid]
    computed = compute_hash(record)
    expected = manifest_hashes.get(rid)
    if computed != expected:
        hash_mismatches.append((rid, computed, expected))

if hash_mismatches:
    print("ERROR: Hash mismatches: " + str(hash_mismatches))
    sys.exit(1)

print("All record hashes verified.")

# Get the ordered list of records to evaluate
ordered_records = [validation_records[rid] for rid in manifest_ids]

# Function to run experiment with a given system prompt
def run_experiment(system_prompt: str, experiment_name: str) -> Tuple[List[Dict[str, Any]], List[TriageResult], List[Dict[str, Any]]]:
    """
    Run the TriageAgent on all records with a custom system prompt.
    Returns:
        - per_record_results: list of dicts with record-level info
        - predictions: list of TriageResult objects (for successful predictions only)
        - ground_truth_records: list of ground truth record dicts (for successful predictions)
    """
    # Monkey-patch the get_triage_system_prompt function
    import ai.prompts.triage as prompts_module
    original_get_prompt = prompts_module.get_triage_system_prompt
    prompts_module.get_triage_system_prompt = lambda: system_prompt

    try:
        # Create agent (will use the patched prompt function)
        agent = TriageAgent()

        per_record_results = []
        predictions = []
        ground_truth_records = []

        start_time = time.time()
        for idx, record in enumerate(ordered_records):
            record_start = time.time()
            rid = record["id"]
            gt_class = record.get("output", {}).get("classification", "unknown")

            try:
                # Run triage
                prediction: TriageResult = agent.triage(record)
                latency_ms = (time.time() - record_start) * 1000

                # Collect successful prediction
                predictions.append(prediction)
                ground_truth_records.append(record)

                # Record-level info
                per_record_results.append({
                    "record_id": rid,
                    "ground_truth_classification": gt_class,
                    "predicted_classification": prediction.classification,
                    "predicted_severity": prediction.severity,
                    "investigation_required": prediction.investigation_required,
                    "confidence": prediction.confidence,
                    "latency_ms": round(latency_ms, 2),
                    "structured_valid": prediction.classification in VALID_CLASSIFICATIONS and prediction.severity in VALID_SEVERITIES,
                    "error_type": None,
                    "error_message": None,
                    "findings_count": len(prediction.findings) if hasattr(prediction, "findings") else 0,
                    "evidence_ids_referenced": getattr(prediction, "evidence_ids", []),
                })

                if (idx + 1) % 5 == 0:
                    print("  Processed " + str(idx + 1) + "/" + str(len(ordered_records)) + " records...")

            except LLMError as e:
                latency_ms = (time.time() - record_start) * 1000
                error_type = type(e).__name__
                # Determine specific error type if possible
                if "HTTP 400" in str(e):
                    if "JSON" in str(e):
                        error_type = "INVALID_JSON"
                    else:
                        error_type = "API_FAILURE"
                elif "HTTP 429" in str(e):
                    error_type = "RATE_LIMIT"
                elif "HTTP 402" in str(e) or "quota" in str(e).lower():
                    error_type = "QUOTA_EXCEEDED"
                elif "timeout" in str(e).lower():
                    error_type = "TIMEOUT"
                else:
                    error_type = "API_FAILURE"

                per_record_results.append({
                    "record_id": rid,
                    "ground_truth_classification": gt_class,
                    "predicted_classification": None,
                    "predicted_severity": None,
                    "investigation_required": None,
                    "confidence": None,
                    "latency_ms": round(latency_ms, 2),
                    "structured_valid": False,
                    "error_type": error_type,
                    "error_message": str(e)[:200],  # Truncate
                    "findings_count": 0,
                    "evidence_ids_referenced": [],
                })
                print("  Record " + rid + ": " + error_type + " - " + str(e)[:100])

            except Exception as e:
                latency_ms = (time.time() - record_start) * 1000
                per_record_results.append({
                    "record_id": rid,
                    "ground_truth_classification": gt_class,
                    "predicted_classification": None,
                    "predicted_severity": None,
                    "investigation_required": None,
                    "confidence": None,
                    "latency_ms": round(latency_ms, 2),
                    "structured_valid": False,
                    "error_type": "UNEXPECTED_ERROR",
                    "error_message": str(e)[:200],
                    "findings_count": 0,
                    "evidence_ids_referenced": [],
                })
                print("  Record " + rid + ": Unexpected error - " + str(e)[:100])

        total_time = time.time() - start_time
        print(experiment_name + " completed in " + str(round(total_time, 2)) + " seconds")
        print("  Successful predictions: " + str(len(predictions)) + "/" + str(len(ordered_records)))
        print("  Failures: " + str(len(ordered_records) - len(predictions)))

        return per_record_results, predictions, ground_truth_records

    finally:
        # Restore original function
        prompts_module.get_triage_system_prompt = original_get_prompt

test
