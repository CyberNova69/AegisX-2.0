#!/usr/bin/env python3
"""
Isolated experiment harness for Phase 3 Controlled Prompt Experiment V2.
Compares baseline prompt vs. experimental prompt V2 on a fixed set of validation records.

Supports fully offline --mock mode with deterministic per-record mock scenarios.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Ensure the project root is in the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.schemas import (
    AlertInput,
    FindingItem,
    RecommendedAction,
    TriageResult,
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
)
from ai.agents.triage_agent import TriageAgent
from ai.llm import LLMClient
from ai.llm.base import BaseLLMProvider
from ai.llm.schemas import LLMRequest, LLMResponse, TokenUsage
from ai.llm.exceptions import (
    LLMError,
    LLMResponseError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMProviderError,
)

# ---------------------------------------------------------------------------
# Error type constants
# ---------------------------------------------------------------------------
ERROR_VALID = "VALID_MODEL_RESPONSE"
ERROR_JSON_VALIDATION = "JSON_VALIDATION_FAILURE"
ERROR_429 = "HTTP_429_RATE_LIMIT"
ERROR_TIMEOUT = "TIMEOUT"
ERROR_OTHER_PROVIDER = "OTHER_PROVIDER_ERROR"


# ---------------------------------------------------------------------------
# Experiment Mock Provider
# ---------------------------------------------------------------------------

class ExperimentMockProvider(BaseLLMProvider):
    """
    Deterministic mock provider for the Phase 3 experiment.
    Maps specific record IDs to controlled scenarios based on a scenario map.
    """

    def __init__(
        self,
        scenario_map: Dict[str, dict],
        default_model: str = "mock-experiment-v2",
    ):
        """
        Args:
            scenario_map: {record_id: {"action": "correct"|"incorrect"|"malformed"|"429"|"timeout", ...}}
            default_model: Model name to report.
        """
        self._scenario_map = scenario_map
        self._default_model = default_model
        self._current_record_id: Optional[str] = None
        self.call_history: List[LLMRequest] = []

    @property
    def name(self) -> str:
        return "mock"

    def set_current_record(self, record_id: str):
        """Set the record ID for the next generate() call."""
        self._current_record_id = record_id

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.call_history.append(request)
        record_id = self._current_record_id
        scenario = self._scenario_map.get(record_id, {})
        action = scenario.get("action", "correct")

        if action == "429":
            raise LLMRateLimitError(
                "HTTP 429 Rate limit exceeded (simulated)",
                provider=self.name,
            )
        elif action == "timeout":
            raise LLMTimeoutError(
                "Request timed out (simulated)",
                provider=self.name,
            )

        # For correct / incorrect / malformed — build a response
        if action == "malformed":
            content = "THIS IS NOT VALID JSON {{{"
            return LLMResponse(
                content=content,
                model=self._default_model,
                provider=self.name,
                usage=TokenUsage(input_tokens=100, output_tokens=20, total_tokens=120),
                finish_reason="stop",
                latency_ms=5.0,
                structured_data=None,
                metadata={},
            )

        # Build a valid JSON response
        ground_truth = scenario.get("ground_truth", "suspicious")
        evidence_ids = scenario.get("evidence_ids", ["EVT-001"])

        if action == "correct":
            classification = ground_truth
        elif action == "incorrect":
            wrong_map = {
                "benign": "suspicious",
                "suspicious": "likely_malicious",
                "likely_malicious": "confirmed_malicious",
                "confirmed_malicious": "benign",
                "insufficient_evidence": "suspicious",
            }
            classification = wrong_map.get(ground_truth, "suspicious")
        else:
            classification = ground_truth

        severity_map = {
            "benign": "informational",
            "suspicious": "medium",
            "likely_malicious": "high",
            "confirmed_malicious": "critical",
            "insufficient_evidence": "low",
        }
        severity = severity_map.get(classification, "medium")

        response_dict = {
            "classification": classification,
            "severity": severity,
            "confidence": 0.85,
            "investigation_required": classification != "benign",
            "summary": f"Mock triage: {classification} for {record_id}",
            "findings": [
                {
                    "finding": f"Mock finding for {record_id}",
                    "evidence_ids": evidence_ids,
                }
            ],
            "evidence_ids": evidence_ids,
            "recommended_actions": [
                {
                    "action": "Review mock finding",
                    "priority": "medium",
                    "rationale": "Mock rationale",
                }
            ],
        }

        content = json.dumps(response_dict)
        return LLMResponse(
            content=content,
            model=self._default_model,
            provider=self.name,
            usage=TokenUsage(input_tokens=100, output_tokens=50, total_tokens=150),
            finish_reason="stop",
            latency_ms=5.0,
            structured_data=response_dict,
            metadata={},
        )


# ---------------------------------------------------------------------------
# Loading utilities
# ---------------------------------------------------------------------------

def load_manifest(manifest_path: Union[str, Path]) -> Dict[str, Any]:
    """Load and return the frozen manifest JSON."""
    path = Path(manifest_path)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_prompt(prompt_path: Union[str, Path]) -> str:
    """Load a prompt text file."""
    path = Path(prompt_path)
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def compute_sha256(text: str) -> str:
    """Compute SHA-256 hash of a text string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def load_validation_dataset(dataset_path: Union[str, Path]) -> Dict[str, Dict[str, Any]]:
    """Load validation.jsonl and return a map from record ID to the full record."""
    path = Path(dataset_path)
    id_to_record = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            id_to_record[record['id']] = record
    return id_to_record


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

def validate_manifest(
    manifest: Dict[str, Any],
    id_to_record: Dict[str, Dict[str, Any]],
) -> List[str]:
    """
    Validate manifest constraints.
    Returns a list of error strings (empty == valid).
    """
    errors = []
    record_ids = manifest.get("record_ids", [])
    ground_truth = manifest.get("ground_truth", [])
    class_counts = manifest.get("class_counts", {})

    # 1. Exactly 50 records
    if len(record_ids) != 50:
        errors.append(f"Expected 50 record_ids, got {len(record_ids)}")

    # 2. No duplicate IDs
    if len(set(record_ids)) != len(record_ids):
        dupes = [rid for rid, cnt in Counter(record_ids).items() if cnt > 1]
        errors.append(f"Duplicate record IDs: {dupes}")

    # 3. Exactly 10 per class
    for cls_name, count in class_counts.items():
        if count != 10:
            errors.append(f"Class '{cls_name}' has {count} records, expected 10")

    expected_classes = {"benign", "suspicious", "likely_malicious", "confirmed_malicious", "insufficient_evidence"}
    if set(class_counts.keys()) != expected_classes:
        errors.append(f"Expected classes {expected_classes}, got {set(class_counts.keys())}")

    # 4. Every ID exists in validation.jsonl
    for rid in record_ids:
        if rid not in id_to_record:
            errors.append(f"Record ID '{rid}' not found in validation dataset")

    # 5. Ground truth matches validation.jsonl
    if len(ground_truth) != len(record_ids):
        errors.append(f"ground_truth length ({len(ground_truth)}) != record_ids length ({len(record_ids)})")
    else:
        for rid, gt_cls in zip(record_ids, ground_truth):
            if rid in id_to_record:
                actual_cls = id_to_record[rid]['output']['classification']
                if actual_cls != gt_cls:
                    errors.append(
                        f"Ground truth mismatch for {rid}: manifest={gt_cls}, dataset={actual_cls}"
                    )

    return errors


# ---------------------------------------------------------------------------
# Mock scenario builder
# ---------------------------------------------------------------------------

def build_mock_scenario_map(
    manifest: Dict[str, Any],
    id_to_record: Dict[str, Dict[str, Any]],
    prompt_name: str,
) -> Dict[str, dict]:
    """
    Build a deterministic scenario map from the frozen manifest.
    Assigns scenarios to specific record IDs from the manifest.
    
    For baseline runs: record index 4 gets 429, index 5 gets timeout, index 6 gets malformed JSON.
    For experimental_v2 runs: record index 7 gets 429, index 8 gets timeout, index 9 gets malformed JSON.
    
    Indexes 0-3 get correct predictions for both.
    Remaining records get varied correct/incorrect to generate paired differences.
    """
    record_ids = manifest["record_ids"]
    ground_truth = manifest["ground_truth"]
    scenario_map = {}

    for idx, (rid, gt) in enumerate(zip(record_ids, ground_truth)):
        # Get evidence IDs from the actual record
        record = id_to_record.get(rid, {})
        evidence_ids = []
        for evt in record.get("input", {}).get("evidence", []):
            if isinstance(evt, dict) and "id" in evt:
                evidence_ids.append(evt["id"])
        if not evidence_ids:
            evidence_ids = ["EVT-001"]

        base_scenario = {
            "ground_truth": gt,
            "evidence_ids": evidence_ids,
        }

        if prompt_name == "baseline":
            if idx == 4:
                base_scenario["action"] = "429"
            elif idx == 5:
                base_scenario["action"] = "timeout"
            elif idx == 6:
                base_scenario["action"] = "malformed"
            elif idx < 20:
                base_scenario["action"] = "correct"
            elif idx < 30:
                # Some incorrect for baseline to show experimental wins
                base_scenario["action"] = "incorrect"
            else:
                base_scenario["action"] = "correct"
        elif prompt_name == "experimental_v2":
            if idx == 7:
                base_scenario["action"] = "429"
            elif idx == 8:
                base_scenario["action"] = "timeout"
            elif idx == 9:
                base_scenario["action"] = "malformed"
            elif idx < 20:
                base_scenario["action"] = "correct"
            elif idx < 25:
                # Experimental also incorrect on some (ties with baseline)
                base_scenario["action"] = "incorrect"
            elif idx < 30:
                # Experimental correct where baseline was incorrect => experimental wins
                base_scenario["action"] = "correct"
            else:
                base_scenario["action"] = "correct"
        else:
            base_scenario["action"] = "correct"

        scenario_map[rid] = base_scenario

    return scenario_map


# ---------------------------------------------------------------------------
# Single-record execution
# ---------------------------------------------------------------------------

def classify_error(exc: Exception) -> str:
    """Map an exception to an error type constant."""
    if isinstance(exc, LLMRateLimitError):
        return ERROR_429
    elif isinstance(exc, LLMTimeoutError):
        return ERROR_TIMEOUT
    elif isinstance(exc, LLMResponseError):
        return ERROR_JSON_VALIDATION
    elif isinstance(exc, (LLMProviderError, LLMError)):
        return ERROR_OTHER_PROVIDER
    else:
        return ERROR_OTHER_PROVIDER


def build_failure_record(
    record_id: str,
    ground_truth: str,
    latency_ms: float,
    error_type: str,
    error_message: str,
    prompt_name: str,
    prompt_sha256: str,
) -> Dict[str, Any]:
    """Build a result record for a failed prediction."""
    return {
        "record_id": record_id,
        "ground_truth": ground_truth,
        "predicted_classification": None,
        "severity": None,
        "confidence": None,
        "structured_output_valid": False,
        "latency_ms": latency_ms,
        "error_type": error_type,
        "error_message": error_message,
        "prompt_name": prompt_name,
        "prompt_sha256": prompt_sha256,
    }


def build_success_record(
    record_id: str,
    ground_truth: str,
    pred: TriageResult,
    latency_ms: float,
    prompt_name: str,
    prompt_sha256: str,
) -> Dict[str, Any]:
    """Build a result record for a successful prediction."""
    cls_valid = pred.classification in VALID_CLASSIFICATIONS
    sev_valid = pred.severity in VALID_SEVERITIES
    return {
        "record_id": record_id,
        "ground_truth": ground_truth,
        "predicted_classification": pred.classification,
        "severity": pred.severity,
        "confidence": pred.confidence,
        "structured_output_valid": cls_valid and sev_valid,
        "latency_ms": latency_ms,
        "error_type": ERROR_VALID,
        "error_message": None,
        "prompt_name": prompt_name,
        "prompt_sha256": prompt_sha256,
    }


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_experiment(
    manifest: Dict[str, Any],
    id_to_record: Dict[str, Dict[str, Any]],
    prompt_content: str,
    prompt_name: str,
    prompt_sha256: str,
    mock: bool = False,
    model_name: str = "openai/gpt-oss-20b",
    temperature: float = 0.7,
    top_p: float = 0.9,
    max_tokens: int = 1000,
    project_root: Optional[Union[str, Path]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Run the experiment with the given prompt content.
    Returns a tuple of (results list, metrics dict).
    
    Monkey-patches get_triage_system_prompt with try/finally guarantee.
    """
    import ai.prompts.triage as triage_prompts_module

    original_get = triage_prompts_module.get_triage_system_prompt

    # Build provider
    mock_provider = None
    if mock:
        scenario_map = build_mock_scenario_map(manifest, id_to_record, prompt_name)
        mock_provider = ExperimentMockProvider(
            scenario_map=scenario_map,
            default_model=model_name,
        )
        llm_client = LLMClient(provider=mock_provider)
    else:
        from ai.llm.config import LLMConfig
        root = Path(project_root) if project_root is not None else PROJECT_ROOT
        config = LLMConfig.load(root)
        config.model_name = model_name
        config.temperature = temperature
        config.max_tokens = max_tokens
        llm_client = LLMClient.from_config(config)

    agent = TriageAgent(llm_client=llm_client)
    results: List[Dict[str, Any]] = []

    try:
        # Patch the system prompt
        triage_prompts_module.get_triage_system_prompt = lambda: prompt_content

        record_ids = manifest["record_ids"]
        ground_truths = manifest["ground_truth"]

        for idx, (record_id, gt) in enumerate(zip(record_ids, ground_truths)):
            record = id_to_record[record_id]
            alert_input = AlertInput.from_dict(record['input'])

            if mock_provider is not None:
                mock_provider.set_current_record(record_id)

            start_time = time.time()
            try:
                pred = agent.triage(alert_input)
                latency_ms = (time.time() - start_time) * 1000
                results.append(build_success_record(
                    record_id, gt, pred, latency_ms, prompt_name, prompt_sha256,
                ))
            except LLMRateLimitError as e:
                latency_ms = (time.time() - start_time) * 1000
                results.append(build_failure_record(
                    record_id, gt, latency_ms, ERROR_429,
                    str(e), prompt_name, prompt_sha256,
                ))
            except LLMTimeoutError as e:
                latency_ms = (time.time() - start_time) * 1000
                results.append(build_failure_record(
                    record_id, gt, latency_ms, ERROR_TIMEOUT,
                    str(e), prompt_name, prompt_sha256,
                ))
            except LLMResponseError as e:
                latency_ms = (time.time() - start_time) * 1000
                results.append(build_failure_record(
                    record_id, gt, latency_ms, ERROR_JSON_VALIDATION,
                    str(e), prompt_name, prompt_sha256,
                ))
            except (LLMError, LLMProviderError) as e:
                latency_ms = (time.time() - start_time) * 1000
                results.append(build_failure_record(
                    record_id, gt, latency_ms, ERROR_OTHER_PROVIDER,
                    str(e), prompt_name, prompt_sha256,
                ))
            except Exception as e:
                latency_ms = (time.time() - start_time) * 1000
                results.append(build_failure_record(
                    record_id, gt, latency_ms, ERROR_OTHER_PROVIDER,
                    str(e), prompt_name, prompt_sha256,
                ))

            if (idx + 1) % 10 == 0:
                print(f"  [{prompt_name}] Processed {idx + 1}/{len(record_ids)} records")

    finally:
        # ALWAYS restore the original function
        triage_prompts_module.get_triage_system_prompt = original_get

    metrics = compute_metrics(results, prompt_name)
    return results, metrics


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(results: List[Dict[str, Any]], prompt_name: str) -> Dict[str, Any]:
    """Compute comprehensive metrics from a list of result records."""
    total = len(results)
    successful = [r for r in results if r["error_type"] == ERROR_VALID]
    failed = [r for r in results if r["error_type"] != ERROR_VALID]

    error_429_count = sum(1 for r in results if r["error_type"] == ERROR_429)
    json_fail_count = sum(1 for r in results if r["error_type"] == ERROR_JSON_VALIDATION)
    timeout_count = sum(1 for r in results if r["error_type"] == ERROR_TIMEOUT)
    other_error_count = sum(1 for r in results if r["error_type"] == ERROR_OTHER_PROVIDER)

    coverage = len(successful) / total if total > 0 else 0.0

    # Valid-prediction accuracy (among successful only)
    correct_valid = sum(
        1 for r in successful
        if r["predicted_classification"] == r["ground_truth"]
    )
    valid_accuracy = correct_valid / len(successful) if successful else 0.0

    # End-to-end accuracy (all records; failures count as wrong)
    correct_e2e = sum(
        1 for r in results
        if r["error_type"] == ERROR_VALID and r["predicted_classification"] == r["ground_truth"]
    )
    e2e_accuracy = correct_e2e / total if total > 0 else 0.0

    # Per-class metrics (using successful predictions only)
    pred_classes = [r["predicted_classification"] for r in successful]
    gt_classes = [r["ground_truth"] for r in successful]
    labels = sorted(list(VALID_CLASSIFICATIONS))

    per_class = _compute_per_class_metrics(pred_classes, gt_classes, labels)
    macro = _compute_macro_metrics(per_class)
    confusion = _compute_confusion_matrix(pred_classes, gt_classes, labels)

    # Prediction distribution
    pred_dist = dict(Counter(r["predicted_classification"] for r in successful))

    # Latency
    latencies = [r["latency_ms"] for r in results]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "prompt_name": prompt_name,
        "attempted": total,
        "successful": len(successful),
        "failed": len(failed),
        "error_429_count": error_429_count,
        "json_validation_failure_count": json_fail_count,
        "timeout_count": timeout_count,
        "other_error_count": other_error_count,
        "coverage": round(coverage, 4),
        "valid_prediction_accuracy": round(valid_accuracy, 4),
        "end_to_end_accuracy": round(e2e_accuracy, 4),
        "macro_precision": macro["macro_precision"],
        "macro_recall": macro["macro_recall"],
        "macro_f1": macro["macro_f1"],
        "per_class_metrics": per_class,
        "confusion_matrix": confusion,
        "prediction_distribution": pred_dist,
        "average_latency_ms": round(avg_latency, 2),
    }


def _compute_per_class_metrics(
    predictions: List[str],
    targets: List[str],
    labels: List[str],
) -> Dict[str, Dict[str, float]]:
    """Compute precision, recall, F1 per class."""
    results = {}
    for label in labels:
        tp = sum(1 for p, t in zip(predictions, targets) if p == label and t == label)
        fp = sum(1 for p, t in zip(predictions, targets) if p == label and t != label)
        fn = sum(1 for p, t in zip(predictions, targets) if p != label and t == label)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        results[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(1 for t in targets if t == label),
        }
    return results


def _compute_macro_metrics(per_class: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    """Compute macro averages from per-class metrics."""
    if not per_class:
        return {"macro_precision": 0.0, "macro_recall": 0.0, "macro_f1": 0.0}
    k = len(per_class)
    return {
        "macro_precision": round(sum(m["precision"] for m in per_class.values()) / k, 4),
        "macro_recall": round(sum(m["recall"] for m in per_class.values()) / k, 4),
        "macro_f1": round(sum(m["f1"] for m in per_class.values()) / k, 4),
    }


def _compute_confusion_matrix(
    predictions: List[str],
    targets: List[str],
    labels: List[str],
) -> Dict[str, Dict[str, int]]:
    """Build confusion matrix: matrix[actual][predicted] = count."""
    matrix = {actual: {pred: 0 for pred in labels} for actual in labels}
    for p, t in zip(predictions, targets):
        if t in matrix:
            if p in matrix[t]:
                matrix[t][p] += 1
            else:
                matrix[t][p] = 1
    return matrix


# ---------------------------------------------------------------------------
# Paired analysis
# ---------------------------------------------------------------------------

def compute_paired_analysis(
    baseline_results: List[Dict[str, Any]],
    experimental_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compare the same record IDs across baseline and experimental runs.
    Both lists must use the same manifest order.
    """
    baseline_by_id = {r["record_id"]: r for r in baseline_results}
    experimental_by_id = {r["record_id"]: r for r in experimental_results}

    all_ids = list(baseline_by_id.keys())

    baseline_wins = 0
    experimental_wins = 0
    ties = 0
    changed_classifications = []
    both_valid_count = 0
    both_valid_correct_baseline = 0
    both_valid_correct_experimental = 0

    for rid in all_ids:
        b = baseline_by_id.get(rid)
        e = experimental_by_id.get(rid)
        if not b or not e:
            continue

        b_valid = b["error_type"] == ERROR_VALID
        e_valid = e["error_type"] == ERROR_VALID

        if not b_valid and not e_valid:
            ties += 1
            continue
        if b_valid and not e_valid:
            baseline_wins += 1
            continue
        if not b_valid and e_valid:
            experimental_wins += 1
            continue

        # Both valid
        both_valid_count += 1
        b_correct = b["predicted_classification"] == b["ground_truth"]
        e_correct = e["predicted_classification"] == e["ground_truth"]

        if b_correct:
            both_valid_correct_baseline += 1
        if e_correct:
            both_valid_correct_experimental += 1

        if b_correct and not e_correct:
            baseline_wins += 1
        elif e_correct and not b_correct:
            experimental_wins += 1
        elif b_correct == e_correct:
            ties += 1

        # Track classification changes
        if b["predicted_classification"] != e["predicted_classification"]:
            changed_classifications.append({
                "record_id": rid,
                "ground_truth": b["ground_truth"],
                "baseline_predicted": b["predicted_classification"],
                "experimental_predicted": e["predicted_classification"],
                "transition": f"{b['predicted_classification']} -> {e['predicted_classification']}",
            })

    # Paired accuracy delta
    b_acc = both_valid_correct_baseline / both_valid_count if both_valid_count > 0 else 0.0
    e_acc = both_valid_correct_experimental / both_valid_count if both_valid_count > 0 else 0.0
    paired_accuracy_delta = e_acc - b_acc

    # Transition counts
    transition_counts = dict(Counter(c["transition"] for c in changed_classifications))

    # Coverage check for conclusiveness
    baseline_coverage = sum(1 for r in baseline_results if r["error_type"] == ERROR_VALID) / len(baseline_results)
    experimental_coverage = sum(1 for r in experimental_results if r["error_type"] == ERROR_VALID) / len(experimental_results)

    experiment_conclusive = baseline_coverage >= 0.7 and experimental_coverage >= 0.7

    return {
        "total_records": len(all_ids),
        "both_valid_count": both_valid_count,
        "baseline_wins": baseline_wins,
        "experimental_wins": experimental_wins,
        "ties": ties,
        "paired_accuracy_delta": round(paired_accuracy_delta, 4),
        "baseline_paired_accuracy": round(b_acc, 4),
        "experimental_paired_accuracy": round(e_acc, 4),
        "changed_classifications": changed_classifications,
        "transition_counts": transition_counts,
        "baseline_coverage": round(baseline_coverage, 4),
        "experimental_coverage": round(experimental_coverage, 4),
        "experiment_conclusive": experiment_conclusive,
        "verdict": "EXPERIMENT_CONCLUSIVE" if experiment_conclusive else "EXPERIMENT_INCONCLUSIVE",
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_results(
    results: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    output_dir: Union[str, Path],
    prompt_name: str,
):
    """Save results and metrics to JSON files."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / f"{prompt_name}_results.json"
    metrics_path = out_dir / f"{prompt_name}_metrics.json"

    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)

    print(f"  Saved {results_path}")
    print(f"  Saved {metrics_path}")


def save_paired_analysis(
    analysis: Dict[str, Any],
    output_dir: Union[str, Path],
):
    """Save paired analysis to JSON."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "paired_analysis.json"
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2)
    print(f"  Saved {path}")


def save_experiment_summary(
    baseline_metrics: Dict[str, Any],
    experimental_metrics: Dict[str, Any],
    paired_analysis: Dict[str, Any],
    baseline_sha: str,
    experimental_sha: str,
    output_dir: Union[str, Path],
):
    """Save a combined experiment summary."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "baseline_prompt_sha256": baseline_sha,
        "experimental_prompt_sha256": experimental_sha,
        "baseline_metrics": baseline_metrics,
        "experimental_metrics": experimental_metrics,
        "paired_analysis": paired_analysis,
    }
    path = out_dir / "experiment_summary.json"
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    print(f"  Saved {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Run Phase 3 Controlled Prompt Experiment V2"
    )
    parser.add_argument("--manifest", required=True, help="Path to manifest JSON")
    parser.add_argument("--baseline-prompt", required=True, help="Path to baseline prompt")
    parser.add_argument("--experimental-prompt", required=True, help="Path to experimental prompt V2")
    parser.add_argument("--output-dir", default="reports/phase3/experiment_v2", help="Output directory")
    parser.add_argument("--model", default="openai/gpt-oss-20b", help="Model name")
    parser.add_argument("--temperature", type=float, default=0.7, help="Temperature")
    parser.add_argument("--top_p", type=float, default=0.9, help="Top p")
    parser.add_argument("--max_tokens", type=int, default=1000, help="Max tokens")
    parser.add_argument("--mock", action="store_true", help="Use deterministic mock provider (offline)")
    args = parser.parse_args()

    # Convert CLI path arguments immediately to Path objects
    manifest_path = Path(args.manifest)
    baseline_prompt_path = Path(args.baseline_prompt)
    experimental_prompt_path = Path(args.experimental_prompt)
    output_dir = Path(args.output_dir)

    print("=" * 70)
    print("Phase 3 Controlled Prompt Experiment V2")
    print("=" * 70)
    mode_str = "MOCK (offline)" if args.mock else "REAL (API)"
    print(f"Mode: {mode_str}")
    print(f"Model: {args.model}")
    print()

    # ── 1. Load manifest ──
    print("[1/7] Loading manifest...")
    manifest = load_manifest(manifest_path)
    print(f"  Loaded {len(manifest['record_ids'])} record IDs")

    # ── 2. Load validation dataset ──
    print("[2/7] Loading validation dataset...")
    dataset_path = PROJECT_ROOT / manifest.get("dataset", "datasets/finetuning/v0.4/validation.jsonl")
    id_to_record = load_validation_dataset(dataset_path)
    print(f"  Loaded {len(id_to_record)} validation records")

    # ── 3. Validate manifest ──
    print("[3/7] Validating manifest...")
    manifest_errors = validate_manifest(manifest, id_to_record)
    if manifest_errors:
        print("  MANIFEST VALIDATION FAILED:")
        for err in manifest_errors:
            print(f"    [X] {err}")
        sys.exit(1)
    print("  [OK] 50 records, 10 per class, no duplicates, ground truth matches")

    # ── 4. Load prompts ──
    print("[4/7] Loading prompts...")
    baseline_prompt = load_prompt(baseline_prompt_path)
    experimental_prompt = load_prompt(experimental_prompt_path)
    baseline_sha = compute_sha256(baseline_prompt)
    experimental_sha = compute_sha256(experimental_prompt)
    print(f"  Baseline SHA-256:     {baseline_sha}")
    print(f"  Experimental SHA-256: {experimental_sha}")

    # ── 5. Run baseline ──
    print("[5/7] Running BASELINE experiment...")
    baseline_results, baseline_metrics = run_experiment(
        manifest=manifest,
        id_to_record=id_to_record,
        prompt_content=baseline_prompt,
        prompt_name="baseline",
        prompt_sha256=baseline_sha,
        mock=args.mock,
        model_name=args.model,
        temperature=args.temperature,
        top_p=args.top_p,
        max_tokens=args.max_tokens,
    )
    save_results(baseline_results, baseline_metrics, output_dir, "baseline")
    print(f"  Baseline: {baseline_metrics['successful']}/{baseline_metrics['attempted']} successful, "
          f"accuracy={baseline_metrics['valid_prediction_accuracy']}")

    # ── 6. Run experimental ──
    print("[6/7] Running EXPERIMENTAL V2 experiment...")
    experimental_results, experimental_metrics = run_experiment(
        manifest=manifest,
        id_to_record=id_to_record,
        prompt_content=experimental_prompt,
        prompt_name="experimental_v2",
        prompt_sha256=experimental_sha,
        mock=args.mock,
        model_name=args.model,
        temperature=args.temperature,
        top_p=args.top_p,
        max_tokens=args.max_tokens,
    )
    save_results(experimental_results, experimental_metrics, output_dir, "experimental_v2")
    print(f"  Experimental: {experimental_metrics['successful']}/{experimental_metrics['attempted']} successful, "
          f"accuracy={experimental_metrics['valid_prediction_accuracy']}")

    # ── 7. Paired analysis ──
    print("[7/7] Computing paired analysis...")
    paired = compute_paired_analysis(baseline_results, experimental_results)
    save_paired_analysis(paired, output_dir)
    save_experiment_summary(
        baseline_metrics, experimental_metrics, paired,
        baseline_sha, experimental_sha, output_dir,
    )

    print()
    print("=" * 70)
    print("Experiment Summary")
    print("=" * 70)
    print(f"  Baseline wins:     {paired['baseline_wins']}")
    print(f"  Experimental wins: {paired['experimental_wins']}")
    print(f"  Ties:              {paired['ties']}")
    print(f"  Paired delta accuracy: {paired['paired_accuracy_delta']:+.4f}")
    print(f"  Verdict:               {paired['verdict']}")
    if paired["transition_counts"]:
        print("  Classification transitions:")
        for transition, count in paired["transition_counts"].items():
            safe_transition = transition.encode("ascii", "replace").decode("ascii")
            print(f"    {safe_transition}: {count}")
    print()
    print("Experiment completed successfully.")


if __name__ == '__main__':
    main()