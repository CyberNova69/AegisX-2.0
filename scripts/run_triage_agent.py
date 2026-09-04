#!/usr/bin/env python3
"""
AegisX TriageAgent Real LLM & Mock Dataset Evaluation Script
=============================================================

Evaluates TriageAgent against synthetic SOC dataset records (from datasets/validated/soc_examples_validated.jsonl).
Supports both MockProvider and Real APIProvider (Groq/OpenAI).

Usage:
    python scripts/run_triage_agent.py --count 100 --provider api
    python scripts/run_triage_agent.py --count 100 --provider mock
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.triage_agent import TriageAgent
from ai.agents.schemas import AlertInput, TriageResult
from ai.evaluation.triage_eval import evaluate_triage_predictions
from ai.llm import LLMClient, LLMConfig, LLMResponseError, LLMAuthenticationError, LLMTimeoutError, LLMProviderError, LLMRateLimitError
from ai.llm.providers.mock import MockProvider

def main():
    parser = argparse.ArgumentParser(description="Evaluate AegisX TriageAgent against SOC dataset")
    parser.add_argument("--count", type=int, default=100, help="Number of records to evaluate (default: 100)")
    parser.add_argument("--dataset", type=str, default=None, help="Input validated dataset file path")
    parser.add_argument("--provider", type=str, choices=["mock", "api", "config"], default="config", help="LLM Provider to use ('mock', 'api', or 'config')")
    parser.add_argument("--model", type=str, default=None, help="LLM model identifier override")
    parser.add_argument("--all-tasks", action="store_true", default=True, help="Evaluate all dataset records with valid alert inputs")
    args = parser.parse_args()

    dataset_path = Path(args.dataset) if args.dataset else PROJECT_ROOT / "datasets" / "validated" / "soc_examples_validated.jsonl"
    if not dataset_path.exists():
        dataset_path = PROJECT_ROOT / "datasets" / "generated" / "soc_examples.jsonl"

    if not dataset_path.exists():
        print(f"Error: Dataset file not found at {dataset_path}")
        return 1

    # Load configuration
    config = LLMConfig.load(PROJECT_ROOT)
    if args.provider != "config":
        config.provider_name = args.provider
    if args.model:
        config.model_name = args.model

    # Determine provider instance
    if config.provider_name == "mock":
        client = LLMClient.from_mock()
    else:
        client = LLMClient.from_config(config)

    agent = TriageAgent(llm_client=client)

    # Load dataset records
    records = []
    dataset_version = "0.2"
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            dataset_version = r.get("metadata", {}).get("dataset_version", dataset_version)
            if args.all_tasks or r.get("task") == "alert_triage":
                records.append(r)
                if len(records) >= args.count:
                    break

    if not records:
        print(f"No valid records found in {dataset_path}")
        return 1

    # Configure mock provider responses if in mock mode
    if config.provider_name == "mock" and isinstance(client.provider, MockProvider):
        for rec in records:
            alert_title = rec.get("input", {}).get("alert", {}).get("title", "")
            out_dict = dict(rec.get("output", {}))
            if "severity" not in out_dict:
                out_dict["severity"] = rec.get("input", {}).get("alert", {}).get("severity", "medium")
            if alert_title:
                client.provider.register_response(alert_title, json.dumps(out_dict))

    print("======================================================================")
    print("  100-record synthetic evaluation of the AegisX triage pipeline.")
    print("======================================================================")
    print(f"  Dataset:         {dataset_path}")
    print(f"  Dataset Version: {dataset_version}")
    print(f"  Target Count:    {len(records)}")
    print(f"  Provider:        {config.provider_name.upper()}")
    print(f"  Model:           {config.model_name}")
    print("======================================================================\n")

    successful_requests = 0
    failed_requests = 0
    schema_failures = 0
    evidence_id_failures = 0
    malformed_json_failures = 0
    api_network_failures = 0

    predictions: list[TriageResult] = []
    valid_records: list[dict] = []
    latencies: list[float] = []

    print("Executing evaluation across dataset records...\n")

    for i, rec in enumerate(records, start=1):
        alert_id = rec.get("id")
        gt_cls = rec.get("output", {}).get("classification")
        alert_input = rec.get("input")

        retries_left = 3
        while retries_left >= 0:
            try:
                start_t = time.time()
                result = agent.triage(alert_input)
                elapsed_ms = (time.time() - start_t) * 1000

                successful_requests += 1
                predictions.append(result)
                valid_records.append(rec)
                latencies.append(result.metadata.get("latency_ms", elapsed_ms))

                print(f"[{i:03d}/{len(records)}] {alert_id} | GT: {gt_cls:20s} | Pred: {result.classification:20s} | Conf: {result.confidence:.2f} | Latency: {result.metadata.get('latency_ms', elapsed_ms):.0f}ms", flush=True)
                break

            except LLMRateLimitError as e:
                retries_left -= 1
                if retries_left >= 0:
                    print(f"[{i:03d}/{len(records)}] {alert_id} | [RATE LIMIT] Retrying in 8s... ({retries_left} retries left)", flush=True)
                    time.sleep(8.0)
                else:
                    failed_requests += 1
                    api_network_failures += 1
                    print(f"[{i:03d}/{len(records)}] {alert_id} | [FAIL - API RATE LIMIT EXHAUSTED]: {e}", flush=True)
                    break

            except LLMResponseError as e:
                failed_requests += 1
                err_str = str(e)
                if "Evidence grounding failure" in err_str:
                    evidence_id_failures += 1
                    print(f"[{i:03d}/{len(records)}] {alert_id} | [FAIL - EVIDENCE ID GROUNDING]: {e}", flush=True)
                elif "Failed to parse structured JSON" in err_str or "JSON" in err_str:
                    malformed_json_failures += 1
                    print(f"[{i:03d}/{len(records)}] {alert_id} | [FAIL - MALFORMED JSON]: {e}", flush=True)
                else:
                    schema_failures += 1
                    print(f"[{i:03d}/{len(records)}] {alert_id} | [FAIL - SCHEMA VALIDATION]: {e}", flush=True)
                break

            except (LLMAuthenticationError, LLMTimeoutError, LLMProviderError) as e:
                failed_requests += 1
                api_network_failures += 1
                print(f"[{i:03d}/{len(records)}] {alert_id} | [FAIL - API NETWORK ERROR]: {e}", flush=True)
                break

            except Exception as e:
                failed_requests += 1
                schema_failures += 1
                print(f"[{i:03d}/{len(records)}] {alert_id} | [FAIL - UNEXPECTED ERROR]: {e}", flush=True)
                break

        # Delay between real API requests to stay comfortably within Groq TPM limits
        if config.provider_name != "mock":
            time.sleep(1.5)

    # Calculate metrics over valid predictions
    metrics = evaluate_triage_predictions(predictions, valid_records)
    metrics_dict = metrics.to_dict()

    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print("\n======================================================================")
    print("  100-record synthetic evaluation of the AegisX triage pipeline.")
    print("======================================================================")
    print(f"  1. Total Records Tested:              {len(records)}")
    print(f"  2. Successful Requests:               {successful_requests}")
    print(f"  3. Failed Requests:                   {failed_requests}")
    print(f"  4. Classification Accuracy:           {metrics_dict['accuracy'] * 100:.1f}%")
    print(f"  5. Investigation Decision Accuracy:   {metrics_dict['investigation_agreement_pct'] * 100:.1f}%")
    print(f"  6. Average Confidence:                {metrics_dict['avg_confidence']:.3f}")
    print(f"  7. Classification Distribution:       {metrics_dict['classification_counts']}")
    print(f"  8. Schema Validation Failures:        {schema_failures}")
    print(f"  9. Evidence-ID Validation Failures:   {evidence_id_failures}")
    print(f" 10. Malformed LLM Responses:           {malformed_json_failures}")
    print(f" 11. API / Network Failures:            {api_network_failures}")
    print(f" 12. Average Latency:                   {avg_latency:.1f} ms")
    print(f" 13. Provider:                          {config.provider_name}")
    print(f" 14. Model:                             {config.model_name}")
    print(f" 15. Dataset Version:                   {dataset_version}")
    print("======================================================================\n")

    return 0

if __name__ == "__main__":
    sys.exit(main())
