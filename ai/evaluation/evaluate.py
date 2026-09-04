"""
AegisX Evaluation Runner
=========================

Entrypoint for executing offline deterministic evaluations or genuine online API
evaluations across Triage, Investigation, ThreatIntel, RAG, and Safety components.
Strictly adheres to provider configurations without silent mock fallbacks.
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.schemas import AlertInput, TriageResult
from ai.agents.triage_agent import TriageAgent
from ai.evaluation.benchmark import BenchmarkReport, generate_comparison_schema
from ai.evaluation.loader import load_test_records
from ai.evaluation.rag_eval import evaluate_rag_retrieval
from ai.evaluation.safety_eval import evaluate_safety_invariants
from ai.evaluation.test_set_firewall import (
    DEFAULT_TEST_SET_PATH,
    EXPECTED_TEST_SET_COUNT,
    EXPECTED_TEST_SET_SHA256,
    TestSetFirewall,
)
from ai.evaluation.triage_eval import evaluate_triage_predictions, TriageEvalMetrics
from ai.evaluation.investigation_eval import evaluate_investigation_scenarios, InvestigationEvalMetrics
from ai.evaluation.threat_intel_eval import evaluate_threat_intel_results, ThreatIntelEvalMetrics
from ai.llm import (
    LLMClient,
    LLMConfig,
    LLMError,
    LLMAuthenticationError,
    LLMConfigurationError,
)
from ai.llm.providers.api import APIProvider
from ai.llm.providers.mock import MockProvider

logger = logging.getLogger("AegisX.Evaluation")

def resolve_evaluation_client(
    provider_name: str = "mock",
    model_name: Optional[str] = None,
    client: Optional[LLMClient] = None,
) -> LLMClient:
    """
    Resolve and validate LLMClient for evaluation.
    Strictly prohibits silent fallback:
      - 'api' MUST use APIProvider; missing key raises LLMAuthenticationError.
      - 'mock' MUST use MockProvider.
    """
    if client is not None:
        return client

    config = LLMConfig.load(PROJECT_ROOT)
    clean_provider = provider_name.strip().lower()

    if clean_provider == "api":
        if not config.api_key:
            raise LLMAuthenticationError(
                "API provider requested but no API key configured. "
                "Set LLM_API_KEY in .env or environment variable.",
                provider="api",
            )
        config.provider_name = "api"
        if model_name:
            config.model_name = model_name
        
        provider = APIProvider(
            api_key=config.api_key,
            base_url=config.api_base_url,
            default_model=config.model_name,
            max_retries=config.max_retries,
            retry_delay=config.retry_delay,
        )
        return LLMClient(provider=provider, config=config)

    elif clean_provider == "mock":
        config.provider_name = "mock"
        if model_name:
            config.model_name = model_name
        elif not config.model_name or config.model_name == "openai/gpt-oss-20b":
            config.model_name = "mock-soc-analyst-v1"

        mock_resp = json.dumps({
            "classification": "suspicious",
            "severity": "medium",
            "confidence": 0.85,
            "summary": "Mock triage evaluation response.",
            "rationale": "Mock triage evaluation response.",
            "findings": [],
            "investigation_required": True,
        })
        provider = MockProvider(default_model=config.model_name, default_response=mock_resp)
        return LLMClient(provider=provider, config=config)

    else:
        raise LLMConfigurationError(
            f"Unsupported evaluation provider '{provider_name}'. Supported: 'mock', 'api'.",
            provider=provider_name,
        )

def run_evaluation_suite(
    provider_name: str = "mock",
    model_name: Optional[str] = None,
    sample_size: Optional[int] = None,
    output_dir: Optional[Path] = None,
    client: Optional[LLMClient] = None,
    eval_investigation: bool = False,
    eval_threat_intel: bool = False,
    eval_rag: bool = True,
) -> BenchmarkReport:
    """
    Execute benchmark evaluation across requested AegisX SOC components.
    """
    # 1. Resolve LLM client (validates provider and credentials)
    active_client = resolve_evaluation_client(
        provider_name=provider_name,
        model_name=model_name,
        client=client,
    )
    actual_provider = active_client.provider.name
    actual_model = active_client.config.model_name

    # Mode must match real provider
    if actual_provider == "api":
        evaluation_mode = "REAL_API_BENCHMARK"
    else:
        evaluation_mode = "MOCK_EVALUATION"

    # 2. Verify firewall and load held-out test set
    firewall_info = TestSetFirewall.verify_test_set_integrity()
    test_records = load_test_records()
    total_test_records = len(test_records)

    if sample_size is not None:
        if sample_size <= 0:
            raise ValueError(f"sample_size must be a positive integer, got {sample_size}")
        eval_records = test_records[:sample_size]
    else:
        eval_records = test_records

    records_evaluated = len(eval_records)

    # 3. Triage Evaluation (runs real agent with active client)
    triage_agent = TriageAgent(llm_client=active_client)
    triage_predictions: List[TriageResult] = []
    failed_record_ids: List[str] = []

    for idx, rec in enumerate(eval_records, start=1):
        alert_inp = AlertInput.from_dict(rec["input"])
        try:
            pred = triage_agent.triage(alert_inp)
            triage_predictions.append(pred)
        except Exception as e:
            rec_id = rec.get("id", f"rec-{idx}")
            logger.error(f"Triage call failed for record {rec_id}: {e}")
            failed_record_ids.append(rec_id)
            # Record explicit failure without collapsing into silent success
            triage_predictions.append(
                TriageResult(
                    classification="unknown",
                    severity="unknown",
                    confidence=0.0,
                    summary=f"Evaluation execution failure: {e}",
                    findings=[],
                    investigation_required=False,
                )
            )

    triage_metrics = evaluate_triage_predictions(triage_predictions, eval_records)

    # 4. RAG Retrieval Evaluation (deterministic, in-memory BM25)
    rag_metrics = None
    if eval_rag:
        rag_metrics = evaluate_rag_retrieval().to_dict()

    # 5. Investigation Agent Evaluation (optional, multi-turn)
    inv_metrics = None
    inv_results = []
    if eval_investigation:
        from ai.agents.investigation_agent import InvestigationAgent
        from ai.agents.investigation_schemas import InvestigationRequest
        from ai.tools.synthetic_data import list_scenarios, get_scenario

        scenarios = [get_scenario(s["key"]) for s in list_scenarios()]
        inv_agent = InvestigationAgent(llm_client=active_client, max_steps=5)
        for scn in scenarios:
            req = InvestigationRequest(
                alert=scn["alert"],
                context=scn["context"],
                max_steps=5,
            )
            res = inv_agent.investigate(req)
            inv_results.append(res.to_dict())
        inv_metrics = evaluate_investigation_scenarios(inv_results, scenarios)

    # 6. Threat Intelligence Evaluation (optional)
    ti_metrics = None
    ti_results = []
    if eval_threat_intel:
        from ai.agents.threat_intel_agent import ThreatIntelAgent
        from ai.agents.threat_intel_schemas import ThreatIntelRequest
        from ai.tools.synthetic_data import list_scenarios, get_scenario

        scenarios = [get_scenario(s["key"]) for s in list_scenarios()]
        ti_agent = ThreatIntelAgent(llm_client=active_client, max_steps=5)
        for scn in scenarios:
            req = ThreatIntelRequest(
                alert=scn["alert"],
                context=scn["context"],
                evidence=scn.get("evidence", []),
            )
            res = ti_agent.enrich(req)
            ti_results.append(res)
        ti_metrics = evaluate_threat_intel_results(ti_results)

    # 7. Safety Invariant Evaluation on actual outputs
    agent_results_for_safety = [p.to_dict() if hasattr(p, "to_dict") else p for p in triage_predictions]
    if inv_results:
        agent_results_for_safety.extend(inv_results)
    if ti_results:
        agent_results_for_safety.extend([r.to_dict() if hasattr(r, "to_dict") else r for r in ti_results])

    safety_metrics = evaluate_safety_invariants(
        agent_results=agent_results_for_safety,
        tested_injections=0,
        blocked_injections=0,
        destructive_attempts=0,
        destructive_blocked=0,
    ).to_dict()

    # 8. Assemble Benchmark Report
    test_set_meta = {
        "dataset_version": "v0.4",
        "test_set_path": str(DEFAULT_TEST_SET_PATH),
        "sha256": firewall_info["sha256"],
        "total_records": total_test_records,
        "records_evaluated": records_evaluated,
        "firewall_verified": True,
        "failed_records_count": len(failed_record_ids),
    }

    report = BenchmarkReport(
        provider_name=actual_provider,
        model_name=actual_model,
        evaluation_mode=evaluation_mode,
        triage_metrics=triage_metrics,
        investigation_metrics=inv_metrics,
        threat_intel_metrics=ti_metrics,
        rag_metrics=rag_metrics,
        safety_metrics=safety_metrics,
        test_set_metadata=test_set_meta,
        notes=f"Evaluated {records_evaluated} out of {total_test_records} held-out test records.",
    )

    if output_dir:
        json_path, md_path = report.save(output_dir)
        print(f"Benchmark reports saved:\n  JSON: {json_path}\n  Markdown: {md_path}")

    return report

def main():
    parser = argparse.ArgumentParser(description="AegisX Benchmark Evaluation Runner")
    parser.add_argument("--provider", default="mock", choices=["mock", "api"], help="LLM Provider: 'mock' (default) or 'api'")
    parser.add_argument("--model", default=None, help="LLM model override (defaults to configured model in .env / model.yaml)")
    parser.add_argument("--sample-size", type=int, default=None, help="Number of held-out test records to evaluate")
    parser.add_argument("--output-dir", type=str, default="reports/evaluation", help="Reports output path")
    parser.add_argument("--eval-investigation", action="store_true", help="Include multi-step investigation agent evaluation")
    parser.add_argument("--eval-threat-intel", action="store_true", help="Include threat intelligence agent evaluation")
    parser.add_argument("--no-rag", action="store_true", help="Skip RAG retrieval evaluation")
    args = parser.parse_args()

    out_dir = Path(args.output_dir) if args.output_dir else None
    report = run_evaluation_suite(
        provider_name=args.provider,
        model_name=args.model,
        sample_size=args.sample_size,
        output_dir=out_dir,
        eval_investigation=args.eval_investigation,
        eval_threat_intel=args.eval_threat_intel,
        eval_rag=not args.no_rag,
    )
    print(f"Evaluation finished: Mode={report.evaluation_mode} Provider={report.provider_name} Model={report.model_name} Records={report.records_evaluated}/{report.total_test_records}")

if __name__ == "__main__":
    main()
