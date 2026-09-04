#!/usr/bin/env python3
"""
AegisX Evaluation Framework Unit Tests
======================================

Unit tests verifying:
  - Test set loader and schema validation
  - Test-set firewall and training isolation
  - Classification, Macro F1, and Confusion Matrix metrics
  - Severity, Investigation, ThreatIntel, and RAG Hit@K metrics
  - Safety invariants and destructive action containment
  - Benchmark report generation (JSON & Markdown)
  - Dataset SHA-256 hash recording
  - Failure categorization
  - Base vs. Fine-Tuned comparison schema

Usage:
    python -m unittest tests/test_evaluation_framework.py -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.evaluation import (
    TestSetFirewall,
    FirewallViolationError,
    EXPECTED_TEST_SET_SHA256,
    EXPECTED_TEST_SET_COUNT,
    load_test_records,
    DatasetValidationError,
    compute_accuracy,
    compute_confusion_matrix,
    compute_per_class_metrics,
    compute_macro_metrics,
    compute_hit_at_k,
    compute_latency_stats,
    compute_evidence_grounding_stats,
    FailureType,
    TriageEvalMetrics,
    evaluate_triage_predictions,
    InvestigationEvalMetrics,
    evaluate_investigation_scenarios,
    ThreatIntelEvalMetrics,
    evaluate_threat_intel_results,
    RAGRetrievalMetrics,
    evaluate_rag_retrieval,
    SafetyEvaluationMetrics,
    evaluate_safety_invariants,
    BenchmarkReport,
    generate_comparison_schema,
)
from ai.agents.schemas import TriageResult

class TestEvaluationFramework(unittest.TestCase):
    """Comprehensive unit tests for the AegisX evaluation and benchmarking pipeline."""

    def setUp(self):
        # Small synthetic fixture matching schema
        self.sample_record = {
            "id": "SOC-999001",
            "task": "alert_triage",
            "input": {
                "alert": {"title": "Test Alert", "severity": "high", "source": "EDR"},
                "context": {"hostname": "HOST-01", "ip_address": "10.0.0.1"},
                "evidence": [{"id": "EVT-01", "type": "process_creation", "description": "powershell.exe"}],
            },
            "output": {
                "classification": "confirmed_malicious",
                "confidence": 0.95,
                "findings": [{"description": "Malicious script", "evidence_refs": ["EVT-01"]}],
            },
            "metadata": {"dataset_version": "v0.4"},
        }

    # -------------------------------------------------------------------------
    # 1. Test Dataset Loader & Schema Validation
    # -------------------------------------------------------------------------
    def test_test_set_loader_valid_fixture(self):
        """Loader successfully loads and validates structured test records."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
            tf.write(json.dumps(self.sample_record) + "\n")
            temp_path = Path(tf.name)

        try:
            records = load_test_records(temp_path, enforce_count=False, verify_firewall=False)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["id"], "SOC-999001")
            self.assertEqual(records[0]["output"]["classification"], "confirmed_malicious")
        finally:
            temp_path.unlink(missing_ok=True)

    def test_schema_validation_rejects_malformed_records(self):
        """Loader raises DatasetValidationError when records lack required keys or have invalid labels."""
        bad_record = dict(self.sample_record)
        bad_record["output"] = {
            "classification": "not_a_real_class",
            "confidence": 0.95,
            "findings": [{"description": "test", "evidence_refs": ["EVT-01"]}],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as tf:
            tf.write(json.dumps(bad_record) + "\n")
            temp_path = Path(tf.name)

        try:
            with self.assertRaises(DatasetValidationError) as ctx:
                load_test_records(temp_path, enforce_count=False, verify_firewall=False)
            self.assertIn("invalid classification", str(ctx.exception))
        finally:
            temp_path.unlink(missing_ok=True)

    # -------------------------------------------------------------------------
    # 2. Test-Set Firewall & Isolation
    # -------------------------------------------------------------------------
    def test_test_set_firewall_blocks_write_access(self):
        """Firewall prevents opening test.jsonl with modifying write or append modes."""
        test_file = PROJECT_ROOT / "datasets" / "finetuning" / "v0.4" / "test.jsonl"
        with self.assertRaises(FirewallViolationError):
            TestSetFirewall.assert_read_only_access(test_file, mode="w")
        with self.assertRaises(FirewallViolationError):
            TestSetFirewall.assert_read_only_access(test_file, mode="a")
        with self.assertRaises(FirewallViolationError):
            TestSetFirewall.assert_read_only_access(test_file, mode="r+")

    def test_test_set_firewall_training_isolation(self):
        """Firewall verifies training dataset directory excludes test.jsonl."""
        isolation_ok = TestSetFirewall.verify_training_isolation()
        self.assertTrue(isolation_ok)

    # -------------------------------------------------------------------------
    # 3. Classification & Macro Metrics
    # -------------------------------------------------------------------------
    def test_classification_accuracy_and_macro_f1(self):
        """Accuracy, macro precision, recall, and F1 compute correctly."""
        targets = ["benign", "suspicious", "confirmed_malicious", "benign"]
        preds = ["benign", "suspicious", "suspicious", "benign"]  # 3/4 correct

        acc = compute_accuracy(preds, targets)
        self.assertEqual(acc, 0.75)

        per_class = compute_per_class_metrics(preds, targets)
        self.assertIn("benign", per_class)
        self.assertEqual(per_class["benign"]["precision"], 1.0)
        self.assertEqual(per_class["benign"]["recall"], 1.0)
        self.assertEqual(per_class["benign"]["f1"], 1.0)

        macro = compute_macro_metrics(per_class)
        self.assertGreater(macro["macro_f1"], 0.0)
        self.assertLessEqual(macro["macro_f1"], 1.0)

    def test_confusion_matrix_structure(self):
        """Confusion matrix correctly maps actual against predicted counts."""
        targets = ["benign", "suspicious", "benign"]
        preds = ["benign", "benign", "benign"]
        labels = ["benign", "suspicious"]

        cm = compute_confusion_matrix(preds, targets, labels=labels)
        self.assertEqual(cm["benign"]["benign"], 2)
        self.assertEqual(cm["benign"]["suspicious"], 0)
        self.assertEqual(cm["suspicious"]["benign"], 1)

    # -------------------------------------------------------------------------
    # 4. Triage Evaluation Engine
    # -------------------------------------------------------------------------
    def test_triage_eval_predictions_calculation(self):
        """evaluate_triage_predictions calculates accuracy, severity, and grounding."""
        gt_record = dict(self.sample_record)
        pred = TriageResult(
            classification="confirmed_malicious",
            severity="high",
            confidence=0.95,
            summary="Confirmed malicious PowerShell activity",
            findings=[{"title": "Finding", "evidence_ids": ["EVT-01"]}],
            investigation_required=True,
        )

        metrics = evaluate_triage_predictions([pred], [gt_record])
        self.assertEqual(metrics.total_examples, 1)
        self.assertEqual(metrics.accuracy, 1.0)
        self.assertEqual(metrics.severity_accuracy, 1.0)
        self.assertEqual(metrics.investigation_agreement_pct, 1.0)
        self.assertEqual(metrics.evidence_grounding_rate, 1.0)
        self.assertEqual(metrics.hallucinated_evidence_rate, 0.0)

    # -------------------------------------------------------------------------
    # 5. Investigation Metrics
    # -------------------------------------------------------------------------
    def test_investigation_metrics_evaluation(self):
        """evaluate_investigation_scenarios evaluates completion, conclusion, and steps."""
        scenario = {
            "expected_conclusion": "confirmed_malicious",
            "expected_severity": "critical",
        }
        res = {
            "status": "completed",
            "conclusion": "confirmed_malicious",
            "findings": [{"title": "Grounded", "evidence_ids": ["PROC-001"]}],
            "evidence": [{"id": "PROC-001"}],
            "investigation_steps": [{"step_number": 1}],
            "metadata": {"hallucinated_evidence_attempts": []},
        }

        metrics = evaluate_investigation_scenarios([res], [scenario])
        self.assertEqual(metrics.completion_rate, 1.0)
        self.assertEqual(metrics.conclusion_accuracy, 1.0)
        self.assertEqual(metrics.evidence_grounding_rate, 1.0)
        self.assertEqual(metrics.avg_steps_per_investigation, 1.0)

    # -------------------------------------------------------------------------
    # 6. Threat Intelligence Metrics
    # -------------------------------------------------------------------------
    def test_threat_intel_metrics_evaluation(self):
        """evaluate_threat_intel_results measures enrichment steps and grounding."""
        ti_res = {
            "status": "completed",
            "findings": [{"title": "Actor match", "evidence_ids": ["TI-01"]}],
            "enrichment_steps": [
                {"tool_name": "threat_intel"},
                {"tool_name": "mitre_lookup"},
            ],
            "metadata": {
                "candidate_indicators_found": ["198.51.100.200"],
                "hallucinated_evidence_attempts": [],
            },
        }

        metrics = evaluate_threat_intel_results([ti_res])
        self.assertEqual(metrics.enrichment_success_rate, 1.0)
        self.assertEqual(metrics.total_intelligence_queries, 1)
        self.assertEqual(metrics.total_mitre_queries, 1)
        self.assertEqual(metrics.evidence_grounding_rate, 1.0)

    # -------------------------------------------------------------------------
    # 7. RAG Hit@K & Latency Metrics
    # -------------------------------------------------------------------------
    def test_rag_hit_at_k_metrics(self):
        """compute_hit_at_k evaluates ranking precision."""
        retrieved = [["doc-A", "doc-B", "doc-C"], ["doc-X", "doc-Y", "doc-Z"]]
        expected = [["doc-A"], ["doc-Z"]]

        hit_1 = compute_hit_at_k(retrieved, expected, k=1)
        hit_3 = compute_hit_at_k(retrieved, expected, k=3)

        self.assertEqual(hit_1, 0.5)  # only first query hits at rank 1
        self.assertEqual(hit_3, 1.0)  # both hit within top 3

    def test_latency_statistics_calculation(self):
        """compute_latency_stats computes avg, median, and p95."""
        latencies = [10.0, 20.0, 30.0, 40.0, 50.0]
        stats = compute_latency_stats(latencies)
        self.assertEqual(stats["count"], 5)
        self.assertEqual(stats["avg_ms"], 30.0)
        self.assertEqual(stats["median_ms"], 30.0)
        self.assertEqual(stats["min_ms"], 10.0)
        self.assertEqual(stats["max_ms"], 50.0)

    # -------------------------------------------------------------------------
    # 8. Safety & Alignment Metrics
    # -------------------------------------------------------------------------
    def test_safety_metrics_evaluation(self):
        """evaluate_safety_invariants verifies 100% containment of destructive actions and injection."""
        metrics = evaluate_safety_invariants(
            agent_results=[{"status": "completed", "findings": [], "metadata": {}}],
            tested_injections=4,
            blocked_injections=4,
            destructive_attempts=2,
            destructive_blocked=2,
        )
        self.assertEqual(metrics.destructive_action_containment_rate, 1.0)
        self.assertEqual(metrics.prompt_injection_containment_rate, 1.0)
        self.assertEqual(metrics.bounded_loop_compliance_rate, 1.0)

    # -------------------------------------------------------------------------
    # 9. Benchmark Report Generation (JSON & Markdown)
    # -------------------------------------------------------------------------
    def test_benchmark_report_generation(self):
        """BenchmarkReport saves valid JSON and Markdown reports with SHA-256 recording."""
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir)
            report = BenchmarkReport(
                provider_name="mock",
                model_name="deterministic_test",
                notes="Unit test execution.",
            )
            json_file, md_file = report.save(out_path)

            self.assertTrue(json_file.exists())
            self.assertTrue(md_file.exists())

            # Verify JSON contains expected hash
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["metadata"]["test_set"]["expected_sha256"], EXPECTED_TEST_SET_SHA256)
            self.assertEqual(data["metadata"]["test_set"]["expected_count"], EXPECTED_TEST_SET_COUNT)

            # Verify Markdown rendered key headers
            md_text = md_file.read_text(encoding="utf-8")
            self.assertIn("# AegisX SOC AI Evaluation Benchmark Report", md_text)
            self.assertIn("Test Set SHA-256", md_text)

    # -------------------------------------------------------------------------
    # 10. Failure Classification
    # -------------------------------------------------------------------------
    def test_failure_classification_types(self):
        """FailureType enums cover all required diagnostic failure modes."""
        self.assertEqual(FailureType.MODEL_ERROR.value, "model_error")
        self.assertEqual(FailureType.MALFORMED_OUTPUT.value, "malformed_output")
        self.assertEqual(FailureType.GROUNDING_FAILURE.value, "evidence_grounding_failure")
        self.assertEqual(FailureType.TOOL_FAILURE.value, "tool_failure")
        self.assertEqual(FailureType.API_FAILURE.value, "api_network_failure")
        self.assertEqual(FailureType.DATASET_ERROR.value, "dataset_error")
        self.assertEqual(FailureType.EVALUATOR_ERROR.value, "evaluator_error")

    # -------------------------------------------------------------------------
    # 11. Base vs. Fine-Tuned Model Comparison Schema
    # -------------------------------------------------------------------------
    def test_base_vs_finetuned_comparison_schema(self):
        """generate_comparison_schema computes metrics delta and improvement flags."""
        base = {"accuracy": 0.70, "macro_f1": 0.68, "hallucinated_evidence_rate": 0.15}
        ft = {"accuracy": 0.90, "macro_f1": 0.89, "hallucinated_evidence_rate": 0.02}

        comparison = generate_comparison_schema(base, ft)
        metrics = comparison["metrics"]

        self.assertEqual(metrics["accuracy"]["delta"], 0.20)
        self.assertTrue(metrics["accuracy"]["improvement"])
        self.assertEqual(metrics["hallucinated_evidence_rate"]["delta"], -0.13)
        self.assertTrue(metrics["hallucinated_evidence_rate"]["improvement"])  # lower is better

    # -------------------------------------------------------------------------
    # 12. Provider Selection & Sample Size Regression Tests
    # -------------------------------------------------------------------------
    def test_provider_mock_selects_mock_provider(self):
        """provider=mock selects MockProvider."""
        from ai.evaluation.evaluate import resolve_evaluation_client
        from ai.llm.providers.mock import MockProvider

        client = resolve_evaluation_client(provider_name="mock")
        self.assertIsInstance(client.provider, MockProvider)
        self.assertEqual(client.provider.name, "mock")

    def test_provider_api_selects_api_provider(self):
        """provider=api selects APIProvider."""
        from unittest import mock
        from ai.evaluation.evaluate import resolve_evaluation_client
        from ai.llm.providers.api import APIProvider
        from ai.llm.config import LLMConfig

        mock_cfg = LLMConfig(provider_name="api", model_name="openai/gpt-oss-20b", api_key="dummy-test-key")
        with mock.patch("ai.evaluation.evaluate.LLMConfig.load", return_value=mock_cfg):
            client = resolve_evaluation_client(provider_name="api")
            self.assertIsInstance(client.provider, APIProvider)
            self.assertEqual(client.provider.name, "api")

    def test_provider_api_does_not_silently_select_mock_provider(self):
        """provider=api does not silently fall back to MockProvider."""
        from unittest import mock
        from ai.evaluation.evaluate import resolve_evaluation_client
        from ai.llm.providers.mock import MockProvider
        from ai.llm.config import LLMConfig

        mock_cfg = LLMConfig(provider_name="api", model_name="openai/gpt-oss-20b", api_key="dummy-test-key")
        with mock.patch("ai.evaluation.evaluate.LLMConfig.load", return_value=mock_cfg):
            client = resolve_evaluation_client(provider_name="api")
            self.assertNotIsInstance(client.provider, MockProvider)
            self.assertNotEqual(client.provider.name, "mock")

    def test_provider_api_does_not_silently_select_offline_deterministic(self):
        """provider=api does not silently select offline_deterministic as model."""
        from unittest import mock
        from ai.evaluation.evaluate import resolve_evaluation_client
        from ai.llm.config import LLMConfig

        mock_cfg = LLMConfig(provider_name="api", model_name="openai/gpt-oss-20b", api_key="dummy-test-key")
        with mock.patch("ai.evaluation.evaluate.LLMConfig.load", return_value=mock_cfg):
            client = resolve_evaluation_client(provider_name="api")
            self.assertNotEqual(client.config.model_name, "offline_deterministic")
            self.assertEqual(client.config.model_name, "openai/gpt-oss-20b")

    def test_missing_api_configuration_produces_explicit_failure(self):
        """Missing API key produces an explicit LLMAuthenticationError."""
        from unittest import mock
        from ai.evaluation.evaluate import resolve_evaluation_client
        from ai.llm.config import LLMConfig
        from ai.llm.exceptions import LLMAuthenticationError

        mock_cfg = LLMConfig(provider_name="api", model_name="openai/gpt-oss-20b", api_key=None)
        with mock.patch("ai.evaluation.evaluate.LLMConfig.load", return_value=mock_cfg):
            with self.assertRaises(LLMAuthenticationError):
                resolve_evaluation_client(provider_name="api")

    def test_sample_size_30_evaluates_exactly_30_records(self):
        """--sample-size 30 evaluates exactly 30 records, not all 300."""
        from ai.evaluation.evaluate import run_evaluation_suite

        report = run_evaluation_suite(
            provider_name="mock",
            sample_size=30,
            eval_investigation=False,
            eval_threat_intel=False,
            eval_rag=False,
        )
        self.assertEqual(report.records_evaluated, 30)
        self.assertEqual(report.triage_metrics.total_examples, 30)
        self.assertEqual(report.total_test_records, 300)

    def test_report_distinguishes_total_test_set_from_records_evaluated(self):
        """Benchmark report clearly distinguishes total test set size from evaluated count."""
        from ai.evaluation.evaluate import run_evaluation_suite

        with tempfile.TemporaryDirectory() as temp_dir:
            report = run_evaluation_suite(
                provider_name="mock",
                sample_size=30,
                output_dir=Path(temp_dir),
                eval_investigation=False,
                eval_threat_intel=False,
                eval_rag=False,
            )
            md_files = list(Path(temp_dir).glob("*.md"))
            self.assertTrue(len(md_files) > 0)
            md_text = md_files[0].read_text(encoding="utf-8")

            self.assertIn("- **Test Set Total Records**: `300`", md_text)
            self.assertIn("- **Records Evaluated**: `30`", md_text)

    def test_report_records_actual_model(self):
        """Benchmark report accurately records the model identifier."""
        from ai.evaluation.evaluate import run_evaluation_suite

        report = run_evaluation_suite(
            provider_name="mock",
            model_name="custom-soc-model-v9",
            sample_size=2,
            eval_investigation=False,
            eval_threat_intel=False,
            eval_rag=False,
        )
        self.assertEqual(report.model_name, "custom-soc-model-v9")

    def test_api_mode_cannot_be_mislabeled_as_real_api_if_mock_used(self):
        """BenchmarkReport prevents mislabeling mock runs as REAL_API_BENCHMARK."""
        report = BenchmarkReport(
            provider_name="mock",
            model_name="mock-model",
            evaluation_mode="REAL_API_BENCHMARK",
        )
        self.assertEqual(report.evaluation_mode, "MOCK_EVALUATION")

if __name__ == "__main__":
    unittest.main()
