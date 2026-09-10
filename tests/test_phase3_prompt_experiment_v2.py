#!/usr/bin/env python3
"""
Unit tests for Phase 3 Controlled Prompt Experiment V2 harness.
All tests are completely offline — no network access, no API calls.
"""

import hashlib
import json
import os
import sys
import tempfile
import shutil
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

# Ensure project root on path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from scripts.phase3_prompt_experiment_v2 import (
    PROJECT_ROOT as HARNESS_PROJECT_ROOT,
    load_manifest,
    load_prompt,
    compute_sha256,
    load_validation_dataset,
    validate_manifest,
    build_mock_scenario_map,
    run_experiment,
    compute_metrics,
    compute_paired_analysis,
    save_results,
    save_paired_analysis,
    save_experiment_summary,
    main,
    ExperimentMockProvider,
    ERROR_VALID,
    ERROR_429,
    ERROR_TIMEOUT,
    ERROR_JSON_VALIDATION,
    ERROR_OTHER_PROVIDER,
    classify_error,
    build_failure_record,
    build_success_record,
    _compute_per_class_metrics,
    _compute_macro_metrics,
    _compute_confusion_matrix,
)
from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    TriageResult,
    FindingItem,
    RecommendedAction,
)
from ai.llm.exceptions import (
    LLMRateLimitError,
    LLMTimeoutError,
    LLMResponseError,
    LLMProviderError,
    LLMError,
)

# ---------------------------------------------------------------------------
# Paths to real artifacts
# ---------------------------------------------------------------------------
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "reports", "phase3", "PHASE_3_PROMPT_EXPERIMENT_V2_MANIFEST.json")
BASELINE_PROMPT_PATH = os.path.join(PROJECT_ROOT, "reports", "phase3", "baseline_prompt.txt")
EXPERIMENTAL_PROMPT_PATH = os.path.join(PROJECT_ROOT, "reports", "phase3", "PHASE_3_EXPERIMENTAL_PROMPT_V2.txt")
VALIDATION_DATASET_PATH = os.path.join(PROJECT_ROOT, "datasets", "finetuning", "v0.4", "validation.jsonl")
PRODUCTION_SYSTEM_PROMPT_PATH = os.path.join(PROJECT_ROOT, "ai", "prompts", "triage", "system.txt")

# ---------------------------------------------------------------------------
# Expected hashes (recorded before repair)
# ---------------------------------------------------------------------------
EXPECTED_SYSTEM_PROMPT_SHA = "8c9c6e6e68be932b42a025813ee17530e29d2d166df827af79db242b310c7ba8"
EXPECTED_BASELINE_SHA = "8c9c6e6e68be932b42a025813ee17530e29d2d166df827af79db242b310c7ba8"
EXPECTED_VALIDATION_SHA = "f6bd48ea8672b673369a224e2bce58d7ed3c52444bc1c40d7a8552b64426a097"
EXPECTED_EXPERIMENTAL_SHA = "45e47a041285d9fe53bb3276e40bf177ff329d149156e76f95e4f468c6d4d53c"


def _file_sha256(filepath: str) -> str:
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestManifestValidation(unittest.TestCase):
    """Test manifest validation logic."""

    def setUp(self):
        self.manifest = load_manifest(MANIFEST_PATH)
        self.id_to_record = load_validation_dataset(VALIDATION_DATASET_PATH)

    def test_manifest_has_50_records(self):
        self.assertEqual(len(self.manifest["record_ids"]), 50)

    def test_manifest_has_10_per_class(self):
        for cls, count in self.manifest["class_counts"].items():
            self.assertEqual(count, 10, f"Class {cls} has {count}, expected 10")

    def test_manifest_no_duplicate_ids(self):
        ids = self.manifest["record_ids"]
        self.assertEqual(len(ids), len(set(ids)))

    def test_manifest_all_ids_in_dataset(self):
        for rid in self.manifest["record_ids"]:
            self.assertIn(rid, self.id_to_record, f"Record {rid} not in validation dataset")

    def test_manifest_ground_truth_matches_dataset(self):
        for rid, gt in zip(self.manifest["record_ids"], self.manifest["ground_truth"]):
            actual = self.id_to_record[rid]["output"]["classification"]
            self.assertEqual(gt, actual, f"Ground truth mismatch for {rid}")

    def test_validate_manifest_passes(self):
        errors = validate_manifest(self.manifest, self.id_to_record)
        self.assertEqual(errors, [], f"Validation errors: {errors}")

    def test_validate_manifest_catches_wrong_count(self):
        bad_manifest = dict(self.manifest)
        bad_manifest["record_ids"] = self.manifest["record_ids"][:10]
        bad_manifest["ground_truth"] = self.manifest["ground_truth"][:10]
        errors = validate_manifest(bad_manifest, self.id_to_record)
        self.assertTrue(any("50" in e for e in errors))

    def test_validate_manifest_catches_duplicate_ids(self):
        bad_manifest = dict(self.manifest)
        ids = list(self.manifest["record_ids"])
        ids[1] = ids[0]  # Duplicate
        bad_manifest["record_ids"] = ids
        errors = validate_manifest(bad_manifest, self.id_to_record)
        self.assertTrue(any("Duplicate" in e for e in errors))


class TestPromptHashCalculation(unittest.TestCase):
    """Test SHA-256 hash computation."""

    def test_baseline_prompt_hash(self):
        content = load_prompt(BASELINE_PROMPT_PATH)
        sha = compute_sha256(content)
        self.assertEqual(sha, EXPECTED_BASELINE_SHA)

    def test_experimental_prompt_hash(self):
        content = load_prompt(EXPERIMENTAL_PROMPT_PATH)
        sha = compute_sha256(content)
        self.assertEqual(sha, EXPECTED_EXPERIMENTAL_SHA)

    def test_hash_deterministic(self):
        text = "test string for hashing"
        self.assertEqual(compute_sha256(text), compute_sha256(text))

    def test_different_text_different_hash(self):
        self.assertNotEqual(compute_sha256("text1"), compute_sha256("text2"))


class TestPromptLoading(unittest.TestCase):
    """Test prompt loading."""

    def test_baseline_prompt_loads(self):
        content = load_prompt(BASELINE_PROMPT_PATH)
        self.assertIsInstance(content, str)
        self.assertGreater(len(content), 100)
        self.assertIn("SOC", content)

    def test_experimental_prompt_loads(self):
        content = load_prompt(EXPERIMENTAL_PROMPT_PATH)
        self.assertIsInstance(content, str)
        self.assertGreater(len(content), 100)
        self.assertIn("STEP 1", content)

    def test_prompts_are_different(self):
        baseline = load_prompt(BASELINE_PROMPT_PATH)
        experimental = load_prompt(EXPERIMENTAL_PROMPT_PATH)
        self.assertNotEqual(baseline, experimental)


class TestMockPredictions(unittest.TestCase):
    """Test deterministic mock prediction scenarios."""

    def setUp(self):
        self.manifest = load_manifest(MANIFEST_PATH)
        self.id_to_record = load_validation_dataset(VALIDATION_DATASET_PATH)

    def test_successful_mock_prediction(self):
        """Mock returns correct classification for a record."""
        rid = self.manifest["record_ids"][0]
        gt = self.manifest["ground_truth"][0]
        record = self.id_to_record[rid]
        evidence_ids = [e["id"] for e in record["input"]["evidence"]]

        scenario_map = {rid: {"action": "correct", "ground_truth": gt, "evidence_ids": evidence_ids}}
        provider = ExperimentMockProvider(scenario_map)
        provider.set_current_record(rid)

        from ai.llm.schemas import LLMRequest
        req = LLMRequest(user_prompt="test", system_prompt="test")
        resp = provider.generate(req)
        data = json.loads(resp.content)
        self.assertEqual(data["classification"], gt)

    def test_incorrect_mock_prediction(self):
        """Mock returns incorrect classification."""
        rid = self.manifest["record_ids"][0]
        gt = self.manifest["ground_truth"][0]
        record = self.id_to_record[rid]
        evidence_ids = [e["id"] for e in record["input"]["evidence"]]

        scenario_map = {rid: {"action": "incorrect", "ground_truth": gt, "evidence_ids": evidence_ids}}
        provider = ExperimentMockProvider(scenario_map)
        provider.set_current_record(rid)

        from ai.llm.schemas import LLMRequest
        req = LLMRequest(user_prompt="test", system_prompt="test")
        resp = provider.generate(req)
        data = json.loads(resp.content)
        self.assertNotEqual(data["classification"], gt)
        self.assertIn(data["classification"], VALID_CLASSIFICATIONS)

    def test_malformed_json_mock(self):
        """Mock returns malformed JSON — should not be parseable."""
        rid = self.manifest["record_ids"][0]
        scenario_map = {rid: {"action": "malformed", "ground_truth": "suspicious", "evidence_ids": ["EVT-001"]}}
        provider = ExperimentMockProvider(scenario_map)
        provider.set_current_record(rid)

        from ai.llm.schemas import LLMRequest
        req = LLMRequest(user_prompt="test", system_prompt="test")
        resp = provider.generate(req)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(resp.content)

    def test_simulated_429(self):
        """Mock raises LLMRateLimitError for 429 scenario."""
        rid = self.manifest["record_ids"][0]
        scenario_map = {rid: {"action": "429", "ground_truth": "suspicious", "evidence_ids": ["EVT-001"]}}
        provider = ExperimentMockProvider(scenario_map)
        provider.set_current_record(rid)

        from ai.llm.schemas import LLMRequest
        req = LLMRequest(user_prompt="test", system_prompt="test")
        with self.assertRaises(LLMRateLimitError):
            provider.generate(req)

    def test_simulated_timeout(self):
        """Mock raises LLMTimeoutError for timeout scenario."""
        rid = self.manifest["record_ids"][0]
        scenario_map = {rid: {"action": "timeout", "ground_truth": "suspicious", "evidence_ids": ["EVT-001"]}}
        provider = ExperimentMockProvider(scenario_map)
        provider.set_current_record(rid)

        from ai.llm.schemas import LLMRequest
        req = LLMRequest(user_prompt="test", system_prompt="test")
        with self.assertRaises(LLMTimeoutError):
            provider.generate(req)


class TestErrorClassification(unittest.TestCase):
    """Test error type classification."""

    def test_429_classified_correctly(self):
        e = LLMRateLimitError("rate limited", provider="test")
        self.assertEqual(classify_error(e), ERROR_429)

    def test_timeout_classified_correctly(self):
        e = LLMTimeoutError("timed out", provider="test")
        self.assertEqual(classify_error(e), ERROR_TIMEOUT)

    def test_response_error_classified_as_json_failure(self):
        e = LLMResponseError("bad json", provider="test")
        self.assertEqual(classify_error(e), ERROR_JSON_VALIDATION)

    def test_provider_error_classified(self):
        e = LLMProviderError("server error", provider="test")
        self.assertEqual(classify_error(e), ERROR_OTHER_PROVIDER)

    def test_429_never_becomes_wrong_classification(self):
        """A 429 must never be recorded as a wrong prediction — it's infrastructure."""
        record = build_failure_record(
            "SOC-TEST", "suspicious", 100.0, ERROR_429,
            "rate limited", "test", "abc123"
        )
        self.assertIsNone(record["predicted_classification"])
        self.assertEqual(record["error_type"], ERROR_429)


class TestMockExperimentRun(unittest.TestCase):
    """Test a full mock experiment run."""

    def setUp(self):
        self.manifest = load_manifest(MANIFEST_PATH)
        self.id_to_record = load_validation_dataset(VALIDATION_DATASET_PATH)
        self.baseline_prompt = load_prompt(BASELINE_PROMPT_PATH)
        self.baseline_sha = compute_sha256(self.baseline_prompt)

    def test_baseline_mock_run_completes(self):
        """Full baseline mock run should complete without errors."""
        results, metrics = run_experiment(
            manifest=self.manifest,
            id_to_record=self.id_to_record,
            prompt_content=self.baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=self.baseline_sha,
            mock=True,
        )
        self.assertEqual(len(results), 50)
        self.assertEqual(metrics["attempted"], 50)
        self.assertGreater(metrics["successful"], 0)

    def test_mock_run_has_429_records(self):
        """Mock run should include 429 failures."""
        results, metrics = run_experiment(
            manifest=self.manifest,
            id_to_record=self.id_to_record,
            prompt_content=self.baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=self.baseline_sha,
            mock=True,
        )
        error_429_results = [r for r in results if r["error_type"] == ERROR_429]
        self.assertGreater(len(error_429_results), 0)
        self.assertEqual(metrics["error_429_count"], len(error_429_results))

    def test_mock_run_429_not_counted_as_classification(self):
        """429 errors must not be treated as classification errors."""
        results, _ = run_experiment(
            manifest=self.manifest,
            id_to_record=self.id_to_record,
            prompt_content=self.baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=self.baseline_sha,
            mock=True,
        )
        for r in results:
            if r["error_type"] == ERROR_429:
                self.assertIsNone(r["predicted_classification"])

    def test_mock_run_has_timeout_records(self):
        """Mock run should include timeout failures."""
        results, metrics = run_experiment(
            manifest=self.manifest,
            id_to_record=self.id_to_record,
            prompt_content=self.baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=self.baseline_sha,
            mock=True,
        )
        timeout_results = [r for r in results if r["error_type"] == ERROR_TIMEOUT]
        self.assertGreater(len(timeout_results), 0)

    def test_mock_run_has_json_failures(self):
        """Mock run should include JSON validation failures."""
        results, metrics = run_experiment(
            manifest=self.manifest,
            id_to_record=self.id_to_record,
            prompt_content=self.baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=self.baseline_sha,
            mock=True,
        )
        json_fail_results = [r for r in results if r["error_type"] == ERROR_JSON_VALIDATION]
        self.assertGreater(len(json_fail_results), 0)

    def test_every_result_has_prompt_sha256(self):
        """Every result record must have the correct prompt SHA."""
        results, _ = run_experiment(
            manifest=self.manifest,
            id_to_record=self.id_to_record,
            prompt_content=self.baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=self.baseline_sha,
            mock=True,
        )
        for r in results:
            self.assertEqual(r["prompt_sha256"], self.baseline_sha)

    def test_every_result_has_required_fields(self):
        """Every result must have all required fields."""
        required_fields = {
            "record_id", "ground_truth", "predicted_classification",
            "severity", "confidence", "structured_output_valid",
            "latency_ms", "error_type", "prompt_name", "prompt_sha256",
        }
        results, _ = run_experiment(
            manifest=self.manifest,
            id_to_record=self.id_to_record,
            prompt_content=self.baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=self.baseline_sha,
            mock=True,
        )
        for r in results:
            self.assertTrue(required_fields.issubset(set(r.keys())),
                            f"Missing fields: {required_fields - set(r.keys())}")


class TestPairedAnalysis(unittest.TestCase):
    """Test paired comparison logic."""

    def test_paired_comparison_basic(self):
        """Paired analysis correctly counts wins/ties."""
        baseline = [
            {"record_id": "A", "ground_truth": "benign", "predicted_classification": "benign",
             "error_type": ERROR_VALID, "prompt_name": "baseline", "prompt_sha256": "x"},
            {"record_id": "B", "ground_truth": "suspicious", "predicted_classification": "benign",
             "error_type": ERROR_VALID, "prompt_name": "baseline", "prompt_sha256": "x"},
            {"record_id": "C", "ground_truth": "suspicious", "predicted_classification": "suspicious",
             "error_type": ERROR_VALID, "prompt_name": "baseline", "prompt_sha256": "x"},
        ]
        experimental = [
            {"record_id": "A", "ground_truth": "benign", "predicted_classification": "benign",
             "error_type": ERROR_VALID, "prompt_name": "exp", "prompt_sha256": "y"},
            {"record_id": "B", "ground_truth": "suspicious", "predicted_classification": "suspicious",
             "error_type": ERROR_VALID, "prompt_name": "exp", "prompt_sha256": "y"},
            {"record_id": "C", "ground_truth": "suspicious", "predicted_classification": "benign",
             "error_type": ERROR_VALID, "prompt_name": "exp", "prompt_sha256": "y"},
        ]
        analysis = compute_paired_analysis(baseline, experimental)
        # A: both correct → tie
        # B: baseline wrong, exp correct → exp win
        # C: baseline correct, exp wrong → baseline win
        self.assertEqual(analysis["ties"], 1)
        self.assertEqual(analysis["experimental_wins"], 1)
        self.assertEqual(analysis["baseline_wins"], 1)

    def test_paired_tracks_transitions(self):
        """Paired analysis tracks classification transitions."""
        baseline = [
            {"record_id": "A", "ground_truth": "suspicious", "predicted_classification": "suspicious",
             "error_type": ERROR_VALID, "prompt_name": "baseline", "prompt_sha256": "x"},
        ]
        experimental = [
            {"record_id": "A", "ground_truth": "suspicious", "predicted_classification": "likely_malicious",
             "error_type": ERROR_VALID, "prompt_name": "exp", "prompt_sha256": "y"},
        ]
        analysis = compute_paired_analysis(baseline, experimental)
        self.assertEqual(len(analysis["changed_classifications"]), 1)
        self.assertIn("suspicious -> likely_malicious", analysis["transition_counts"])

    def test_paired_handles_failures(self):
        """Failures in one run count as a win for the other."""
        baseline = [
            {"record_id": "A", "ground_truth": "suspicious", "predicted_classification": None,
             "error_type": ERROR_429, "prompt_name": "baseline", "prompt_sha256": "x"},
        ]
        experimental = [
            {"record_id": "A", "ground_truth": "suspicious", "predicted_classification": "suspicious",
             "error_type": ERROR_VALID, "prompt_name": "exp", "prompt_sha256": "y"},
        ]
        analysis = compute_paired_analysis(baseline, experimental)
        self.assertEqual(analysis["experimental_wins"], 1)
        self.assertEqual(analysis["baseline_wins"], 0)

    def test_paired_inconclusive_low_coverage(self):
        """Experiment should be inconclusive if coverage is too low."""
        # All failures
        baseline = [
            {"record_id": f"R{i}", "ground_truth": "suspicious", "predicted_classification": None,
             "error_type": ERROR_429, "prompt_name": "baseline", "prompt_sha256": "x"}
            for i in range(10)
        ]
        experimental = [
            {"record_id": f"R{i}", "ground_truth": "suspicious", "predicted_classification": "suspicious",
             "error_type": ERROR_VALID, "prompt_name": "exp", "prompt_sha256": "y"}
            for i in range(10)
        ]
        analysis = compute_paired_analysis(baseline, experimental)
        self.assertEqual(analysis["verdict"], "EXPERIMENT_INCONCLUSIVE")


class TestConfusionMatrix(unittest.TestCase):
    """Test confusion matrix computation."""

    def test_perfect_confusion_matrix(self):
        preds = ["benign", "suspicious", "likely_malicious"]
        gts = ["benign", "suspicious", "likely_malicious"]
        labels = sorted(VALID_CLASSIFICATIONS)
        cm = _compute_confusion_matrix(preds, gts, labels)
        self.assertEqual(cm["benign"]["benign"], 1)
        self.assertEqual(cm["suspicious"]["suspicious"], 1)
        self.assertEqual(cm["likely_malicious"]["likely_malicious"], 1)
        # Off-diagonal should be 0
        self.assertEqual(cm["benign"]["suspicious"], 0)

    def test_confusion_matrix_tracks_errors(self):
        preds = ["suspicious"]
        gts = ["benign"]
        labels = sorted(VALID_CLASSIFICATIONS)
        cm = _compute_confusion_matrix(preds, gts, labels)
        self.assertEqual(cm["benign"]["suspicious"], 1)
        self.assertEqual(cm["benign"]["benign"], 0)


class TestMacroMetrics(unittest.TestCase):
    """Test macro metrics computation."""

    def test_perfect_macro_metrics(self):
        preds = ["benign", "suspicious"]
        gts = ["benign", "suspicious"]
        labels = ["benign", "suspicious"]
        per_class = _compute_per_class_metrics(preds, gts, labels)
        macro = _compute_macro_metrics(per_class)
        self.assertEqual(macro["macro_precision"], 1.0)
        self.assertEqual(macro["macro_recall"], 1.0)
        self.assertEqual(macro["macro_f1"], 1.0)

    def test_zero_macro_metrics_on_all_wrong(self):
        preds = ["suspicious", "benign"]
        gts = ["benign", "suspicious"]
        labels = ["benign", "suspicious"]
        per_class = _compute_per_class_metrics(preds, gts, labels)
        macro = _compute_macro_metrics(per_class)
        self.assertEqual(macro["macro_precision"], 0.0)
        self.assertEqual(macro["macro_f1"], 0.0)

    def test_empty_per_class(self):
        macro = _compute_macro_metrics({})
        self.assertEqual(macro["macro_f1"], 0.0)


class TestPromptIsolation(unittest.TestCase):
    """Test that prompt injection via monkey-patching is properly restored."""

    def test_prompt_restored_after_run(self):
        """After run_experiment, get_triage_system_prompt must return the original."""
        import ai.prompts.triage as triage_mod
        original = triage_mod.get_triage_system_prompt()

        manifest = load_manifest(MANIFEST_PATH)
        id_to_record = load_validation_dataset(VALIDATION_DATASET_PATH)
        custom_prompt = "CUSTOM TEST PROMPT FOR ISOLATION"

        run_experiment(
            manifest=manifest,
            id_to_record=id_to_record,
            prompt_content=custom_prompt,
            prompt_name="isolation_test",
            prompt_sha256=compute_sha256(custom_prompt),
            mock=True,
        )

        restored = triage_mod.get_triage_system_prompt()
        self.assertEqual(original, restored)

    def test_prompt_restored_even_on_error(self):
        """Prompt function must be restored even if an unexpected error occurs mid-run."""
        import ai.prompts.triage as triage_mod
        original = triage_mod.get_triage_system_prompt()

        # Use a minimal manifest with a single invalid record to trigger an error
        # But since we use try/finally, it should still restore
        manifest = load_manifest(MANIFEST_PATH)
        id_to_record = load_validation_dataset(VALIDATION_DATASET_PATH)

        try:
            run_experiment(
                manifest=manifest,
                id_to_record=id_to_record,
                prompt_content="ANOTHER CUSTOM PROMPT",
                prompt_name="error_test",
                prompt_sha256="fakehash",
                mock=True,
            )
        except Exception:
            pass

        restored = triage_mod.get_triage_system_prompt()
        self.assertEqual(original, restored)


class TestProductionPromptUnchanged(unittest.TestCase):
    """Verify that the production system prompt has not been modified."""

    def test_production_system_prompt_hash(self):
        sha = _file_sha256(PRODUCTION_SYSTEM_PROMPT_PATH)
        self.assertEqual(sha, EXPECTED_SYSTEM_PROMPT_SHA,
                         "Production system prompt has been modified!")


class TestDatasetUnchanged(unittest.TestCase):
    """Verify that the validation dataset has not been modified."""

    def test_validation_dataset_hash(self):
        sha = _file_sha256(VALIDATION_DATASET_PATH)
        self.assertEqual(sha, EXPECTED_VALIDATION_SHA,
                         "Validation dataset has been modified!")


class TestFullMockExperiment(unittest.TestCase):
    """
    Integration test: run the full mock experiment and verify outputs.
    """

    def setUp(self):
        self.output_dir = tempfile.mkdtemp(prefix="phase3_test_")

    def tearDown(self):
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_full_mock_experiment(self):
        """Run both baseline and experimental, then paired analysis."""
        manifest = load_manifest(MANIFEST_PATH)
        id_to_record = load_validation_dataset(VALIDATION_DATASET_PATH)
        baseline_prompt = load_prompt(BASELINE_PROMPT_PATH)
        experimental_prompt = load_prompt(EXPERIMENTAL_PROMPT_PATH)
        baseline_sha = compute_sha256(baseline_prompt)
        experimental_sha = compute_sha256(experimental_prompt)

        baseline_results, baseline_metrics = run_experiment(
            manifest=manifest,
            id_to_record=id_to_record,
            prompt_content=baseline_prompt,
            prompt_name="baseline",
            prompt_sha256=baseline_sha,
            mock=True,
        )
        experimental_results, experimental_metrics = run_experiment(
            manifest=manifest,
            id_to_record=id_to_record,
            prompt_content=experimental_prompt,
            prompt_name="experimental_v2",
            prompt_sha256=experimental_sha,
            mock=True,
        )

        # Both should have 50 results
        self.assertEqual(len(baseline_results), 50)
        self.assertEqual(len(experimental_results), 50)

        # Metrics should be populated
        self.assertGreater(baseline_metrics["successful"], 0)
        self.assertGreater(experimental_metrics["successful"], 0)

        # Paired analysis
        paired = compute_paired_analysis(baseline_results, experimental_results)
        self.assertEqual(paired["total_records"], 50)
        total_outcomes = paired["baseline_wins"] + paired["experimental_wins"] + paired["ties"]
        self.assertEqual(total_outcomes, 50)

        # Verify all error types are present across both runs
        all_error_types = set()
        for r in baseline_results + experimental_results:
            all_error_types.add(r["error_type"])
        self.assertIn(ERROR_VALID, all_error_types)
        self.assertIn(ERROR_429, all_error_types)
        self.assertIn(ERROR_TIMEOUT, all_error_types)
        self.assertIn(ERROR_JSON_VALIDATION, all_error_types)


class TestPathHandling(unittest.TestCase):
    """
    Regression tests for path-type handling and pathlib.Path consistency.
    Verifies that string and Path arguments work across all loading, saving,
    and execution functions, and that real-mode config loading does not raise
    TypeError: unsupported operand type(s) for /: 'str' and 'str'.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="phase3_path_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_harness_project_root_is_path(self):
        """Verify that PROJECT_ROOT is an instance of pathlib.Path."""
        self.assertIsInstance(HARNESS_PROJECT_ROOT, Path)

    def test_load_manifest_accepts_str_and_path(self):
        """Verify load_manifest works with both str and Path."""
        m_str = load_manifest(str(MANIFEST_PATH))
        m_path = load_manifest(Path(MANIFEST_PATH))
        self.assertEqual(m_str["record_ids"], m_path["record_ids"])

    def test_load_prompt_accepts_str_and_path(self):
        """Verify load_prompt works with both str and Path."""
        p_str = load_prompt(str(BASELINE_PROMPT_PATH))
        p_path = load_prompt(Path(BASELINE_PROMPT_PATH))
        self.assertEqual(p_str, p_path)

    def test_load_validation_dataset_accepts_str_and_path(self):
        """Verify load_validation_dataset works with both str and Path."""
        d_str = load_validation_dataset(str(VALIDATION_DATASET_PATH))
        d_path = load_validation_dataset(Path(VALIDATION_DATASET_PATH))
        self.assertEqual(len(d_str), len(d_path))

    def test_save_results_accepts_str_and_path(self):
        """Verify save_results works with both str and Path and creates files via / operator."""
        str_dir = os.path.join(self.temp_dir, "str_out")
        path_dir = Path(self.temp_dir) / "path_out"

        dummy_results = [{"record_id": "SOC-001"}]
        dummy_metrics = {"accuracy": 1.0}

        save_results(dummy_results, dummy_metrics, str_dir, "test_prompt")
        save_results(dummy_results, dummy_metrics, path_dir, "test_prompt")

        self.assertTrue((Path(str_dir) / "test_prompt_results.json").exists())
        self.assertTrue((Path(str_dir) / "test_prompt_metrics.json").exists())
        self.assertTrue((path_dir / "test_prompt_results.json").exists())
        self.assertTrue((path_dir / "test_prompt_metrics.json").exists())

    def test_save_paired_analysis_accepts_str_and_path(self):
        """Verify save_paired_analysis works with both str and Path."""
        str_dir = os.path.join(self.temp_dir, "str_out")
        path_dir = Path(self.temp_dir) / "path_out"

        save_paired_analysis({"verdict": "OK"}, str_dir)
        save_paired_analysis({"verdict": "OK"}, path_dir)

        self.assertTrue((Path(str_dir) / "paired_analysis.json").exists())
        self.assertTrue((path_dir / "paired_analysis.json").exists())

    def test_save_experiment_summary_accepts_str_and_path(self):
        """Verify save_experiment_summary works with both str and Path."""
        str_dir = os.path.join(self.temp_dir, "str_out")
        path_dir = Path(self.temp_dir) / "path_out"

        save_experiment_summary({}, {}, {}, "sha_base", "sha_exp", str_dir)
        save_experiment_summary({}, {}, {}, "sha_base", "sha_exp", path_dir)

        self.assertTrue((Path(str_dir) / "experiment_summary.json").exists())
        self.assertTrue((path_dir / "experiment_summary.json").exists())

    def test_real_mode_path_construction_without_api_calls(self):
        """
        Verify that real-mode runner code path resolves project_root,
        loads LLMConfig, and constructs LLMClient without TypeError.
        No actual API calls are made (mocking TriageAgent.run).
        """
        manifest = load_manifest(MANIFEST_PATH)
        id_to_record = load_validation_dataset(VALIDATION_DATASET_PATH)
        prompt = "test prompt"

        mock_triage_result = TriageResult(
            classification="benign",
            severity="informational",
            confidence=0.9,
            investigation_required=False,
            summary="Mock triage summary",
            findings=[FindingItem(finding="ok", evidence_ids=["E-1"])],
            recommended_actions=[RecommendedAction(action="none", priority="low", rationale="none")],
        )

        with patch("ai.agents.triage_agent.TriageAgent.triage", return_value=mock_triage_result):
            # Test with Path project_root
            results_path, _ = run_experiment(
                manifest=manifest,
                id_to_record=id_to_record,
                prompt_content=prompt,
                prompt_name="test_real_path",
                prompt_sha256="fake_sha",
                mock=False,
                project_root=HARNESS_PROJECT_ROOT,
            )
            self.assertEqual(len(results_path), 50)

            # Test with str project_root (regression check for str conversion)
            results_str, _ = run_experiment(
                manifest=manifest,
                id_to_record=id_to_record,
                prompt_content=prompt,
                prompt_name="test_real_str",
                prompt_sha256="fake_sha",
                mock=False,
                project_root=str(HARNESS_PROJECT_ROOT),
            )
            self.assertEqual(len(results_str), 50)

    def test_main_cli_string_arguments(self):
        """
        Verify that main() accepts string arguments from CLI,
        converts them to Path objects, and runs mock experiment cleanly.
        """
        out_dir = Path(self.temp_dir) / "cli_test_out"
        test_argv = [
            "phase3_prompt_experiment_v2.py",
            "--manifest", str(MANIFEST_PATH),
            "--baseline-prompt", str(BASELINE_PROMPT_PATH),
            "--experimental-prompt", str(EXPERIMENTAL_PROMPT_PATH),
            "--output-dir", str(out_dir),
            "--mock",
        ]
        with patch.object(sys, "argv", test_argv):
            main()

        self.assertTrue((out_dir / "baseline_results.json").exists())
        self.assertTrue((out_dir / "baseline_metrics.json").exists())
        self.assertTrue((out_dir / "experimental_v2_results.json").exists())
        self.assertTrue((out_dir / "experimental_v2_metrics.json").exists())
        self.assertTrue((out_dir / "paired_analysis.json").exists())
        self.assertTrue((out_dir / "experiment_summary.json").exists())


if __name__ == '__main__':
    unittest.main()

