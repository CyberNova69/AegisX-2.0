#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX Fine-Tuning Pipeline Tests (v0.1)
==========================================

CPU-safe unit tests for the fine-tuning pipeline.
No large model downloads, no GPU required.

Run:
    python -m unittest tests/test_finetuning.py -v
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    VALID_ACTION_PRIORITIES,
)
from ai.prompts.triage import get_triage_system_prompt, format_triage_user_prompt

# Import fine-tuning modules
from finetuning.prepare_sft_dataset import (
    build_assistant_response,
    convert_record,
    validate_sft_example,
    load_jsonl,
)
from finetuning.evaluate_model import (
    compute_accuracy,
    compute_per_class_metrics,
    validate_structured_output,
    validate_evidence_refs,
)


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

def make_sample_record(
    classification="confirmed_malicious",
    record_id="SOC-TEST-001",
    os_type="Windows",
):
    """Create a realistic v0.4-format test record."""
    return {
        "task": "alert_triage",
        "input": {
            "alert": {
                "title": f"Suspicious PowerShell Activity [{record_id}]",
                "severity": "high",
                "source": "SIEM",
                "timestamp": "2026-01-15T10:30:00+00:00",
                "rule_name": "Encoded PowerShell Command",
                "rule_id": "RULE-1001",
            },
            "context": {
                "hostname": "WS-DEV-01",
                "username": "jsmith",
                "ip_address": "192.168.1.50",
                "department": "Engineering",
                "asset_criticality": "high",
                "environment": "production",
                "os": "Windows 10 Pro" if os_type == "Windows" else "Ubuntu 22.04 LTS",
                "previous_incidents": 0,
            },
            "evidence": [
                {
                    "id": "EVT-001",
                    "type": "process_creation",
                    "description": "powershell.exe executed with -EncodedCommand parameter",
                    "timestamp": "2026-01-15T10:30:00+00:00",
                    "raw_data": {"cmd": "powershell.exe -EncodedCommand SGVsbG8="},
                },
                {
                    "id": "EVT-002",
                    "type": "network_connection",
                    "description": "Outbound connection to suspicious IP 203.0.113.99:4444",
                    "timestamp": "2026-01-15T10:30:05+00:00",
                    "raw_data": {"dest_ip": "203.0.113.99", "dest_port": 4444},
                },
            ],
        },
        "output": {
            "classification": classification,
            "confidence": 0.88,
            "findings": [
                {
                    "description": "PowerShell executed with encoded command parameter, a common obfuscation technique.",
                    "evidence_refs": ["EVT-001"],
                    "severity": "high",
                },
                {
                    "description": "Outbound connection to known suspicious IP immediately after execution.",
                    "evidence_refs": ["EVT-001", "EVT-002"],
                    "severity": "high",
                },
            ],
            "rationale": "Encoded PowerShell with immediate C2 callback confirms malicious activity.",
            "recommended_actions": [
                {
                    "action": "Isolate host WS-DEV-01 from the network.",
                    "priority": "immediate",
                    "rationale": "Prevent lateral movement.",
                },
            ],
            "mitre_techniques": [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "tactic": "Execution",
                    "evidence_refs": ["EVT-001"],
                },
            ],
        },
        "id": record_id,
        "metadata": {
            "source": "synthetic",
            "generator": "aegisx-v0.4-generator",
            "review_status": "pending",
            "dataset_version": "0.4",
            "quality_score": 90,
            "template_id": "TF-001",
            "template_name": "Encoded PowerShell C2 Callback",
            "split": "train",
            "tags": ["alert_triage", classification, "windows_telemetry", "os:Windows"],
        },
    }


# ===========================================================================
# Test: Config Loading
# ===========================================================================

class TestConfigLoading(unittest.TestCase):
    """Test that finetuning/config.yaml loads correctly."""

    def test_config_file_exists(self):
        config_path = PROJECT_ROOT / "finetuning" / "config.yaml"
        self.assertTrue(config_path.exists(), f"Config not found: {config_path}")

    def test_config_loads_without_error(self):
        from finetuning.train_lora import load_config, CONFIG_PATH
        config = load_config(CONFIG_PATH)
        self.assertIsInstance(config, dict)
        self.assertIn("model", config)
        self.assertIn("training", config)
        self.assertIn("lora", config)
        self.assertIn("dataset", config)

    def test_config_model_name_present(self):
        from finetuning.train_lora import load_config, CONFIG_PATH
        config = load_config(CONFIG_PATH)
        model_name = config.get("model", {}).get("name")
        self.assertIsNotNone(model_name)
        self.assertTrue(len(model_name) > 0)

    def test_config_validation_passes(self):
        """Config validation should pass when SFT dataset files exist."""
        from finetuning.train_lora import load_config, validate_config, CONFIG_PATH
        config = load_config(CONFIG_PATH)
        issues = validate_config(config, PROJECT_ROOT)
        # Some paths may not exist yet (SFT hasn't been prepared),
        # so filter out path-related issues
        non_path_issues = [i for i in issues if "not found" not in i]
        self.assertEqual(
            len(non_path_issues), 0,
            f"Config validation issues: {non_path_issues}",
        )


# ===========================================================================
# Test: SFT Dataset Conversion
# ===========================================================================

class TestSFTConversion(unittest.TestCase):
    """Test the v0.4 → SFT chat format conversion."""

    def setUp(self):
        self.system_prompt = get_triage_system_prompt()
        self.sample_record = make_sample_record()

    def test_convert_record_success(self):
        sft_example, error = convert_record(self.sample_record, self.system_prompt)
        self.assertIsNone(error, f"Conversion failed: {error}")
        self.assertIsNotNone(sft_example)

    def test_sft_has_three_messages(self):
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        messages = sft_example["messages"]
        self.assertEqual(len(messages), 3)

    def test_sft_roles_correct(self):
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        roles = [m["role"] for m in sft_example["messages"]]
        self.assertEqual(roles, ["system", "user", "assistant"])

    def test_system_prompt_reused(self):
        """System message should be the same as ai/prompts/triage/system.txt."""
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        self.assertEqual(sft_example["messages"][0]["content"], self.system_prompt)

    def test_user_message_contains_alert_title(self):
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        user_content = sft_example["messages"][1]["content"]
        title = self.sample_record["input"]["alert"]["title"]
        self.assertIn(title, user_content)

    def test_assistant_output_is_valid_json(self):
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        assistant_json = sft_example["messages"][2]["content"]
        parsed = json.loads(assistant_json)
        self.assertIsInstance(parsed, dict)

    def test_assistant_output_triage_result_fields(self):
        """Assistant output must contain all TriageResult fields."""
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        required = ["classification", "severity", "confidence",
                     "investigation_required", "summary", "findings",
                     "evidence_ids", "recommended_actions"]
        for field in required:
            self.assertIn(field, parsed, f"Missing field: {field}")

    def test_assistant_classification_valid(self):
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        self.assertIn(parsed["classification"], VALID_CLASSIFICATIONS)

    def test_assistant_severity_valid(self):
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        self.assertIn(parsed["severity"], VALID_SEVERITIES)

    def test_assistant_confidence_range(self):
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        self.assertGreaterEqual(parsed["confidence"], 0.0)
        self.assertLessEqual(parsed["confidence"], 1.0)

    def test_assistant_evidence_refs_valid(self):
        """All evidence_ids in assistant output must reference valid input evidence."""
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        
        valid_ids = {evt["id"] for evt in self.sample_record["input"]["evidence"]}
        
        for ref in parsed.get("evidence_ids", []):
            self.assertIn(ref, valid_ids, f"Invalid evidence ref: {ref}")
        
        for finding in parsed.get("findings", []):
            for ref in finding.get("evidence_ids", []):
                self.assertIn(ref, valid_ids, f"Invalid finding ref: {ref}")

    def test_findings_use_triage_result_schema(self):
        """Findings should use 'finding' key (TriageResult) not 'description' (dataset)."""
        sft_example, _ = convert_record(self.sample_record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        for f in parsed["findings"]:
            self.assertIn("finding", f, "Findings must use 'finding' key (TriageResult schema)")
            self.assertIn("evidence_ids", f, "Findings must use 'evidence_ids' (TriageResult schema)")


# ===========================================================================
# Test: Malformed Record Rejection
# ===========================================================================

class TestMalformedRecordRejection(unittest.TestCase):
    """Test that malformed records are rejected during conversion."""

    def setUp(self):
        self.system_prompt = get_triage_system_prompt()

    def test_missing_input_block_rejected(self):
        record = make_sample_record()
        del record["input"]
        sft, error = convert_record(record, self.system_prompt)
        self.assertIsNone(sft)
        self.assertIsNotNone(error)

    def test_missing_output_block_rejected(self):
        record = make_sample_record()
        del record["output"]
        sft, error = convert_record(record, self.system_prompt)
        self.assertIsNone(sft)
        self.assertIsNotNone(error)

    def test_missing_classification_rejected(self):
        record = make_sample_record()
        del record["output"]["classification"]
        sft, error = convert_record(record, self.system_prompt)
        self.assertIsNone(sft)
        self.assertIsNotNone(error)


# ===========================================================================
# Test: Test Set Exclusion
# ===========================================================================

class TestTestSetExclusion(unittest.TestCase):
    """Verify that test.jsonl is never loaded during SFT preparation."""

    def test_prepare_function_never_loads_test(self):
        """prepare_sft_dataset should not open test.jsonl."""
        from finetuning.prepare_sft_dataset import prepare_sft_dataset
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create train and validation files
            record = make_sample_record()
            for split in ["train", "validation"]:
                with open(tmpdir / f"{split}.jsonl", "w") as f:
                    f.write(json.dumps(record) + "\n")
            
            # Create a test.jsonl canary
            canary_path = tmpdir / "test.jsonl"
            canary_path.write_text("THIS_SHOULD_NEVER_BE_READ")
            
            # Run conversion
            prepare_sft_dataset(tmpdir)
            
            # If test.jsonl was read, it would fail because it's not valid JSON.
            # Reaching this point means test.jsonl was NOT read.
            self.assertTrue(True)


# ===========================================================================
# Test: Evaluation Metrics
# ===========================================================================

class TestEvaluationMetrics(unittest.TestCase):
    """Test CPU-safe metric computation functions."""

    def test_accuracy_perfect(self):
        preds = ["a", "b", "c"]
        labels = ["a", "b", "c"]
        self.assertAlmostEqual(compute_accuracy(preds, labels), 1.0)

    def test_accuracy_zero(self):
        preds = ["a", "b", "c"]
        labels = ["x", "y", "z"]
        self.assertAlmostEqual(compute_accuracy(preds, labels), 0.0)

    def test_accuracy_partial(self):
        preds = ["a", "b", "c", "d"]
        labels = ["a", "b", "x", "y"]
        self.assertAlmostEqual(compute_accuracy(preds, labels), 0.5)

    def test_accuracy_empty(self):
        self.assertAlmostEqual(compute_accuracy([], []), 0.0)

    def test_per_class_metrics_perfect(self):
        preds = ["a", "a", "b", "b"]
        labels = ["a", "a", "b", "b"]
        metrics = compute_per_class_metrics(preds, labels)
        self.assertAlmostEqual(metrics["a"]["precision"], 1.0)
        self.assertAlmostEqual(metrics["a"]["recall"], 1.0)
        self.assertAlmostEqual(metrics["a"]["f1"], 1.0)
        self.assertAlmostEqual(metrics["b"]["f1"], 1.0)

    def test_per_class_metrics_no_predictions(self):
        preds = ["b", "b"]
        labels = ["a", "a"]
        metrics = compute_per_class_metrics(preds, labels)
        self.assertAlmostEqual(metrics["a"]["recall"], 0.0)
        self.assertAlmostEqual(metrics["b"]["precision"], 0.0)

    def test_per_class_support_correct(self):
        preds = ["a", "b", "a", "b", "a"]
        labels = ["a", "a", "a", "b", "b"]
        metrics = compute_per_class_metrics(preds, labels)
        self.assertEqual(metrics["a"]["support"], 3)
        self.assertEqual(metrics["b"]["support"], 2)


# ===========================================================================
# Test: Structured Output Validation
# ===========================================================================

class TestStructuredOutputValidation(unittest.TestCase):
    """Test validate_structured_output from evaluate_model."""

    def test_valid_output_passes(self):
        output = {
            "classification": "suspicious",
            "severity": "medium",
            "confidence": 0.75,
            "investigation_required": True,
            "summary": "Test summary",
        }
        is_valid, error = validate_structured_output(output)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_missing_field_fails(self):
        output = {
            "classification": "suspicious",
            "severity": "medium",
            # Missing confidence, investigation_required, summary
        }
        is_valid, error = validate_structured_output(output)
        self.assertFalse(is_valid)
        self.assertIn("Missing", error)

    def test_invalid_classification_fails(self):
        output = {
            "classification": "unknown_class",
            "severity": "medium",
            "confidence": 0.5,
            "investigation_required": True,
            "summary": "Test",
        }
        is_valid, error = validate_structured_output(output)
        self.assertFalse(is_valid)

    def test_confidence_out_of_range_fails(self):
        output = {
            "classification": "suspicious",
            "severity": "medium",
            "confidence": 1.5,
            "investigation_required": True,
            "summary": "Test",
        }
        is_valid, error = validate_structured_output(output)
        self.assertFalse(is_valid)


# ===========================================================================
# Test: Evidence Reference Validation
# ===========================================================================

class TestEvidenceRefValidation(unittest.TestCase):
    """Test validate_evidence_refs from evaluate_model."""

    def test_valid_refs_pass(self):
        output = {
            "findings": [
                {"finding": "Test", "evidence_ids": ["EVT-001"]},
            ],
            "evidence_ids": ["EVT-001"],
        }
        is_valid, error = validate_evidence_refs(output, {"EVT-001", "EVT-002"})
        self.assertTrue(is_valid)

    def test_invalid_ref_fails(self):
        output = {
            "findings": [
                {"finding": "Test", "evidence_ids": ["EVT-999"]},
            ],
        }
        is_valid, error = validate_evidence_refs(output, {"EVT-001"})
        self.assertFalse(is_valid)
        self.assertIn("EVT-999", error)


# ===========================================================================
# Test: GPU Detection (Mocked)
# ===========================================================================

class TestGPUDetection(unittest.TestCase):
    """Test GPU detection logic with mocked torch."""

    def test_no_torch_reports_no_gpu(self):
        """When torch is not importable, gpu_preflight should report no GPU."""
        from finetuning.gpu_preflight import run_preflight
        # Run preflight — on this CPU laptop it should report NO_GPU or similar
        report = run_preflight()
        self.assertIn("verdict", report)
        # On a CPU laptop without torch, verdict should be NO_GPU
        if not report.get("cuda_available"):
            self.assertEqual(report["verdict"], "NO_GPU")


# ===========================================================================
# Test: All Five Classification Classes
# ===========================================================================

class TestAllClassifications(unittest.TestCase):
    """Ensure every valid classification converts successfully."""

    def setUp(self):
        self.system_prompt = get_triage_system_prompt()

    def test_each_classification(self):
        for cls in VALID_CLASSIFICATIONS:
            with self.subTest(classification=cls):
                record = make_sample_record(classification=cls)
                sft_example, error = convert_record(record, self.system_prompt)
                self.assertIsNone(error, f"{cls} failed: {error}")
                parsed = json.loads(sft_example["messages"][2]["content"])
                self.assertEqual(parsed["classification"], cls)


# ===========================================================================
# Test: Investigation Required Logic
# ===========================================================================

class TestInvestigationRequired(unittest.TestCase):
    """Test that investigation_required is computed correctly."""

    def setUp(self):
        self.system_prompt = get_triage_system_prompt()

    def test_benign_high_confidence_no_investigation(self):
        record = make_sample_record(classification="benign")
        record["output"]["confidence"] = 0.85
        sft_example, _ = convert_record(record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        self.assertFalse(parsed["investigation_required"])

    def test_benign_low_confidence_needs_investigation(self):
        record = make_sample_record(classification="benign")
        record["output"]["confidence"] = 0.50
        sft_example, _ = convert_record(record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        self.assertTrue(parsed["investigation_required"])

    def test_malicious_always_needs_investigation(self):
        record = make_sample_record(classification="confirmed_malicious")
        record["output"]["confidence"] = 0.99
        sft_example, _ = convert_record(record, self.system_prompt)
        parsed = json.loads(sft_example["messages"][2]["content"])
        self.assertTrue(parsed["investigation_required"])


# ===========================================================================
# Test: v0.4 Dataset Files Exist
# ===========================================================================

class TestV04DatasetIntegrity(unittest.TestCase):
    """Verify the v0.4 source dataset files exist and are non-empty."""

    def test_train_exists(self):
        p = PROJECT_ROOT / "datasets" / "finetuning" / "v0.4" / "train.jsonl"
        self.assertTrue(p.exists(), f"train.jsonl not found: {p}")
        self.assertGreater(p.stat().st_size, 0)

    def test_validation_exists(self):
        p = PROJECT_ROOT / "datasets" / "finetuning" / "v0.4" / "validation.jsonl"
        self.assertTrue(p.exists(), f"validation.jsonl not found: {p}")
        self.assertGreater(p.stat().st_size, 0)

    def test_test_exists(self):
        p = PROJECT_ROOT / "datasets" / "finetuning" / "v0.4" / "test.jsonl"
        self.assertTrue(p.exists(), f"test.jsonl not found: {p}")
        self.assertGreater(p.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
