#!/usr/bin/env python3
"""
AegisX Dataset Pipeline Tests (v0.2)
=====================================

Comprehensive unit tests for dataset generation, structural validation,
semantic quality verification, MITRE reference checking, negative testing,
and quality scoring.

Usage:
    python -m unittest tests/test_dataset.py -v
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from generate_dataset import (
    VALID_TASKS,
    VALID_CLASSIFICATIONS,
    generate_dataset,
    generate_record,
    SyntheticValueGenerator,
    compute_task_counts,
    calculate_quality_score,
)
from validate_dataset import (
    validate_record,
    validate_file,
    ValidationResult,
    load_mitre_reference,
)
import random

class TestGeneratorOutputV2(unittest.TestCase):
    """Test v0.2 generator enhancements."""

    def test_generator_output_count(self):
        for count in [1, 5, 10, 20]:
            records = generate_dataset(count=count, seed=42)
            self.assertEqual(len(records), count)

    def test_version_is_0_2(self):
        records = generate_dataset(count=5, seed=42)
        for r in records:
            self.assertEqual(r["metadata"]["dataset_version"], "0.2")

    def test_quality_score_presence_and_range(self):
        records = generate_dataset(count=20, seed=42)
        for r in records:
            qs = r["metadata"].get("quality_score")
            self.assertIsNotNone(qs)
            self.assertIsInstance(qs, int)
            self.assertGreaterEqual(qs, 0)
            self.assertLessEqual(qs, 100)

    def test_timestamp_chronological_ordering(self):
        records = generate_dataset(count=20, seed=42)
        for r in records:
            evidences = r["input"]["evidence"]
            timestamps = [datetime.fromisoformat(e["timestamp"]) for e in evidences if "timestamp" in e]
            self.assertEqual(timestamps, sorted(timestamps), f"Record {r['id']} evidence timestamps not ordered.")

    def test_deterministic_seed(self):
        r1 = generate_dataset(count=10, seed=42)
        r2 = generate_dataset(count=10, seed=42)
        for a, b in zip(r1, r2):
            c1 = json.loads(json.dumps(a))
            c2 = json.loads(json.dumps(b))
            c1["metadata"].pop("created_at", None)
            c2["metadata"].pop("created_at", None)
            self.assertEqual(c1, c2)

    def test_all_task_types_present(self):
        records = generate_dataset(count=100, seed=42)
        tasks_present = {r["task"] for r in records}
        for task in VALID_TASKS:
            self.assertIn(task, tasks_present)

    def test_evidence_grounding(self):
        records = generate_dataset(count=25, seed=42)
        for r in records:
            evt_ids = {e["id"] for e in r["input"]["evidence"]}
            for f in r["output"]["findings"]:
                for ref in f["evidence_refs"]:
                    self.assertIn(ref, evt_ids)

    def test_unique_dynamic_hashes(self):
        gen = SyntheticValueGenerator(random.Random(42))
        h1 = gen.file_hash(malicious=True)
        h2 = gen.file_hash(malicious=True)
        self.assertNotEqual(h1, h2)
        self.assertEqual(len(h1), 64)

class TestQualityScoring(unittest.TestCase):
    """Test automated quality scoring calculations."""

    def test_perfect_record_score(self):
        record = {
            "id": "SOC-000001",
            "task": "alert_triage",
            "input": {
                "alert": {"title": "Test", "severity": "medium", "source": "EDR"},
                "context": {"hostname": "PC-001", "username": "employee01"},
                "evidence": [
                    {"id": "EVT-001", "type": "process_creation", "description": "evt1", "timestamp": "2026-01-01T10:00:00+00:00"},
                    {"id": "EVT-002", "type": "network_connection", "description": "evt2", "timestamp": "2026-01-01T10:01:00+00:00"}
                ]
            },
            "output": {
                "classification": "suspicious",
                "confidence": 0.55,
                "findings": [{"description": "Finding", "evidence_refs": ["EVT-001", "EVT-002"]}],
                "rationale": "Clear rationale",
                "recommended_actions": [{"action": "Action", "priority": "high"}]
            },
            "metadata": {"source": "synthetic", "generator": "test", "review_status": "pending", "dataset_version": "0.2"}
        }
        score = calculate_quality_score(record)
        self.assertEqual(score, 100)

class TestMitreReference(unittest.TestCase):
    """Test MITRE reference loading and validation."""

    def test_load_mitre_reference(self):
        known_ids = load_mitre_reference(PROJECT_ROOT)
        self.assertIn("T1059.001", known_ids)
        self.assertIn("T1566.001", known_ids)

    def test_generator_uses_known_mitre_ids(self):
        known_ids = load_mitre_reference(PROJECT_ROOT)
        records = generate_dataset(count=50, seed=42)
        for r in records:
            for tech in r["output"].get("mitre_techniques", []):
                tid = tech.get("technique_id")
                self.assertIn(tid, known_ids, f"Technique ID {tid} not found in mitre_reference.json")

class TestNegativeValidationCases(unittest.TestCase):
    """Negative testing suite verifying validator catches invalid records and semantic issues."""

    def setUp(self):
        self.known_mitre = load_mitre_reference(PROJECT_ROOT)
        self.valid_record = {
            "id": "SOC-000001",
            "task": "alert_triage",
            "input": {
                "alert": {"title": "Test Alert", "severity": "medium", "source": "EDR"},
                "context": {"hostname": "PC-001", "username": "employee01"},
                "evidence": [
                    {"id": "EVT-001", "type": "process_creation", "description": "e1", "timestamp": "2026-01-01T10:00:00+00:00"}
                ]
            },
            "output": {
                "classification": "suspicious",
                "confidence": 0.55,
                "findings": [{"description": "f1", "evidence_refs": ["EVT-001"]}]
            },
            "metadata": {"source": "synthetic", "generator": "test", "review_status": "pending", "dataset_version": "0.2"}
        }

    def test_missing_id(self):
        rec = json.loads(json.dumps(self.valid_record))
        del rec["id"]
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("missing required top-level field: id" in e for e in res.errors))

    def test_invalid_task(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["task"] = "invalid_soc_task"
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("invalid task" in e for e in res.errors))

    def test_invalid_classification(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["output"]["classification"] = "definitely_malicious_xyz"
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("invalid classification" in e for e in res.errors))

    def test_invalid_severity(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["input"]["alert"]["severity"] = "super_critical"
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("invalid alert severity" in e for e in res.errors))

    def test_confidence_greater_than_one(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["output"]["confidence"] = 1.25
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("confidence 1.25 out of range" in e for e in res.errors))

    def test_confidence_less_than_zero(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["output"]["confidence"] = -0.5
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("confidence -0.5 out of range" in e for e in res.errors))

    def test_missing_evidence_array(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["input"]["evidence"] = []
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("evidence array must not be empty" in e for e in res.errors))

    def test_broken_evidence_reference(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["output"]["findings"][0]["evidence_refs"] = ["EVT-999"]
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("non-existent evidence 'EVT-999'" in e for e in res.errors))

    def test_invalid_mitre_technique_pattern(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["output"]["mitre_techniques"] = [{"technique_id": "INVALID-1059", "technique_name": "Bad"}]
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("invalid technique_id pattern" in e for e in res.errors))

    def test_unknown_mitre_technique_warning(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["output"]["mitre_techniques"] = [{"technique_id": "T9999.001", "technique_name": "Fake Technique"}]
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertTrue(res.is_valid)
        self.assertTrue(any("not found in mitre_reference.json" in w for w in res.warnings))

    def test_out_of_order_timestamps_warning(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["input"]["evidence"] = [
            {"id": "EVT-001", "type": "process_creation", "description": "e1", "timestamp": "2026-01-01T10:10:00+00:00"},
            {"id": "EVT-002", "type": "network_connection", "description": "e2", "timestamp": "2026-01-01T10:02:00+00:00"}
        ]
        rec["output"]["findings"][0]["evidence_refs"] = ["EVT-001", "EVT-002"]
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertTrue(res.is_valid)
        self.assertTrue(any("not in chronological order" in w for w in res.warnings))

    def test_severity_classification_mismatch_warning(self):
        rec = json.loads(json.dumps(self.valid_record))
        rec["input"]["alert"]["severity"] = "critical"
        rec["output"]["classification"] = "benign"
        rec["output"]["confidence"] = 0.85
        res = ValidationResult()
        validate_record(rec, res, self.known_mitre)
        self.assertTrue(res.is_valid)
        self.assertTrue(any("alert severity is 'critical' but output classification is 'benign'" in w for w in res.warnings))

class TestFileValidationAndSplitting(unittest.TestCase):
    """Test file validation and output split logic."""

    def test_valid_jsonl_file_validation(self):
        records = generate_dataset(count=10, seed=42)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
            tmp_path = Path(f.name)

        try:
            res, loaded = validate_file(tmp_path, PROJECT_ROOT)
            self.assertTrue(res.is_valid)
            self.assertEqual(len(loaded), 10)
        finally:
            tmp_path.unlink()

    def test_malformed_json_line(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write('{"valid": "json"}\n')
            f.write('{this_is_bad_json}\n')
            tmp_path = Path(f.name)

        try:
            res, loaded = validate_file(tmp_path, PROJECT_ROOT)
            self.assertFalse(res.is_valid)
            self.assertTrue(any("invalid JSON" in e for e in res.errors))
        finally:
            tmp_path.unlink()

if __name__ == "__main__":
    unittest.main()
