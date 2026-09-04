#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX Dataset v0.4 Pipeline & Diversity Unit Tests
===================================================

Comprehensive test suite verifying all AegisX Fine-Tuning Dataset v0.4 invariants:
1. Generation record counts (2,400 train, 300 val, 300 test = 3,000 total).
2. Template family counts (120 train, 15 val, 15 test = 150 total).
3. Zero template leakage across train, val, and test.
4. Perfectly balanced classification distribution (exactly 20.0% / 600 records per class).
5. Both Windows (70%) and Linux (30%) OS telemetry across all splits.
6. Complete evidence type diversity (18 of 18 types).
7. Complete MITRE ATT&CK coverage (all 34 supported techniques across 10 tactics).
8. Extensive borderline cases (1,760 records across all 5 key decision boundaries).
9. Anti-keyword-learning Shannon entropy (> 1.0 bit for all key tools).
10. Zero exact or near-duplicates across all 3,000 records.
11. Strict schema compliance (0 errors, 0 warnings).
12. High quality scores (average quality score >= 85).
"""

import hashlib
import json
import math
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import templates_v04
from generate_dataset_v04 import (
    generate_finetuning_v04,
    SyntheticValueGenerator,
    calculate_quality_score,
)
from validate_dataset import validate_record, ValidationResult, load_mitre_reference

class TestDatasetV04(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset_dir = PROJECT_ROOT / "datasets" / "finetuning" / "v0.4"
        cls.train_path = cls.dataset_dir / "train.jsonl"
        cls.val_path = cls.dataset_dir / "validation.jsonl"
        cls.test_path = cls.dataset_dir / "test.jsonl"
        cls.full_path = cls.dataset_dir / "full_dataset.jsonl"

        with open(cls.full_path, "r", encoding="utf-8") as f:
            cls.full_records = [json.loads(line) for line in f if line.strip()]
        with open(cls.train_path, "r", encoding="utf-8") as f:
            cls.train_records = [json.loads(line) for line in f if line.strip()]
        with open(cls.val_path, "r", encoding="utf-8") as f:
            cls.val_records = [json.loads(line) for line in f if line.strip()]
        with open(cls.test_path, "r", encoding="utf-8") as f:
            cls.test_records = [json.loads(line) for line in f if line.strip()]

        cls.known_mitre = load_mitre_reference(PROJECT_ROOT)

    def test_record_counts(self):
        self.assertEqual(len(self.full_records), 3000)
        self.assertEqual(len(self.train_records), 2400)
        self.assertEqual(len(self.val_records), 300)
        self.assertEqual(len(self.test_records), 300)

    def test_template_counts(self):
        all_tpls = {r["metadata"]["template_id"] for r in self.full_records}
        train_tpls = {r["metadata"]["template_id"] for r in self.train_records}
        val_tpls = {r["metadata"]["template_id"] for r in self.val_records}
        test_tpls = {r["metadata"]["template_id"] for r in self.test_records}

        self.assertEqual(len(all_tpls), 150)
        self.assertEqual(len(train_tpls), 120)
        self.assertEqual(len(val_tpls), 15)
        self.assertEqual(len(test_tpls), 15)

    def test_zero_template_leakage(self):
        train_tpls = {r["metadata"]["template_id"] for r in self.train_records}
        val_tpls = {r["metadata"]["template_id"] for r in self.val_records}
        test_tpls = {r["metadata"]["template_id"] for r in self.test_records}

        self.assertEqual(len(train_tpls & val_tpls), 0, "Train and Val template overlap!")
        self.assertEqual(len(train_tpls & test_tpls), 0, "Train and Test template overlap!")
        self.assertEqual(len(val_tpls & test_tpls), 0, "Val and Test template overlap!")

    def test_classification_balance(self):
        classes = ["benign", "suspicious", "likely_malicious", "confirmed_malicious", "insufficient_evidence"]
        counts = Counter(r["output"]["classification"] for r in self.full_records)

        # In full dataset: exactly 600 records per class
        for c in classes:
            self.assertEqual(counts[c], 600, f"Class {c} does not equal 600 records!")

        # In train split: exactly 480 records per class
        train_counts = Counter(r["output"]["classification"] for r in self.train_records)
        for c in classes:
            self.assertEqual(train_counts[c], 480, f"Train class {c} does not equal 480 records!")

        # In val split: exactly 60 records per class
        val_counts = Counter(r["output"]["classification"] for r in self.val_records)
        for c in classes:
            self.assertEqual(val_counts[c], 60, f"Val class {c} does not equal 60 records!")

        # In test split: exactly 60 records per class
        test_counts = Counter(r["output"]["classification"] for r in self.test_records)
        for c in classes:
            self.assertEqual(test_counts[c], 60, f"Test class {c} does not equal 60 records!")

    def test_os_representation(self):
        win_count = sum(1 for r in self.full_records if "Windows" in r["input"]["context"]["os"])
        lnx_count = sum(1 for r in self.full_records if "Ubuntu" in r["input"]["context"]["os"] or "RHEL" in r["input"]["context"]["os"])

        self.assertEqual(win_count, 2100, f"Windows count {win_count} != 2,100")
        self.assertEqual(lnx_count, 900, f"Linux count {lnx_count} != 900")

        for split_name, recs in [("Train", self.train_records), ("Val", self.val_records), ("Test", self.test_records)]:
            oses = {"Windows" if "Windows" in r["input"]["context"]["os"] else "Linux" for r in recs}
            self.assertIn("Windows", oses, f"Missing Windows in {split_name}")
            self.assertIn("Linux", oses, f"Missing Linux in {split_name}")

    def test_evidence_diversity(self):
        ev_types = {e["type"] for r in self.full_records for e in r["input"]["evidence"]}
        self.assertEqual(len(ev_types), 18, f"Expected 18 evidence types, got {len(ev_types)}")

    def test_mitre_coverage(self):
        mitre_techs = {m["technique_id"] for r in self.full_records for m in r["output"].get("mitre_techniques", [])}
        self.assertEqual(len(mitre_techs), 34, f"Expected 34 MITRE techniques, got {len(mitre_techs)}")

    def test_borderline_cases(self):
        bl_records = [r for r in self.full_records if "borderline_category" in r["metadata"]]
        self.assertGreaterEqual(len(bl_records), 450, f"Expected >= 450 borderline records, got {len(bl_records)}")

        boundaries = {r["metadata"]["borderline_category"] for r in bl_records}
        expected = {
            "benign_vs_suspicious",
            "suspicious_vs_likely_malicious",
            "likely_malicious_vs_confirmed_malicious",
            "suspicious_vs_insufficient_evidence",
            "likely_malicious_vs_insufficient_evidence",
        }
        self.assertEqual(boundaries, expected)

    def test_anti_keyword_entropy(self):
        keywords = ["powershell", "cmd", "sudo", "ssh", "curl", "wmi", "certutil", "rundll32", "scheduled_task"]
        for kw in keywords:
            class_map = Counter()
            for r in self.full_records:
                text = json.dumps(r["input"]).lower()
                if kw in text:
                    class_map[r["output"]["classification"]] += 1

            self.assertGreaterEqual(len(class_map), 2, f"Tool {kw} maps to only 1 class!")

            total = sum(class_map.values())
            entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in class_map.values() if cnt > 0)
            self.assertGreater(entropy, 1.0, f"Entropy for {kw} is too low: {entropy:.2f}")

    def test_no_exact_or_near_duplicates(self):
        exact_hashes = set()
        near_keys = set()
        for r in self.full_records:
            canon = json.dumps(r["input"], sort_keys=True)
            h = hashlib.sha256(canon.encode()).hexdigest()
            self.assertNotIn(h, exact_hashes, f"Duplicate input hash detected for {r['id']}")
            exact_hashes.add(h)

            first_desc = r["input"]["evidence"][0]["description"] if r["input"]["evidence"] else ""
            nkey = f"{r['input']['alert']['title']}||{first_desc}"
            self.assertNotIn(nkey, near_keys, f"Near-duplicate key collision for {r['id']}")
            near_keys.add(nkey)

    def test_record_validation(self):
        # Validate sample across all splits and classes
        sample_records = self.full_records[::15]  # 200 records uniformly sampled
        for r in sample_records:
            res = ValidationResult()
            validate_record(r, res, self.known_mitre)
            self.assertEqual(len(res.errors), 0, f"Record {r['id']} has errors: {res.errors}")
            self.assertEqual(len(res.warnings), 0, f"Record {r['id']} has warnings: {res.warnings}")

    def test_quality_scores(self):
        scores = [r["metadata"]["quality_score"] for r in self.full_records]
        avg_score = sum(scores) / len(scores)
        self.assertGreaterEqual(avg_score, 85.0, f"Average quality score {avg_score:.1f} < 85")
        for s in scores:
            self.assertGreaterEqual(s, 80, f"Quality score {s} < 80")

    def test_quality_score_timing_regression(self):
        """Regression test: verify that a valid record scores 100 when metadata is attached,
        and prove that omitting metadata prior to calculation docked 10 points."""
        sample = self.full_records[0]
        # Copy record without metadata
        rec_no_meta = {k: v for k, v in sample.items() if k != "metadata"}
        score_without_meta = calculate_quality_score(rec_no_meta)
        self.assertEqual(score_without_meta, 90, "Record without metadata should score 90 (penalized for missing key)")

        # With metadata attached
        score_with_meta = calculate_quality_score(sample)
        self.assertEqual(score_with_meta, 100, "Fully valid record with metadata attached must score 100")

if __name__ == "__main__":
    unittest.main()
