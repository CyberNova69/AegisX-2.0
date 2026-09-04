#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for AegisX Fine-Tuning Dataset v0.5
=========================================

Validates:
- Target record counts (2,400 train, 300 val, 300 test, 3,000 full)
- Strict template-family isolation across splits (zero leakage)
- Perfect 5-class balance (20.0% each)
- Absence of exact or near duplicates
- Evidence grounding rate (100% grounded, 0 hallucinated refs)
- Presence of benign distractor telemetry (~30% of records)
- High anti-keyword Shannon entropy (H >= 1.0 for all critical tools)
- Correct borderline representation (1,760 records / 58.7%)
- Quality score average = 100.0 (quality timing defect resolved)
- Schema validation conformance across all splits
"""

import hashlib
import json
import math
import sys
import unittest
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from validate_dataset import validate_record, ValidationResult, load_mitre_reference

class TestDatasetV05(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset_dir = PROJECT_ROOT / "datasets" / "finetuning" / "v0.5"
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

    def test_classification_balance(self):
        # 600 per class in full
        counts = Counter(r["output"]["classification"] for r in self.full_records)
        expected_classes = ["benign", "suspicious", "likely_malicious", "confirmed_malicious", "insufficient_evidence"]
        for c in expected_classes:
            self.assertEqual(counts[c], 600, f"Class {c} has count {counts[c]} != 600 in full dataset")

        # 480 per class in train
        train_counts = Counter(r["output"]["classification"] for r in self.train_records)
        for c in expected_classes:
            self.assertEqual(train_counts[c], 480, f"Class {c} has count {train_counts[c]} != 480 in train")

        # 60 per class in validation
        val_counts = Counter(r["output"]["classification"] for r in self.val_records)
        for c in expected_classes:
            self.assertEqual(val_counts[c], 60, f"Class {c} has count {val_counts[c]} != 60 in validation")

        # 60 per class in test
        test_counts = Counter(r["output"]["classification"] for r in self.test_records)
        for c in expected_classes:
            self.assertEqual(test_counts[c], 60, f"Class {c} has count {test_counts[c]} != 60 in test")

    def test_zero_template_leakage(self):
        train_tmpls = {r["metadata"]["template_id"] for r in self.train_records}
        val_tmpls = {r["metadata"]["template_id"] for r in self.val_records}
        test_tmpls = {r["metadata"]["template_id"] for r in self.test_records}

        self.assertEqual(len(train_tmpls), 120, "Train should have exactly 120 templates")
        self.assertEqual(len(val_tmpls), 15, "Val should have exactly 15 templates")
        self.assertEqual(len(test_tmpls), 15, "Test should have exactly 15 templates")

        self.assertEqual(len(train_tmpls & val_tmpls), 0, "Leakage between Train and Validation!")
        self.assertEqual(len(train_tmpls & test_tmpls), 0, "Leakage between Train and Test!")
        self.assertEqual(len(val_tmpls & test_tmpls), 0, "Leakage between Validation and Test!")

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

    def test_evidence_grounding_and_no_hallucinations(self):
        total_refs = 0
        hallucinated_refs = 0
        for r in self.full_records:
            ev_ids = {e["id"] for e in r["input"]["evidence"]}
            for f in r["output"].get("findings", []):
                for ref in f.get("evidence_refs", []):
                    total_refs += 1
                    if ref not in ev_ids:
                        hallucinated_refs += 1
            for m in r["output"].get("mitre_techniques", []):
                for ref in m.get("evidence_refs", []):
                    total_refs += 1
                    if ref not in ev_ids:
                        hallucinated_refs += 1
        self.assertGreater(total_refs, 5000)
        self.assertEqual(hallucinated_refs, 0, f"Found {hallucinated_refs} hallucinated evidence references!")

    def test_distractor_telemetry_presence(self):
        distractor_count = 0
        for r in self.full_records:
            ev_ids = {e["id"] for e in r["input"]["evidence"]}
            cited = set()
            for f in r["output"].get("findings", []):
                cited.update(f.get("evidence_refs", []))
            for m in r["output"].get("mitre_techniques", []):
                cited.update(m.get("evidence_refs", []))
            if len(ev_ids - cited) > 0:
                distractor_count += 1
        distractor_rate = distractor_count / len(self.full_records)
        self.assertGreaterEqual(distractor_rate, 0.20, f"Distractor rate {distractor_rate:.2f} is below 20%")
        self.assertLessEqual(distractor_rate, 0.40, f"Distractor rate {distractor_rate:.2f} is above 40%")

    def test_anti_keyword_entropy(self):
        target_keywords = [
            "powershell", "psexec", "ssh", "scheduled task",
            "failed login", "suspicious", "malicious", "attack", "ransomware"
        ]
        for kw in target_keywords:
            class_map = Counter()
            for r in self.full_records:
                text = json.dumps(r["input"]).lower()
                if kw in text:
                    class_map[r["output"]["classification"]] += 1

            self.assertGreaterEqual(len(class_map), 2, f"Keyword {kw} maps to fewer than 2 classes: {dict(class_map)}")
            total = sum(class_map.values())
            entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in class_map.values() if cnt > 0)
            self.assertGreaterEqual(entropy, 1.0, f"Entropy for keyword '{kw}' is too low: {entropy:.2f} (< 1.0)")

    def test_borderline_representation(self):
        borderline = [r for r in self.full_records if "borderline_category" in r.get("metadata", {})]
        self.assertEqual(len(borderline), 1760, f"Expected 1760 borderline records, found {len(borderline)}")

    def test_quality_scores(self):
        scores = [r["metadata"]["quality_score"] for r in self.full_records]
        avg_score = sum(scores) / len(scores)
        self.assertEqual(avg_score, 100.0, f"Average quality score {avg_score:.1f} != 100.0")
        for s in scores:
            self.assertEqual(s, 100, f"Record has quality score {s} != 100")

    def test_record_validation(self):
        # Sample 200 records across all splits and classes
        sample_records = self.full_records[::15]
        for r in sample_records:
            res = ValidationResult()
            validate_record(r, res, self.known_mitre)
            self.assertEqual(len(res.errors), 0, f"Record {r['id']} has validation errors: {res.errors}")
            self.assertEqual(len(res.warnings), 0, f"Record {r['id']} has validation warnings: {res.warnings}")

if __name__ == "__main__":
    unittest.main()
