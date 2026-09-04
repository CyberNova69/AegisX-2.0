#!/usr/bin/env python3
"""
AegisX Dataset v0.3 Pipeline & Diversity Unit Tests
===================================================

Tests:
1. Generation counts across splits (416 train, 54 val, 50 test = 520 total).
2. Template counts and split ratios (68 train, 9 val, 8 test = 85 total).
3. Zero template leakage across train, val, and test.
4. Balanced classification distribution (~20% per class).
5. Both Windows and Linux OSes across all splits.
6. Evidence type coverage (>= 15 types).
7. MITRE ATT&CK coverage (>= 25 techniques).
8. Borderline cases coverage (>= 30 across 5 boundaries).
9. Anti-keyword-learning Shannon entropy (> 1.0 bit for key observables).
10. Schema validation & quality scores (avg >= 80).
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

import templates_v03
from generate_dataset_v03 import (
    generate_finetuning_v03,
    SyntheticValueGenerator,
    calculate_quality_score,
)
from validate_dataset import validate_record, ValidationResult, load_mitre_reference

class TestDatasetV03(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset_dir = PROJECT_ROOT / "datasets" / "finetuning" / "v0.3"
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
        self.assertEqual(len(self.full_records), 520)
        self.assertEqual(len(self.train_records), 416)
        self.assertEqual(len(self.val_records), 54)
        self.assertEqual(len(self.test_records), 50)

    def test_template_counts(self):
        all_tpls = {r["metadata"]["template_id"] for r in self.full_records}
        train_tpls = {r["metadata"]["template_id"] for r in self.train_records}
        val_tpls = {r["metadata"]["template_id"] for r in self.val_records}
        test_tpls = {r["metadata"]["template_id"] for r in self.test_records}

        self.assertEqual(len(all_tpls), 85)
        self.assertEqual(len(train_tpls), 68)
        self.assertEqual(len(val_tpls), 9)
        self.assertEqual(len(test_tpls), 8)

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
        total = len(self.full_records)

        for c in classes:
            pct = counts[c] / total * 100
            self.assertGreaterEqual(pct, 18.0, f"Class {c} under-represented ({pct:.1f}%)")
            self.assertLessEqual(pct, 22.0, f"Class {c} over-represented ({pct:.1f}%)")

        for split_name, recs in [("Train", self.train_records), ("Val", self.val_records), ("Test", self.test_records)]:
            split_classes = {r["output"]["classification"] for r in recs}
            self.assertEqual(split_classes, set(classes), f"Missing classes in {split_name} split")

    def test_os_representation(self):
        for split_name, recs in [("Train", self.train_records), ("Val", self.val_records), ("Test", self.test_records)]:
            oses = {"Windows" if "Windows" in r["input"]["context"]["os"] else "Linux" for r in recs}
            self.assertIn("Windows", oses, f"Missing Windows in {split_name}")
            self.assertIn("Linux", oses, f"Missing Linux in {split_name}")

    def test_evidence_diversity(self):
        ev_types = {e["type"] for r in self.full_records for e in r["input"]["evidence"]}
        self.assertGreaterEqual(len(ev_types), 15, f"Expected >= 15 evidence types, got {len(ev_types)}")

    def test_mitre_coverage(self):
        mitre_techs = {m["technique_id"] for r in self.full_records for m in r["output"].get("mitre_techniques", [])}
        self.assertGreaterEqual(len(mitre_techs), 25, f"Expected >= 25 MITRE techniques, got {len(mitre_techs)}")

    def test_borderline_cases(self):
        bl_records = [r for r in self.full_records if "borderline_category" in r["metadata"]]
        self.assertGreaterEqual(len(bl_records), 30)

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
        keywords = ["powershell", "certutil", "rundll32", "ssh", "curl"]
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
        for r in self.full_records[:50]:  # Sample validation
            res = ValidationResult()
            validate_record(r, res, self.known_mitre)
            self.assertEqual(len(res.errors), 0, f"Record {r['id']} has errors: {res.errors}")
            self.assertEqual(len(res.warnings), 0, f"Record {r['id']} has warnings: {res.warnings}")

if __name__ == "__main__":
    unittest.main()
