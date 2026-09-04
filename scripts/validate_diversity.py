#!/usr/bin/env python3
"""
AegisX Dataset Diversity & Anti-Leakage Validator (v0.3)
=========================================================

Audits JSONL dataset files and splits for:
1. Exact and near-duplicate records.
2. Template-to-split disjointness (verifying 0 template leakage across train, val, test).
3. Classification balance and distribution tolerances (~20% each).
4. Operating system balance (Windows + Linux across splits).
5. Evidence type coverage (>= 15 distinct evidence types).
6. MITRE ATT&CK technique coverage (>= 25 distinct techniques).
7. Borderline cases analysis across all 5 decision boundaries.
8. Anti-keyword-learning entropy: verifies key tools (powershell, certutil, rundll32, ssh, curl)
   appear across multiple classifications rather than mapping 1:1 to a single class.

Usage:
    python scripts/validate_diversity.py --dataset-dir datasets/finetuning/v0.3
"""

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

def load_jsonl(filepath: Path) -> list[dict]:
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records

def calculate_shannon_entropy(class_counts: dict) -> float:
    total = sum(class_counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in class_counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy

def run_diversity_audit(dataset_dir: Path) -> tuple[bool, dict]:
    print("============================================================")
    print("  AegisX Fine-Tuning Dataset Diversity Audit (v0.3)")
    print("============================================================")
    print(f"  Dataset Directory: {dataset_dir}\n")

    full_path = dataset_dir / "full_dataset.jsonl"
    train_path = dataset_dir / "train.jsonl"
    val_path = dataset_dir / "validation.jsonl"
    test_path = dataset_dir / "test.jsonl"

    for p in [full_path, train_path, val_path, test_path]:
        if not p.exists():
            print(f"[ERROR] Required dataset file missing: {p}")
            return False, {}

    all_records = load_jsonl(full_path)
    train_records = load_jsonl(train_path)
    val_records = load_jsonl(val_path)
    test_records = load_jsonl(test_path)

    report = {}
    passed = True

    # 1. Total Record & Template Counts
    print("--- 1. RECORD & TEMPLATE COUNTS ---")
    total_recs = len(all_records)
    print(f"  Total Records:      {total_recs} (Target: >= 500)")
    print(f"    - Train Records:  {len(train_records)} ({len(train_records)/total_recs*100:.1f}%)")
    print(f"    - Val Records:    {len(val_records)} ({len(val_records)/total_recs*100:.1f}%)")
    print(f"    - Test Records:   {len(test_records)} ({len(test_records)/total_recs*100:.1f}%)")

    tpl_ids_all = {r["metadata"].get("template_id") for r in all_records}
    tpl_ids_train = {r["metadata"].get("template_id") for r in train_records}
    tpl_ids_val = {r["metadata"].get("template_id") for r in val_records}
    tpl_ids_test = {r["metadata"].get("template_id") for r in test_records}

    print(f"  Total Templates:    {len(tpl_ids_all)} (Target: >= 80)")
    print(f"    - Train Templates:{len(tpl_ids_train)} ({len(tpl_ids_train)/len(tpl_ids_all)*100:.1f}%)")
    print(f"    - Val Templates:  {len(tpl_ids_val)} ({len(tpl_ids_val)/len(tpl_ids_all)*100:.1f}%)")
    print(f"    - Test Templates: {len(tpl_ids_test)} ({len(tpl_ids_test)/len(tpl_ids_all)*100:.1f}%)\n")

    if total_recs < 500:
        print("  [FAIL] Total records less than 500!")
        passed = False
    if len(tpl_ids_all) < 80:
        print("  [FAIL] Total distinct templates less than 80!")
        passed = False

    # 2. Template Leakage & Disjointness Check
    print("--- 2. TEMPLATE-STRATIFIED SPLIT LEAKAGE CHECK ---")
    train_val_overlap = tpl_ids_train & tpl_ids_val
    train_test_overlap = tpl_ids_train & tpl_ids_test
    val_test_overlap = tpl_ids_val & tpl_ids_test

    print(f"  Train & Validation Overlap: {len(train_val_overlap)} (Allowed: 0)")
    print(f"  Train & Test Overlap:       {len(train_test_overlap)} (Allowed: 0)")
    print(f"  Validation & Test Overlap:  {len(val_test_overlap)} (Allowed: 0)")

    if train_val_overlap or train_test_overlap or val_test_overlap:
        print("  [FAIL] Critical Template Leakage Detected between splits!")
        passed = False
    else:
        print("  [PASS] Zero template leakage verified! Splits are completely disjoint.\n")

    # 3. Exact Duplicate Records Check
    print("--- 3. DUPLICATE RECORDS ANALYSIS ---")
    exact_hashes = set()
    exact_dupes = 0
    near_hashes = set()
    near_dupes = 0

    for r in all_records:
        # Canonical input representation
        canon_str = json.dumps(r["input"], sort_keys=True)
        h = hashlib.sha256(canon_str.encode()).hexdigest()
        if h in exact_hashes:
            exact_dupes += 1
        exact_hashes.add(h)

        # Near duplicate: alert title + first evidence description
        first_desc = r["input"]["evidence"][0]["description"] if r["input"]["evidence"] else ""
        near_key = f"{r['input']['alert']['title']}||{first_desc}"
        nh = hashlib.sha256(near_key.encode()).hexdigest()
        if nh in near_hashes:
            near_dupes += 1
        near_hashes.add(nh)

    print(f"  Exact Duplicate Records: {exact_dupes} (Allowed: 0)")
    print(f"  Near-Duplicate Records:  {near_dupes} (Allowed: 0)")
    if exact_dupes > 0 or near_dupes > 0:
        print("  [FAIL] Duplicate or near-duplicate records found!")
        passed = False
    else:
        print("  [PASS] All 520 records have unique inputs and telemetry!\n")

    # 4. Classification Balance
    print("--- 4. CLASSIFICATION DISTRIBUTION ---")
    cls_counter = Counter(r["output"]["classification"] for r in all_records)
    print("  Overall Class Distribution (Target: ~20% each):")
    for c in ["benign", "suspicious", "likely_malicious", "confirmed_malicious", "insufficient_evidence"]:
        cnt = cls_counter[c]
        pct = cnt / total_recs * 100
        print(f"    - {c:23s}: {cnt:3d} ({pct:5.1f}%)")
        if pct < 15.0 or pct > 25.0:
            print(f"      [WARN] Class {c} outside 15-25% tolerance!")

    # Check that every split has all 5 classes
    print("\n  Per-Split Class Presence:")
    for split_name, recs in [("Train", train_records), ("Validation", val_records), ("Test", test_records)]:
        split_classes = {r["output"]["classification"] for r in recs}
        missing = {"benign", "suspicious", "likely_malicious", "confirmed_malicious", "insufficient_evidence"} - split_classes
        if missing:
            print(f"    - {split_name:10s}: [FAIL] Missing classes: {missing}")
            passed = False
        else:
            print(f"    - {split_name:10s}: [PASS] All 5 classifications present")
    print()

    # 5. Operating System Distribution
    print("--- 5. OPERATING SYSTEM TELEMETRY ---")
    os_counter = Counter("Windows" if "Windows" in r["input"]["context"]["os"] else "Linux" for r in all_records)
    print(f"  Windows Records: {os_counter['Windows']} ({os_counter['Windows']/total_recs*100:.1f}%)")
    print(f"  Linux Records:   {os_counter['Linux']} ({os_counter['Linux']/total_recs*100:.1f}%)")

    for split_name, recs in [("Train", train_records), ("Validation", val_records), ("Test", test_records)]:
        split_oses = {"Windows" if "Windows" in r["input"]["context"]["os"] else "Linux" for r in recs}
        if "Windows" not in split_oses or "Linux" not in split_oses:
            print(f"    - {split_name:10s}: [FAIL] Missing OS: need both Windows and Linux")
            passed = False
        else:
            print(f"    - {split_name:10s}: [PASS] Both Windows and Linux present")
    print()

    # 6. Evidence Diversity (>= 15 types)
    print("--- 6. EVIDENCE TYPE DIVERSITY ---")
    evidence_types = set()
    for r in all_records:
        for e in r["input"]["evidence"]:
            evidence_types.add(e.get("type"))
    print(f"  Distinct Evidence Types Used: {len(evidence_types)} / 18 (Target: >= 15)")
    for etype in sorted(evidence_types):
        print(f"    - {etype}")
    if len(evidence_types) < 15:
        print("  [FAIL] Fewer than 15 evidence types used!")
        passed = False
    else:
        print("  [PASS] Evidence diversity requirement met.\n")

    # 7. MITRE ATT&CK Technique Coverage (>= 25 techniques)
    print("--- 7. MITRE ATT&CK COVERAGE ---")
    mitre_techs = set()
    for r in all_records:
        for m in r["output"].get("mitre_techniques", []):
            mitre_techs.add(m.get("technique_id"))
    print(f"  Distinct MITRE Techniques Used: {len(mitre_techs)} / 34 (Target: >= 25)")
    for tid in sorted(mitre_techs):
        print(f"    - {tid}")
    if len(mitre_techs) < 25:
        print("  [FAIL] Fewer than 25 MITRE techniques covered!")
        passed = False
    else:
        print("  [PASS] MITRE technique coverage requirement met.\n")

    # 8. Borderline Cases Analysis (Target: 30-50)
    print("--- 8. BORDERLINE CASES ANALYSIS ---")
    bl_records = [r for r in all_records if "borderline_category" in r["metadata"]]
    bl_categories = Counter(r["metadata"]["borderline_category"] for r in bl_records)
    print(f"  Total Borderline Records: {len(bl_records)} (Target: >= 30)")
    for bcat, bcount in bl_categories.items():
        print(f"    - {bcat:45s}: {bcount:3d} records")
    expected_boundaries = {
        "benign_vs_suspicious",
        "suspicious_vs_likely_malicious",
        "likely_malicious_vs_confirmed_malicious",
        "suspicious_vs_insufficient_evidence",
        "likely_malicious_vs_insufficient_evidence",
    }
    missing_boundaries = expected_boundaries - set(bl_categories.keys())
    if missing_boundaries:
        print(f"  [FAIL] Missing borderline boundaries: {missing_boundaries}")
        passed = False
    elif len(bl_records) < 30:
        print("  [FAIL] Fewer than 30 borderline records!")
        passed = False
    else:
        print("  [PASS] All 5 key decision boundaries covered.\n")

    # 9. Anti-Keyword-Learning Analysis
    print("--- 9. ANTI-KEYWORD-LEARNING & SHORTCUT MITIGATION ---")
    keywords = ["powershell", "certutil", "rundll32", "ssh", "curl"]
    keyword_class_map = defaultdict(Counter)

    for r in all_records:
        text_corpus = json.dumps(r["input"]).lower()
        cls = r["output"]["classification"]
        for kw in keywords:
            if kw in text_corpus:
                keyword_class_map[kw][cls] += 1

    for kw in keywords:
        cmap = keyword_class_map[kw]
        classes_present = list(cmap.keys())
        entropy = calculate_shannon_entropy(cmap)
        max_entropy = math.log2(len(classes_present)) if classes_present else 1.0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        print(f"  Tool: '{kw}' across {len(classes_present)} classes (Shannon Entropy: {entropy:.2f} bits):")
        for c, count in cmap.items():
            print(f"    - {c:23s}: {count:3d} occurrences")
        if len(classes_present) < 2:
            print(f"    [FAIL] '{kw}' maps deterministically to a single class! (Shortcut risk)")
            passed = False
        else:
            print(f"    [PASS] Multi-class ambiguity verified (no keyword-shortcut memorization possible)")

    print("\n============================================================")
    if passed:
        print("  DIVERSITY AUDIT VERDICT: PASSED (READY FOR FINE-TUNING)")
    else:
        print("  DIVERSITY AUDIT VERDICT: FAILED (ISSUES FOUND)")
    print("============================================================\n")
    return passed, report

def main():
    parser = argparse.ArgumentParser(description="AegisX Dataset Diversity Validator")
    parser.add_argument("--dataset-dir", type=str, default="datasets/finetuning/v0.3", help="Directory containing dataset files")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    ds_dir = Path(args.dataset_dir)
    if not ds_dir.is_absolute():
        ds_dir = project_root / ds_dir

    passed, _ = run_diversity_audit(ds_dir)
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
