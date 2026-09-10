#!/usr/bin/env python3
"""
Generate a deterministic manifest of 50 validation records (10 per class) for the Phase 3 Controlled Prompt Experiment V2.
"""

import json
import hashlib
from collections import defaultdict

def load_validation_records(filepath):
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            records.append(json.loads(line.strip()))
    return records

def main():
    validation_path = 'datasets/finetuning/v0.4/validation.jsonl'
    records = load_validation_records(validation_path)

    # Group by class
    class_to_records = defaultdict(list)
    for rec in records:
        cls = rec['output']['classification']
        class_to_records[cls].append(rec)

    # For each class, sort by id (deterministic) and take first 10
    selected = []
    class_counts = {}
    for cls in ['benign', 'suspicious', 'likely_malicious', 'confirmed_malicious', 'insufficient_evidence']:
        cls_records = class_to_records.get(cls, [])
        # Sort by id
        cls_records_sorted = sorted(cls_records, key=lambda x: x['id'])
        selected_10 = cls_records_sorted[:10]
        selected.extend(selected_10)
        class_counts[cls] = len(selected_10)
        if len(selected_10) < 10:
            raise ValueError(f"Not enough records for class {cls}: expected 10, got {len(selected_10)}")

    # Sort selected by id for consistent manifest ordering
    selected_sorted = sorted(selected, key=lambda x: x['id'])

    # Build manifest
    manifest = {
        "dataset": validation_path,
        "dataset_version": records[0]['metadata']['dataset_version'] if records else "unknown",
        "selection_method": "sorted by id within class, take first 10",
        "selection_seed": "lexicographic sort on id (no seed)",
        "record_ids": [rec['id'] for rec in selected_sorted],
        "ground_truth": [rec['output']['classification'] for rec in selected_sorted],
        "class_counts": class_counts,
        # We'll compute the hash of the manifest without this field, then add it
    }

    # Compute SHA-256 of the manifest JSON string (without the hash field)
    manifest_json_no_hash = json.dumps(manifest, sort_keys=True, indent=2)
    manifest_hash = hashlib.sha256(manifest_json_no_hash.encode('utf-8')).hexdigest()
    manifest["manifest_hash"] = manifest_hash

    # Write manifest
    output_path = 'reports/phase3/PHASE_3_PROMPT_EXPERIMENT_V2_MANIFEST.json'
    with open(output_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"Manifest written to {output_path}")
    print(f"Total records: {len(selected_sorted)}")
    print(f"Class distribution: {class_counts}")
    print(f"Manifest hash: {manifest_hash}")

    # Verify
    print("\nVerification:")
    print(f"  Dataset version: {manifest['dataset_version']}")
    print(f"  Selection method: {manifest['selection_method']}")
    print(f"  Record IDs count: {len(manifest['record_ids'])}")
    print(f"  Ground truth counts: {defaultdict(int, [(cls, manifest['ground_truth'].count(cls)) for cls in class_counts])}")

if __name__ == '__main__':
    main()