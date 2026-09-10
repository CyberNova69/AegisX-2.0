#!/usr/bin/env python3
"""
Phase 3 Label & Dataset Boundary Audit - Local Analysis
"""

import json
import os
from collections import defaultdict, Counter

def load_jsonl(filepath):
    """Load JSONL file and return list of records."""
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            records.append(json.loads(line.strip()))
    return records

def extract_class_distribution(records):
    """Extract distribution of classifications."""
    distribution = Counter()
    for record in records:
        classification = record['output']['classification']
        distribution[classification] += 1
    return distribution

def get_sample_records(records, classification, limit=10):
    """Get sample records for a given classification."""
    samples = []
    for record in records:
        if record['output']['classification'] == classification:
            samples.append(record)
            if len(samples) >= limit:
                break
    return samples

def analyze_boundary(records, class1, class2, boundary_name):
    """Analyze boundary between two classifications."""
    print(f"\n=== {boundary_name} ===")

    class1_records = get_sample_records(records, class1, 5)
    class2_records = get_sample_records(records, class2, 5)

    print(f"{class1} samples:")
    for i, record in enumerate(class1_records):
        print(f"  {i+1}. ID: {record['id']}")
        print(f"     Alert: {record['input']['alert']['title']}")
        print(f"     Evidence count: {len(record['input']['evidence'])}")
        if 'borderline_category' in record['metadata']:
            print(f"     Borderline: {record['metadata']['borderline_category']}")
        print()

    print(f"{class2} samples:")
    for i, record in enumerate(class2_records):
        print(f"  {i+1}. ID: {record['id']}")
        print(f"     Alert: {record['input']['alert']['title']}")
        print(f"     Evidence count: {len(record['input']['evidence'])}")
        if 'borderline_category' in record['metadata']:
            print(f"     Borderline: {record['metadata']['borderline_category']}")
        print()

def find_similar_records_different_labels(records, limit_pairs=5):
    """Find records with similar alert types but different labels."""
    # Group by template_id or similar alert patterns
    template_groups = defaultdict(list)
    for record in records:
        template_id = record['metadata'].get('template_id', 'unknown')
        template_groups[template_id].append(record)

    similar_diff_label = []
    for template_id, group in template_groups.items():
        if len(group) > 1:
            classifications = [r['output']['classification'] for r in group]
            if len(set(classifications)) > 1:  # Different labels in same template
                similar_diff_label.append((template_id, group))

    print(f"\n=== Similar Alert Templates, Different Labels ===")
    print(f"Found {len(similar_diff_label)} templates with multiple labels")

    for i, (template_id, group) in enumerate(similar_diff_label[:limit_pairs]):
        print(f"\n{i+1}. Template ID: {template_id}")
        for record in group:
            print(f"   - {record['id']}: {record['output']['classification']}")
            print(f"     Alert: {record['input']['alert']['title'][:60]}...")
        print()

def analyze_insufficient_evidence(records):
    """Analyze insufficient_evidence records for missing information."""
    print(f"\n=== Insufficient Evidence Analysis ===")
    insuff_records = get_sample_records(records, 'insufficient_evidence', 10)

    missing_info_indicators = []
    for record in insuff_records:
        rationale = record['output'].get('rationale', '')
        additional_evidence = record['output'].get('additional_evidence_needed', [])

        missing_indicators = []
        if 'missing' in rationale.lower():
            missing_indicators.append('rationale mentions missing')
        if additional_evidence:
            missing_indicators.append(f'additional evidence needed: {len(additional_evidence)} items')
        if 'command line' in rationale.lower():
            missing_indicators.append('missing command line')
        if 'process' in rationale.lower() and ('parent' in rationale.lower() or 'attribution' in rationale.lower()):
            missing_indicators.append('missing process info')
        if 'destination' in rationale.lower() or 'network' in rationale.lower():
            missing_indicators.append('missing network destination')
        if 'context' in rationale.lower():
            missing_indicators.append('missing context')

        if missing_indicators:
            missing_info_indicators.append((record['id'], missing_indicators, rationale[:100]))

    print(f"Insufficient evidence records with explicit missing info indicators: {len(missing_info_indicators)}/{len(insuff_records)}")
    for record_id, indicators, rationale in missing_info_indicators[:5]:
        print(f"  {record_id}: {indicators}")
        print(f"    Rationale: {rationale}")
    print()

def analyze_confirmed_malicious(records):
    """Analyze confirmed_malicious records for explicit outcomes."""
    print(f"\n=== Confirmed Malicious Analysis ===")
    conf_records = get_sample_records(records, 'confirmed_malicious', 10)

    outcome_indicators = []
    for record in conf_records:
        findings = record['output'].get('findings', [])
        rationale = record['output'].get('rationale', '')

        has_outcome = False
        outcome_evidence = []

        # Check for explicit outcomes in findings
        for finding in findings:
            desc = finding.get('description', '').lower()
            if any(word in desc for word in ['observed', 'confirmed', 'established', 'successful', 'achieved', 'delivered', 'installed', 'created', 'modified', 'deleted', 'stolen', 'exfiltrated']):
                has_outcome = True
                outcome_evidence.append(desc[:50])

        # Check rationale
        if any(word in rationale.lower() for word in ['confirmed', 'observed', 'successful', 'achieved', 'delivered']):
            has_outcome = True
            outcome_evidence.append(rationale[:50])

        if has_outcome:
            outcome_indicators.append((record['id'], outcome_evidence[:2]))

    print(f"Confirmed malicious records with explicit outcome indicators: {len(outcome_indicators)}/{len(conf_records)}")
    for record_id, evidence in outcome_indicators[:5]:
        print(f"  {record_id}: {evidence}")
    print()

def analyze_controlled_experiment_errors():
    """Analyze the controlled baseline results for errors."""
    print(f"\n=== Controlled Experiment Error Analysis ===")
    try:
        with open('reports/phase3/controlled_baseline_results.json', 'r') as f:
            results = json.load(f)

        errors = [r for r in results if r['predicted'] is None]
        print(f"Total records: {len(results)}")
        print(f"Errors (failed predictions): {len(errors)}")
        print(f"Success rate: {(len(results)-len(errors))/len(results)*100:.1f}%")

        # Load validation records to get ground truth
        val_records = load_jsonl('datasets/finetuning/v0.4/validation.jsonl')
        val_dict = {r['id']: r for r in val_records}

        print("\nError details:")
        for error in errors:
            record_id = error['record_id']
            if record_id in val_dict:
                record = val_dict[record_id]
                gt = record['output']['classification']
                print(f"  {record_id}: GT={gt}, Predicted={error['predicted']}")
                print(f"    Alert: {record['input']['alert']['title']}")
                print(f"    Evidence: {len(record['input']['evidence'])} items")
                if 'borderline_category' in record['metadata']:
                    print(f"    Borderline: {record['metadata']['borderline_category']}")
            else:
                print(f"  {record_id}: Not found in validation set")
            print()

    except Exception as e:
        print(f"Error loading controlled baseline results: {e}")

def main():
    print("Starting Phase 3 Label & Dataset Boundary Audit...")

    # Load datasets
    print("Loading datasets...")
    train_records = load_jsonl('datasets/finetuning/v0.4/train.jsonl')
    val_records = load_jsonl('datasets/finetuning/v0.4/validation.jsonl')
    test_records = load_jsonl('datasets/finetuning/v0.4/test.jsonl')

    print(f"Train records: {len(train_records)}")
    print(f"Validation records: {len(val_records)}")
    print(f"Test records: {len(test_records)}")

    # Class distributions
    print("\n=== CLASS DISTRIBUTIONS ===")
    print("Train:", dict(extract_class_distribution(train_records)))
    print("Validation:", dict(extract_class_distribution(val_records)))
    print("Test:", dict(extract_class_distribution(test_records)))

    # Analyze each boundary using validation set (balanced)
    analyze_boundary(val_records, 'benign', 'suspicious', 'Boundary 1: benign <-> suspicious')
    analyze_boundary(val_records, 'suspicious', 'likely_malicious', 'Boundary 2: suspicious <-> likely_malicious')
    analyze_boundary(val_records, 'likely_malicious', 'confirmed_malicious', 'Boundary 3: likely_malicious <-> confirmed_malicious')
    analyze_boundary(val_records, 'suspicious', 'insufficient_evidence', 'Boundary 4: suspicious <-> insufficient_evidence')
    analyze_boundary(val_records, 'benign', 'insufficient_evidence', 'Boundary 5: benign <-> insufficient_evidence')

    # Specialized analyses
    analyze_insufficient_evidence(val_records)
    analyze_confirmed_malicious(val_records)
    find_similar_records_different_labels(val_records)
    analyze_controlled_experiment_errors()

    print("\nAnalysis complete.")

if __name__ == '__main__':
    main()