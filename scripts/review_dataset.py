#!/usr/bin/env python3
"""
AegisX Dataset Human Review Tool (v0.2)
========================================

CLI tool for security analysts to inspect, review, approve, or reject
generated synthetic SOC dataset records prior to inclusion in training/eval sets.

Usage:
    python scripts/review_dataset.py datasets/validated/soc_examples_validated.jsonl
    python scripts/review_dataset.py datasets/generated/soc_examples.jsonl --batch-approve-threshold 90
"""

import argparse
import json
import sys
from pathlib import Path

def display_record(record: dict, index: int, total: int):
    inp = record.get("input", {})
    alert = inp.get("alert", {})
    ctx = inp.get("context", {})
    out = record.get("output", {})
    meta = record.get("metadata", {})

    print("\n" + "=" * 70)
    print(f" Record {index}/{total} — ID: {record.get('id')} | Task: {record.get('task')}")
    print("=" * 70)
    print(f" Status:        {meta.get('review_status', 'pending').upper()}")
    print(f" Quality Score: {meta.get('quality_score', 'N/A')}/100")
    print(f" Alert:         {alert.get('title')} (Severity: {alert.get('severity')})")
    print(f" Context:       Host: {ctx.get('hostname')} | User: {ctx.get('username')} | Dept: {ctx.get('department')}")
    print("\n--- EVIDENCE ---")
    for evt in inp.get("evidence", []):
        print(f"  [{evt.get('id')}] ({evt.get('type')}) {evt.get('description')}")

    print("\n--- OUTPUT ANALYSIS ---")
    print(f" Classification: {out.get('classification')} (Confidence: {out.get('confidence')})")
    print(" Findings:")
    for f in out.get("findings", []):
        refs = ", ".join(f.get("evidence_refs", []))
        print(f"   - {f.get('description')} (Refs: {refs})")

    if out.get("mitre_techniques"):
        print(" MITRE ATT&CK:")
        for m in out["mitre_techniques"]:
            print(f"   - [{m.get('technique_id')}] {m.get('technique_name')} ({m.get('tactic')})")

    if out.get("recommended_actions"):
        print(" Recommended Actions:")
        for a in out["recommended_actions"]:
            print(f"   - [{a.get('priority').upper()}] {a.get('action')}")

    if meta.get("reviewer_notes"):
        print(f"\n Reviewer Notes: {meta.get('reviewer_notes')}")
    print("=" * 70)

def review_interactive(records: list[dict], output_path: Path):
    modified = False
    total = len(records)
    i = 0
    while i < total:
        rec = records[i]
        display_record(rec, i + 1, total)

        print("\nAction: [a]pprove, [r]eject, [n]eeds revision, [s]kip, [b]ack, [c]omment, [q]uit")
        choice = input("Select option > ").strip().lower()

        if choice == "a":
            rec["metadata"]["review_status"] = "approved"
            modified = True
            i += 1
        elif choice == "r":
            rec["metadata"]["review_status"] = "rejected"
            modified = True
            i += 1
        elif choice == "n":
            rec["metadata"]["review_status"] = "needs_revision"
            modified = True
            i += 1
        elif choice == "s":
            i += 1
        elif choice == "b":
            i = max(0, i - 1)
        elif choice == "c":
            note = input("Enter reviewer notes > ").strip()
            if note:
                rec["metadata"]["reviewer_notes"] = note
                modified = True
        elif choice == "q":
            break

    if modified:
        with open(output_path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\nSaved updated reviews to {output_path}")

def batch_approve(records: list[dict], threshold: int, output_path: Path):
    approved_count = 0
    for r in records:
        qs = r.get("metadata", {}).get("quality_score", 0)
        if isinstance(qs, int) and qs >= threshold:
            r["metadata"]["review_status"] = "approved"
            approved_count += 1

    with open(output_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Batch approved {approved_count}/{len(records)} records with quality_score >= {threshold}.")
    print(f"Updated dataset saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="AegisX Dataset Human Review Tool v0.2")
    parser.add_argument("file", type=str, help="Path to JSONL dataset file")
    parser.add_argument("--batch-approve-threshold", type=int, default=None, help="Batch approve records with quality_score >= threshold")
    parser.add_argument("--output", type=str, default=None, help="Output file path (defaults to overwrite input)")
    args = parser.parse_args()

    filepath = Path(args.file)
    output_path = Path(args.output) if args.output else filepath

    if not filepath.exists():
        print(f"Error: File not found: {filepath}")
        return 1

    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    print(f"Loaded {len(records)} records from {filepath}")

    if args.batch_approve_threshold is not None:
        batch_approve(records, args.batch_approve_threshold, output_path)
    else:
        review_interactive(records, output_path)

    return 0

if __name__ == "__main__":
    sys.exit(main())
