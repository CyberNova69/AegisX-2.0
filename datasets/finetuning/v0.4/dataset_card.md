# AegisX SOC Fine-Tuning Dataset Card (v0.4)

## Dataset Summary
- **Name**: aegisx-soc-finetuning
- **Version**: 0.4
- **Total Records**: 3,000
- **Template Families**: 150 (150 distinct scenarios across 18 domains)
- **Generator**: `scripts/generate_dataset_v04.py` (seed 42)
- **Creation Date**: 2026-09-03
- **Quality Score Average**: 90.0 / 100

## Split Architecture (Template-Stratified)
| Split | Records | Templates | Description |
|---|---|---|---|
| **Train** | 2,400 (80.0%) | 120 (80.0%) | Supervised fine-tuning training set (24 per class) |
| **Validation** | 300 (10.0%) | 15 (10.0%) | Evaluation checkpoint evaluation (3 per class) |
| **Test** | 300 (10.0%) | 15 (10.0%) | Held-out unseen template generalization benchmark (3 per class) |

> [!IMPORTANT]
> **Zero Template Leakage Guarantee**: No template family in Train appears in Validation or Test.
> $\text{Templates}(\text{Train}) \cap \text{Templates}(\text{Val}) = \emptyset$, $\text{Templates}(\text{Train}) \cap \text{Templates}(\text{Test}) = \emptyset$, $\text{Templates}(\text{Val}) \cap \text{Templates}(\text{Test}) = \emptyset$.

## Classification Distribution (Perfect 20.0% Balance)
- `benign`: 600 (20.0%)
- `suspicious`: 600 (20.0%)
- `likely_malicious`: 600 (20.0%)
- `confirmed_malicious`: 600 (20.0%)
- `insufficient_evidence`: 600 (20.0%)

## Borderline Cases
- Deliberate borderline records: 1,760 (58.7%)
- Across 88 borderline template families spanning all 5 key decision boundaries:
  1. `benign_vs_suspicious`
  2. `suspicious_vs_likely_malicious`
  3. `likely_malicious_vs_confirmed_malicious`
  4. `suspicious_vs_insufficient_evidence`
  5. `likely_malicious_vs_insufficient_evidence`

## Operating Systems
- Windows: 2,100 records (70.0%)
- Linux: 900 records (30.0%)

## Anti-Keyword Learning
Common administrative tools (`powershell`, `cmd`, `sudo`, `ssh`, `curl`, `wmi`, `certutil`, `rundll32`, `scheduled_task`) appear across multiple classes to prevent shortcut heuristics during SFT.
