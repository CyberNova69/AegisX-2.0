# AegisX SOC Fine-Tuning Dataset Card (v0.3)

## Dataset Summary
- **Name**: aegisx-soc-finetuning
- **Version**: 0.3
- **Total Records**: 520
- **Template Families**: 85
- **Generator**: `scripts/generate_dataset_v03.py` (seed 42)
- **Creation Date**: 2026-09-03
- **Quality Score Average**: 90.0 / 100

## Split Architecture (Template-Stratified)
| Split | Records | Templates | Description |
|---|---|---|---|
| **Train** | 416 | 68 (80.0%) | Supervised training set |
| **Validation** | 54 | 9 (10.6%) | Validation checkpoint evaluation |
| **Test** | 50 | 8 (9.4%) | Held-out unseen template generalization benchmark |

> [!IMPORTANT]
> **Zero Template Leakage Guarantee**: No template family in Train appears in Validation or Test.

## Classification Distribution
- `benign`: 105 (20.2%)
- `suspicious`: 105 (20.2%)
- `likely_malicious`: 103 (19.8%)
- `confirmed_malicious`: 104 (20.0%)
- `insufficient_evidence`: 103 (19.8%)

## Borderline Cases
- Deliberate borderline records: 257
- Spans all 5 key decision boundaries (benign ↔ suspicious, suspicious ↔ likely_malicious, likely_malicious ↔ confirmed_malicious, suspicious ↔ insufficient_evidence, likely_malicious ↔ insufficient_evidence).

## Operating Systems
- Windows: 430 records (82.7%)
- Linux: 90 records (17.3%)
