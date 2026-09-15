# AegisX SOC Fine-Tuning Dataset Card (v1.0)

## 1. Dataset Summary
- **Name**: aegisx-soc-finetuning
- **Version**: 1.0
- **Format**: SFT Chat (`messages` + `metadata` JSONL)
- **Total Records**: 120,358
- **Train**: 96,086 records (164.3 MB)
- **Validation**: 12,156 records (20.8 MB)
- **Test**: 12,116 records (20.7 MB)
- **Synthetic Ratio**: 6.2% synthetic, 93.8% real telemetry
- **Integration Date**: 2026-09-12
- **Verification Date**: 2026-09-14
- **Provenance**: Externally supplied — real Sysmon/Windows security telemetry + curated CTI

## 2. Nature & Origin

This is the **first real-telemetry dataset** in the AegisX fine-tuning pipeline.

Previous versions (v0.3–v0.5) were 100% synthetic, template-generated datasets with 1K–3K records.
Version 1.0 is a 40× scale-up with predominantly real security telemetry.

### Data Sources (from metadata `source` field)
- **Real telemetry (93.8%)**: event_normalization, alert_classification, sigma_detection_qa, sigma_alert_classification, elastic_mitre_mapping, elastic_detection_qa, splunk_investigation_planning, false_positive_analysis, cti_* (malware classification, CVE assessment, ATT&CK, STIX, IOC, APT reports)
- **Synthetic (6.2%)**: synthetic_triage_classification, synthetic_attack_stories, synthetic_threat_hunting, synthetic_response_planning, synthetic_investigation_traces, synthetic_false_positive_reasoning

### Task Types
| Task | Records | % |
|---|---:|---:|
| general_soc_reasoning | 50,484 | 41.9% |
| event_normalization | 50,000 | 41.6% |
| sigma_analysis | 5,751 | 4.8% |
| elastic_analysis | 4,080 | 3.4% |
| cti_qa | 2,862 | 2.4% |
| alert_classification | 2,509 | 2.1% |
| false_positive_analysis | 2,392 | 2.0% |
| splunk_analysis | 2,168 | 1.8% |
| threat_hunting | 496 | 0.4% |
| report_summarization | 216 | 0.2% |

## 3. Schema

Each record is one JSONL line:
```json
{
  "messages": [
    {"role": "system", "content": "<task-specific system prompt>"},
    {"role": "user",   "content": "<security event/alert>"},
    {"role": "assistant", "content": "<model response>"}
  ],
  "metadata": {
    "task": "general_soc_reasoning",
    "family": "alert",
    "source": "alert_classification",
    "group_id": "<hex>",
    "difficulty": "unknown",
    "mitre_techniques": [],
    "canonical_hash": "<sha256>",
    "telemetry_hash": "<sha256>",
    "ua_hash": "<sha256>",
    "is_synthetic": false,
    "split": "train"
  }
}
```

Schema is **100% consistent** across all three splits. Zero missing fields, zero empty content.

## 4. Split Architecture
| Split | Records | Size | Synthetic | Real |
|---|---:|---:|---:|---:|
| Train | 96,086 | 164.3 MB | 5,888 (6.1%) | 90,198 (93.9%) |
| Validation | 12,156 | 20.8 MB | 744 (6.1%) | 11,412 (93.9%) |
| Test | 12,116 | 20.7 MB | 781 (6.4%) | 11,335 (93.6%) |

## 5. Leakage Verification (Zero Leakage Confirmed)

All six hash types checked across all three split pairs:

| Overlap Type | Train↔Val | Train↔Test | Val↔Test |
|---|---:|---:|---:|
| canonical_hash | 0 | 0 | 0 |
| telemetry_hash | 0 | 0 | 0 |
| ua_hash | 0 | 0 | 0 |
| full_record | 0 | 0 | 0 |
| content (messages) | 0 | 0 | 0 |
| group_id | 0 | 0 | 0 |

**Zero leakage verified across all hash types and all split pairs.**

## 6. Intra-Split Duplicate Analysis

| Metric | Train | Validation | Test |
|---|---:|---:|---:|
| Exact full-record dups | 0 | 0 | 0 |
| Canonical hash dups | 0 | 0 | 0 |
| Telemetry hash dups | 6,893 (7.2%) | 1,007 (8.3%) | 966 (8.0%) |
| Unique group_ids | 89,193 | 11,149 | 11,150 |

Note: Telemetry hash duplicates indicate records that share the same underlying telemetry event
but have different canonical representations (different tasks/prompts applied to the same event).
This is expected and desirable for multi-task training.

## 7. Fine-Tuning Compatibility

- Files are **already in SFT chat format** (`messages` array)
- **No SFT conversion needed** — `finetuning/prepare_sft_dataset.py` is NOT required
- Directly consumed by `finetuning/train_lora.py` via `load_dataset("json")`
- `formatting_func` applies `tokenizer.apply_chat_template(example["messages"])`
- Test set consumed read-only by `finetuning/evaluate_model.py`

## 8. Comparison with Previous Versions
| Version | Records | Type | Synthetic | Real | SFT Conversion |
|---|---:|---|---:|---:|---|
| v0.3 | 1,000 | Raw + SFT | 100% | 0% | Required |
| v0.4 | 3,000 | Raw + SFT | 100% | 0% | Required |
| v0.5 | 3,000 | Raw + SFT | 100% | 0% | Required |
| **v1.0** | **120,358** | **SFT only** | **6.2%** | **93.8%** | **Not needed** |

## 9. Cryptographic Hashes
- `train.jsonl`: `40877f2748d889f8009698b4a00bf75343da758588467b6b99c95b9dde902d21`
- `validation.jsonl`: `1fa6d39d8b55fde359767c9f6f728dd7b3da2121056d177f0391f89b0f13b5e6`
- `test.jsonl`: `a625f709cc30db835baf34918f66193b9bf6dffe786b0d4085174c2fcd3a3145`

## 10. Protected Dataset Integrity
- v0.4/test.jsonl: `bff898861f75a0982d6c2f6efdba99f0c5e8549a4b0ea72a687e91a8d80a4333` ✓ Verified intact
- v0.5/test.jsonl: `33389cf3f7f836920e47d45b654d8ec1ba56bb69d191e0ff9bb616e5cdef3aa5` ✓ Verified intact

## 11. Known Limitations
1. **Provenance gaps**: No source record identifier, source label, transformation version, or quality score in metadata
2. **Telemetry hash overlap within splits** (~7-8%): Same underlying events appear with different tasks — expected for multi-task training but may affect task-specific evaluation
3. **External origin**: Exact generation pipeline and curation methodology unknown
