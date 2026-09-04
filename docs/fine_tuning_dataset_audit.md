# AegisX Fine-Tuning Dataset Audit Report

**Date**: 2026-09-03  
**Auditor**: AI/ML Engineer (Member 2)  
**Dataset Version**: 0.2  
**Schema Version**: draft-07 (JSON Schema)  
**Purpose**: Determine readiness of current dataset for supervised LoRA/QLoRA fine-tuning  
**Methodology**: Automated quantitative analysis of all dataset files + manual code review of generator, validator, and review scripts  
**Status**: All statistics independently verified against live `datasets/` files on 2026-09-03  

---

## Table of Contents

1. [Current Dataset Inventory](#1-current-dataset-inventory)
2. [Record Schema](#2-record-schema-v02)
3. [Classification Labels](#3-classification-labels)
4. [Alert Severity Labels](#4-alert-severity-labels)
5. [Evidence Fields](#5-evidence-fields)
6. [MITRE ATT&CK Coverage](#6-mitre-attck-coverage)
7. [OS / Endpoint / Context Fields](#7-os--endpoint--context-fields)
8. [Suitability for Supervised Fine-Tuning](#8-suitability-for-supervised-fine-tuning)
9. [Class Distribution Analysis](#9-class-distribution-analysis)
10. [Duplicate and Near-Duplicate Risks](#10-duplicate-and-near-duplicate-risks)
11. [Train/Test Leakage Risks](#11-traintest-leakage-risks)
12. [Current Dataset Suitability Assessment](#12-current-dataset-suitability-assessment)
13. [Additional Examples Required](#13-additional-examples-required)
14. [Recommended Target Dataset Size](#14-recommended-target-dataset-size)
15. [Recommended Train/Validation/Test Split](#15-recommended-trainvalidationtest-split)
16. [Existing Records: Evaluation-Only Recommendation](#16-existing-records-evaluation-only-recommendation)
17. [Verdict](#verdict)

---

## 1. Current Dataset Inventory

### 1.1 Dataset Files Discovered

| Location | File | Records | Size (bytes) | Status |
|---|---|---|---|---|
| `datasets/generated/` | `soc_examples.jsonl` | 100 | 229,317 | Generated (seed=42) |
| `datasets/validated/` | `soc_examples_validated.jsonl` | 100 | 229,317 | Validated (identical) |
| `datasets/validated/` | `soc_examples_rejected.jsonl` | 0 | 0 | Empty (zero rejections) |
| `datasets/raw/` | `.gitkeep` only | 0 | — | Empty |
| `datasets/reviewed/` | `.gitkeep` only | 0 | — | Empty |
| `datasets/train/` | `.gitkeep` only | 0 | — | Empty |
| `datasets/validation/` | `.gitkeep` only | 0 | — | Empty |
| `datasets/test/` | `.gitkeep` only | 0 | — | Empty |

> [!IMPORTANT]
> The `generated/` and `validated/` datasets are **byte-identical** (229,317 bytes each). Zero records were rejected by validation. No train/val/test split has been created. No human-reviewed records exist. The training module (`ai/training/`) contains empty scaffolding files only (`config.yaml`, `dataset_loader.py`, `preprocessing.py`, `train.py` — all 0 bytes).

### 1.2 Metadata Files

| File | Purpose |
|---|---|
| `schema.json` | JSON Schema draft-07 (346 lines, comprehensive with additionalProperties: false) |
| `mitre_reference.json` | 34 MITRE ATT&CK technique definitions across 10 tactics |
| `generation_config.yaml` | Target distributions for task, classification, severity, evidence, confidence |
| `dataset_card.md` | ML dataset card (v0.1 noted, actual data is v0.2) |

### 1.3 Configuration Files

| File | Purpose |
|---|---|
| `configs/dataset.yaml` | Dataset paths, generation defaults, validation settings, lifecycle |
| `configs/model.yaml` | Model config (currently `mock` provider, `mock-soc-analyst-v1`) |

### 1.4 Pipeline Scripts

| Script | Purpose | Lines |
|---|---|---|
| `generate_dataset.py` | Template-based synthetic generator with quality scoring | 957 |
| `validate_dataset.py` | Structural + semantic validator with output splitting | 457 |
| `review_dataset.py` | Interactive human review CLI + batch approve | 145 |

---

## 2. Record Schema (v0.2)

Each record contains **5 required top-level fields** (`id`, `task`, `input`, `output`, `metadata`). Schema enforces `additionalProperties: false` at the top level.

```
{
  "id":       "SOC-XXXXXX",                    // Pattern: ^SOC-[0-9]{6}$
  "task":     "alert_triage",                   // 7 enum values
  "input": {
    "alert":    {                                // Required: title, severity, source
      "title": "...",                            //   minLength: 1
      "severity": "low"|"medium"|"high"|...,     //   5 enum values
      "source": "EDR"|"SIEM"|...,                //   free string, minLength: 1
      "timestamp": "ISO 8601",                   //   optional
      "rule_name": "...",                         //   optional
      "rule_id": "..."                            //   optional
    },
    "context":  {                                // All fields optional
      "hostname": "...",
      "username": "...",
      "ip_address": "...",
      "department": "...",
      "asset_criticality": "low"|"medium"|"high"|"critical",
      "environment": "production"|"staging"|"development"|"corporate"|"dmz",
      "os": "...",
      "previous_incidents": 0+
    },
    "evidence": [                                // Required, minItems: 1
      {
        "id": "EVT-XXX",                         // Pattern: ^EVT-[0-9]{3,6}$
        "type": "process_creation"|...,           // 18 enum values
        "description": "...",                     // minLength: 1
        "timestamp": "ISO 8601",                  // optional
        "raw_data": { ... }                       // optional, free-form object
      }
    ]
  },
  "output": {
    "classification":           "benign"|"suspicious"|"likely_malicious"|"confirmed_malicious"|"insufficient_evidence",
    "confidence":               0.0 - 1.0,
    "findings":                 [ { "description", "evidence_refs" (required), "severity" (optional) } ],
    "rationale":                "...",                                          // optional
    "mitre_techniques":         [ { "technique_id", "technique_name", "tactic", "evidence_refs" } ],  // optional
    "recommended_actions":      [ { "action", "priority", "rationale" } ],     // optional
    "investigation_steps":      [ { "step", "purpose", "data_sources" } ],     // optional
    "summary":                  "...",                                          // optional
    "additional_evidence_needed": [ "..." ]                                    // optional
  },
  "metadata": {
    "source":          "synthetic",              // Enum: ["synthetic"] only
    "generator":       "aegisx-template-generator",
    "review_status":   "pending"|"approved"|"rejected"|"needs_revision",
    "dataset_version": "0.2",
    "quality_score":   0-100,                    // optional
    "reviewer_notes":  "...",                    // optional
    "created_at":      "ISO 8601",               // optional
    "tags":            ["task_type", "classification"]  // optional
  }
}
```

> [!TIP]
> The schema is well-designed for fine-tuning. The `input` to `output` structure maps directly to a supervised training pair (prompt to completion). The `metadata` fields provide filtering and stratification capabilities.

---

## 3. Classification Labels

**5 classification labels** defined in schema. All 5 are present in the dataset.

| Classification | Count | Actual % | Target % (generation_config) | Delta |
|---|---|---|---|---|
| `likely_malicious` | 38 | **38.0%** | 20% | **+18.0** |
| `suspicious` | 27 | 27.0% | 25% | +2.0 |
| `confirmed_malicious` | 14 | 14.0% | 20% | -6.0 |
| `insufficient_evidence` | 12 | 12.0% | 15% | -3.0 |
| `benign` | 9 | **9.0%** | **20%** | **-11.0** |

> [!WARNING]
> **Severe class imbalance**: `benign` is critically underrepresented at 9% (target: 20%). `likely_malicious` is overrepresented at 38% (target: 20%). This imbalance is **structural** — it is caused by the template-to-task binding in the generator:
>
> - `incident_summarization` (10 records) maps to 100% `likely_malicious`
> - `response_recommendation` (10 records) maps to 100% `confirmed_malicious`
> - `evidence_analysis` maps to 33% `benign`, 67% `likely_malicious`
>
> The classification distribution **cannot be controlled independently** from the task distribution without adding new templates.

### Classification x Task Cross-Tab (Verified)

| Task | benign | suspicious | likely_mal | confirmed_mal | insuff_evid |
|---|---|---|---|---|---|
| alert_triage | 4 | 2 | 5 | 4 | 5 |
| investigation_planning | 0 | 13 | 0 | 0 | 7 |
| evidence_analysis | 5 | 0 | 10 | 0 | 0 |
| mitre_mapping | 0 | 8 | 7 | 0 | 0 |
| incident_summarization | 0 | 0 | **10** | 0 | 0 |
| threat_intelligence | 0 | 4 | 6 | 0 | 0 |
| response_recommendation | 0 | 0 | 0 | **10** | 0 |

> [!CAUTION]
> **5 of 7 task types produce only 1-2 classification labels.** Only `alert_triage` produces all 5 classification outcomes. A model trained on this data would learn that task type alone predicts classification — a spurious shortcut.

---

## 4. Alert Severity Labels

**5 severity levels** defined in schema. Only **3 of 5** are present in the dataset.

| Severity | Count | Actual % | Target % (generation_config) |
|---|---|---|---|
| `high` | 59 | **59.0%** | 25% |
| `medium` | 27 | 27.0% | 30% |
| `low` | 14 | 14.0% | 20% |
| `informational` | 0 | **0.0%** | **10%** |
| `critical` | 0 | **0.0%** | **15%** |

> [!CAUTION]
> **Two severity levels are completely absent**: `informational` and `critical`. No template in the generator produces these severities, despite being valid in the schema and having non-zero target weights in `generation_config.yaml`. A fine-tuned model would never learn to handle informational-severity policy alerts or critical-severity active breach scenarios.

---

## 5. Evidence Fields

### 5.1 Evidence Types Used (11 of 18 possible)

| Type | Count | | Type | Count |
|---|---|---|---|---|
| `process_creation` | 77 | | `threat_intel_match` | 10 |
| `authentication` | 36 | | `service_creation` | 5 |
| `network_connection` | 30 | | `registry_modification` | 5 |
| `file_modification` | 22 | | | |
| `dns_query` | 16 | | | |
| `email` | 14 | | | |
| `proxy_log` | 10 | | | |
| `user_report` | 10 | | | |

### 5.2 Evidence Types Never Used (7 of 18)

| Unused Evidence Type | Impact on Fine-Tuning |
|---|---|
| `firewall_log` | No learning on perimeter defense events |
| `scheduled_task` | Missing persistence mechanism evidence |
| `wmi_activity` | Missing living-off-the-land technique evidence |
| `powershell_log` | Distinct from `process_creation` — script block logging absent |
| `sysmon_event` | Missing Sysmon-specific telemetry reasoning |
| `vulnerability_scan` | No vulnerability assessment context training |
| `other` | No catch-all evidence type training |

### 5.3 Evidence Items Per Record

| Count | Records | Percentage |
|---|---|---|
| 1 item | 12 | 12% |
| 2 items | 45 | 45% |
| 3 items | 39 | 39% |
| 4 items | 4 | 4% |
| 5+ items | **0** | **0%** |

**Average**: 2.35 items/record  
**Config max**: 8 items/record (never reached)

> [!NOTE]
> No template produces more than 4 evidence items. For fine-tuning, complex multi-evidence scenarios (5-8 items) are essential to teach the model to correlate across many signals and weigh conflicting evidence.

---

## 6. MITRE ATT&CK Coverage

### 6.1 Records with MITRE Mappings

- **40 of 100** records contain `mitre_techniques` arrays
- **60 of 100** records have **no** MITRE mappings at all

### 6.2 Techniques Used (11 of 34 in reference)

| Technique ID | Name | Count | Tactic |
|---|---|---|---|
| T1071.001 | Web Protocols | 14 | Command and Control |
| T1204.002 | Malicious File | 10 | Execution |
| T1082 | System Information Discovery | 8 | Discovery |
| T1087.002 | Domain Account Discovery | 8 | Discovery |
| T1110.003 | Password Spraying | 7 | Credential Access |
| T1078.002 | Domain Accounts | 7 | Defense Evasion |
| T1071.004 | DNS | 6 | Command and Control |
| T1569.002 | Service Execution | 5 | Execution |
| T1021.002 | SMB/Windows Admin Shares | 5 | Lateral Movement |
| T1566.001 | Spearphishing Attachment | 4 | Initial Access |
| T1059.001 | PowerShell | 4 | Execution |

### 6.3 Tactics Coverage

| Tactic | Techniques Used / Available | Record Occurrences |
|---|---|---|
| Execution | 3 / 6 | 19 |
| Command and Control | 2 / 3 | 20 |
| Discovery | 2 / 4 | 16 |
| Credential Access | 1 / 4 | 7 |
| Defense Evasion | 1 / 6 | 7 |
| Lateral Movement | 1 / 2 | 5 |
| Initial Access | 1 / 2 | 4 |
| **Persistence** | **0 / 3** | **0** |
| **Impact** | **0 / 2** | **0** |
| **Exfiltration** | **0 / 2** | **0** |

### 6.4 Unused MITRE Techniques (23 of 34)

| Technique ID | Name | Tactic |
|---|---|---|
| T1059.003 | Windows Command Shell | Execution |
| T1059.005 | Visual Basic | Execution |
| T1059.006 | Python | Execution |
| T1566.002 | Spearphishing Link | Initial Access |
| T1078 | Valid Accounts | Defense Evasion |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1027.010 | Command Obfuscation | Defense Evasion |
| T1036.005 | Match Legitimate Name or Location | Defense Evasion |
| T1055 | Process Injection | Defense Evasion |
| T1053.005 | Scheduled Task | Persistence |
| T1547.001 | Registry Run Keys | Persistence |
| T1543.003 | Windows Service | Persistence |
| T1003.001 | LSASS Memory | Credential Access |
| T1003.003 | NTDS | Credential Access |
| T1110.001 | Password Guessing | Credential Access |
| T1018 | Remote System Discovery | Discovery |
| T1046 | Network Service Discovery | Discovery |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1486 | Data Encrypted for Impact | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration |

> [!WARNING]
> **23 MITRE techniques are defined in `mitre_reference.json` but never appear in any dataset record.** Persistence, Impact, and Exfiltration tactics have **zero** representation. Only 40% of records contain MITRE mappings at all.

---

## 7. OS / Endpoint / Context Fields

### 7.1 OS Distribution

| OS | Count | Percentage |
|---|---|---|
| Windows Server 2022 | 37 | 37% |
| Windows 11 Enterprise | 32 | 32% |
| Windows 10 Enterprise | 31 | 31% |
| **Linux (Ubuntu 22.04 / RHEL 8)** | **0** | **0%** |

> [!NOTE]
> Despite Linux hostnames existing in the generator's value pools (`SRV-WEB-01`, `DMZ-WEB-01`, `DEV-LNX-001`, etc.) and Linux OS choices (`Ubuntu 22.04 LTS`, `RHEL 8`), **no template actually generates Linux-context records**. All 100 records are Windows-only. The generator's `create_context()` method supports Linux, but every template calls it with `os_family="Windows"`.

### 7.2 Environment Distribution

| Environment | Count | % |
|---|---|---|
| staging | 29 | 29% |
| corporate | 29 | 29% |
| development | 27 | 27% |
| production | 15 | 15% |
| **dmz** | **0** | **0%** |

> [!NOTE]
> `dmz` is a valid schema value and exists in the generator's enum but is never generated because `create_context()` selects randomly from `["production", "staging", "corporate", "development"]` — `dmz` is omitted from that randomization list.

### 7.3 Asset Criticality (Approximately Uniform)

| Criticality | Count |
|---|---|
| high | 28 |
| critical | 27 |
| low | 23 |
| medium | 22 |

### 7.4 Confidence Ranges Per Classification (Verified)

| Classification | Min | Max | Average | Config Range |
|---|---|---|---|---|
| benign | 0.76 | 0.93 | 0.83 | [0.75, 0.95] PASS |
| suspicious | 0.42 | 0.69 | 0.55 | [0.40, 0.70] PASS |
| likely_malicious | 0.65 | 0.87 | 0.77 | [0.65, 0.88] PASS |
| confirmed_malicious | 0.88 | 0.98 | 0.93 | [0.88, 0.99] PASS |
| insufficient_evidence | 0.18 | 0.43 | 0.32 | [0.15, 0.45] PASS |

All confidence scores fall within their configured ranges. **PASS**.

### 7.5 Quality Scores

| Score | Records |
|---|---|
| 85 | 12 |
| 90 | 88 |

**Average**: 89.4/100. **Min**: 85, **Max**: 90.  
The 12 records scoring 85 are single-evidence `insufficient_evidence` records (5 pts deducted for evidence richness: only 1 evidence item gives 5/10 instead of 10/10).

---

## 8. Suitability for Supervised Fine-Tuning

### 8.1 What the Dataset Contains (Strengths)

| Criterion | Status | Notes |
|---|---|---|
| Structured input/output pairs | PASS | `input` maps to `output` — direct prompt/completion pair |
| Evidence-grounded findings | PASS | All findings reference valid EVT-IDs present in input |
| Confidence calibration | PASS | Ranges are coherent per classification (verified) |
| MITRE ATT&CK labels | PARTIAL | Only 40/100 records, 11/34 techniques |
| Actionable recommendations | PASS | Present in all records |
| Quality scores | PASS | All 85-90/100, zero rejections |
| Schema validation | PASS | 100/100 pass structural + semantic validation |
| Deterministic generation | PASS | Seeded random produces reproducible results |
| Unique IDs | PASS | 100 unique SOC-IDs, 100 unique input hashes |
| Temporal consistency | PASS | Evidence timestamps chronologically ordered |

### 8.2 What the Dataset Lacks for Fine-Tuning (Critical Gaps)

| Gap | Impact | Severity |
|---|---|---|
| Only **100 records** | Far below minimum viable fine-tuning size (500+) | CRITICAL |
| Only **16 unique scenario templates** | Model will memorize templates, not learn reasoning | CRITICAL |
| **Severe class imbalance** (benign = 9%) | Model will under-predict benign, high false positive rate | CRITICAL |
| **No `informational` or `critical` severity** | Model will not learn full severity spectrum | HIGH |
| **7 evidence types never used** | Model will not handle firewall/sysmon/WMI/scheduled_task evidence | HIGH |
| **No Linux endpoint records** | Model will only learn Windows-context reasoning | HIGH |
| **No borderline/ambiguous cases** | Model will not learn nuanced decision boundaries | CRITICAL |
| **All review_status = "pending"** | No human-verified ground truth | MEDIUM |
| **No train/val/test split** | Cannot evaluate generalization | MEDIUM |
| **3 tactics with zero coverage** | Persistence/Impact/Exfiltration blind spots | HIGH |
| **60% of records lack MITRE mappings** | Incomplete technique attribution training | MEDIUM |
| **Max 4 evidence items** (config allows 8) | No complex multi-signal correlation training | MEDIUM |
| **Training module is empty scaffolding** | No data loader, preprocessor, or training script implemented | MEDIUM |

---

## 9. Class Distribution Analysis

### 9.1 Current vs. Required for Balanced Fine-Tuning

| Classification | Current (100) | Current % | Target (500) | Target % | Additional Needed |
|---|---|---|---|---|---|
| benign | 9 | 9.0% | 100 | 20.0% | ~91 |
| suspicious | 27 | 27.0% | 125 | 25.0% | ~98 |
| likely_malicious | 38 | 38.0% | 100 | 20.0% | ~62 |
| confirmed_malicious | 14 | 14.0% | 100 | 20.0% | ~86 |
| insufficient_evidence | 12 | 12.0% | 75 | 15.0% | ~63 |
| **TOTAL** | **100** | | **500** | | **~400** |

### 9.2 Subtlety Gap: Missing Boundary Cases

The current dataset has **zero** examples at the boundaries between adjacent classifications:

| Boundary | Current Examples | Description |
|---|---|---|
| benign <-> suspicious | 0 | E.g., admin PowerShell that is slightly unusual but authorized |
| suspicious <-> likely_malicious | 0 | E.g., tool use with one corroborating indicator |
| likely_malicious <-> confirmed_malicious | 0 | E.g., strong indicators but missing definitive proof |
| suspicious <-> insufficient_evidence | 0 | E.g., anomalous activity with incomplete telemetry |

These boundary cases are **essential** for fine-tuning a model to produce calibrated outputs rather than binary decisions.

---

## 10. Duplicate and Near-Duplicate Risks

### 10.1 Exact Duplicates

- **0 exact duplicate input hashes** across 100 records (PASS)
- The seeded random generator produces unique context values (hostname, IP, timestamps, hashes) per record
- All 100 SOC-IDs are unique

### 10.2 Near-Duplicates (Same Template Pattern)

> [!CAUTION]
> **100% of records are near-duplicates by template structure.** There are only **16 unique alert titles** across 100 records. Every record with the same title follows the identical narrative structure, differing only in randomly selected hostnames, usernames, IPs, timestamps, and hashes.

| Alert Title (Template) | Count | Classification | Notes |
|---|---|---|---|
| Internal Network Reconnaissance Detected | 11 | All `suspicious` | Identical narrative x11 |
| Service Account Interactive Authentication | 10 | All `confirmed_malicious` | Identical narrative x10 |
| Execution of Unsigned DLL via Rundll32 | 10 | All `likely_malicious` | Identical narrative x10 |
| Executive Impersonation Email Attack | 10 | All `likely_malicious` | Identical narrative x10 |
| Command Line Reconnaissance Utility Sequence | 8 | All `suspicious` | Identical narrative x8 |
| Password Spray Attack Detected | 7 | All `likely_malicious` | Identical narrative x7 |
| High Volume File Modifications | 7 | All `insufficient_evidence` | Identical narrative x7 |
| High Frequency DGA DNS Lookups | 6 | All `likely_malicious` | Identical narrative x6 |
| Remote Service Execution via PsExec | 5 | All `likely_malicious` | Identical narrative x5 |
| Unusual Process Execution: certutil.exe | 5 | All `insufficient_evidence` | Identical narrative x5 |
| Registry Persistence Key Created | 5 | All `benign` | Identical narrative x5 |
| WINWORD spawning PowerShell with Encoded Command | 4 | All `confirmed_malicious` | Identical narrative x4 |
| PowerShell execution by Admin | 4 | All `benign` | Identical narrative x4 |
| Threat Intel Match: HackTool Hash | 4 | All `suspicious` | Identical narrative x4 |
| Domain Account Lockout Burst | 2 | All `suspicious` | Identical narrative x2 |
| Multiple Failed Logins Followed by Success | 2 | All `suspicious` | Identical narrative x2 |

**A model fine-tuned on this dataset would learn to classify by alert title keyword matching, not by evidence reasoning.**

### 10.3 Template to Classification Determinism

Every template deterministically maps to **exactly one** classification. This means:
- Alert title alone is a perfect predictor of classification
- The model learns **no** conditional reasoning based on evidence
- Template diversity, not record count, is the true dataset size

**Effective unique training examples**: **16** (not 100)

---

## 11. Train/Test Leakage Risks

> [!CAUTION]
> **HIGH LEAKAGE RISK if naive random splitting is used.**
>
> Because records with the same alert title share identical narrative structure and always produce the same classification, any random 80/20 split will place near-identical records in both train and test sets. The model would achieve artificially high test accuracy by memorizing template patterns rather than learning security reasoning.

### Leakage Mitigation Requirements

1. **Split by template (alert title), not by record** — all instances of a given template must go entirely into train OR test, never both
2. With only 16 templates, a template-level split is **not viable** for the current dataset — you need at least ~5 templates per split x 3 splits = 15 templates minimum, leaving no margin
3. **The current 100 records should NOT be split at all** — they should be reserved as an evaluation-only set (see Section 16)

---

## 12. Current Dataset Suitability Assessment

| Criterion | Verdict | Detail |
|---|---|---|
| Schema quality | Excellent | Well-structured, comprehensive, evidence-grounded |
| Record quality | High | 85-90/100 quality scores, zero validation errors |
| Confidence calibration | Excellent | All within configured ranges |
| Volume | Insufficient | 100 records is 5-10x below minimum |
| Diversity | Critically low | 16 templates, each repeating 2-11 times |
| Class balance | Skewed | benign 9% (target 20%), likely_malicious 38% (target 20%) |
| Severity coverage | Incomplete | 2 of 5 levels absent (informational, critical) |
| Evidence type coverage | Incomplete | 7 of 18 types unused |
| MITRE coverage | Partial | 23 of 34 techniques unused, 3 tactics empty |
| OS coverage | Windows-only | No Linux records despite generator support |
| DMZ environment | Absent | Valid schema value, never generated |
| Human review | None | All 100 records are `review_status: "pending"` |
| Train/val/test split | None | Directories exist but are empty |
| Borderline cases | None | Zero examples at classification boundaries |
| Training module | Scaffolding only | `ai/training/` files are all empty (0 bytes) |

---

## 13. Additional Examples Required

### 13.1 New Templates Needed (Priority Order)

| Priority | Category | Templates | Examples | Why |
|---|---|---|---|---|
| **P0** | Benign PowerShell (SCCM, GPO, patching, maintenance, WSUS) | 5-8 | 15-20 | benign at 9% — model must learn legitimate admin PowerShell |
| **P0** | Legitimate admin activity (RDP to servers, service restarts, AD queries, group policy, backup) | 5-8 | 15-20 | Reduces false positives on standard IT operations |
| **P0** | Borderline suspicious to benign (user password typo then success, IT tool in wrong context) | 4-6 | 10-15 | Critical for calibrated decision boundaries |
| **P0** | Borderline suspicious to likely_malicious (suspicious + one corroborating indicator) | 4-6 | 10-15 | Key triage decision boundary |
| **P0** | Borderline likely_malicious to confirmed_malicious (strong indicators, missing definitive proof) | 3-5 | 8-12 | Teaches confidence calibration |
| **P1** | Ransomware scenarios (T1486, T1490 — encryption, shadow copy deletion) | 4-6 | 10-15 | Impact tactic completely missing |
| **P1** | Data exfiltration (T1048, T1567 — cloud upload, unencrypted exfil) | 4-6 | 10-15 | Exfiltration tactic completely missing |
| **P1** | Persistence mechanisms (T1053 scheduled task, T1547 run key, T1543 service) | 4-6 | 10-15 | Persistence tactic completely missing |
| **P1** | Linux-specific scenarios (cron persistence, SSH brute force, web shell, rootkit) | 5-8 | 10-15 | Cross-platform reasoning |
| **P2** | Informational severity (routine vulnerability scan, policy compliance check) | 3-5 | 8-10 | Missing severity level |
| **P2** | Critical severity (active breach, ransomware deployment, DC compromise) | 3-5 | 8-10 | Missing severity level |
| **P2** | Complex multi-evidence scenarios (5-8 evidence items, mixed signal types) | 4-6 | 10-15 | Teaches deep evidence correlation |
| **P2** | Firewall/WMI/Sysmon/Scheduled Task evidence types | 4-6 | 10-15 | Fills 7 unused evidence types |
| **P2** | DMZ environment scenarios (web server compromise, public-facing service) | 2-3 | 5-8 | Missing environment context |
| **P3** | Insufficient evidence with conflicting signals (benign process + suspicious destination) | 3-5 | 8-10 | Teaches restraint under ambiguity |
| **P3** | False positive chains (benign tool triggering multiple detection rules) | 3-5 | 8-10 | Reduces hallucinated malicious findings |
| **P3** | Multi-stage attack chains (initial access to execution to persistence to exfil) | 3-5 | 8-10 | Teaches attack lifecycle reasoning |

**Estimated new templates needed**: **65-95** (vs. current 16)  
**Estimated new records needed**: **~400-500** (to reach 500-600 total)

### 13.2 Special Attention Categories (Per Requirements)

| Category | Current Status | What's Needed |
|---|---|---|
| Benign PowerShell | 4 records (admin maintenance only) | SCCM, GPO push, WSUS update, disk cleanup, printer setup — 10+ more |
| Legitimate administrative activity | 9 records (admin PS + registry Zoom install) | RDP admin, service restart, AD query, group policy, backup job — 15+ more |
| Suspicious but inconclusive | 27 records (all template-bound) | Varied scenarios with different evidence patterns — 15+ more |
| Likely malicious | 38 records (over-represented, template-bound) | Need fewer per template, more template diversity |
| Confirmed malicious | 14 records (macro + service account only) | Ransomware, APT, credential dump, data theft — 10+ more |
| Insufficient evidence | 12 records (certutil + file rename only) | Varied missing telemetry scenarios — 10+ more |
| Borderline cases | **0 records** | **10-15 per boundary — highest priority** |

---

## 14. Recommended Target Dataset Size

### For Student Research LoRA/QLoRA Experiment

| Parameter | Recommendation | Rationale |
|---|---|---|
| **Minimum viable** | **500 records** | Smallest size for meaningful LoRA with 5 output classes |
| **Recommended** | **800-1,000 records** | Better generalization, proper stratified split |
| **Ideal (if time allows)** | **2,000-5,000 records** | Production-grade, per-class per-task stratification |
| **Unique templates** | **80-120** | At least 5-8 per classification x task combination |
| **Base model** | Llama 3.x 8B or Mistral 7B | Fits in single consumer GPU VRAM with 4-bit QLoRA |
| **Quantization** | 4-bit (QLoRA) or 8-bit (LoRA) | QLoRA preferred for consumer GPU memory constraints |
| **LoRA rank** | r=16 to r=64 | Standard for task-specific fine-tuning |
| **LoRA alpha** | 2x rank (32-128) | Common scaling factor |
| **Target modules** | `q_proj`, `v_proj` minimum; add `k_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj` for deeper adaptation | Standard Llama/Mistral target layers |
| **Training epochs** | 3-5 | Prevents overfitting on small dataset |
| **Learning rate** | 2e-4 to 5e-5 | Standard QLoRA learning rate range |
| **Batch size** | 4-8 (with gradient accumulation to effective 16-32) | Fits RTX 3060+ VRAM |
| **Max sequence length** | 2048-4096 tokens | SOC records average ~500-1500 tokens |

> [!TIP]
> For a Monday college GPU session, **500 records with 80+ templates** is the practical minimum. QLoRA on an 8B model with 500 records takes approximately **30-60 minutes** on a single consumer GPU (RTX 3060 12GB or better). Budget 2-3 hours total including data loading, tokenization, training, and evaluation.

---

## 15. Recommended Train/Validation/Test Split

### 15.1 Split Strategy

| Set | Percentage | Records (at 500) | Purpose |
|---|---|---|---|
| **Train** | 70% | 350 | Fine-tuning |
| **Validation** | 15% | 75 | Hyperparameter tuning, early stopping |
| **Test** | 15% | 75 | Final held-out evaluation |

### 15.2 Split Rules (Mandatory)

1. **Split by template, not by record** — all instances of a given template go to one set only (prevents structural leakage)
2. **Stratify by classification** — each set must contain all 5 classification labels
3. **Stratify by task type** — each set should contain examples from all 7 task types
4. **Stratify by severity** — each set should span at least 4 of 5 severity levels
5. **No cross-contamination** — zero template overlap between train and test
6. **Reserve existing 100 records** — current v0.2 records go to test only (see Section 16)

### 15.3 Recommended Implementation

```
datasets/
  train/
    soc_train.jsonl          # 350 NEW records from expanded templates
  validation/
    soc_validation.jsonl     # 75 NEW records from expanded templates
  test/
    soc_test.jsonl           # 75 records (include current 100 as evaluation baseline)
```

---

## 16. Existing Records: Evaluation-Only Recommendation

> [!IMPORTANT]
> **All 100 current v0.2 records should be reserved as evaluation-only (test set).**

### Rationale

1. They were used in the Phase 3 real-LLM evaluation (98/100 records scored by Groq API)
2. They have established baseline metrics (60.2% classification accuracy, 90.8% investigation accuracy)
3. Including them in training would **invalidate** the existing evaluation baseline
4. New fine-tuning data should be generated from **expanded templates** to avoid train-on-test contamination
5. The template-level near-duplication means any record sharing a template with a test record would leak structural information into training

### Operational Implication

- The current 100 records become the **pre-fine-tuning evaluation benchmark**
- After fine-tuning, re-run the TriageAgent on these same 100 records
- Compare fine-tuned model accuracy vs. the 60.2% baseline to measure improvement
- This gives a clean **before/after** comparison with zero data contamination

---

## Verdict

## NOT READY

### Critical Blockers (must fix before fine-tuning)

| # | Blocker | Current | Required |
|---|---|---|---|
| 1 | **Volume** | 100 records | 500+ records |
| 2 | **Template diversity** | 16 templates | 80+ templates |
| 3 | **Class imbalance** | benign 9%, likely_malicious 38% | ~20% each |
| 4 | **Borderline cases** | 0 examples | 30-50 boundary examples |
| 5 | **Severity gaps** | 3 of 5 levels present | All 5 levels |
| 6 | **Evidence type gaps** | 11 of 18 types used | 15+ types |
| 7 | **MITRE coverage** | 11 of 34 techniques | 25+ techniques |
| 8 | **OS coverage** | Windows only | Windows + Linux |
| 9 | **Train/val/test split** | None | Template-stratified split |

### What Must Be Done Before Monday

1. **Expand generator templates** from 16 to 80+ covering all gaps in Section 13
2. **Generate 500+ records** with balanced class distribution
3. **Add borderline/ambiguous cases** between adjacent classifications (P0 priority)
4. **Fill missing severity levels** (informational, critical)
5. **Fill missing evidence types** (firewall, WMI, sysmon, scheduled_task, powershell_log, vulnerability_scan)
6. **Add Linux scenarios** (cron, SSH, web shell)
7. **Add DMZ environment scenarios**
8. **Create template-stratified train/val/test split**
9. **Reserve current 100 records as evaluation-only baseline**
10. **Implement `ai/training/` module** (dataset loader, preprocessor, training script)

### What the Dataset Does Well (Preserve These)

- **Excellent schema design** — directly maps to fine-tuning input/output format
- **Strong evidence grounding** — all findings reference valid evidence IDs
- **Coherent confidence calibration** per classification (verified in range)
- **Comprehensive validation pipeline** already exists and works
- **Human review tooling** already built (interactive CLI + batch approve)
- **Quality scoring engine** functional and producing meaningful scores
- **Directory structure and lifecycle pipeline** already in place
- **Deterministic reproducible generation** with seeded randomness
- **Zero validation errors** — 100% structural and semantic pass rate
- **Provider-independent LLM architecture** ready for local model swap
