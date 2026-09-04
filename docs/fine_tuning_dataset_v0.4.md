# AegisX Fine-Tuning Dataset v0.4 Report
**A Research-Ready Synthetic SOC Triage Fine-Tuning Dataset**

---

## 1. Executive Summary & Purpose of v0.4

The **AegisX v0.4 Fine-Tuning Dataset** is a high-volume, diverse, research-ready synthetic SOC triage dataset specifically engineered for Supervised Fine-Tuning (SFT) of security-analysis large language models (LLMs).

Prepared for execution on a dedicated college machine equipped with an NVIDIA GPU and sufficient VRAM, this dataset scales the dataset capacity from the prototype scale of v0.3 (520 records, 85 templates) to a fine-tuning dataset of **exactly 3,000 records** generated across **150 distinct template families**.

### Important Context & Research Scope
> [!IMPORTANT]
> **Research-Ready Scope**: This dataset is developed for an academic/student SOC engineering project. It does **NOT** claim to represent production enterprise telemetry or real-world SOC accuracy. It is designed as a **research-ready synthetic dataset** for learning structured security triage semantics without exposing private corporate credentials or real employee telemetry.

---

## 2. Dataset Architecture & Specifications

| Dimension | Target Specification | Actual Realized in v0.4 | Status |
|---|---|---|---|
| **Total Record Count** | Exactly 3,000 records | **3,000 records** | **MET (100%)** |
| **Train Split** | 2,400 records (80.0%) | **2,400 records (80.0%)** | **MET (100%)** |
| **Validation Split** | 300 records (10.0%) | **300 records (10.0%)** | **MET (100%)** |
| **Test Split** | 300 records (10.0%) | **300 records (10.0%)** | **MET (100%)** |
| **Template Families** | $\ge 120$ families (Target: 150) | **150 distinct families** | **MET (100%)** |
| **Records per Template** | Exactly 20 records each | **20 records per template** | **MET (100%)** |
| **Template Leakage** | 0 template overlap | **0 overlap across all pairs** | **MET (100%)** |
| **Class Distribution** | 20.0% each (18%–22% tolerance) | **Exactly 20.0% (600 each)** | **MET (100%)** |
| **Operating Systems** | Windows 65%–75%, Linux 25%–35% | **Windows 70.0%, Linux 30.0%** | **MET (100%)** |
| **Evidence Types** | $\ge 15$ types (Target: 16–18) | **18 / 18 types (100%)** | **MET (100%)** |
| **MITRE ATT&CK** | 34 supported techniques / 10 tactics | **34 / 34 techniques (100%)** | **MET (100%)** |
| **Borderline Cases** | $\ge 15\%$ ($\ge 450$ records, 5 boundaries) | **1,760 records (58.7%)** | **MET (391% of target)** |
| **Anti-Keyword Entropy** | Shannon entropy $> 1.0$ bit | **All tools $> 1.40$ bits** | **MET (100%)** |
| **Duplicate Records** | 0 exact, 0 near-duplicates | **0 exact, 0 near-duplicates** | **MET (100%)** |
| **Schema Validation** | 0 errors, 0 warnings | **0 errors, 0 warnings** | **MET (100%)** |

---

## 3. Split Architecture & Mathematical Disjointness

The dataset enforces a strict **template-stratified split** where every template family generates exactly 20 records:

| Split | Records | Percentage | Template Families | Templates / Class | File Location |
|---|---|---|---|---|---|
| **Train** | 2,400 | 80.0% | 120 (80.0%) | Exactly 24 per class | [train.jsonl](file:///c:/Users/makwa/AegisX/datasets/finetuning/v0.4/train.jsonl) |
| **Validation** | 300 | 10.0% | 15 (10.0%) | Exactly 3 per class | [validation.jsonl](file:///c:/Users/makwa/AegisX/datasets/finetuning/v0.4/validation.jsonl) |
| **Test** | 300 | 10.0% | 15 (10.0%) | Exactly 3 per class | [test.jsonl](file:///c:/Users/makwa/AegisX/datasets/finetuning/v0.4/test.jsonl) |
| **Total** | **3,000** | **100.0%** | **150** | **Exactly 30 per class** | [full_dataset.jsonl](file:///c:/Users/makwa/AegisX/datasets/finetuning/v0.4/full_dataset.jsonl) |

### Mathematical Disjointness Proof
$$\text{Templates}(\text{Train}) \cap \text{Templates}(\text{Val}) = \emptyset \quad (\text{Overlap} = 0)$$
$$\text{Templates}(\text{Train}) \cap \text{Templates}(\text{Test}) = \emptyset \quad (\text{Overlap} = 0)$$
$$\text{Templates}(\text{Val}) \cap \text{Templates}(\text{Test}) = \emptyset \quad (\text{Overlap} = 0)$$

Because template families in Train never appear in Validation or Test, evaluation scores reflect genuine semantic reasoning on unseen scenarios rather than memorization of template structure.

---

## 4. 150 Template Families Across 18 Security Domains

The 150 template families are organized into **18 distinct security domains**:

| Domain # | Domain Name | Template Range | Template Count | Target OS Platforms |
|---|---|---|---|---|
| **1** | PowerShell & Scripting | TF-001 – TF-008 | 8 templates | Windows |
| **2** | Living-off-the-Land (LotL) | TF-009 – TF-016 | 8 templates | Windows |
| **3** | Authentication & Identity | TF-017 – TF-024 | 8 templates | Windows |
| **4** | Persistence Mechanisms | TF-025 – TF-032 | 8 templates | Windows / Linux |
| **5** | Defense Evasion & Injection | TF-033 – TF-039 | 7 templates | Windows |
| **6** | Credential Access | TF-040 – TF-046 | 7 templates | Windows |
| **7** | Discovery & Reconnaissance | TF-047 – TF-053 | 7 templates | Windows / Linux |
| **8** | Lateral Movement | TF-054 – TF-060 | 7 templates | Windows / Linux |
| **9** | Network C2 & Tunneling | TF-061 – TF-067 | 7 templates | Windows |
| **10** | Impact & Ransomware | TF-068 – TF-073 | 6 templates | Windows |
| **11** | Data Exfiltration | TF-074 – TF-078 | 5 templates | Windows / Linux |
| **12** | Linux Endpoint Telemetry | TF-079 – TF-085 | 7 templates | Linux |
| **13** | Multi-Stage Attack Chains | TF-086 – TF-097 | 12 templates | Windows / Linux |
| **14** | Incomplete Telemetry & Missing Context | TF-098 – TF-107 | 10 templates | Windows / Linux |
| **15** | Admin Workflows & Malicious Lookalikes | TF-108 – TF-117 | 10 templates | Windows / Linux |
| **16** | Linux Enterprise Telemetry (systemd, sudo, ssh) | TF-118 – TF-129 | 12 templates | Linux |
| **17** | Enterprise Business Contexts | TF-130 – TF-140 | 11 templates | Windows / Linux |
| **18** | Threat Intelligence & Conflicting Evidence | TF-141 – TF-150 | 10 templates | Windows / Linux |
| **Total** | **All 18 Domains** | **TF-001 – TF-150** | **150 templates** | **105 Win / 45 Linux** |

A complete machine-readable catalog is archived in [template_inventory.json](file:///c:/Users/makwa/AegisX/datasets/finetuning/v0.4/template_inventory.json).

---

## 5. Classification Distribution (Target vs Actual)

Every classification is represented with exact mathematical equality:

| Classification | Target % | Total Count | Total % | Train Split | Validation Split | Test Split |
|---|---|---|---|---|---|---|
| `benign` | 20.0% | **600** | **20.0%** | 480 (20.0%) | 60 (20.0%) | 60 (20.0%) |
| `suspicious` | 20.0% | **600** | **20.0%** | 480 (20.0%) | 60 (20.0%) | 60 (20.0%) |
| `likely_malicious` | 20.0% | **600** | **20.0%** | 480 (20.0%) | 60 (20.0%) | 60 (20.0%) |
| `confirmed_malicious` | 20.0% | **600** | **20.0%** | 480 (20.0%) | 60 (20.0%) | 60 (20.0%) |
| `insufficient_evidence`| 20.0% | **600** | **20.0%** | 480 (20.0%) | 60 (20.0%) | 60 (20.0%) |
| **Total** | **100.0%** | **3,000** | **100.0%** | **2,400 (100.0%)** | **300 (100.0%)** | **300 (100.0%)** |

All three splits independently contain exactly 20.0% of each classification, avoiding split imbalance.

---

## 6. Operating System Telemetry Distribution

Operating system coverage achieves the target 70 / 30 ratio:

| Operating System | Templates | Total Records | Total % | Target Range | Status |
|---|---|---|---|---|---|
| **Windows** (Workstations & Servers) | 105 | 2,100 | **70.0%** | 65% – 75% | **OPTIMAL** |
| **Linux** (Servers & Development nodes) | 45 | 900 | **30.0%** | 25% – 35% | **OPTIMAL** |

### Per-Split OS Breakdown
- **Train**: 84 Windows templates (1,680 records, 70.0%) / 36 Linux templates (720 records, 30.0%)
- **Validation**: 11 Windows templates (220 records, 73.3%) / 4 Linux templates (80 records, 26.7%)
- **Test**: 10 Windows templates (200 records, 66.7%) / 5 Linux templates (100 records, 33.3%)

---

## 7. Evidence Type Coverage (18 / 18 Types)

All 18 evidence types defined in `datasets/metadata/schema.json` are utilized:

| # | Evidence Type | Description |
|---|---|---|
| 1 | `process_creation` | Sysmon EID 1 / Linux auditd EXECVE execution telemetry |
| 2 | `network_connection` | EDR socket events, internal pivots, outbound C2 connections |
| 3 | `file_modification` | Dropped payloads, batch file creation, database dump files |
| 4 | `registry_modification` | Windows Run keys, security provider tampering, service configs |
| 5 | `authentication` | Windows 4624/4625 logons, PAM authentication, sudo, SSH |
| 6 | `dns_query` | Subdomain tunneling queries, sinkhole resolutions, external C2 lookups |
| 7 | `email` | Inbound phishing attachments, macro documents, spearphishing links |
| 8 | `firewall_log` | Perimeter drop events, rejected ports, external reconnaissance bursts |
| 9 | `proxy_log` | Corporate web proxy logs, cloud storage categories, user agent headers |
| 10 | `scheduled_task` | Windows Task Scheduler 106 events, Linux crontab configurations |
| 11 | `service_creation` | System service registrations, systemd unit deployments |
| 12 | `wmi_activity` | Win32_Process.Create, WMI command executions, persistence |
| 13 | `powershell_log` | ScriptBlock logging EID 4104, AMSI triggers, encoded commands |
| 14 | `sysmon_event` | Process access handles (LSASS injection), named pipe events |
| 15 | `threat_intel_match` | Threat feed hash matches, known C2 IPs, domain sinkhole hits |
| 16 | `vulnerability_scan` | Nessus/OpenVAS authorized scanner telemetry, NAC registry logs |
| 17 | `user_report` | PhishAlarm employee reports, IT helpdesk support tickets |
| 18 | `other` | Core switchport physical link state changes, hardware events |

---

## 8. Complete MITRE ATT&CK Technique Coverage (34 / 34)

All 34 supported techniques across all 10 tactics from `datasets/metadata/mitre_reference.json` are represented:

| MITRE Tactic | Technique ID | Technique Name |
|---|---|---|
| **Execution** | T1059.001 | PowerShell |
| | T1059.003 | Windows Command Shell |
| | T1059.005 | Visual Basic |
| | T1059.006 | Python |
| | T1204.002 | Malicious File |
| | T1569.002 | Service Execution |
| **Initial Access** | T1566.001 | Spearphishing Attachment |
| | T1566.002 | Spearphishing Link |
| **Defense Evasion** | T1078 | Valid Accounts |
| | T1078.002 | Domain Accounts |
| | T1027 | Obfuscated Files or Information |
| | T1027.010 | Command Obfuscation |
| | T1036.005 | Match Legitimate Name or Location |
| | T1055 | Process Injection |
| **Persistence** | T1053.005 | Scheduled Task |
| | T1547.001 | Registry Run Keys |
| | T1543.003 | Windows Service |
| **Credential Access** | T1003.001 | LSASS Memory |
| | T1003.003 | NTDS |
| | T1110.001 | Password Guessing |
| | T1110.003 | Password Spraying |
| **Discovery** | T1087.002 | Domain Account Discovery |
| | T1018 | Remote System Discovery |
| | T1082 | System Information Discovery |
| | T1046 | Network Service Discovery |
| **Lateral Movement** | T1021.001 | Remote Desktop Protocol |
| | T1021.002 | SMB/Windows Admin Shares |
| **Command and Control** | T1105 | Ingress Tool Transfer |
| | T1071.001 | Web Protocols |
| | T1071.004 | DNS |
| **Impact** | T1486 | Data Encrypted for Impact |
| | T1490 | Inhibit System Recovery |
| **Exfiltration** | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol |
| | T1567.002 | Exfiltration to Cloud Storage |

---

## 9. Borderline & Hard Cases Analysis

The dataset contains **1,760 deliberate borderline records (58.7%)** across **88 template families**, surpassing the requirement of $\ge 15\%$ ($\ge 450$ records):

| Decision Boundary | Borderline Records | Key Discrimination Challenge |
|---|---|---|
| `benign_vs_suspicious` | 560 records | Routine administrative scripting vs anomalous execution |
| `suspicious_vs_likely_malicious` | 600 records | Unusual tool activity vs active malicious weaponization |
| `likely_malicious_vs_confirmed_malicious` | 20 records | Strong behavioral malice vs definitive compromise evidence |
| `suspicious_vs_insufficient_evidence` | 500 records | Suspicious event indicators vs truncated/missing audit logs |
| `likely_malicious_vs_insufficient_evidence` | 80 records | High-impact alert vs unconfirmed external network payload |
| **Total** | **1,760 records (58.7%)** | **All 5 critical SOC triage boundaries covered** |

---

## 10. Anti-Keyword-Learning & Shortcut Mitigation

To prevent the LLM from learning simple lexical shortcuts (such as `"powershell" -> malicious` or `"certutil" -> malicious`), key administrative utilities and commands appear across multiple classes:

| Tool / Observable | Class Diversity | Shannon Entropy | Normalized Entropy | Evaluation Status |
|---|---|---|---|---|
| `powershell` | 5 classes | **2.21 bits** | 0.95 | **PASSED** (High ambiguity) |
| `cmd` | 5 classes | **2.11 bits** | 0.91 | **PASSED** (High ambiguity) |
| `sudo` | 3 classes | **1.41 bits** | 0.89 | **PASSED** (Multi-class spread) |
| `ssh` | 4 classes | **1.97 bits** | 0.98 | **PASSED** (High ambiguity) |
| `curl` | 4 classes | **1.95 bits** | 0.98 | **PASSED** (High ambiguity) |
| `wmi` | 3 classes | **1.58 bits** | 1.00 | **PASSED** (Perfect equal spread) |
| `certutil` | 5 classes | **2.25 bits** | 0.97 | **PASSED** (High ambiguity) |
| `rundll32` | 4 classes | **1.92 bits** | 0.96 | **PASSED** (High ambiguity) |
| `scheduled_task` | 3 classes | **1.53 bits** | 0.97 | **PASSED** (Multi-class spread) |

Every key tool demonstrates a Shannon entropy $> 1.40$ bits, providing sufficient ambiguity to compel the fine-tuned LLM to examine contextual arguments and evidence relationships rather than relying on keyword heuristics.

---

## 11. Zero-Duplicate Guarantee

- **Exact Duplicate Inputs**: **0 records**
- **Near-Duplicate Telemetry (Title + Primary Evidence)**: **0 records**

To prevent near-duplicate collisions among the 20 instances generated per template, each instance incorporates dynamic incident identifiers (`ALT-XXXXX`), randomized target hostnames, varying timestamps, and process IDs.

---

## 12. Quality Scoring & Schema Validation

- **Strict Schema Validation**: **100% PASS** (Validated via `scripts/validate_dataset.py --strict datasets/finetuning/v0.4/full_dataset.jsonl` with **0 errors and 0 warnings**).
- **Average Automated Quality Score**: **90.0 / 100**
- **Minimum Record Score**: **80 / 100**
- **Maximum Record Score**: **100 / 100**

---

## 13. College GPU PC Readiness (Monday Execution Plan)

### Directory Structure of Deliverables in `datasets/finetuning/v0.4/`:
- `train.jsonl` (2,400 records)
- `validation.jsonl` (300 records)
- `test.jsonl` (300 records)
- `full_dataset.jsonl` (3,000 records)
- `template_inventory.json` (Catalog of all 150 templates)
- `split_metadata.json` (Record counts, file hashes, leakage proofs)
- `generation_config.yaml` (Complete generation reproducibility parameters)
- `dataset_card.md` (Standardized model-card metadata)
- `validation_report.json` (Complete output of diversity validator)
- `quality_report.json` (Statistical breakdown of quality scores)

### Fine-Tuning Execution Format
The JSONL records use the standard prompt-completion schema:
```json
{
  "id": "SOC-000001",
  "task": "alert_triage",
  "input": { ... },
  "output": { ... },
  "metadata": { ... }
}
```
This format converts directly into instruction-tuning chat templates (e.g. ChatML, Llama-3-Instruct format, or ShareGPT format) using standard HuggingFace `trl` (SFTTrainer), PyTorch, or Unsloth pipelines on the college GPU machine.

---

## 14. Verification Test Evidence

All 72 tests in the repository unit test suite pass with zero errors:
```
Ran 72 tests in 1.502s
OK
```

### Verified Test Suites:
1. `tests/test_dataset.py` (25 tests for schema and scoring baselines)
2. `tests/test_dataset_v03.py` (11 tests for v0.3 dataset invariants)
3. `tests/test_dataset_v04.py` (12 tests for v0.4 dataset invariants)
4. `tests/test_llm.py` (13 tests for LLM interface and providers)
5. `tests/test_triage_agent.py` (11 tests for TriageAgent integration)
