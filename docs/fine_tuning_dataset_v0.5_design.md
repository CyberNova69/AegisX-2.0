# AegisX Fine-Tuning Dataset v0.5 Design Specification

**Document Version**: 1.0.0  
**Author**: AegisX Senior ML & Cybersecurity Dataset Engineering Team  
**Date**: 2026-09-04  
**Target Dataset**: `datasets/finetuning/v0.5/`  
**Status**: APPROVED FOR IMPLEMENTATION  

---

## 1. Executive Summary & Design Rationale

The AegisX **v0.4** dataset successfully established a 3,000-record benchmark with strict train/validation/test template-family isolation, 100% evidence grounding, and balanced 5-class distribution. However, the Phase 1 comprehensive audit identified several limitations inherent in pure template-based synthetic generation:
1. **Linguistic Uniformity**: Within each template family, the 20 generated instances shared identical sentence skeletons in `findings` and `rationale`, differing only by slot-filled values (IPs, usernames, hostnames).
2. **Absence of Background Noise**: Every evidence item in v0.4 alerts was directly relevant to the incident; real SOC alerts inevitably contain irrelevant background enterprise telemetry.
3. **Keyword Shortcut Vulnerability**: Without proactive distribution of administrative tools (e.g., PowerShell, SSH, PsExec) across classes, LLMs risk learning trivial keyword heuristics rather than cybersecurity reasoning.
4. **Quality-Score Evaluation Timing Defect**: Metadata was evaluated before being attached, causing a uniform 90/100 score across all v0.4 records.

The **v0.5** dataset is designed to solve these challenges while preserving the proven 3,000-record scale, strict 80/10/10 template-family isolation, and protected benchmark standard.

> [!IMPORTANT]
> **v0.4 Benchmark Freeze**: `datasets/finetuning/v0.4/` is strictly frozen. The v0.4 test set SHA-256 (`BFF898861F75A0982D6C2F6EFDBA99F0C5E8549A4B0EA72A687E91A8D80A4333`) remains the untouchable held-out standard. v0.5 is generated into `datasets/finetuning/v0.5/`.

---

## 2. Dataset Specifications

| Dimension | v0.4 Baseline | v0.5 Target Specification | Justification |
| :--- | :--- | :--- | :--- |
| **Total Record Count** | 3,000 | **3,000** | Preserves benchmark comparability without bloating GPU training time. |
| **Train Split** | 2,400 (80%) | **2,400 (80%)** | 120 template families × 20 variations. |
| **Validation Split** | 300 (10%) | **300 (10%)** | 15 template families × 20 variations. |
| **Test Split** | 300 (10%) | **300 (10%)** | 15 template families × 20 variations (held-out evaluation benchmark). |
| **Class Balance** | Exactly 20% per class | **Exactly 20% per class** | 600 records each: `benign`, `insufficient_evidence`, `suspicious`, `likely_malicious`, `confirmed_malicious`. |
| **Template Families** | 150 unique families | **150 unique families** | Reuses validated attack scenarios while upgrading instance generation. |
| **Split Leakage** | 0% overlap | **0% overlap** | Strict template-family isolation (120 train / 15 val / 15 test). |
| **Linguistic Phrasing** | Single static template | **4 polymorphic styles** | Prevents overfitting to grammatical patterns across 20 instances. |
| **Benign Distractor Telemetry** | None (0%) | **25% – 35% of alerts** | Injects irrelevant background events (browser, update, auth) to train telemetry filtering. |
| **Telemetry Noise** | None | **Controlled temporal/process jitter** | Realistic timestamps, varied time deltas, multi-process context. |
| **Borderline Cases** | 1,760 (58.7%) | **1,760 (58.7%)** | Maintained across 88 borderline template families with enhanced counter-arguments. |
| **Quality Score Mechanics**| Docked to 90 (timing bug)| **Fixed (100 / 100)** | Metadata attached before quality scoring calculation. |
| **Target SFT Format** | `sft/train`, `sft/val` | **`sft/train`, `sft/val`** | Direct ingestion into HuggingFace TRL / Unsloth for fine-tuning. |

---

## 3. Linguistic Diversity Strategy

To ensure fine-tuned models learn generalizable security analysis rather than syntactic pattern matching, v0.5 introduces **deterministic offline polymorphic rendering**:

### 3.1 Rationale Phrasing Styles
Each generated record selects from 4 distinct analytical reasoning frameworks based on record seed:
1. **Evidentiary-Deductive (`style_deductive`)**:
   - Begins with the foundational forensic evidence: *"Analysis of authentication logs and endpoint process execution reveals..."*
   - Connects evidence items to MITRE tactics, concluding with the classification verdict.
2. **Threat-Hypothesis Evaluation (`style_hypothesis`)**:
   - Explicitly evaluates competing explanations: *"While execution of [process] can indicate administrative maintenance, the observed network beaconing to [external_ip] refutes benign intent..."*
   - Essential for borderline and suspicious classifications.
3. **Clinical SOC Analyst Notes (`style_clinical`)**:
   - Terse, high-signal, professional triage syntax: *"Triage confirms unauthorized execution chain. Initial vector: [vector]. Secondary activity: [action]. High confidence adversary presence."*
4. **Forensic Chronology (`style_chronological`)**:
   - Structures reasoning along the event timeline: *"At T0, initial access was observed via [evt1]. Within [delta], adversary progressed to [evt2], establishing [technique]."*

### 3.2 Finding Phrasing Variation
Findings rotate through:
- Active adversary framing: *"Adversary invoked obfuscated PowerShell cradle to bypass script block logging."*
- System impact framing: *"Unauthorized administrative privilege modification detected on domain asset."*
- Forensic observation framing: *"Process rundll32.exe loaded unsigned payload update.dll from user temporary directory."*

---

## 4. Benign Distractor Telemetry Strategy

In commercial SOC operations, alerts rarely contain only the pure indicators of compromise. They arrive surrounded by mundane operating system and user activity.

### 4.1 Distractor Categories
1. **Browser Telemetry**:
   - `chrome.exe` or `msedge.exe` querying standard cloud endpoints (`clients2.google.com`, `edge.activity.windows.com`, `login.microsoftonline.com`).
2. **Operating System Maintenance**:
   - `TiWorker.exe` or `TrustedInstaller.exe` initiating normal system service health checks.
   - `svchost.exe -k netsvcs` background RPC checks.
3. **Routine Authentication**:
   - Standard Kerberos ticket renewal (`Logon Type 3`) from corporate domain controller.
   - Workstation screen unlock event.
4. **Cloud Synchronization**:
   - `OneDrive.exe` background sync poll over HTTPS port 443.

### 4.2 Distractor Integration Rules
- Injected into 25%–35% of `likely_malicious`, `confirmed_malicious`, and `suspicious` alerts.
- Injected distractors MUST have valid `id` (e.g., `EVT-003`), valid telemetry schemas, and chronological timestamp alignment.
- **Grounding Invariant**: Distractor event IDs are **NEVER** cited in malicious `findings` or `mitre_techniques`. The model must learn that citing distractor IDs is a hallucination.

---

## 5. Controlled Telemetry Noise Strategy

v0.5 incorporates structured, deterministic noise:
1. **Dynamic Time Deltas**: Time between evidence events varies realistically from 12 seconds to 8 minutes, simulating real attack pacing rather than uniform fixed increments.
2. **Variable Evidence Counts**: Alerts contain between 2 and 5 evidence items (mean: ~2.8 items/record).
3. **Multi-Host Context**: Relevant lateral movement alerts include evidence originating from source workstation alongside destination server telemetry.

---

## 6. Borderline Cases & Boundary Calibration

v0.5 maintains the 88 designated borderline template families (58.7% of the dataset) and enriches their reasoning:
- **`benign_vs_suspicious`**: Explicitly states why legitimate administrative PowerShell, IT monitoring tools, or bulk backup scripts lack malice.
- **`suspicious_vs_likely_malicious`**: Highlights the critical missing piece of evidence (e.g., lack of external C2 connection) that prevents immediate malicious confirmation.
- **`suspicious_vs_insufficient_evidence`**: Explains why fragmented logs or unverified origin IPs mandate the `insufficient_evidence` triage label with follow-up queries.

---

## 7. Anti-Shortcut Testing & Feature Decoupling

To prevent the model from learning naive keyword associations, v0.5 enforces entropy constraints across critical keywords:
- `powershell` MUST appear across `benign` (admin scripts), `suspicious` (unusual execution), `insufficient_evidence` (truncated logs), and `confirmed_malicious` (encoded downloaders).
- `psexec` / `ssh` / `rdp` MUST appear in authorized IT administration scenarios as well as lateral movement scenarios.
- `failed login` MUST appear in benign password expiration bursts as well as password spraying.

Each target keyword must have a Shannon entropy $H \ge 1.0$ across the 5 classification classes.

---

## 8. Split & Test-Set Policy

- **Train Split (`train.jsonl`)**: 2,400 records generated exclusively from Template Families `TF-001` through `TF-120`.
- **Validation Split (`validation.jsonl`)**: 300 records generated exclusively from Template Families `TF-121` through `TF-135`.
- **Test Split (`test.jsonl`)**: 300 records generated exclusively from Template Families `TF-136` through `TF-150`.
- **Overlap**: **Strictly 0.0%**. No record ID, no input fingerprint, and no template family crosses split boundaries.
- **v0.5 Test Set Protection**: Upon generation, `datasets/finetuning/v0.5/test.jsonl` will be hashed with SHA-256 and frozen.

---

## 9. Quality Verification & Acceptance Criteria

v0.5 generation will be accepted only when:
1. All 3,000 records pass JSONL parsing with 0 schema errors.
2. Every cited evidence reference is grounded (100% grounding rate; 0 hallucinated refs).
3. Quality score timing bug is resolved: all structurally valid records score 100/100.
4. Distractor evidence items are present and correctly unreferenced in malicious findings.
5. All 34 approved MITRE ATT&CK techniques are represented.
6. Test suite `python -m pytest tests/ -v` passes 100% (222+ tests).
7. Frozen v0.4 test set hash remains strictly `BFF898861F75A0982D6C2F6EFDBA99F0C5E8549A4B0EA72A687E91A8D80A4333`.
