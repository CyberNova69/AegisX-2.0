# AegisX SOC Fine-Tuning Dataset Card (v0.5)

## 1. Dataset Summary
- **Name**: aegisx-soc-finetuning
- **Version**: 0.5
- **Total Records**: 3,000
- **Template Families**: 150 (150 distinct scenarios across 18 domains)
- **Generator**: `scripts/generate_dataset_v05.py` (seed 42)
- **Creation Date**: 2026-09-04
- **Quality Score Average**: 100.0 / 100
- **License / Provenance**: Proprietary Research Synthetic Data (AegisX SOC Project, Member 2)

## 2. Synthetic Nature & Intended Use
- **Synthetic Origin**: 100% synthetic research dataset constructed using programmatic template factories, procedural slot filling, and parameter randomization.
- **Intended Use**: Supervised Fine-Tuning (SFT) of Small/Medium Large Language Models (e.g., Llama-3-8B, Qwen-2.5-7B) for SOC alert triage, incident classification, evidence citation, and response action recommendations on dedicated GPU hardware.
- **Explicit Non-Endorsement**: This dataset is NOT derived from active enterprise production logs. It must NOT be claimed as "enterprise ground truth" or "production-validated" without real SOC deployment.

## 3. Key Improvements in v0.5
1. **Polymorphic Linguistic Diversity**: 4 distinct analytical reasoning frameworks (Evidentiary-Deductive, Hypothesis-Testing, SOC Clinical Analyst, Forensic Chronology) to prevent syntactic overfitting across instances.
2. **Benign Distractor Telemetry**: ~30% of records contain realistic background enterprise events (browser HTTPS, OS component servicing, Kerberos ticket renewal, cloud sync) with strict non-referencing in malicious findings.
3. **Controlled Telemetry Noise**: Variable time deltas (15s to 75s) and realistic process contexts.
4. **Anti-Keyword Shortcut Decoupling**: Target tools (`powershell`, `psexec`, `ssh`, `failed login`, `ransomware`) appear across multiple classes to prevent shortcut heuristics (Shannon entropy $H \ge 1.0$ for all target keywords).
5. **Quality-Score Bug Resolved**: Metadata attached prior to evaluation, yielding 100/100 structural compliance score.

## 4. Split Architecture (Template-Stratified)
| Split | Records | Templates | Description |
|---|---|---|---|
| **Train** | 2,400 (80.0%) | 120 (80.0%) | Supervised fine-tuning training set (24 per class) |
| **Validation** | 300 (10.0%) | 15 (10.0%) | Evaluation checkpoint evaluation (3 per class) |
| **Test** | 300 (10.0%) | 15 (10.0%) | Held-out unseen template generalization benchmark (3 per class) |

> [!IMPORTANT]
> **Zero Template Leakage Guarantee**: No template family in Train appears in Validation or Test.
> $\text{Templates}(\text{Train}) \cap \text{Templates}(\text{Val}) = \emptyset$, $\text{Templates}(\text{Train}) \cap \text{Templates}(\text{Test}) = \emptyset$, $\text{Templates}(\text{Val}) \cap \text{Templates}(\text{Test}) = \emptyset$.

## 5. Classification Distribution (Perfect 20.0% Balance)
- `benign`: 600 (20.0%)
- `suspicious`: 600 (20.0%)
- `likely_malicious`: 600 (20.0%)
- `confirmed_malicious`: 600 (20.0%)
- `insufficient_evidence`: 600 (20.0%)

## 6. Borderline Representation
- Total borderline records: 1,760 (58.7%) across 88 borderline template families.
- Boundaries calibrated: `benign_vs_suspicious`, `suspicious_vs_likely_malicious`, `likely_malicious_vs_confirmed_malicious`, `suspicious_vs_insufficient_evidence`, `likely_malicious_vs_insufficient_evidence`.

## 7. Known Risks & Limitations
- **Synthetic Purity Risk**: Alerts are cleaner than real enterprise SIEM/EDR raw logs, which typically feature massive unparsed text and noise.
- **Language Model Overfitting**: Models trained for excessive epochs (>3 epochs) may memorize stylistic artifacts despite polymorphic rendering. LoRA/QLoRA training for 2–3 epochs is strongly recommended.
- **Fixed Operational Timeframe**: Timestamps fall within January 2026. Models will not inherently understand real-world seasonal patterns.

## 8. Cryptographic Hashes (v0.5)
- `train.jsonl`: `0914521724EA8E9B49CA5D8970D27B27E08D21606CF9BC47022F768A73FC11A6`
- `validation.jsonl`: `85AF74CE8038485B48F1DA3B6EEEB4F5FB9A07184163C9FF13A99D66E2162076`
- `test.jsonl`: `33389CF3F7F836920E47D45B654D8EC1BA56BB69D191E0FF9BB616E5CDEF3AA5`
- `full_dataset.jsonl`: `2590055A3AB3BD50E006FE8D6B76C2D225B7202AF2D84B4DA432B21C20CBE356`
