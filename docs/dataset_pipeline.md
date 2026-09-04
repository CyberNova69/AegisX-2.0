# AegisX Dataset Pipeline (v0.2)

## 1. Purpose

The AegisX dataset pipeline produces **high-quality, synthetic Security Operations Center (SOC) data** for:

- **LLM evaluation**: Measuring language model performance on cybersecurity triage and analysis tasks
- **Agent evaluation**: Benchmarking agentic SOC workflows and tool calling accuracy
- **Prompt development**: Iterating on prompts with evidence-grounded input/output pairs
- **Investigation planning**: Training step-by-step SOC investigation procedures
- **Future fine-tuning**: Building domain-specific training data for QLoRA model adaptation (Phase 10)

All data is **100% synthetic** — no real security incidents, credentials, or personal information are included.

---

## 2. v0.2 Quality Enhancements

Version 0.2 introduces major semantic quality and cybersecurity correctness upgrades:

1. **Context & Entity Consistency**:
   - OS-aware process execution (e.g. Windows processes like `WINWORD.EXE` only run on Windows OSes).
   - Consistent user, host, IP, department, and role bindings across evidence items within the same scenario.
2. **Chronological Timestamp Logic**:
   - Evidence timestamps follow strict chronological order (e.g., email received → attachment opened → shell spawned → external network connection).
3. **Dynamic Synthetic File Hashes**:
   - Generates unique SHA256 hashes per record deterministically, avoiding hash collisions.
4. **Coherent Confidence Ranges**:
   - Enforces classification-specific confidence bounds (e.g., `confirmed_malicious` [0.88 - 0.99], `insufficient_evidence` [0.15 - 0.45]).
5. **MITRE ATT&CK Local Reference**:
   - Canonical lookup table at `datasets/metadata/mitre_reference.json` ensuring technique IDs are validated against known MITRE definitions.
6. **Automated Quality Score (0–100)**:
   - Self-evaluates each record across 10 semantic criteria (evidence richness, grounding, temporal ordering, entity consistency, actionability, etc.).
7. **Semantic Validation & Output Splitting**:
   - `validate_dataset.py` segregates generated output into `datasets/validated/` and `datasets/rejected/` based on structural validity and quality score threshold (>= 70).
8. **Analyst Review Tool**:
   - `review_dataset.py` provides interactive CLI review and threshold-based batch approvals.

---

## 3. Dataset Task Types

The dataset supports 7 SOC task types:

| Task | Description |
|---|---|
| `alert_triage` | Classify and prioritize security alerts based on context and evidence |
| `investigation_planning` | Create step-by-step investigation plans for security events |
| `evidence_analysis` | Analyze individual pieces of security evidence for indicators |
| `mitre_mapping` | Map observed activity to MITRE ATT&CK techniques and tactics |
| `incident_summarization` | Produce executive summaries of security incidents |
| `threat_intelligence` | Assess threat intelligence matches and IOC relevance |
| `response_recommendation` | Recommend containment and remediation actions |

---

## 4. Quick Start Commands

```bash
# Run Unit Tests (14 tests)
python -m unittest tests/test_dataset.py -v

# Generate 100 Synthetic Examples (v0.2)
python scripts/generate_dataset.py --count 100 --seed 42

# Validate and Split Output into Validated & Rejected
python scripts/validate_dataset.py datasets/generated/soc_examples.jsonl \
  --output-validated datasets/validated/soc_examples_validated.jsonl \
  --output-rejected datasets/validated/soc_examples_rejected.jsonl

# Batch Approve High-Quality Records (Quality Score >= 85)
python scripts/review_dataset.py datasets/validated/soc_examples_validated.jsonl --batch-approve-threshold 85
```

---

## 5. File Structure

```
datasets/
├── generated/           # Output from generate_dataset.py
│   └── soc_examples.jsonl
├── metadata/
│   ├── schema.json          # Canonical JSON Schema (v0.2)
│   ├── generation_config.yaml  # Generation parameters
│   ├── mitre_reference.json # MITRE ATT&CK technique reference
│   └── dataset_card.md      # ML dataset card
├── validated/           # Automated quality gate output
│   ├── soc_examples_validated.jsonl
│   └── soc_examples_rejected.jsonl
├── reviewed/            # Human-reviewed records
├── train/               # Training split (future)
├── validation/          # Validation split (future)
└── test/                # Test split (future)

scripts/
├── generate_dataset.py  # Synthetic data generator v0.2
├── validate_dataset.py  # Dataset validator v0.2
└── review_dataset.py    # Analyst review tool v0.2
```
