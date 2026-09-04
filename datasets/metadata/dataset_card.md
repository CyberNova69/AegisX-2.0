# AegisX SOC Synthetic Dataset

## Dataset Description

A synthetic Security Operations Center (SOC) dataset designed for evaluating and training AI systems on security analysis tasks.

## Dataset Summary

- **Name**: aegisx-soc-synthetic
- **Version**: 0.1
- **Source**: Synthetic (template-based generation)
- **Language**: English
- **License**: Internal use only
- **Size**: Variable (configurable generation)

## Intended Use

- LLM evaluation on security analysis tasks
- AI agent evaluation and benchmarking
- Prompt development and iteration
- Investigation workflow training
- Future fine-tuning of security-specific models

## Task Types

| Task | Description |
|---|---|
| alert_triage | Classify and prioritize security alerts |
| investigation_planning | Create investigation plans for security events |
| evidence_analysis | Analyze security evidence for indicators |
| mitre_mapping | Map activity to MITRE ATT&CK framework |
| incident_summarization | Summarize security incidents |
| threat_intelligence | Assess threat intelligence relevance |
| response_recommendation | Recommend containment and response actions |

## Data Fields

Each record contains:
- **id**: Unique identifier (SOC-XXXXXX)
- **task**: SOC task type
- **input**: Alert details, context, and evidence array
- **output**: Classification, confidence, findings, and recommendations
- **metadata**: Source, generator, review status, version

## Classification Labels

- `benign` — Legitimate activity
- `suspicious` — Unusual but not confirmed malicious
- `likely_malicious` — Strong indicators of malicious intent
- `confirmed_malicious` — Confirmed malicious activity
- `insufficient_evidence` — Not enough information to classify

## Limitations

- All data is synthetic and template-based
- Scenarios may not cover all real-world attack patterns
- Generated reasoning follows templated patterns
- Not a substitute for real SOC experience data
- Should be supplemented with human-reviewed and LLM-augmented examples

## Generation

```bash
python scripts/generate_dataset.py --count 100 --seed 42
```

## Ethical Considerations

- No real security incidents, credentials, or personal data are included
- All hostnames, usernames, IPs, and other identifiers are synthetic
- Dataset is clearly marked as synthetic in metadata
- Not intended for producing real security assessments without human oversight
