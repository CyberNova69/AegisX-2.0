# AegisX

Agentic AI-powered Security Operations Center (SOC) platform.

## Project Status

**Current Phase**: Phase 1 — Dataset Foundation

## Team

| Member | Responsibility |
|--------|---------------|
| Member 1 | Endpoint telemetry, detection, alert generation, correlation |
| Member 2 | AI/LLM layer, SOC datasets, agentic AI, RAG, evaluation |
| Member 3 | Backend/platform, database, dashboard, API integration |

## Development Phases

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Dataset Foundation | 🟢 Complete |
| 2 | LLM Interface | 🟢 Complete |
| 3 | Triage Agent | 🟢 Complete |
| 4 | Safe Agentic Investigation Engine | 🟢 Complete |
| 5 | Multi-Agent Orchestration | 🟡 Stub only (`ai/orchestration/workflow.py` is empty) |
| 6 | RAG | 🟢 Complete (BM25/TF-IDF, lexical only) |
| 7 | Threat Intelligence Agent | 🟢 Complete |
| 8 | Evaluation Framework | 🟢 Complete |
| 9 | Fine-Tuning Pipeline (QLoRA) | 🟡 Pipeline complete — training not yet run |
| 10 | Real Endpoint Integration | ⏳ Planned |

> **Note**: accuracy is currently the project's main blocker — see
> [Productization Roadmap](docs/PRODUCTIZATION_ROADMAP.md). Latest benchmark:
> classification accuracy `0.30`, macro F1 `0.17`. Safety invariants are at `1.00`.

## Quick Start (Phase 1)

### Prerequisites

- Python 3.12+
- No external dependencies required

### Generate Dataset

```bash
# Generate 10 examples for testing
python scripts/generate_dataset.py --count 10 --seed 42

# Generate 100 examples (initial dataset)
python scripts/generate_dataset.py --count 100 --seed 42
```

### Validate Dataset

```bash
python scripts/validate_dataset.py datasets/generated/soc_examples.jsonl
```

### Run Tests

```bash
python -m unittest tests/test_dataset.py -v
```

## Project Structure

```
AegisX/
├── ai/                     # AI/ML components (future phases)
│   ├── agents/             # Investigation and triage agents
│   ├── evaluation/         # LLM and agent evaluation
│   ├── llm/                # LLM interface layer
│   ├── orchestration/      # Multi-agent orchestration
│   ├── prompts/            # Prompt templates
│   ├── rag/                # Retrieval-Augmented Generation
│   ├── tools/              # Agent tools
│   └── training/           # Fine-tuning pipeline
├── configs/                # Configuration files
├── datasets/               # Dataset pipeline
│   ├── generated/          # Generated synthetic data
│   ├── metadata/           # Schema, dataset card, configs
│   ├── reviewed/           # Human-reviewed data
│   ├── raw/                # External data sources
│   ├── train/              # Training split (future)
│   ├── validation/         # Validation split (future)
│   └── test/               # Test split (future)
├── docs/                   # Documentation
├── experiments/            # Experiment tracking
├── notebooks/              # Jupyter notebooks
├── scripts/                # Pipeline scripts
├── tests/                  # Unit tests
├── .gitignore
├── README.md
└── requirements.txt
```

## Quick Start (Phase 4 — Investigation Agent)

```bash
# List all 10 synthetic investigation scenarios
python scripts/run_investigation_agent.py --list-scenarios

# Run investigation on a scenario (offline with MockProvider)
python scripts/run_investigation_agent.py --scenario malicious_powershell

# Run investigation tests
python -m unittest tests/test_investigation_tools.py -v
python -m unittest tests/test_investigation_agent.py -v
```

## Documentation

- [Productization Roadmap](docs/PRODUCTIZATION_ROADMAP.md) — Gap analysis and plan from prototype to shippable product
- [Evaluation & Benchmarking](docs/evaluation.md) — Phase 5: Evaluation Framework & Test-Set Firewall
- [Threat Intelligence & RAG](docs/threat_intel_and_rag.md) — Phase 5: RAG and Threat Intelligence Tools
- [Investigation Agent](docs/investigation_agent.md) — Phase 4: Safe Agentic Investigation Engine v0.1
- [College GPU Fine-Tuning Runbook](docs/college_gpu_finetuning_runbook.md) — Fine-tuning pipeline v0.1
- [Dataset Pipeline](docs/dataset_pipeline.md) — Full documentation for the dataset generation and validation pipeline
- [Dataset Card](datasets/metadata/dataset_card.md) — ML dataset card
- [Schema](datasets/metadata/schema.json) — JSON Schema for dataset records
