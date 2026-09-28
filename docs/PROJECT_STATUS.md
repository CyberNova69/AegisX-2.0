# AegisX 2.0 — Project Status

> **Date**: 2026-09-23
> **Source**: Derived from current source code, configs, tests, and project structure.

---

## 1. What AegisX Is

AegisX is an AI-assisted Security Operations Center (SOC) platform. It processes security telemetry through autonomous AI agents (triage, investigation, threat intelligence) augmented with Retrieval-Augmented Generation (RAG) and produces structured, evidence-grounded assessment reports for human SOC analysts.

---

## 2. Current Architecture

Multi-agent SOC pipeline:
**Telemetry Ingestion → Detection → Correlation → Triage → Investigation → Threat Intel → Response Recommendations**

All agents use a provider-independent LLM interface (`ai/llm/`). All response actions require human approval.

Full architecture documented in [ARCHITECTURE.md](file:///c:/Users/makwa/AegisX/docs/ARCHITECTURE.md).

---

## 3. Implementation Status

### Implemented & Validated ✅

| Component | Location | Tests | Status |
|-----------|----------|-------|--------|
| **Triage Agent** | `ai/agents/triage_agent.py` | `test_triage_agent.py` | 5-class classification with evidence grounding |
| **Investigation Agent** | `ai/agents/investigation_agent.py` | `test_investigation_agent.py` | Multi-turn agentic loop, max_steps=5 |
| **Threat Intel Agent** | `ai/agents/threat_intel_agent.py` | `test_threat_intel_agent.py` | Indicator discovery + MITRE mapping |
| **LLM Interface** | `ai/llm/` | `test_llm.py` | Mock + API providers, secret redaction |
| **BM25 RAG** | `ai/rag/` | `test_rag.py`, `test_ingestion.py` | In-memory BM25, MITRE + TI corpus (47 chunks) |
| **Conditional Reranker** | `ai/rag/reranker.py` | `test_reranker_integration.py` | cross-encoder/ms-marco-MiniLM-L-6-v2, Strategy C |
| **Ingestion Pipeline** | `ai/ingestion/` | `test_ingestion_processing.py` | Normalize → Canonicalize → Detect |
| **Detection Engine** | `backend/detection/` | `test_detection_engine.py` | Rule-based detection |
| **Correlation Engine** | `backend/correlation/` | `test_correlation_engine.py` | Entity/time-based correlation |
| **FastAPI Backend** | `backend/api/` | `test_api.py`, `test_jwt_and_audit.py` | RBAC (4-role), API key auth |
| **PostgreSQL Persistence** | `backend/database/` | `test_postgres_runtime.py` | Dual-mode (in-memory / PostgreSQL) |
| **Safety Invariants** | `ai/evaluation/safety_eval.py` | `test_response_safety.py` | All 4 safety metrics at 100% |
| **Evaluation Framework** | `ai/evaluation/` | `test_evaluation_framework.py` | Triage, Investigation, RAG, Safety |
| **Data Platform** | `aegisx_data/` | `test_data_platform/` | Adapters, processing, SFT, versioning |
| **Dataset Pipeline** | `scripts/generate_dataset*.py` | `test_dataset*.py` (v0.3–v0.5) | v0.2→v1.0 evolution |
| **Finetuning Pipeline** | `finetuning/` | `test_finetuning.py` | QLoRA training, evaluation, inference |
| **Orchestration** | `ai/orchestration/workflow.py` | `test_orchestration.py`, `test_e2e_pipeline.py` | Full pipeline orchestrator |
| **Investigation Tools** | `ai/tools/` | `test_investigation_tools.py` | 7 read-only tools + ToolRegistry |
| **Prompt Templates** | `ai/prompts/` | Tested via agent tests | Triage, Investigation, Threat Intel |

### Experimental (Validated but Feature-Flagged) ⚗️

| Component | Flag | Status |
|-----------|------|--------|
| **Neural Reranker** | `reranker.enabled=false` | Validated through Phase 8 (Hit@1: 92.31%, MRR: 0.8654) |
| **Canary Deployment** | `canary.enabled=false` | Validated at 0%/5%/10%/25%/50% canary stages |
| **Ragas Evaluation** | Isolated layer | Phase 10 complete, Ragas 0.4.3 integrated |

### In Progress 🔄

| Component | Status |
|-----------|--------|
| **Qwen2.5-7B Fine-tuning** | Running on separate GPU machine (DO NOT TOUCH) |

### Planned 📋

| Component | Notes |
|-----------|-------|
| RTX laptop deployment | Pending pendrive transfer |
| GPU inference (reranker + model) | After RTX setup |
| `reranker.enabled=true` production enablement | After measured GPU benchmarks |
| Dashboard / UI | Not started |
| Docker / CI deployment | Not started |

---

## 4. Current RAG Implementation

- **Algorithm**: Okapi BM25 (pure Python, stdlib-only)
- **Corpus**: 47 chunks (34 MITRE ATT&CK techniques + 13 threat intel indicators)
- **Reranker**: `cross-encoder/ms-marco-MiniLM-L-6-v2` (feature-flagged OFF)
- **Strategy**: C (domain diversity preservation) with conditional routing
- **Fallback**: Automatic BM25 fallback on reranker failure
- **Config**: `configs/rag.yaml`
- **Measured Performance** (Phase 8):
  - BM25 p95: 1.3 ms
  - Router p95: 0.1 ms
  - CPU reranker warm p50: 265.1 ms, p95: 374.3 ms
  - Hit@1: 92.31%, MRR: 0.8654
  - IOC retention: 100%, Fallback: 100%

---

## 5. Current Model

- **Base model**: Qwen2.5-7B (fine-tuning in progress on separate machine)
- **Training method**: QLoRA (4-bit quantized, LoRA rank 16)
- **Training dataset**: `datasets/finetuning/v1.0/` (160 MB train, 20 MB validation, 20 MB test)
- **Reranker model**: `cross-encoder/ms-marco-MiniLM-L-6-v2` (88 MB, CPU)
- **Offline testing**: MockProvider (deterministic, no API required)
- **API testing**: APIProvider (OpenAI-compatible endpoints)

---

## 6. Dataset Status

| Version | Records | Status |
|---------|---------|--------|
| v0.3 | 520 | Historical (85 templates) |
| v0.4 | 3,000 | Historical baseline (150 templates) |
| v0.5 | 3,000 | Improved (anti-shortcut, distractor telemetry) |
| v1.0 | ~30,000 | **Current production dataset** |

Test set firewall: SHA-256 integrity enforced in `ai/evaluation/test_set_firewall.py`.

---

## 7. Test Suite

- **Total tests**: 667
- **Status**: All passing
- **Runtime**: ~20 seconds
- **Command**: `pytest tests/ -v`
- **Requirements**: CPU-only, no API keys, no GPU, no external dependencies

---

## 8. Important Configuration

| File | Purpose |
|------|---------|
| `configs/rag.yaml` | RAG retrieval, reranker, canary settings |
| `configs/model.yaml` | LLM provider, model, generation parameters |
| `configs/agents.yaml` | Agent configuration |
| `configs/dataset.yaml` | Dataset pipeline settings |
| `configs/data_platform.yaml` | Data platform configuration |
| `.env.example` | Environment variable template (secrets) |

---

## 9. Runtime Requirements

- **Python**: 3.12.10
- **PyTorch**: 2.14.0+cpu
- **Transformers**: 5.17.0
- **sentence-transformers**: 6.1.0
- **rerankers**: 0.10.0
- **Ragas**: 0.4.3
- **Dependencies**: `requirements.txt` (production), `requirements-finetuning.txt` (GPU training)

---

## 10. Completed Phases

| Phase | Description | Evidence |
|-------|-------------|----------|
| 1 | Dataset Foundation (v0.2→v0.5) | `datasets/finetuning/`, `docs/`, test suites |
| 2 | LLM Interface | `ai/llm/`, `test_llm.py` |
| 3 | Triage Agent + Accuracy Experiments | `ai/agents/triage_agent.py`, `reports/phase3/` |
| 4 | Investigation Agent | `ai/agents/investigation_agent.py`, `ai/tools/` |
| 5 | RAG + Threat Intel | `ai/rag/`, `ai/tools/synthetic_threat_intel.py` |
| 6 | Backend + PostgreSQL | `backend/`, `reports/backend/` |
| 7 | Canary Validation | `experiments/toolkit_rag/phase7_canary/` |
| 8 | Production Readiness | `experiments/toolkit_rag/phase8_production_readiness/` |
| 9 | Toolkit Library Audit | `experiments/toolkit_setup/` |
| 10 | Ragas Evaluation | `experiments/toolkit_rag/phase10_ragas_eval/` |
