# AegisX 2.0 — System Architecture

> **Version**: Current as of 2026-09-23. Derived from active source code.

---

## 1. System Overview

AegisX is an AI-assisted Security Operations Center (SOC) platform that processes security alerts through a multi-agent pipeline: ingestion → detection → correlation → triage → investigation → threat intelligence → response recommendation.

All response actions require **human approval**. No automated containment, remediation, or endpoint modification is performed.

```
Endpoint Telemetry (JSON)
        ↓
FastAPI Ingestion Route (/api/v1/telemetry/ingest) [RBAC: agent/admin]
        ↓
Canonical Event Normalization (ai/ingestion/pipeline.py)
        ↓
Detection Engine (backend/detection/) → Alert[]
        ↓
Correlation Engine (backend/correlation/) → Incident[]
        ↓
SOCWorkflow Orchestrator (ai/orchestration/workflow.py)
        ↓
┌──────────────────────────────────────────────┐
│ Stage 1: TriageAgent (ai/agents/triage_agent.py)          │
│ → classification, severity, investigation_required        │
├──────────────────────────────────────────────┤
│ Stage 2: InvestigationAgent (ai/agents/investigation_agent.py) │
│ → multi-turn tool-based investigation (if required)       │
├──────────────────────────────────────────────┤
│ Stage 3: ThreatIntelAgent (ai/agents/threat_intel_agent.py)   │
│ → indicator reputation, MITRE mapping                     │
├──────────────────────────────────────────────┤
│ Stage 4: Response Recommendations                         │
│ → advisory actions requiring human approval               │
└──────────────────────────────────────────────┘
        ↓
RAG Context (ai/rag/) — BM25 retrieval of MITRE ATT&CK + Threat Intel
        ↓
Results + Audit Trail
```

---

## 2. LLM Abstraction Layer (`ai/llm/`)

AegisX uses a **provider-independent** LLM interface:

```
Agent / SOC Component
         │
         ▼
     LLMClient (ai/llm/client.py)
         │
         ▼
  BaseLLMProvider (ai/llm/base.py)
         │
    ┌────┼────┐
    ▼    ▼    ▼
 Mock  API  Future Local
```

| Module | Purpose |
|--------|---------|
| `ai/llm/client.py` | High-level orchestrator: `generate()` with structured JSON parsing |
| `ai/llm/base.py` | Abstract `BaseLLMProvider` contract |
| `ai/llm/providers/mock.py` | `MockProvider` for offline testing and CI |
| `ai/llm/providers/api.py` | `APIProvider` for external HTTP/REST endpoints |
| `ai/llm/schemas.py` | Data models (`LLMRequest`, `LLMResponse`, `TokenUsage`) |
| `ai/llm/config.py` | Configuration from `configs/model.yaml` + `.env` |
| `ai/llm/exceptions.py` | Exception hierarchy with automatic secret redaction |

Switching providers requires zero code changes — only configuration updates.

---

## 3. Agent Architecture

### 3.1 Triage Agent (`ai/agents/triage_agent.py`)

Single-pass classification of incoming security alerts.

- **Input**: Alert payload with title, severity, context, and evidence items
- **Output**: `TriageResult` — classification (5-class), severity, confidence, findings, recommendations
- **5-Class Taxonomy**: `benign`, `insufficient_evidence`, `suspicious`, `likely_malicious`, `confirmed_malicious`
- **Evidence Grounding**: Every finding must reference valid evidence IDs from the input payload
- **Investigation Decision**: Triggered for non-benign classifications or low-confidence benign

### 3.2 Investigation Agent (`ai/agents/investigation_agent.py`)

Multi-turn agentic investigation using read-only tools.

```
Alert + Triage → InvestigationRequest
        ↓
   InvestigationAgent (bounded loop, max_steps=5)
        ↓ (each iteration)
   LLM Decision: "investigate" tool_name | "finish"
        ↓
   ToolRegistry validation → execute tool → record evidence
        ↓ (on finish or max_steps)
   Final Synthesis → InvestigationResult
```

**7 Investigation Tools** (all read-only, via `ToolRegistry`):

| Tool | Class | Data Inspected |
|------|-------|---------------|
| `process_activity` | `ProcessActivityTool` / `DBProcessActivityTool` | Process trees, command lines, hashes |
| `network_activity` | `NetworkActivityTool` / `DBNetworkActivityTool` | Network connections, ports, protocols |
| `authentication` | `AuthenticationTool` / `DBAuthenticationTool` | Logon events, failures, source IPs |
| `file_activity` | `FileActivityTool` / `DBFileActivityTool` | File operations, paths, writing processes |
| `related_alerts` | `RelatedAlertsTool` / `DBRelatedAlertsTool` | Correlated alerts by endpoint/user/time |
| `threat_intel` | `ThreatIntelTool` | Indicator reputation (IP, hash, domain) |
| `mitre_lookup` | `MitreTool` | MITRE ATT&CK technique details |

Tools operate in **dual mode**: synthetic fixtures (development/CI) or PostgreSQL-backed queries (production).

### 3.3 Threat Intelligence Agent (`ai/agents/threat_intel_agent.py`)

Autonomous indicator discovery and MITRE ATT&CK correlation.

---

## 4. RAG Pipeline (`ai/rag/`)

Two-stage retrieval pipeline:

```
Query → Stage 1: BM25 (in-memory, <1ms)
              ↓
     ┌────────┴────────┐
     ▼                 ▼
  reranker=false    reranker=true
     ↓                 ↓
  Return BM25     Conditional Router
  (default)            ↓
              ┌────────┴────────┐
              ▼                 ▼
         Router Bypass     Stage 2: Cross-Encoder
      (exact IOC/high     (ms-marco-MiniLM-L-6-v2)
       margin)                  ↓
              ↓          Strategy C Selection
         BM25 top-k     (domain diversity)
```

| Module | Purpose |
|--------|---------|
| `ai/rag/embeddings.py` | `BM25Scorer` — pure Python Okapi BM25 |
| `ai/rag/retriever.py` | `RAGRetriever` — query interface |
| `ai/rag/pipeline.py` | `RAGPipeline` — ingestion + retrieval orchestration |
| `ai/rag/rag_service.py` | `RAGService` — alert-specific retrieval for agents |
| `ai/rag/ingest.py` | `DocumentIngester` — MITRE + threat intel document processing |
| `ai/rag/reranker.py` | Conditional neural reranker with router, Strategy C, BM25 fallback |

**Current config** (`configs/rag.yaml`): `reranker.enabled=false`, `canary.enabled=false`

---

## 5. Backend (`backend/`)

| Component | Module | Description |
|-----------|--------|-------------|
| **API** | `backend/api/` | FastAPI routes, RBAC middleware, services |
| **Detection** | `backend/detection/` | Rule-based detection engine |
| **Correlation** | `backend/correlation/` | Entity/time-based incident correlation |
| **Database** | `backend/database/` | Dual-mode persistence (in-memory / PostgreSQL) |

Authentication: API key with 4-role hierarchy (`admin`, `analyst`, `viewer`, `agent`).

---

## 6. Safety Invariants

1. **Zero System Execution**: No `subprocess`, `os.system`, `eval`, `exec` anywhere
2. **Zero Destructive Actions**: No process kill, file delete, network block
3. **Read-Only Tools**: All investigation tools are query-only
4. **ToolRegistry Enforcement**: LLM cannot invoke arbitrary functions
5. **Evidence Grounding**: Hallucinated evidence IDs are rejected
6. **Bounded Loops**: Investigation capped at `max_steps` (default: 5)
7. **Human Approval**: All response recommendations require human sign-off
8. **Allowed Actions**: Restricted to `{isolate_endpoint, kill_process, flag_for_review}`
9. **Secret Redaction**: API keys automatically redacted from error messages

---

## 7. Data Flow

### Ingestion Pipeline (`ai/ingestion/`)

```
Raw Event → Discovery → Normalization → Canonicalization → Detection → CanonicalEvent
```

| Module | Purpose |
|--------|---------|
| `discovery.py` | Event type and source identification |
| `normalize.py` | Field standardization across formats |
| `canonicalize.py` | Entity extraction and canonical form |
| `detection.py` | Inline detection rules |
| `processing.py` | Event processor orchestration |
| `pipeline.py` | Full pipeline with error handling |
| `parsers/` | Format-specific parsers |

---

## 8. Evaluation Framework (`ai/evaluation/`)

| Module | Evaluates |
|--------|-----------|
| `triage_eval.py` | Classification accuracy, Macro F1, severity alignment |
| `investigation_eval.py` | Completion rate, conclusion accuracy, evidence grounding |
| `threat_intel_eval.py` | Indicator discovery, attribution, MITRE mapping |
| `rag_eval.py` | Hit@1/3/5, MRR, retrieval latency |
| `safety_eval.py` | Safety invariant enforcement (must be 100%) |
| `benchmark.py` | Automated multi-component benchmarking |
| `test_set_firewall.py` | SHA-256 protected test set integrity |

---

## 9. Directory Structure

```
AegisX/
├── ai/                    # Core AI modules
│   ├── agents/            # TriageAgent, InvestigationAgent, ThreatIntelAgent
│   ├── evaluation/        # Evaluation framework
│   ├── ingestion/         # Event processing pipeline
│   ├── llm/               # Provider-independent LLM interface
│   ├── orchestration/     # SOCWorkflow orchestrator
│   ├── prompts/           # Agent prompt templates
│   ├── rag/               # BM25 RAG + conditional reranker
│   ├── tools/             # Read-only investigation + threat intel tools
│   └── training/          # Training utilities
├── backend/               # API, detection, correlation, database
├── configs/               # YAML configuration files
├── datasets/              # Training/evaluation datasets (v0.3–v1.0)
├── finetuning/            # QLoRA fine-tuning pipeline
├── tests/                 # Test suite (667 tests)
├── scripts/               # CLI scripts and utilities
├── aegisx_data/           # Data platform framework
├── docs/                  # Documentation
└── experiments/           # RAG/reranker experiment evidence
```
