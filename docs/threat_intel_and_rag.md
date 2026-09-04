# AegisX — Threat Intelligence, MITRE ATT&CK & RAG (Phase 5)

> **Disclaimer**: Phase 5 uses a **synthetic threat intelligence database** and official **MITRE ATT&CK references**. It is 100% offline, CPU-safe, and does not require third-party API keys or live network telemetry.

---

## 1. Overview

Phase 5 equips AegisX with **Threat Intelligence enrichment** and **Retrieval-Augmented Generation (RAG)**:
1. **Threat Intelligence Database (`ai/tools/synthetic_threat_intel.py`)**:
   Deterministic indicator reputations (IPs, hashes, domains), malware family profiles, threat actors (FIN7, LockBit Gang), and MITRE technique links.
2. **CPU-Safe RAG Engine (`ai/rag/`)**:
   In-memory Okapi BM25 scoring algorithm, document ingestion, and prompt context formatting without heavy GPU or PyTorch dependencies.
3. **Read-Only Intelligence Tools (`ai/tools/`)**:
   - `threat_intel` (`ThreatIntelTool`): Queries indicator reputation and emits structured `threat_intel_match` evidence.
   - `mitre_lookup` (`MitreTool`): Queries 34 MITRE ATT&CK techniques, tactics, and adversary behavior details.
4. **ToolRegistry Integration (`ai/tools/registry.py`)**:
   Expanded from 5 core tools to 7 investigation and intelligence tools.

---

## 2. Tool Reference

### `threat_intel` (`ThreatIntelTool`)
- **Purpose**: Query reputation, threat actors, and malware families for an IP, hash, or domain.
- **Input Schema**:
  ```json
  {
    "indicator": "198.51.100.200",
    "indicator_type": "ip"
  }
  ```
- **Evidence Produced**:
  ```json
  {
    "id": "TI-198_51_100_200",
    "type": "threat_intel_match",
    "description": "Threat intelligence match for 198.51.100.200: MALICIOUS (Cobalt Strike attributed to FIN7)",
    "timestamp": "2026-02-20T00:00:00Z",
    "raw_data": {
      "reputation": "malicious",
      "confidence": 0.96,
      "threat_actor": "FIN7",
      "malware_family": "Cobalt Strike",
      "tags": ["c2", "cobalt_strike", "fin7"]
    }
  }
  ```

### `mitre_lookup` (`MitreTool`)
- **Purpose**: Look up MITRE ATT&CK technique details, tactics, and descriptions.
- **Input Schema**:
  ```json
  {
    "technique_id": "T1059.001"
  }
  ```
  *or keyword query:*
  ```json
  {
    "query": "PowerShell execution"
  }
  ```
- **Evidence Produced**:
  ```json
  {
    "id": "MITRE-T1059_001",
    "type": "other",
    "description": "MITRE ATT&CK T1059.001 (PowerShell) - Tactic: Execution...",
    "timestamp": "2026-02-20T00:00:00Z",
    "raw_data": { ... }
  }
  ```

---

## 3. ToolRegistry Configuration

The `ToolRegistry` provides flexible registry creation:

```python
from ai.tools import create_default_registry, create_threat_intel_registry

# Phase 4 Core Registry (5 investigation tools)
core_reg = create_default_registry()
# ['authentication', 'file_activity', 'network_activity', 'process_activity', 'related_alerts']

# Phase 5 Extended Registry (7 investigation & intelligence tools)
intel_reg = create_threat_intel_registry()
# ['authentication', 'file_activity', 'mitre_lookup', 'network_activity', 'process_activity', 'related_alerts', 'threat_intel']
```

---

## 4. InvestigationAgent Integration (Phase 5 Part 3)

The `InvestigationAgent` natively incorporates `threat_intel` and `mitre_lookup`:

```python
from ai.agents import InvestigationAgent

# By default, InvestigationAgent initializes with all 7 tools enabled:
agent = InvestigationAgent(max_steps=5, enable_threat_intel=True)

# Querying threat intelligence in an investigation turn:
# 1. Step 1: Query process_activity -> finds powershell.exe connecting to 198.51.100.200
# 2. Step 2: Query threat_intel -> indicator: 198.51.100.200 -> yields TI-198_51_100_200 (FIN7 Cobalt Strike C2)
# 3. Step 3: Finish -> Findings cite TI-198_51_100_200 with zero evidence hallucination
result = agent.investigate(request)
```

---

## 5. ThreatIntelAgent — Autonomous Enrichment (Phase 5 Part 4)

The `ThreatIntelAgent` is a specialized, autonomous intelligence enrichment agent that complements the SOC pipeline.

### Responsibility Boundary vs InvestigationAgent

| Aspect | `InvestigationAgent` | `ThreatIntelAgent` |
|---|---|---|
| **Primary Scope** | Endpoint & telemetry investigation | Intelligence correlation & technique mapping |
| **Input** | `InvestigationRequest` (Alert + telemetry) | `ThreatIntelRequest` (Alert, context, indicators) |
| **Tools Used** | Process, Network, Auth, File, Alerts (+ TI) | `threat_intel`, `mitre_lookup` strictly |
| **Output** | `InvestigationResult` (Incident conclusion) | `ThreatIntelResult` (Enrichment report & actor context) |
| **Endpoint Action** | None (Read-only telemetry) | None (Read-only intelligence) |

### Conceptual Architecture

```text
InvestigationResult / Alert Context
                 ↓
         [ThreatIntelAgent]
                 ↓
     Autonomous Indicator Discovery (IP, Hash, Domain, Technique)
                 ↓
     Structured Intelligence Decision (query_threat_intel | query_mitre | finish)
                 ↓
            ToolRegistry
       ├── threat_intel  (Synthetic Threat DB)
       └── mitre_lookup  (MITRE ATT&CK Corpus)
                 ↓
     Retrieved Intelligence (Fenced as Untrusted Data)
                 ↓
     Correlation & Strict Evidence Grounding Audit
                 ↓
         [ThreatIntelResult]
```

### Supported Intelligence Actions
- `query_threat_intel`: Queries synthetic reputation, threat actor, and malware family for an indicator (`ip`, `hash`, `domain`).
- `query_mitre`: Queries MITRE technique details by technique ID (e.g. `T1059.001`) or keyword search.
- `finish`: Concludes enrichment and synthesizes findings.
- `insufficient_evidence`: Concludes that context lacks actionable indicators.

### Evidence Grounding & Hallucination Defense
- All citations in `findings[].evidence_ids` must match IDs gathered during initial context or returned by tools.
- Any hallucinated ID (e.g. `TI-FAKE_APT99_HOST`) is automatically stripped and logged in `metadata["hallucinated_evidence_attempts"]`.

### Untrusted Data & Prompt Injection Protection
- Retrieved threat reports and RAG chunks are treated strictly as **UNTRUSTED DATA** and fenced inside `<UNTRUSTED_RETRIEVED_EVIDENCE>` blocks.
- The agent audits retrieved text for prompt injection keywords (e.g. `ignore previous instructions`, `override rules`), logging warnings in `metadata["prompt_injection_warnings"]` and preventing execution.

### Synthetic Data Limitations
- **Synthetic Research Data Only**: All threat intelligence records are synthetic. Attribution is presented as repository-record inference, not verified real-world attribution.
- MITRE technique matches indicate behavioral classification, not proof of specific threat actor campaigns.

---

## 6. Running Unit Tests

All Phase 5 tests run 100% offline on CPU:

```bash
# Run RAG ingestion and retrieval tests (19 tests)
python -m unittest tests/test_rag.py -v

# Run Threat Intel & MITRE tool tests (15 tests)
python -m unittest tests/test_threat_intel_tools.py -v

# Run InvestigationAgent Threat Intel integration tests (5 tests)
python -m unittest tests/test_investigation_threat_intel_integration.py -v

# Run ThreatIntelAgent autonomous enrichment tests (12 tests)
python -m unittest tests/test_threat_intel_agent.py -v

# Run complete repository test suite (198 tests)
python -m unittest discover -s tests -p "test_*.py"
```
