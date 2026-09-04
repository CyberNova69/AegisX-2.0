# AegisX SOC Alert Triage Agent (Phase 3)

## 1. Purpose

The AegisX SOC Alert Triage Agent (`TriageAgent`) is the first autonomous agent module built in AegisX. It analyzes incoming security alerts, host/user context, and event evidence to produce structured, evidence-grounded triage assessments.

The agent operates strictly through the provider-independent `LLMClient` abstraction layer established in Phase 2.

---

## 2. Target Architecture

```
                    SECURITY ALERT
                          │
                          ▼
                     TriageAgent
                          │
                          ▼
                      LLMClient
                          │
                          ▼
                 BaseLLMProvider
                          │
                ┌─────────┴─────────┐
                ▼                   ▼
          MockProvider         APIProvider
                │                   │
                ▼                   ▼
          (Offline/CI)       (LLM Endpoint)
                │                   │
                └─────────┬─────────┘
                          ▼
                 Structured Response
                          │
                          ▼
                    TriageResult
```

---

## 3. Data Schemas

### Input Schema (`AlertInput`)

```json
{
  "alert": {
    "title": "WINWORD spawning PowerShell with Encoded Command",
    "severity": "high",
    "source": "EDR",
    "rule_id": "RULE-5264"
  },
  "context": {
    "hostname": "PC-042",
    "username": "employee01",
    "department": "Finance",
    "os": "Windows 10 Enterprise",
    "ip_address": "10.0.1.42"
  },
  "evidence": [
    {
      "id": "EVT-001",
      "type": "process_creation",
      "description": "WINWORD.EXE spawned powershell.exe with -Enc parameter",
      "timestamp": "2026-01-15T10:00:00+00:00"
    },
    {
      "id": "EVT-002",
      "type": "network_connection",
      "description": "powershell.exe connected to 198.51.100.42:443",
      "timestamp": "2026-01-15T10:00:15+00:00"
    }
  ]
}
```

### Output Schema (`TriageResult`)

```json
{
  "classification": "confirmed_malicious",
  "severity": "high",
  "confidence": 0.95,
  "investigation_required": true,
  "summary": "Macro document spawned obfuscated PowerShell establishing C2 connection.",
  "findings": [
    {
      "finding": "WINWORD launched encoded PowerShell",
      "evidence_ids": ["EVT-001"]
    },
    {
      "finding": "PowerShell established outbound C2 connection",
      "evidence_ids": ["EVT-002"]
    }
  ],
  "evidence_ids": ["EVT-001", "EVT-002"],
  "recommended_actions": [
    {
      "action": "Isolate host PC-042",
      "priority": "immediate",
      "rationale": "Prevent lateral movement"
    }
  ]
}
```

---

## 4. Evidence Grounding Enforcement

- Every finding returned by `TriageAgent` MUST reference valid evidence IDs (`EVT-XXX`) present in the input alert payload.
- `TriageAgent._validate_and_build_result` programmatically verifies evidence IDs.
- Referencing non-existent evidence IDs (e.g. `EVT-999`) raises an explicit `LLMResponseError`, rejecting ungrounded or hallucinated outputs.

---

## 5. Security Reasoning & Decision Logic

- **Contextual Reasoning**: PowerShell, `cmd.exe`, failed logins, scheduled tasks, or external connections are NOT automatically classified as malicious without corroborating context.
- **Uncertainty Handling**: Incomplete or ambiguous telemetry triggers the `insufficient_evidence` classification and requests targeted telemetry collection in recommended actions.
- **Investigation Decision (`investigation_required`)**:
  - High confidence `benign` ($\ge 0.75$): `False`
  - `suspicious`, `likely_malicious`, `confirmed_malicious`, `insufficient_evidence`: `True`

---

## 6. Quick Start Commands

```bash
# Run Phase 3 TriageAgent Unit Tests (11 tests, offline)
python -m unittest tests/test_triage_agent.py -v

# Run Complete Project Test Suite (49 tests: Phase 1 + 2 + 3)
python -m unittest discover -s tests -p "test_*.py" -v

# Run Dataset Evaluation Script (Level 2: 10 alert_triage records)
python scripts/run_triage_agent.py --count 10
```

---

## 7. Python Usage Example

```python
from ai.agents import TriageAgent
from ai.llm import LLMClient

# Initialize TriageAgent using MockProvider
agent = TriageAgent(llm_client=LLMClient.from_mock())

alert_payload = {
    "alert": {"title": "Suspicious PowerShell Activity", "severity": "medium", "source": "EDR"},
    "context": {"hostname": "PC-001", "username": "employee01", "os": "Windows 10"},
    "evidence": [
        {"id": "EVT-001", "type": "process_creation", "description": "powershell.exe launched"}
    ]
}

result = agent.triage(alert_payload)
print(f"Classification: {result.classification}")
print(f"Confidence: {result.confidence}")
print(f"Investigation Required: {result.investigation_required}")
```
