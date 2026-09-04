# AegisX — Safe Agentic Investigation Engine v0.1

> **Disclaimer**: Phase 4 uses purely **synthetic telemetry**. It does **NOT** inspect real employee PCs, run commands on user machines, or perform automated endpoint containment or remediation.

---

## 1. What Phase 4 Is

Phase 4 introduces the **Safe Agentic Investigation Engine v0.1** to the AegisX SOC platform. While Phase 3 developed single-pass triage (determining whether an alert is malicious or benign and whether it requires investigation), Phase 4 enables **autonomous multi-turn investigation**.

When an alert requires investigation, the `InvestigationAgent` queries read-only tools, reviews returned telemetry evidence, iterates to collect missing context, and synthesizes a grounded investigation report with prioritized recommendations for human analysts.

---

## 2. Why Triage Alone Is Insufficient

Security alerts in modern enterprise SOCs rarely arrive with complete, decisive evidence:
- An alert might flag an encoded PowerShell invocation, but omit the parent process or network connections.
- An alert might indicate multiple failed logins, but lack context on whether the account was subsequently compromised.
- An alert might catch a dropped file in a temp directory, but omit the downloading process.

A single-pass triage agent can only guess or classify as `insufficient_evidence`. An **investigation agent** actively queries surrounding telemetry to resolve ambiguities before presenting findings to the human analyst.

---

## 3. What Agentic Investigation Means

Agentic investigation means the LLM functions as an active reasoning agent within a tightly constrained, deterministic environment:
1. It formulates an investigation plan based on the alert.
2. It chooses which query to execute next (e.g. process tree vs. network callbacks vs. authentication events).
3. It evaluates whether the returned evidence is sufficient or if another dimension must be checked.
4. It halts when enough evidence is collected (or when a maximum step threshold is reached).

---

## 4. The Investigation Loop

```
Security Alert + Triage Assessment
               ↓
     [InvestigationRequest]
               ↓
    ┌──────────────────────┐
    │  InvestigationAgent  │
    └──────────┬───────────┘
               │ (Decision Prompt)
               ↓
           [  LLM  ]
               │ (JSON: "investigate" or "finish")
               ↓
      [Validate Decision]
         ├── If "finish" ───────────┐
         └── If "investigate"       │
                 ↓                  │
          [ToolRegistry]            │
                 ↓                  │
      [Execute Read-Only Tool]      │
                 ↓                  │
       [Record ToolResult]          │
                 ↓                  │
      [Append Verified Evidence]    │
                 │                  │
         (Repeat if < max_steps)    │
                 ↓                  │
    ┌──────────────────────┐        │
    │ Final Synthesis Turn │ <──────┘
    └──────────┬───────────┘
               ↓
    [Evidence Grounding Audit]
               ↓
     [InvestigationResult]
```

---

## 5. ToolRegistry

To guarantee safety, the `InvestigationAgent` never invokes tools directly or via raw function pointers. All tool requests pass through the `ToolRegistry`:
- **Allowlist Enforcement**: Only tools explicitly registered in the registry can be retrieved and executed.
- **Rejection**: Any hallucinated, unapproved, or unknown tool name results in immediate rejection (`LLMResponseError`).
- **Read-Only Verification**: The registry rejects any tool whose `read_only` property is not `True`.

---

## 6. The Five Investigation Tools

| Tool Identifier | Tool Class | Purpose | Data Inspected |
|---|---|---|---|
| `process_activity` | `ProcessActivityTool` | Inspect process execution trees | PID, parent process, command line, user, binary hash, execution timestamp |
| `network_activity` | `NetworkActivityTool` | Inspect network connections | Source endpoint, dest IP, dest port, protocol, connection status, timestamp |
| `authentication` | `AuthenticationTool` | Inspect user logon events | Username, source IP, logon type, success/failure, failure counts |
| `file_activity` | `FileActivityTool` | Inspect file modifications | File path, operation (create/modify), writing process, user, hash |
| `related_alerts` | `RelatedAlertsTool` | Find correlated alerts | Correlated alerts sharing endpoint, user, or correlation ID |

All five tools are query-only and extract data strictly from synthetic telemetry.

---

## 7. Synthetic Telemetry Store

Located in `ai/tools/synthetic_data.py`, this module contains 10 deterministic SOC investigation scenarios:
1. `benign_powershell`: Scheduled IT maintenance script (`Get-HealthStatus.ps1`) executed via task scheduler. (Expected: `benign`)
2. `suspicious_powershell`: Base64 encoded PowerShell executed from developer terminal without external C2. (Expected: `suspicious`)
3. `malicious_powershell`: `WINWORD.EXE` spawning encoded PowerShell connecting to port 4444 and dropping a startup payload. (Expected: `confirmed_malicious`)
4. `suspicious_login`: Off-hours login from a new international source IP. (Expected: `suspicious`)
5. `brute_force_authentication`: 52 failed SSH logins followed by successful authentication and authorized_keys tampering. (Expected: `likely_malicious`)
6. `suspicious_process_chain`: `rundll32.exe` spawning `regsvr32.exe` to register a DLL in ProgramData. (Expected: `suspicious`)
7. `suspicious_outbound_connection`: Fixed 60-second beaconing to an uncategorized external IP. (Expected: `likely_malicious`)
8. `suspicious_file_activity`: Chrome browser dropping an unsigned `.exe` in user AppData Temp. (Expected: `suspicious`)
9. `multi_stage_attack`: Multi-stage ransomware attack combining WMI lateral movement, shadow copy deletion, C2 exfiltration, and mass file encryption. (Expected: `confirmed_malicious`)
10. `insufficient_evidence`: Truncated log fragment mentioning certutil with zero parameters. (Expected: `insufficient_evidence`)

---

## 8. Evidence Grounding & Hallucination Prevention

Evidence grounding is strictly enforced in `InvestigationAgent`:
- The agent maintains an internal pool of verified evidence IDs originating from:
  1. The initial alert's evidence array (e.g. `EVT-001`)
  2. Telemetry items returned by successfully executed tools (e.g. `PROC-001`, `NET-001`)
- When the model returns findings in the final synthesis, every referenced evidence ID is checked against the verified pool.
- **Hallucinated IDs are rejected**: Any ID not in the verified pool is stripped from the finding and recorded in the audit trail (`result.metadata["hallucinated_evidence_attempts"]`).

---

## 9. Safety Controls

Phase 4 includes defense-in-depth safety controls:
1. **Zero System Execution**: No `subprocess`, `os.system`, `os.popen`, `shell=True`, `exec()`, or `eval()`.
2. **Zero Destructive Actions**: No process termination, file deletion, network blocking, or account lockout.
3. **No Direct Tool Execution by LLM**: The LLM outputs untrusted JSON. The agent validates the action and tool name against the `ToolRegistry` before calling the tool.
4. **Offline & Sandbox Operation**: Queries run against static in-memory data; no live endpoints or network sockets are contacted.
5. **Human Analyst Focus**: All recommendations are advisory for human review, never executed autonomously.

---

## 10. `max_steps` Enforcement

To prevent infinite loops or cost overruns, investigations are strictly bounded by `max_steps` (default: 5):
- The agent tracks completed steps in each iteration.
- If `len(steps) >= max_steps` and the model has not chosen `action: "finish"`, the loop automatically terminates.
- The agent proceeds directly to the synthesis phase and marks the status as `"incomplete"` or `"completed"` based on gathered context.

---

## 11. Running the CLI

The CLI runner is located at `scripts/run_investigation_agent.py`:

```bash
# List all available synthetic scenarios
python scripts/run_investigation_agent.py --list-scenarios

# Run investigation on a specific scenario (using default MockProvider)
python scripts/run_investigation_agent.py --scenario malicious_powershell

# Run with custom step limit
python scripts/run_investigation_agent.py --scenario malicious_powershell --max-steps 3

# Run other scenarios
python scripts/run_investigation_agent.py --scenario suspicious_login
python scripts/run_investigation_agent.py --scenario insufficient_evidence

# Output machine-readable JSON
python scripts/run_investigation_agent.py --scenario malicious_powershell --json

# Run against a configured live API model (Groq/OpenAI)
python scripts/run_investigation_agent.py --scenario malicious_powershell --provider api
```

---

## 12. Running Tests

All tests run 100% offline on CPU without API keys, GPU, or external dependencies:

```bash
# Run investigation tool and safety tests
python -m unittest tests/test_investigation_tools.py -v

# Run investigation agent unit and integration tests
python -m unittest tests/test_investigation_agent.py -v

# Run the complete AegisX regression suite
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 13. Synthetic Evaluation

The evaluation framework in `ai/evaluation/investigation_eval.py` evaluates agent performance across batches of synthetic scenarios:

```python
from ai.evaluation.investigation_eval import evaluate_investigation_scenarios

# Measures: completion_rate, conclusion_accuracy, evidence_grounding_rate,
# hallucinated_evidence_rate, max_step_violations, and structured_output_validity_rate.
metrics = evaluate_investigation_scenarios(results, expected_scenarios)
print(metrics.to_dict())
```

Metrics are explicitly stamped with: `evaluation_type: "SYNTHETIC EVALUATION"`.

---

## 14. Current Limitations

- **Synthetic Telemetry Only**: Telemetry records are deterministic in-memory scenarios, not live feeds.
- **Read-Only Scope**: The engine cannot perform containment, blocking, or remediation.
- **Fixed Toolset**: Exactly five read-only investigation tools are registered in Phase 4.
- **No External Threat Intel**: Integration with VirusTotal, AlienVault, or MITRE ATT&CK APIs is scheduled for later phases.

---

## 15. Future Real Endpoint Integration

In future phases:
- The `BaseInvestigationTool` interface will be implemented by live connectors (e.g. Sysmon, osquery, OpenSearch, Velociraptor).
- Because `InvestigationAgent` interacts exclusively with `ToolRegistry` and `BaseInvestigationTool`, the agent architecture will remain unchanged when live telemetry providers are plugged in.
