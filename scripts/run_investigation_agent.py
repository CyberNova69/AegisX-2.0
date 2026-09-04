#!/usr/bin/env python3
"""
AegisX SOC Investigation Agent CLI Runner
==========================================

Runs multi-turn SOC investigation scenarios with MockProvider or real APIProvider.
Provides human-readable step-by-step traces or machine-readable JSON output.

Usage:
    python scripts/run_investigation_agent.py --list-scenarios
    python scripts/run_investigation_agent.py --scenario malicious_powershell
    python scripts/run_investigation_agent.py --scenario suspicious_login
    python scripts/run_investigation_agent.py --scenario insufficient_evidence
    python scripts/run_investigation_agent.py --scenario malicious_powershell --max-steps 3
    python scripts/run_investigation_agent.py --scenario malicious_powershell --json
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.investigation_agent import InvestigationAgent
from ai.agents.investigation_schemas import InvestigationRequest
from ai.llm import LLMClient, LLMConfig
from ai.llm.providers.mock import MockProvider
from ai.tools.synthetic_data import SYNTHETIC_SCENARIOS, list_scenarios, get_scenario

def create_scenario_mock_provider(scenario_key: str, scenario_data: dict) -> MockProvider:
    """
    Construct a deterministic MockProvider that guides the InvestigationAgent
    through realistic investigation turns for the selected scenario.
    """
    provider = MockProvider()

    # Turn 1 decision: investigate primary suspicious vector
    turn1_tool = "process_activity"
    if "network" in scenario_key or "beacon" in scenario_key:
        turn1_tool = "network_activity"
    elif "auth" in scenario_key or "login" in scenario_key:
        turn1_tool = "authentication"
    elif "file" in scenario_key:
        turn1_tool = "file_activity"

    turn1_decision = json.dumps({
        "action": "investigate",
        "tool_name": turn1_tool,
        "tool_input": {"hostname": scenario_data["context"]["hostname"], "scenario": scenario_key},
        "purpose": f"Inspect {turn1_tool} to correlate initial alert telemetry.",
    })
    provider.register_response("INVESTIGATION STEP 1", turn1_decision)

    # Turn 2 decision: investigate secondary vector or conclude
    if scenario_key == "insufficient_evidence":
        turn2_decision = json.dumps({
            "action": "finish",
            "stop_reason": "No additional telemetry available for target host.",
        })
    elif scenario_key in ("malicious_powershell", "multi_stage_attack"):
        turn2_decision = json.dumps({
            "action": "investigate",
            "tool_name": "network_activity",
            "tool_input": {"hostname": scenario_data["context"]["hostname"], "scenario": scenario_key},
            "purpose": "Check for external C2 callbacks following process execution.",
        })
    else:
        turn2_decision = json.dumps({
            "action": "finish",
            "stop_reason": "Telemetry collection complete; sufficient context gathered.",
        })
    provider.register_response("INVESTIGATION STEP 2", turn2_decision)

    # Turn 3 decision (for multi-stage attacks)
    turn3_decision = json.dumps({
        "action": "finish",
        "stop_reason": "Sufficient evidence collected across process and network dimensions.",
    })
    provider.register_response("INVESTIGATION STEP 3", turn3_decision)

    # Final Conclusion Synthesis
    exp_conc = scenario_data.get("expected_conclusion", "suspicious")
    exp_sev = scenario_data.get("expected_severity", "medium")

    # Collect valid evidence IDs from initial alert and queried tools
    eids = [e["id"] for e in scenario_data.get("initial_evidence", [])]
    tool_cat_map = {
        "process_activity": "process",
        "network_activity": "network",
        "authentication": "auth",
        "file_activity": "file",
        "related_alerts": "alerts",
    }
    queried_cats = [tool_cat_map[turn1_tool]]
    if scenario_key in ("malicious_powershell", "multi_stage_attack"):
        queried_cats.append("network")
    for cat in queried_cats:
        for item in scenario_data.get("telemetry", {}).get(cat, []):
            if "id" in item:
                eids.append(item["id"])

    sample_eids = eids[:2] if eids else ["EVT-001"]

    conclusion_response = json.dumps({
        "status": "completed" if exp_conc != "insufficient_evidence" else "insufficient_evidence",
        "conclusion": exp_conc,
        "severity": exp_sev,
        "confidence": 0.92 if exp_conc != "insufficient_evidence" else 0.35,
        "findings": [
            {
                "finding_id": "FIND-001",
                "title": f"Correlated {scenario_data['title']}",
                "description": f"Investigation determined activity aligns with {exp_conc} profile.",
                "evidence_ids": sample_eids,
                "confidence": 0.90 if exp_conc != "insufficient_evidence" else 0.35,
            }
        ],
        "recommended_actions": [
            {
                "action": "Isolate host and preserve memory" if exp_conc in ("likely_malicious", "confirmed_malicious") else "Review with endpoint owner",
                "priority": "immediate" if exp_conc == "confirmed_malicious" else "medium",
                "rationale": "Mitigate risk based on investigation findings.",
            }
        ],
        "limitations": "Read-only synthetic investigation. No endpoint remediation performed.",
    })
    provider.register_response("FINAL INVESTIGATION SYNTHESIS", conclusion_response)
    provider.default_response = conclusion_response

    return provider

def main():
    parser = argparse.ArgumentParser(description="AegisX SOC Investigation Agent CLI")
    parser.add_argument("--list-scenarios", action="store_true", help="List all available synthetic investigation scenarios")
    parser.add_argument("--scenario", type=str, default="malicious_powershell", help="Scenario key name to investigate")
    parser.add_argument("--max-steps", type=int, default=5, help="Maximum investigation steps (default: 5)")
    parser.add_argument("--provider", type=str, choices=["mock", "api"], default="mock", help="LLM provider: 'mock' (default) or 'api'")
    parser.add_argument("--json", action="store_true", help="Output raw JSON investigation result")
    args = parser.parse_args()

    if args.list_scenarios:
        scenarios = list_scenarios()
        print("\n============================================================")
        print("  AegisX Phase 4 — Available Synthetic Scenarios")
        print("============================================================")
        for scn in scenarios:
            print(f"  [{scn['key']:<28}] {scn['id']} | Expected: {scn['expected_conclusion']:<20} | {scn['title']}")
        print("============================================================\n")
        return 0

    scenario_data = get_scenario(args.scenario)
    if not scenario_data:
        print(f"Error: Unknown scenario '{args.scenario}'. Use --list-scenarios to see options.", file=sys.stderr)
        return 1

    # Setup LLM Client
    if args.provider == "api":
        config = LLMConfig.load()
        config.provider_name = "api"
        llm_client = LLMClient.from_config(config)
    else:
        provider = create_scenario_mock_provider(args.scenario, scenario_data)
        llm_client = LLMClient(provider=provider)

    agent = InvestigationAgent(llm_client=llm_client, max_steps=args.max_steps)

    # Build InvestigationRequest
    request = InvestigationRequest(
        investigation_id=f"INV-{scenario_data['scenario_id']}",
        alert=scenario_data["alert"],
        triage_result={
            "classification": scenario_data["expected_conclusion"],
            "severity": scenario_data["expected_severity"],
            "confidence": 0.85,
            "investigation_required": True,
        },
        initial_evidence=scenario_data["initial_evidence"],
        context=scenario_data["context"],
    )

    if not args.json:
        print("\n============================================================")
        print(f"  AEGISX SOC INVESTIGATION ENGINE v0.1")
        print(f"  Investigation ID : {request.investigation_id}")
        print(f"  Scenario Key     : {args.scenario}")
        print(f"  Target Hostname  : {request.context.get('hostname')}")
        print(f"  Alert Title      : {request.alert.get('title')}")
        print(f"  Provider         : {args.provider.upper()}")
        print("============================================================")

    result = agent.investigate(request)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    # Human-readable report
    print("\n--- INVESTIGATION EXECUTION TRACE ---")
    for step in result.investigation_steps:
        print(f"\n[Step {step.step_number}] Tool Invocation: {step.tool_name}")
        print(f"  Purpose     : {step.purpose}")
        data_count = step.result.get("data", {}).get("count", 0)
        print(f"  Items Found : {data_count}")
        if step.evidence_ids:
            print(f"  Evidence IDs: {', '.join(step.evidence_ids)}")

    print("\n--- FINAL INVESTIGATION REPORT ---")
    print(f"  Status        : {result.status.upper()}")
    print(f"  Conclusion    : {result.conclusion.upper()}")
    print(f"  Severity      : {result.severity.upper()}")
    print(f"  Confidence    : {result.confidence:.2f}")
    print(f"  Total Evidence: {len(result.evidence)} items")

    print("\n  Findings:")
    for f in result.findings:
        eids = ", ".join(f.evidence_ids) if f.evidence_ids else "None"
        print(f"    - [{f.finding_id}] {f.title}: {f.description} (Evidence: {eids})")

    print("\n  Recommended Actions:")
    for a in result.recommended_actions:
        print(f"    - [{a.get('priority', 'medium').upper()}] {a.get('action')} ({a.get('rationale')})")

    print(f"\n  Limitations   : {result.limitations}")
    print("============================================================\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
