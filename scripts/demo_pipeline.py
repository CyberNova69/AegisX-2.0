#!/usr/bin/env python3
"""
AegisX — End-to-End SOC Pipeline Demo
======================================

Runs the full automated chain on a synthetic security alert:

    Security Alert
        -> TriageAgent        (classification, severity, confidence)
        -> decision branch    (is investigation required?)
        -> InvestigationAgent (multi-turn read-only evidence collection)
        -> Final report       (findings + MITRE + recommended actions)

This script wires together agents that already existed but were never
connected. It uses MockProvider so the demo is fully deterministic and
runs offline with no API key, no quota, and no network.

Usage:
    python scripts/demo_pipeline.py                          # default scenario
    python scripts/demo_pipeline.py --scenario multi_stage_attack
    python scripts/demo_pipeline.py --scenario benign_powershell
    python scripts/demo_pipeline.py --list
    python scripts/demo_pipeline.py --all                    # run every scenario
    python scripts/demo_pipeline.py --json                   # machine-readable

NOTE: This is a demonstration of pipeline architecture on synthetic data.
      It is NOT a measure of real-world SOC accuracy.
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.investigation_agent import InvestigationAgent
from ai.agents.investigation_schemas import InvestigationRequest
from ai.agents.triage_agent import TriageAgent
from ai.llm import LLMClient
from ai.llm.providers.mock import MockProvider
from ai.tools.synthetic_data import SYNTHETIC_SCENARIOS, get_scenario, list_scenarios

# Import the existing scenario mock builder so investigation behaviour is
# identical to the already-tested Phase 4 runner. Reuse, do not rebuild.
from scripts.run_investigation_agent import create_scenario_mock_provider


# ---------------------------------------------------------------------------
# Triage mock response
# ---------------------------------------------------------------------------

def build_triage_response(scenario_data: dict) -> str:
    """Deterministic triage verdict the TriageAgent will validate and return."""
    classification = scenario_data.get("expected_conclusion", "suspicious")
    severity = scenario_data.get("expected_severity", "medium")
    alert = scenario_data.get("alert", {})
    evidence = scenario_data.get("initial_evidence", [])
    evidence_ids = [e.get("id") for e in evidence if e.get("id")]

    # Benign + high confidence is the only branch that skips investigation.
    confidence = 0.91 if classification == "benign" else 0.86
    if classification == "insufficient_evidence":
        confidence = 0.34

    summary = (
        f"Alert '{alert.get('title', 'Unknown')}' on host "
        f"{scenario_data.get('context', {}).get('hostname', 'unknown')} "
        f"assessed as {classification.replace('_', ' ')}."
    )

    return json.dumps({
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "findings": [
            {
                "finding": f"Initial alert telemetry consistent with {classification.replace('_', ' ')} activity.",
                "evidence_ids": evidence_ids,
                "confidence": confidence,
            }
        ],
        "evidence_ids": evidence_ids,
        "recommended_actions": [
            {
                "action": (
                    "Isolate host and preserve volatile memory"
                    if classification in ("likely_malicious", "confirmed_malicious")
                    else "Review with endpoint owner"
                ),
                "priority": "immediate" if classification == "confirmed_malicious" else "medium",
                "rationale": "Based on triage assessment of available evidence.",
            }
        ],
        "rationale": summary,
    })


def build_provider(scenario_key: str, scenario_data: dict) -> MockProvider:
    """
    One provider serving the whole pipeline.

    The Phase 4 runner already registers the investigation turns; we add the
    triage turn on top so both agents share a single deterministic provider.
    """
    provider = create_scenario_mock_provider(scenario_key, scenario_data)
    alert_title = scenario_data.get("alert", {}).get("title", "")
    if alert_title:
        provider.register_response(alert_title, build_triage_response(scenario_data))
    return provider


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(scenario_key: str, verbose: bool = True) -> dict:
    """Execute alert -> triage -> investigation -> report for one scenario."""
    scenario_data = get_scenario(scenario_key)
    if not scenario_data:
        raise ValueError(f"Unknown scenario '{scenario_key}'")

    provider = build_provider(scenario_key, scenario_data)
    client = LLMClient(provider=provider)

    alert = scenario_data["alert"]
    context = scenario_data["context"]
    evidence = scenario_data.get("initial_evidence", [])

    # --- Stage 1: Triage -------------------------------------------------
    triage_agent = TriageAgent(llm_client=client)
    triage = triage_agent.triage({
        "alert": alert,
        "context": context,
        "evidence": evidence,
    })

    # --- Stage 2: Decision branch ---------------------------------------
    investigation_result = None
    if triage.investigation_required:
        investigation_agent = InvestigationAgent(llm_client=client, max_steps=5)
        request = InvestigationRequest(
            investigation_id=f"INV-{scenario_data['scenario_id']}",
            alert=alert,
            triage_result=triage.to_dict(),
            initial_evidence=evidence,
            context=context,
        )
        investigation_result = investigation_agent.investigate(request)

    return {
        "scenario": scenario_key,
        "alert": alert,
        "context": context,
        "triage": triage.to_dict(),
        "investigation": investigation_result.to_dict() if investigation_result else None,
        "expected_conclusion": scenario_data.get("expected_conclusion"),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

BAR = "=" * 72


def render(result: dict) -> None:
    triage = result["triage"]
    alert = result["alert"]

    print(f"\n{BAR}")
    print("  AEGISX — AUTOMATED SOC PIPELINE")
    print(BAR)
    print(f"  Scenario        : {result['scenario']}")
    print(f"  Alert           : {alert.get('title')}")
    print(f"  Host            : {result['context'].get('hostname')}")
    print(f"  User            : {result['context'].get('username')}")
    print(f"  Source          : {alert.get('source')} / rule {alert.get('rule_id')}")
    print(f"  Provider        : MOCK (deterministic, offline)")

    print(f"\n{BAR}")
    print("  STAGE 1 — AI TRIAGE")
    print(BAR)
    print(f"  Classification  : {triage['classification'].upper()}")
    print(f"  Severity        : {triage['severity'].upper()}")
    print(f"  Confidence      : {triage['confidence']:.2f}")
    print(f"  Investigation   : {'REQUIRED' if triage['investigation_required'] else 'NOT REQUIRED'}")
    if triage.get("summary"):
        print(f"  Summary         : {triage['summary']}")
    if triage.get("evidence_ids"):
        print(f"  Evidence        : {', '.join(triage['evidence_ids'])}")

    print(f"\n{BAR}")
    print("  STAGE 2 — DECISION")
    print(BAR)
    if triage["investigation_required"]:
        print("  Triage confidence below the benign-safe threshold.")
        print("  -> Routing to InvestigationAgent for evidence collection.")
    else:
        print("  Classified BENIGN with confidence >= 0.75.")
        print("  -> Investigation skipped. Alert closed pending analyst review.")

    inv = result["investigation"]
    if not inv:
        print(f"\n{BAR}")
        print("  PIPELINE COMPLETE — no investigation performed")
        print(BAR)
        print(f"  Expected verdict: {result['expected_conclusion']}")
        print(f"  Triage verdict  : {triage['classification']}")
        print("  MATCH" if triage["classification"] == result["expected_conclusion"] else "  MISMATCH")
        print()
        return

    print(f"\n{BAR}")
    print("  STAGE 3 — AGENTIC INVESTIGATION")
    print(BAR)
    for step in inv.get("investigation_steps", []):
        count = step.get("result", {}).get("data", {}).get("count", 0)
        print(f"  [Step {step.get('step_number')}] {step.get('tool_name')}")
        print(f"           purpose : {step.get('purpose')}")
        print(f"           found   : {count} item(s)"
              + (f" -> {', '.join(step.get('evidence_ids', []))}" if step.get("evidence_ids") else ""))

    print(f"\n{BAR}")
    print("  STAGE 4 — FINAL REPORT")
    print(BAR)
    print(f"  Status          : {str(inv.get('status')).upper()}")
    print(f"  Conclusion      : {str(inv.get('conclusion')).upper()}")
    print(f"  Severity        : {str(inv.get('severity')).upper()}")
    print(f"  Confidence      : {inv.get('confidence', 0):.2f}")
    print(f"  Evidence items  : {len(inv.get('evidence', []))}")

    if inv.get("findings"):
        print("\n  Findings:")
        for f in inv["findings"]:
            eids = ", ".join(f.get("evidence_ids", [])) or "none"
            print(f"    - [{f.get('finding_id')}] {f.get('title')}")
            print(f"      {f.get('description')}")
            print(f"      evidence: {eids}")

    if inv.get("recommended_actions"):
        print("\n  Recommended actions (analyst approval required):")
        for a in inv["recommended_actions"]:
            print(f"    - [{str(a.get('priority', 'medium')).upper()}] {a.get('action')}")
            print(f"      {a.get('rationale')}")

    print(f"\n  Limitations     : {inv.get('limitations')}")

    print(f"\n{BAR}")
    print("  GROUND TRUTH CHECK")
    print(BAR)
    print(f"  Expected verdict: {result['expected_conclusion']}")
    print(f"  Pipeline verdict: {inv.get('conclusion')}")
    print("  MATCH" if inv.get("conclusion") == result["expected_conclusion"] else "  MISMATCH")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisX end-to-end SOC pipeline demo")
    parser.add_argument("--scenario", type=str, default="malicious_powershell",
                        help="Scenario key to run (default: malicious_powershell)")
    parser.add_argument("--list", action="store_true", help="List available scenarios")
    parser.add_argument("--all", action="store_true", help="Run every scenario")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    if args.list:
        print(f"\n{BAR}")
        print("  AegisX — Available Scenarios")
        print(BAR)
        for scn in list_scenarios():
            print(f"  {scn['key']:<30} {scn['id']}  expected: {scn['expected_conclusion']}")
        print(BAR)
        print()
        return 0

    keys = list(SYNTHETIC_SCENARIOS.keys()) if args.all else [args.scenario]

    if args.json:
        out = [run_pipeline(k, verbose=False) for k in keys]
        print(json.dumps(out if args.all else out[0], indent=2))
        return 0

    if args.all:
        print(f"\n{BAR}")
        print(f"  AEGISX — FULL PIPELINE SWEEP ({len(keys)} scenarios)")
        print(BAR)

    matches = 0
    failures = []
    for key in keys:
        try:
            res = run_pipeline(key)
        except Exception as exc:
            failures.append((key, str(exc)))
            print(f"\n  [FAIL] {key}: {exc}")
            continue

        if args.all:
            ok = (res["investigation"]["conclusion"] == res["expected_conclusion"]
                  if res["investigation"]
                  else res["triage"]["classification"] == res["expected_conclusion"])
            matches += int(ok)
            print(f"  [{'OK' if ok else 'XX'}] {key:<30} -> "
                  f"{(res['investigation'] or res['triage']).get('conclusion') or res['triage']['classification']}")
        else:
            render(res)

    if args.all:
        print(f"\n{BAR}")
        print(f"  RESULT: {matches}/{len(keys)} scenarios matched expected verdict")
        if failures:
            print(f"  {len(failures)} scenario(s) errored:")
            for key, err in failures:
                print(f"    - {key}: {err}")
        print(BAR)
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
