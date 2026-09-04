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
from ai.agents.threat_intel_agent import ThreatIntelAgent
from ai.agents.threat_intel_schemas import ThreatIntelRequest
from ai.agents.triage_agent import TriageAgent
from ai.llm import LLMClient
from ai.llm.providers.mock import MockProvider
from ai.tools.registry import create_threat_intel_registry
from ai.tools.synthetic_data import SYNTHETIC_SCENARIOS, get_scenario, list_scenarios
from ai.tools.synthetic_threat_intel import get_threat_intel

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


# MITRE ATT&CK technique each scenario maps to, taken from the project's own
# reference set (datasets/metadata/mitre_reference.json). Technique IDs are
# used rather than keyword queries because they resolve deterministically.
MITRE_TECHNIQUE = {
    "benign_powershell": "T1053.005",             # Scheduled Task
    "suspicious_powershell": "T1027.010",         # Command Obfuscation
    "malicious_powershell": "T1566.001",          # Spearphishing Attachment
    "suspicious_login": "T1078",                  # Valid Accounts
    "brute_force_authentication": "T1110.003",    # Password Spraying
    "suspicious_process_chain": "T1055",          # Process Injection
    "suspicious_outbound_connection": "T1071.001",  # Web Protocols
    "suspicious_file_activity": "T1036.005",      # Match Legitimate Name
    "multi_stage_attack": "T1486",                # Data Encrypted for Impact
    "insufficient_evidence": "T1027",             # Obfuscated Files (provisional)
}


def build_threat_intel_synthesis(indicators: list) -> str:
    """Deterministic TI synthesis. Findings cite no IDs to avoid grounding violations."""
    primary = indicators[0].get("indicator") if indicators else None
    summary = (
        f"Threat intelligence correlation completed on {len(indicators)} indicator(s)."
        if indicators else
        "No network indicators present in collected evidence; intel enrichment limited to MITRE context."
    )
    findings = []
    if primary:
        findings.append({
            "finding_id": "TI-001",
            "title": f"Indicator {primary} checked against threat intelligence",
            "description": "Indicator reputation, actor attribution and malware family resolved from the threat intelligence store.",
            "category": "reputation",
            "indicator": primary,
            "confidence": 0.8,
            "evidence_ids": [],
        })
    findings.append({
        "finding_id": "TI-002",
        "title": "MITRE ATT&CK technique context attached",
        "description": "Observed behaviour mapped to MITRE ATT&CK technique context for analyst reference.",
        "category": "mitre",
        "confidence": 0.75,
        "evidence_ids": [],
    })
    return json.dumps({
        "status": "completed",
        "confidence": 0.8 if primary else 0.6,
        "summary": summary,
        "findings": findings,
        "recommendations": [
            {
                "action": "Block indicator at egress firewall and add to watchlist"
                if primary else "Correlate with additional telemetry before action",
                "priority": "high" if primary else "medium",
            }
        ],
    })


def build_threat_intel_mock(provider: MockProvider, scenario_key: str,
                            scenario_data: dict, indicators: list) -> None:
    """
    Register the ThreatIntelAgent turn sequence on the shared provider.

    Turn 1: query threat intel for the first indicator (if any)
    Turn 2: query MITRE for scenario-relevant technique context
    Turn 3: finish
    Final:  synthesis
    """
    step1 = {"action": "finish"}
    if indicators:
        step1 = {
            "action": "query_threat_intel",
            "indicator": indicators[0].get("indicator"),
            "indicator_type": indicators[0].get("type", "unknown"),
            "reason": f"Check reputation and attribution for {indicators[0].get('indicator')}.",
        }

    step2 = {
        "action": "query_mitre",
        "technique_id": MITRE_TECHNIQUE.get(scenario_key, "T1059.001"),
        "reason": "Resolve MITRE ATT&CK technique context for observed behaviour.",
    }
    step3 = {"action": "finish", "reason": "Sufficient intelligence context gathered."}

    for n, decision in ((1, step1), (2, step2), (3, step3)):
        provider.register_response(
            f"THREAT INTELLIGENCE ENRICHMENT STEP {n} OF", json.dumps(decision)
        )

    # Any later step also terminates safely.
    provider.register_response("THREAT INTELLIGENCE ENRICHMENT STEP", json.dumps(step3))
    provider.register_response(
        "FINAL THREAT INTELLIGENCE SYNTHESIS", build_threat_intel_synthesis(indicators)
    )


def build_provider(scenario_key: str, scenario_data: dict) -> MockProvider:
    """
    One provider serving the whole pipeline.

    The Phase 4 runner already registers the investigation turns; we add the
    triage turn on top so both agents share a single deterministic provider.
    """
    provider = create_scenario_mock_provider(scenario_key, scenario_data)
    # Key on the triage prompt's own intro line, NOT the alert title: the alert
    # title also appears in the investigation and threat-intel prompts, and
    # MockProvider returns the first substring match.
    provider.register_response(
        "Please analyze the following security alert", build_triage_response(scenario_data)
    )
    return provider


def extract_indicators(scenario_data: dict) -> list:
    """Pull candidate IOCs out of the alert using the agent's own extractor."""
    probe = ThreatIntelAgent(tool_registry=create_threat_intel_registry())
    request = ThreatIntelRequest(
        request_id="TI-PROBE",
        alert=scenario_data.get("alert", {}),
        context=scenario_data.get("context", {}),
        initial_evidence=scenario_data.get("initial_evidence", []),
    )
    indicators = probe.extract_candidate_indicators(request)
    # Prefer indicators that exist in the intel store so the demo surfaces a
    # real reputation verdict instead of "unknown". Unknown ones are kept last.
    known = [i for i in indicators if get_threat_intel(i.get("indicator"))]
    unknown = [i for i in indicators if not get_threat_intel(i.get("indicator"))]
    return known + unknown


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(scenario_key: str, verbose: bool = True) -> dict:
    """Execute alert -> triage -> investigation -> report for one scenario."""
    scenario_data = get_scenario(scenario_key)
    if not scenario_data:
        raise ValueError(f"Unknown scenario '{scenario_key}'")

    alert = scenario_data["alert"]
    context = scenario_data["context"]
    evidence = scenario_data.get("initial_evidence", [])

    indicators = extract_indicators(scenario_data)

    provider = build_provider(scenario_key, scenario_data)
    build_threat_intel_mock(provider, scenario_key, scenario_data, indicators)
    client = LLMClient(provider=provider)

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

    # --- Stage 3: Threat intelligence + MITRE enrichment ----------------
    # Runs whenever there is an indicator to check or an investigation was
    # performed, so MITRE context is attached to every investigated alert.
    threat_intel_result = None
    if investigation_result is not None or indicators:
        ti_agent = ThreatIntelAgent(
            llm_client=client,
            tool_registry=create_threat_intel_registry(),
            max_steps=3,
        )
        ti_request = ThreatIntelRequest(
            request_id=f"TI-{scenario_data['scenario_id']}",
            alert=alert,
            context=context,
            initial_evidence=(
                investigation_result.evidence if investigation_result is not None
                else evidence
            ),
        )
        threat_intel_result = ti_agent.enrich(ti_request)

    return {
        "scenario": scenario_key,
        "alert": alert,
        "context": context,
        "triage": triage.to_dict(),
        "investigation": investigation_result.to_dict() if investigation_result else None,
        "threat_intel": threat_intel_result.to_dict() if threat_intel_result else None,
        "expected_conclusion": scenario_data.get("expected_conclusion"),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

BAR = "=" * 72


def render_threat_intel(result: dict) -> None:
    """Render the threat intelligence + MITRE stage (Stage 4)."""
    ti = result.get("threat_intel")
    if not ti:
        return

    print(f"\n{BAR}")
    print("  STAGE 4 — THREAT INTELLIGENCE + MITRE")
    print(BAR)

    for step in ti.get("enrichment_steps", []):
        params = step.get("query_params", {}) or {}
        detail = params.get("indicator") or params.get("technique_id") or params.get("query") or ""
        print(f"  [Step {step.get('step_number')}] {step.get('tool_name')} -> {detail}")
        print(f"           {step.get('purpose')}")
        if step.get("evidence_ids"):
            print(f"           evidence: {', '.join(step['evidence_ids'])}")

    if ti.get("indicators_analyzed"):
        print("\n  Indicator reputation:")
        for ind in ti["indicators_analyzed"]:
            print(f"    - {ind.get('indicator')} [{ind.get('type')}]")
            print(f"      reputation: {ind.get('reputation')} · actor: {ind.get('threat_actor')}"
                  f" · malware: {ind.get('malware_family')}")

    if ti.get("mitre_techniques"):
        print("\n  MITRE ATT&CK mapping:")
        for t in ti["mitre_techniques"]:
            print(f"    - {t.get('technique_id')}  {t.get('technique_name')}"
                  f"  [{t.get('tactic')}]")

    if ti.get("findings"):
        print("\n  Intel findings:")
        for f in ti["findings"]:
            print(f"    - [{f.get('finding_id')}] {f.get('title')}")

    if ti.get("summary"):
        print(f"\n  Summary: {ti['summary']}")


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
        render_threat_intel(result)
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

    render_threat_intel(result)

    print(f"\n{BAR}")
    print("  STAGE 5 — FINAL REPORT")
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
