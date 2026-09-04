"""
AegisX Threat Intelligence Agent (ThreatIntelAgent)
===================================================

Specialized autonomous threat intelligence enrichment agent.
Extracts candidate indicators from security alerts, queries controlled
intelligence tools via ToolRegistry, enforces strict evidence grounding,
and produces structured ThreatIntelResult reports.

100% read-only, CPU-safe, and offline.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Union

from ai.agents.threat_intel_schemas import (
    ThreatIntelDecision,
    ThreatIntelFinding,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatIntelStep,
    VALID_THREAT_INTEL_ACTIONS,
    VALID_THREAT_INTEL_STATUSES,
)
from ai.llm import LLMClient, LLMResponseError
from ai.prompts.threat_intel import (
    format_threat_intel_decision_prompt,
    format_threat_intel_synthesis_prompt,
    load_threat_intel_system_prompt,
)
from ai.tools.registry import ToolRegistry, create_threat_intel_registry

logger = logging.getLogger("AegisX.ThreatIntelAgent")

# Regex patterns for autonomous indicator discovery
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
MITRE_TID_REGEX = re.compile(r"\bT1[0-9]{3}(?:\.[0-9]{3})?\b")

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"override\s+(?:safety|rules)", re.IGNORECASE),
    re.compile(r"new\s+(?:system\s+)?instruction", re.IGNORECASE),
]

class ThreatIntelAgent:
    """
    Autonomous intelligence enrichment agent.
    Safely queries threat_intel and mitre_lookup tools to enrich SOC alerts.
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        tool_registry: Optional[ToolRegistry] = None,
        max_steps: int = 5,
    ):
        self.llm_client = llm_client or LLMClient()
        self.tool_registry = tool_registry or create_threat_intel_registry()
        self.max_steps = max(1, int(max_steps))

    def extract_candidate_indicators(self, request: ThreatIntelRequest) -> List[Dict[str, str]]:
        """
        Discover candidate IPs, hashes, and technique IDs from context and evidence.
        """
        found: List[Dict[str, str]] = []
        seen: Set[str] = set()

        def add_ind(ind: str, itype: str, source: str):
            clean = ind.strip().lower()
            if clean not in seen and len(clean) > 3:
                seen.add(clean)
                found.append({"indicator": ind.strip(), "type": itype, "source": source})

        # 1. Explicit request indicators
        for ind in request.indicators:
            add_ind(ind, "explicit", "request.indicators")

        # 2. Alert search
        alert_blob = f"{request.alert.get('title', '')} {request.alert.get('description', '')} {json.dumps(request.alert)}"
        for ip in IPV4_REGEX.findall(alert_blob):
            if ip not in {"0.0.0.0", "255.255.255.255"}:
                add_ind(ip, "ip", "alert")
        for h in SHA256_REGEX.findall(alert_blob):
            add_ind(h, "hash", "alert")
        for tid in MITRE_TID_REGEX.findall(alert_blob):
            add_ind(tid, "technique", "alert")

        # 3. Context search
        for k, v in request.context.items():
            if isinstance(v, str):
                if IPV4_REGEX.match(v) and v not in {"0.0.0.0", "255.255.255.255"}:
                    add_ind(v, "ip", f"context.{k}")
                elif SHA256_REGEX.match(v):
                    add_ind(v, "hash", f"context.{k}")

        # 4. Evidence search
        for evt in request.initial_evidence:
            desc = evt.get("description", "")
            raw_str = json.dumps(evt.get("raw_data", {}))
            blob = f"{desc} {raw_str}"

            for ip in IPV4_REGEX.findall(blob):
                if ip not in {"0.0.0.0", "255.255.255.255"}:
                    add_ind(ip, "ip", f"evidence[{evt.get('id', 'item')}]")
            for h in SHA256_REGEX.findall(blob):
                add_ind(h, "hash", f"evidence[{evt.get('id', 'item')}]")
            for tid in MITRE_TID_REGEX.findall(blob):
                add_ind(tid, "technique", f"evidence[{evt.get('id', 'item')}]")

        return found

    def enrich(
        self,
        request_data: Union[Dict[str, Any], ThreatIntelRequest],
    ) -> ThreatIntelResult:
        """
        Execute bounded autonomous intelligence enrichment.
        """
        if isinstance(request_data, dict):
            request = ThreatIntelRequest.from_dict(request_data)
        elif isinstance(request_data, ThreatIntelRequest):
            request = request_data
        else:
            raise ValueError("request_data must be a ThreatIntelRequest or dictionary.")

        logger.info(f"Starting threat intelligence enrichment for request '{request.request_id}'")

        # Extract indicators
        candidate_indicators = self.extract_candidate_indicators(request)

        # Handle empty/missing context gracefully
        if not candidate_indicators and not request.alert and not request.initial_evidence:
            return ThreatIntelResult(
                request_id=request.request_id,
                status="insufficient_evidence",
                confidence=0.0,
                summary="Insufficient alert context or indicators provided for threat intelligence enrichment.",
                findings=[],
                indicators_analyzed=[],
                mitre_techniques=[],
                evidence_ids=[],
                enrichment_steps=[],
                recommendations=[],
                metadata={"reason": "empty_context"},
            )

        steps: List[ThreatIntelStep] = []
        accumulated_evidence: List[Dict[str, Any]] = list(request.initial_evidence)
        valid_evidence_ids: Set[str] = request.get_valid_evidence_ids()
        indicators_analyzed: List[Dict[str, Any]] = []
        mitre_techniques: List[Dict[str, Any]] = []
        prompt_injection_warnings: List[str] = []

        system_prompt = load_threat_intel_system_prompt()
        status = "completed"
        step_number = 1

        # ---------------------------------------------------------------------
        # Bounded Enrichment Loop
        # ---------------------------------------------------------------------
        while step_number <= self.max_steps:
            decision_prompt = format_threat_intel_decision_prompt(
                request=request,
                steps=steps,
                accumulated_evidence=accumulated_evidence,
                candidate_indicators=candidate_indicators,
                step_number=step_number,
                max_steps=self.max_steps,
            )

            try:
                response = self.llm_client.generate(
                    user_prompt=decision_prompt,
                    system_prompt=system_prompt,
                    response_schema={"type": "object"},
                )
            except Exception as e:
                logger.error(f"LLM failure during threat intel step {step_number}: {e}")
                status = "failed"
                break

            decision_data = response.structured_data
            if not decision_data:
                try:
                    decision_data = json.loads(response.content)
                except Exception as e:
                    raise LLMResponseError(
                        f"Failed to parse threat intel decision as JSON: {e}",
                        provider=response.provider,
                    )

            action = decision_data.get("action")
            if action not in VALID_THREAT_INTEL_ACTIONS:
                raise LLMResponseError(
                    f"Invalid threat intelligence action '{action}'. "
                    f"Must be one of {sorted(VALID_THREAT_INTEL_ACTIONS)}",
                    provider=response.provider,
                )

            # Check for terminal actions
            if action == "finish":
                logger.info(f"Threat intelligence enrichment finished voluntarily at step {step_number}.")
                break
            elif action == "insufficient_evidence":
                logger.info(f"Threat intelligence enrichment concluded insufficient evidence at step {step_number}.")
                status = "insufficient_evidence"
                break

            # Execute tool queries
            if action == "query_threat_intel":
                indicator = decision_data.get("indicator")
                if not indicator or not isinstance(indicator, str):
                    raise LLMResponseError(
                        "Action 'query_threat_intel' requires a valid string 'indicator'.",
                        provider=response.provider,
                    )

                if not self.tool_registry.has("threat_intel"):
                    raise LLMResponseError(
                        "Tool 'threat_intel' is not available in ToolRegistry.",
                        provider=response.provider,
                    )

                tool = self.tool_registry.get("threat_intel")
                tool_input = {
                    "indicator": indicator.strip(),
                    "indicator_type": decision_data.get("indicator_type", "unknown"),
                }
                tool_res = tool.execute(tool_input)

                step_evidence_ids = []
                if tool_res.success and tool_res.evidence:
                    for evt in tool_res.evidence:
                        eid = evt.get("id")
                        if eid:
                            step_evidence_ids.append(eid)
                            valid_evidence_ids.add(eid)
                            accumulated_evidence.append(evt)

                if tool_res.data:
                    indicators_analyzed.append({
                        "indicator": indicator,
                        "type": tool_input["indicator_type"],
                        "reputation": tool_res.data.get("reputation", "unknown"),
                        "threat_actor": tool_res.data.get("threat_actor", "Unknown"),
                        "malware_family": tool_res.data.get("malware_family", "None"),
                    })

                steps.append(
                    ThreatIntelStep(
                        step_number=step_number,
                        action=action,
                        tool_name="threat_intel",
                        query_params=tool_input,
                        purpose=decision_data.get("reason", f"Enrich {indicator}"),
                        result=tool_res.to_dict(),
                        evidence_ids=step_evidence_ids,
                    )
                )

            elif action == "query_mitre":
                tid = decision_data.get("technique_id")
                query = decision_data.get("query")
                if not tid and not query:
                    raise LLMResponseError(
                        "Action 'query_mitre' requires 'technique_id' or 'query'.",
                        provider=response.provider,
                    )

                if not self.tool_registry.has("mitre_lookup"):
                    raise LLMResponseError(
                        "Tool 'mitre_lookup' is not available in ToolRegistry.",
                        provider=response.provider,
                    )

                tool = self.tool_registry.get("mitre_lookup")
                tool_input = {"technique_id": tid, "query": query}
                tool_res = tool.execute(tool_input)

                step_evidence_ids = []
                if tool_res.success and tool_res.evidence:
                    for evt in tool_res.evidence:
                        eid = evt.get("id")
                        if eid:
                            step_evidence_ids.append(eid)
                            valid_evidence_ids.add(eid)
                            accumulated_evidence.append(evt)

                if tool_res.data and "techniques" in tool_res.data:
                    for t in tool_res.data["techniques"][:3]:
                        mitre_techniques.append({
                            "technique_id": t.get("technique_id"),
                            "technique_name": t.get("technique_name"),
                            "tactic": t.get("tactic"),
                        })

                steps.append(
                    ThreatIntelStep(
                        step_number=step_number,
                        action=action,
                        tool_name="mitre_lookup",
                        query_params=tool_input,
                        purpose=decision_data.get("reason", f"MITRE lookup for {tid or query}"),
                        result=tool_res.to_dict(),
                        evidence_ids=step_evidence_ids,
                    )
                )

            # Audit prompt injection attempts in retrieved results
            for evt in tool_res.evidence or []:
                raw_text = f"{evt.get('description', '')} {json.dumps(evt.get('raw_data', {}))}"
                for pattern in INJECTION_PATTERNS:
                    if pattern.search(raw_text):
                        warning_msg = f"Potential prompt injection detected in retrieved evidence {evt.get('id')}"
                        logger.warning(warning_msg)
                        prompt_injection_warnings.append(warning_msg)

            step_number += 1

        # ---------------------------------------------------------------------
        # Final Report Synthesis
        # ---------------------------------------------------------------------
        synth_prompt = format_threat_intel_synthesis_prompt(
            request=request,
            steps=steps,
            accumulated_evidence=accumulated_evidence,
            valid_evidence_ids=valid_evidence_ids,
        )

        synth_res = self.llm_client.generate(
            user_prompt=synth_prompt,
            system_prompt=system_prompt,
            response_schema={"type": "object"},
        )

        synth_data = synth_res.structured_data
        if not synth_data:
            try:
                synth_data = json.loads(synth_res.content)
            except Exception as e:
                raise LLMResponseError(
                    f"Failed to parse threat intel synthesis as JSON: {e}",
                    provider=synth_res.provider,
                )

        # Evidence Grounding Audit
        raw_findings = synth_data.get("findings", [])
        grounded_findings: List[ThreatIntelFinding] = []
        hallucinated_evidence_attempts: List[str] = []

        for idx, f_item in enumerate(raw_findings):
            if not isinstance(f_item, dict):
                continue

            f_id = f_item.get("finding_id", f"TI-FIND-{idx+1:02d}")
            title = f_item.get("title", "Threat Intelligence Observation")
            desc = f_item.get("description", "")
            category = f_item.get("category", "reputation")
            indicator = f_item.get("indicator")
            f_conf = f_item.get("confidence", 0.7)
            if not isinstance(f_conf, (int, float)) or not (0.0 <= f_conf <= 1.0):
                f_conf = 0.5

            raw_ev_ids = f_item.get("evidence_ids", [])
            verified_ids = []
            for eid in raw_ev_ids:
                eid_str = str(eid).strip()
                if eid_str in valid_evidence_ids:
                    verified_ids.append(eid_str)
                else:
                    logger.warning(
                        f"Evidence grounding violation: Finding '{f_id}' cited unverified ID '{eid_str}'."
                    )
                    hallucinated_evidence_attempts.append(eid_str)

            grounded_findings.append(
                ThreatIntelFinding(
                    finding_id=f_id,
                    title=title,
                    description=desc,
                    category=category,
                    evidence_ids=verified_ids,
                    indicator=indicator,
                    confidence=float(f_conf),
                )
            )

        overall_conf = synth_data.get("confidence", 0.5)
        if not isinstance(overall_conf, (int, float)) or not (0.0 <= overall_conf <= 1.0):
            overall_conf = 0.5

        final_status = synth_data.get("status", status)
        if final_status not in VALID_THREAT_INTEL_STATUSES:
            final_status = status

        return ThreatIntelResult(
            request_id=request.request_id,
            status=final_status,
            confidence=float(overall_conf),
            summary=synth_data.get("summary", "Threat intelligence correlation completed."),
            findings=grounded_findings,
            indicators_analyzed=indicators_analyzed or synth_data.get("indicators_analyzed", []),
            mitre_techniques=mitre_techniques or synth_data.get("mitre_techniques", []),
            evidence_ids=sorted(list(valid_evidence_ids)),
            enrichment_steps=steps,
            recommendations=synth_data.get("recommendations", []),
            metadata={
                "hallucinated_evidence_attempts": hallucinated_evidence_attempts,
                "prompt_injection_warnings": prompt_injection_warnings,
                "candidate_indicators_found": [c["indicator"] for c in candidate_indicators],
                "steps_executed": len(steps),
            },
        )
