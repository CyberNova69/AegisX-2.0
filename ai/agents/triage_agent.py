"""
AegisX SOC Alert Triage Agent
==============================

The TriageAgent is the primary alert triage analyst agent in AegisX.
It analyzes incoming security alerts, context, and evidence via the provider-independent LLMClient.
Enforces evidence grounding, output validation, confidence calibration, and structured decision generation.
"""

import json
import logging
from typing import Any, Dict, Optional, Union

from ai.agents.schemas import (
    AlertInput,
    FindingItem,
    RecommendedAction,
    TriageResult,
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    VALID_ACTION_PRIORITIES,
)
from ai.llm import LLMClient, LLMResponseError, LLMError
from ai.prompts.triage import get_triage_system_prompt, format_triage_user_prompt

logger = logging.getLogger("AegisX.TriageAgent")

class TriageAgent:
    """
    SOC Alert Triage Agent.
    Strictly uses LLMClient for LLM interactions. Does NOT import vendor SDKs.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()

    def triage(self, alert_data: Union[Dict[str, Any], AlertInput]) -> TriageResult:
        """
        Triage an incoming security alert and return an evidence-grounded TriageResult.
        
        Args:
            alert_data: Dict or AlertInput dataclass containing alert, context, and evidence.
            
        Returns:
            TriageResult: Validated, structured triage assessment.
        """
        if isinstance(alert_data, dict):
            alert_input = AlertInput.from_dict(alert_data)
            raw_input_dict = alert_data
        elif isinstance(alert_data, AlertInput):
            alert_input = alert_data
            raw_input_dict = {
                "alert": alert_input.alert,
                "context": alert_input.context,
                "evidence": alert_input.evidence,
            }
        else:
            raise ValueError("alert_data must be a dictionary or AlertInput instance.")

        valid_evt_ids = alert_input.get_valid_evidence_ids()

        # Format prompts
        system_prompt = get_triage_system_prompt()
        user_prompt = format_triage_user_prompt(raw_input_dict)

        # Expected output JSON schema hint
        schema_hint = {"type": "object"}

        logger.info(f"Triaging Alert: '{alert_input.alert.get('title')}' on host {alert_input.context.get('hostname')}")

        # Send request through provider-agnostic LLMClient
        response = self.llm_client.generate(
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            response_schema=schema_hint,
        )

        # Parse and validate the response
        structured_output = response.structured_data
        if not structured_output:
            try:
                structured_output = json.loads(response.content)
            except Exception as e:
                raise LLMResponseError(
                    f"TriageAgent failed to parse LLM response into JSON: {e}",
                    provider=response.provider,
                )

        triage_result = self._validate_and_build_result(
            raw_output=structured_output,
            valid_evt_ids=valid_evt_ids,
            response=response,
        )

        return triage_result

    def _validate_and_build_result(
        self,
        raw_output: Dict[str, Any],
        valid_evt_ids: set[str],
        response: Any,
    ) -> TriageResult:
        """Validate LLM triage output fields and evidence grounding."""

        # 1. Validate Classification
        cls = raw_output.get("classification")
        if not cls or cls not in VALID_CLASSIFICATIONS:
            raise LLMResponseError(
                f"Invalid classification '{cls}'. Must be one of: {sorted(VALID_CLASSIFICATIONS)}",
                provider=response.provider,
            )

        # 2. Validate Severity
        sev = raw_output.get("severity")
        if not sev or sev not in VALID_SEVERITIES:
            # Fallback to input alert's severity if valid
            alert_sev = valid_evt_ids.get("_alert_severity") if isinstance(valid_evt_ids, dict) else None
            if alert_sev in VALID_SEVERITIES:
                sev = alert_sev
            else:
                raise LLMResponseError(
                    f"Invalid severity '{sev}'. Must be one of: {sorted(VALID_SEVERITIES)}",
                    provider=response.provider,
                )

        # 3. Validate Confidence
        conf = raw_output.get("confidence")
        if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
            raise LLMResponseError(
                f"Invalid confidence '{conf}'. Must be a float between 0.0 and 1.0",
                provider=response.provider,
            )

        # 4. Findings & Evidence Grounding Check
        raw_findings = raw_output.get("findings", [])
        if not isinstance(raw_findings, list):
            raise LLMResponseError("findings field must be a list.", provider=response.provider)

        validated_findings: list[FindingItem] = []
        referenced_evt_ids: set[str] = set()

        for idx, item in enumerate(raw_findings):
            if not isinstance(item, dict):
                continue
            desc = item.get("finding") or item.get("description") or ""
            refs = item.get("evidence_ids") or item.get("evidence_refs") or []
            if not isinstance(refs, list):
                refs = []

            # Verify every evidence reference exists in the input alert
            for ref in refs:
                if ref not in valid_evt_ids:
                    raise LLMResponseError(
                        f"Evidence grounding failure: Finding[{idx}] references evidence ID '{ref}' which does not exist in input evidence ({valid_evt_ids}).",
                        provider=response.provider,
                    )
                referenced_evt_ids.add(ref)

            validated_findings.append(FindingItem(finding=desc, evidence_ids=refs))

        # Check top-level evidence_ids if provided
        top_refs = raw_output.get("evidence_ids", [])
        if isinstance(top_refs, list):
            for ref in top_refs:
                if ref not in valid_evt_ids:
                    raise LLMResponseError(
                        f"Evidence grounding failure: Top-level evidence_ids references '{ref}' which does not exist in input evidence.",
                        provider=response.provider,
                    )
                referenced_evt_ids.add(ref)

        # 5. Context-aware investigation_required decision
        inv_req = raw_output.get("investigation_required")
        if not isinstance(inv_req, bool):
            inv_req = self._compute_investigation_required(cls, conf)

        # 6. Validate Recommended Actions
        raw_actions = raw_output.get("recommended_actions", [])
        validated_actions: list[RecommendedAction] = []
        if isinstance(raw_actions, list):
            for act in raw_actions:
                if isinstance(act, dict):
                    action_text = act.get("action", "")
                    priority = act.get("priority", "medium")
                    if priority not in VALID_ACTION_PRIORITIES:
                        priority = "medium"
                    rationale = act.get("rationale", "")
                    if action_text:
                        validated_actions.append(
                            RecommendedAction(action=action_text, priority=priority, rationale=rationale)
                        )

        summary = raw_output.get("summary", f"Triage decision: {cls} (severity: {sev}, confidence: {conf})")

        metadata = {
            "model": response.model,
            "provider": response.provider,
            "latency_ms": response.latency_ms,
            "usage": response.usage.to_dict(),
        }

        return TriageResult(
            classification=cls,
            severity=sev,
            confidence=float(conf),
            investigation_required=inv_req,
            summary=summary,
            findings=validated_findings,
            evidence_ids=sorted(list(referenced_evt_ids)),
            recommended_actions=validated_actions,
            metadata=metadata,
        )

    @staticmethod
    def _compute_investigation_required(classification: str, confidence: float) -> bool:
        """Determines whether investigation is required based on classification and confidence."""
        if classification == "benign" and confidence >= 0.75:
            return False
        return True
