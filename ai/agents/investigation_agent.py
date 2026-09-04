"""
AegisX SOC Investigation Agent
===============================

Autonomous, evidence-grounded SOC alert investigation agent.
Orchestrates multi-turn investigations using approved read-only tools.
Enforces strict loop bounds, evidence grounding, and human-in-the-loop safety.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union

from ai.agents.investigation_schemas import (
    InvestigationDecision,
    InvestigationFinding,
    InvestigationRequest,
    InvestigationResult,
    InvestigationStep,
    VALID_INVESTIGATION_ACTIONS,
    VALID_INVESTIGATION_STATUSES,
)
from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    VALID_ACTION_PRIORITIES,
)
from ai.llm import LLMClient, LLMResponseError, LLMError
from ai.prompts.investigation import (
    get_investigation_system_prompt,
    format_investigation_decision_prompt,
    format_investigation_conclusion_prompt,
)
from ai.tools.registry import ToolRegistry, create_default_registry

logger = logging.getLogger("AegisX.InvestigationAgent")

class InvestigationAgent:
    """
    Safe, multi-step investigation agent.
    Never executes tools directly without registry allowlist validation.
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        tool_registry: Optional[ToolRegistry] = None,
        max_steps: int = 5,
        enable_threat_intel: bool = True,
    ):
        self.llm_client = llm_client or LLMClient()
        if tool_registry is not None:
            self.tool_registry = tool_registry
        else:
            self.tool_registry = create_default_registry(include_threat_intel=enable_threat_intel)
        self.max_steps = max(1, int(max_steps))

    def investigate(
        self,
        request_data: Union[Dict[str, Any], InvestigationRequest],
    ) -> InvestigationResult:
        """
        Execute bounded multi-step investigation loop on security alert.

        Args:
            request_data: InvestigationRequest object or dictionary.

        Returns:
            InvestigationResult: Complete evidence-grounded investigation report.
        """
        if isinstance(request_data, dict):
            request = InvestigationRequest.from_dict(request_data)
        elif isinstance(request_data, InvestigationRequest):
            request = request_data
        else:
            raise ValueError("request_data must be an InvestigationRequest or dictionary.")

        logger.info(
            f"Starting Investigation {request.investigation_id} for alert '{request.alert.get('title')}' "
            f"on host {request.context.get('hostname')}"
        )

        steps: List[InvestigationStep] = []
        accumulated_evidence: List[Dict[str, Any]] = list(request.initial_evidence)
        valid_evidence_ids: set = request.get_valid_evidence_ids()
        hallucinated_evidence_attempts: List[str] = []
        rejected_evidence_ids: List[str] = []

        system_prompt = get_investigation_system_prompt()
        status = "completed"
        early_finish_data: Optional[Dict[str, Any]] = None

        # ---------------------------------------------------------------------
        # Controlled Investigation Loop (bounded by max_steps)
        # ---------------------------------------------------------------------
        while len(steps) < self.max_steps:
            current_step_num = len(steps) + 1
            available_tools = self.tool_registry.get_tool_descriptions()

            decision_prompt = format_investigation_decision_prompt(
                request=request,
                steps=steps,
                available_tools=available_tools,
                max_steps=self.max_steps,
            )

            # Query LLM for next decision
            response = self.llm_client.generate(
                user_prompt=decision_prompt,
                system_prompt=system_prompt,
                response_schema={"type": "object"},
            )

            raw_decision = response.structured_data
            if not raw_decision:
                try:
                    raw_decision = json.loads(response.content)
                except Exception as e:
                    raise LLMResponseError(
                        f"Failed to parse LLM investigation decision as JSON: {e}",
                        provider=response.provider,
                    )

            # Check if model returned a final conclusion directly
            if "conclusion" in raw_decision and "findings" in raw_decision:
                early_finish_data = raw_decision
                break

            # Validate action
            action = raw_decision.get("action")
            if not action or action not in VALID_INVESTIGATION_ACTIONS:
                raise LLMResponseError(
                    f"Invalid investigation action '{action}'. Must be one of: {sorted(VALID_INVESTIGATION_ACTIONS)}",
                    provider=response.provider,
                )

            if action == "finish":
                logger.info(f"Investigation {request.investigation_id}: LLM chose finish at step {current_step_num}.")
                break

            # action == "investigate": validate tool selection
            tool_name = raw_decision.get("tool_name")
            if not tool_name or not isinstance(tool_name, str):
                raise LLMResponseError(
                    "Action 'investigate' requires a valid non-empty 'tool_name' string.",
                    provider=response.provider,
                )

            if not self.tool_registry.has(tool_name):
                raise LLMResponseError(
                    f"Hallucinated or unapproved tool requested: '{tool_name}'. Available: {self.tool_registry.list_tools()}",
                    provider=response.provider,
                )

            tool = self.tool_registry.get(tool_name)
            tool_input = raw_decision.get("tool_input")
            if tool_input is None:
                tool_input = {"hostname": request.context.get("hostname", "")}

            purpose = raw_decision.get("purpose", "")

            # Execute tool through registry
            logger.info(f"Step {current_step_num}: Executing approved tool '{tool_name}'")
            tool_result = tool.execute(tool_input)

            # Collect evidence IDs produced by this step
            step_evidence_ids: List[str] = []
            if tool_result.success:
                for item in tool_result.evidence:
                    if isinstance(item, dict) and "id" in item:
                        eid = item["id"]
                        step_evidence_ids.append(eid)
                        valid_evidence_ids.add(eid)
                        accumulated_evidence.append(item)

            step_record = InvestigationStep(
                step_number=current_step_num,
                tool_name=tool_name,
                tool_input=tool_input,
                purpose=purpose,
                result=tool_result.to_dict(),
                evidence_ids=step_evidence_ids,
            )
            steps.append(step_record)

            if not tool_result.success:
                logger.warning(f"Tool '{tool_name}' reported failure: {tool_result.error}")

        # Check if max_steps was reached without finish
        if len(steps) >= self.max_steps and not early_finish_data:
            logger.warning(f"Investigation {request.investigation_id} reached max_steps limit ({self.max_steps}).")
            if len(valid_evidence_ids) <= len(request.get_valid_evidence_ids()):
                status = "incomplete"

        # ---------------------------------------------------------------------
        # Conclusion Synthesis Phase
        # ---------------------------------------------------------------------
        if early_finish_data:
            conclusion_data = early_finish_data
        else:
            conclusion_prompt = format_investigation_conclusion_prompt(
                request=request,
                steps=steps,
                accumulated_evidence=accumulated_evidence,
            )

            synth_response = self.llm_client.generate(
                user_prompt=conclusion_prompt,
                system_prompt=system_prompt,
                response_schema={"type": "object"},
            )

            conclusion_data = synth_response.structured_data
            if not conclusion_data:
                try:
                    conclusion_data = json.loads(synth_response.content)
                except Exception as e:
                    raise LLMResponseError(
                        f"Failed to parse investigation synthesis as JSON: {e}",
                        provider=synth_response.provider,
                    )

        # ---------------------------------------------------------------------
        # Validation & Evidence Grounding Check
        # ---------------------------------------------------------------------
        conclusion = conclusion_data.get("conclusion")
        if not conclusion or conclusion not in VALID_CLASSIFICATIONS:
            conclusion = request.alert.get("severity", "suspicious")
            if conclusion not in VALID_CLASSIFICATIONS:
                conclusion = "suspicious"

        severity = conclusion_data.get("severity")
        if not severity or severity not in VALID_SEVERITIES:
            severity = request.alert.get("severity", "medium")
            if severity not in VALID_SEVERITIES:
                severity = "medium"

        conf = conclusion_data.get("confidence", 0.5)
        if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
            conf = 0.5

        final_status = conclusion_data.get("status", status)
        if final_status not in VALID_INVESTIGATION_STATUSES:
            final_status = status

        # Validate findings against valid_evidence_ids
        raw_findings = conclusion_data.get("findings", [])
        validated_findings: List[InvestigationFinding] = []

        if isinstance(raw_findings, list):
            for idx, f_item in enumerate(raw_findings):
                if not isinstance(f_item, dict):
                    continue
                f_id = f_item.get("finding_id", f"FIND-{idx+1:03d}")
                title = f_item.get("title", f"Finding {idx+1}")
                desc = f_item.get("description", "")
                claimed_eids = f_item.get("evidence_ids", [])
                f_conf = f_item.get("confidence", conf)
                if not (0.0 <= f_conf <= 1.0):
                    f_conf = conf

                verified_eids: List[str] = []
                for eid in claimed_eids:
                    if eid in valid_evidence_ids:
                        verified_eids.append(eid)
                    else:
                        logger.warning(
                            f"Evidence grounding failure: Finding '{f_id}' referenced non-existent evidence ID '{eid}'."
                        )
                        hallucinated_evidence_attempts.append(eid)
                        rejected_evidence_ids.append(eid)

                # Keep finding only with verified evidence IDs
                validated_findings.append(
                    InvestigationFinding(
                        finding_id=f_id,
                        title=title,
                        description=desc,
                        evidence_ids=verified_eids,
                        confidence=f_conf,
                    )
                )

        # Recommended Actions
        raw_actions = conclusion_data.get("recommended_actions", [])
        validated_actions: List[Dict[str, Any]] = []
        if isinstance(raw_actions, list):
            for act in raw_actions:
                if isinstance(act, dict) and "action" in act:
                    priority = act.get("priority", "medium")
                    if priority not in VALID_ACTION_PRIORITIES:
                        priority = "medium"
                    validated_actions.append({
                        "action": act["action"],
                        "priority": priority,
                        "rationale": act.get("rationale", ""),
                    })

        limitations = conclusion_data.get(
            "limitations",
            "Read-only synthetic investigation. No endpoint containment or destructive remediation executed."
        )

        metadata = {
            "steps_executed": len(steps),
            "max_steps": self.max_steps,
            "hallucinated_evidence_attempts": hallucinated_evidence_attempts,
            "rejected_evidence_ids": rejected_evidence_ids,
            "total_evidence_collected": len(accumulated_evidence),
        }

        return InvestigationResult(
            investigation_id=request.investigation_id,
            alert_id=str(request.alert.get("id", "UNKNOWN")),
            status=final_status,
            conclusion=conclusion,
            severity=severity,
            confidence=float(conf),
            findings=validated_findings,
            evidence=accumulated_evidence,
            investigation_steps=steps,
            recommended_actions=validated_actions,
            limitations=limitations,
            metadata=metadata,
        )
