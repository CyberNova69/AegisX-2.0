"""AegisX Multi-Agent SOC Pipeline Orchestrator.

Implements the core SOC pipeline workflow:

    Incident → TriageAgent → InvestigationAgent → ThreatIntelAgent →
    Response Recommendation → (Human Approval) → Response

Each agent receives the output of the previous stage. All decisions
are logged for audit trail. No automated response execution — all
response actions require human approval.

This module is the central coordination point that connects:
- Detection → Correlation → AI Triage → Investigation → Response
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ai.llm import LLMClient
from ai.agents.schemas import TriageResult
from ai.agents.triage_agent import TriageAgent

logger = logging.getLogger("AegisX.Orchestration")


@dataclass
class WorkflowStep:
    """Record of a single step in the SOC workflow."""
    step_name: str
    agent_type: str
    status: str = "pending"  # pending | running | completed | failed | skipped
    started_at: float = 0.0
    completed_at: float = 0.0
    duration_ms: float = 0.0
    result: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def agent_name(self) -> str:
        return self.agent_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_name": self.step_name,
            "agent_type": self.agent_type,
            "agent_name": self.agent_type,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class WorkflowResult:
    """Complete result of a SOC pipeline workflow execution."""
    incident_id: str = ""
    status: str = "pending"  # pending | completed | failed | partial
    steps: List[WorkflowStep] = field(default_factory=list)
    triage_result: Optional[Dict[str, Any]] = None
    investigation_result: Optional[Dict[str, Any]] = None
    threat_intel_result: Optional[Dict[str, Any]] = None
    rag_context: Optional[str] = None
    response_recommendations: List[Dict[str, Any]] = field(default_factory=list)
    total_duration_ms: float = 0.0
    requires_human_approval: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "status": self.status,
            "steps": [s.to_dict() for s in self.steps],
            "triage_result": self.triage_result,
            "investigation_result": self.investigation_result,
            "threat_intel_result": self.threat_intel_result,
            "rag_context": self.rag_context,
            "response_recommendations": self.response_recommendations,
            "total_duration_ms": self.total_duration_ms,
            "requires_human_approval": self.requires_human_approval,
        }


class SOCWorkflow:
    """Sequential multi-agent SOC pipeline orchestrator.

    Orchestrates the Incident → Triage → Investigation → TI → Response
    pipeline. Each agent receives structured output from the previous
    stage, enabling progressive context enrichment.

    All workflow execution is synchronous and bounded. The workflow
    respects the safety invariants:
      - All response actions are advisory only
      - Human approval is required for any response execution
      - LLM output never directly authorizes destructive actions

    Usage:
        workflow = SOCWorkflow(llm_client=client)
        result = workflow.run(incident_data)
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        enable_investigation: bool = True,
        enable_threat_intel: bool = True,
        enable_rag: bool = True,
        max_investigation_steps: int = 5,
    ):
        self.llm_client = llm_client or LLMClient.from_mock()
        self.enable_investigation = enable_investigation
        self.enable_threat_intel = enable_threat_intel
        self.enable_rag = enable_rag
        self.max_investigation_steps = max_investigation_steps

    def run(self, incident_data: Any) -> WorkflowResult:
        """Execute the full SOC pipeline on an incident.

        Args:
            incident_data: Dict with 'alert', 'context', 'evidence' keys
                           (the standard AlertInput contract) OR an Incident object/dict.

        Returns:
            WorkflowResult with all agent outputs and recommendations.
        """
        start_time = time.time()

        if hasattr(incident_data, "to_triage_input"):
            incident_id_str = getattr(incident_data, "incident_id", "incident")
            incident_data = incident_data.to_triage_input()
        elif isinstance(incident_data, dict) and "alert" not in incident_data:
            from backend.api.routes.incidents import _build_triage_input
            incident_id_str = incident_data.get("incident_id", "incident")
            incident_data = _build_triage_input(incident_data)
        else:
            incident_id_str = (
                incident_data.get("alert", {}).get("title", "unknown")
                if isinstance(incident_data, dict) else "unknown"
            )

        result = WorkflowResult(
            incident_id=incident_id_str,
        )

        # Step 1: Triage
        triage_step = self._run_triage(incident_data)
        result.steps.append(triage_step)

        if triage_step.status == "completed":
            result.triage_result = triage_step.result
        else:
            result.status = "failed"
            result.total_duration_ms = (time.time() - start_time) * 1000
            return result

        # Decision gate: should we investigate?
        triage_data = triage_step.result
        should_investigate = triage_data.get("investigation_required", True)
        classification = triage_data.get("classification", "suspicious")

        # Step 2: Investigation (if warranted)
        if should_investigate and self.enable_investigation:
            inv_step = self._run_investigation(incident_data, triage_data)
            result.steps.append(inv_step)

            if inv_step.status == "completed":
                result.investigation_result = inv_step.result
                result.rag_context = inv_step.result.get("rag_context")
        else:
            skip_step = WorkflowStep(
                step_name="Investigation",
                agent_type="InvestigationAgent",
                status="skipped",
            )
            result.steps.append(skip_step)

        # Step 3: Threat Intelligence (if enabled)
        if self.enable_threat_intel:
            ti_step = self._run_threat_intel(incident_data, triage_data)
            result.steps.append(ti_step)

            if ti_step.status == "completed":
                result.threat_intel_result = ti_step.result
        else:
            skip_step = WorkflowStep(
                step_name="Threat Intelligence",
                agent_type="ThreatIntelAgent",
                status="skipped",
            )
            result.steps.append(skip_step)

        # Step 4: Generate response recommendations
        result.response_recommendations = self._generate_recommendations(
            triage_data,
            result.investigation_result,
            result.threat_intel_result,
        )

        # All responses require human approval
        result.requires_human_approval = True
        result.status = "completed"
        result.total_duration_ms = (time.time() - start_time) * 1000

        # Persist traces and audit logs via AppServices if available
        try:
            from backend.api.services import get_services
            services = get_services()
            for step in result.steps:
                if step.status != "skipped":
                    inv_id = (result.investigation_result or {}).get("investigation_id")
                    services.trace_store.add(
                        agent_type=step.agent_type,
                        investigation_id=inv_id,
                        incident_id=result.incident_id,
                        model=getattr(self.llm_client, "model", "mock"),
                        provider=getattr(self.llm_client, "provider_name", "mock"),
                        latency_ms=step.duration_ms,
                        structured_output=step.result,
                    )
            services.audit_store.add(
                action="workflow_execution",
                user_id="ai_orchestrator",
                resource_type="incident",
                resource_id=result.incident_id,
                details={
                    "status": result.status,
                    "steps_count": len(result.steps),
                    "duration_ms": result.total_duration_ms,
                    "requires_human_approval": result.requires_human_approval,
                    "recommendations_count": len(result.response_recommendations),
                },
            )
        except Exception as trace_exc:
            logger.debug("Automated trace/audit logging skipped: %s", trace_exc)

        logger.info(
            "Workflow completed: %s (%d steps, %.0fms, classification=%s)",
            result.incident_id,
            len(result.steps),
            result.total_duration_ms,
            classification,
        )

        return result

    def _run_triage(self, incident_data: Dict[str, Any]) -> WorkflowStep:
        """Execute the Triage Agent."""
        step = WorkflowStep(
            step_name="Triage",
            agent_type="TriageAgent",
            status="running",
            started_at=time.time(),
        )

        try:
            agent = TriageAgent(llm_client=self.llm_client)
            triage_result = agent.triage(incident_data)

            step.result = triage_result.to_dict()
            step.status = "completed"

            logger.info(
                "Triage completed: classification=%s, confidence=%.2f",
                triage_result.classification, triage_result.confidence,
            )

        except Exception as exc:
            step.status = "failed"
            step.error = str(exc)
            logger.error("Triage failed: %s", exc)

        step.completed_at = time.time()
        step.duration_ms = (step.completed_at - step.started_at) * 1000
        return step

    def _run_investigation(
        self,
        incident_data: Dict[str, Any],
        triage_data: Dict[str, Any],
    ) -> WorkflowStep:
        """Execute the Investigation Agent."""
        step = WorkflowStep(
            step_name="Investigation",
            agent_type="InvestigationAgent",
            status="running",
            started_at=time.time(),
        )

        try:
            from ai.agents.investigation_agent import InvestigationAgent

            # Determine registry: DB-backed when PostgreSQL is active,
            # otherwise InvestigationAgent creates a synthetic-only registry.
            tool_registry = None
            try:
                from backend.api.services import get_services as _get_svc
                _svc = _get_svc()
                if _svc.is_db_available:
                    from ai.tools.registry import create_default_registry
                    tool_registry = create_default_registry(
                        include_threat_intel=True,
                        use_database=True,
                        db_pool=_svc.db_pool,
                    )
                    logger.info("Investigation using DB-backed tool registry")
            except Exception as reg_exc:
                logger.debug("DB registry creation skipped: %s", reg_exc)

            agent = InvestigationAgent(
                llm_client=self.llm_client,
                tool_registry=tool_registry,
                max_steps=self.max_investigation_steps,
            )

            inv_data = dict(incident_data)
            if "initial_evidence" not in inv_data:
                inv_data["initial_evidence"] = inv_data.get("evidence", [])
            if "triage_result" not in inv_data:
                inv_data["triage_result"] = triage_data
            if "investigation_id" not in inv_data:
                inv_data["investigation_id"] = f"INV-{incident_data.get('alert', {}).get('id', '001')}"

            rag_context = None
            if self.enable_rag:
                try:
                    from ai.rag.rag_service import RAGService
                    title = incident_data.get("alert", {}).get("title", "")
                    rule_id = incident_data.get("alert", {}).get("rule_id")
                    rag_res = RAGService.get_instance().retrieve_for_alert(title, technique_id=rule_id)
                    rag_context = rag_res.get("formatted_context")
                    inv_data["rag_context"] = rag_context
                except Exception as rag_exc:
                    logger.debug("RAG retrieval skipped: %s", rag_exc)

            inv_result = agent.investigate(inv_data)
            step.result = inv_result.to_dict()
            if rag_context:
                step.result["rag_context"] = rag_context
            step.status = "completed"

            logger.info(
                "Investigation completed: %d steps, classification=%s",
                inv_result.total_steps, inv_result.classification,
            )

        except Exception as exc:
            step.status = "failed"
            step.error = str(exc)
            logger.error("Investigation failed: %s", exc)

        step.completed_at = time.time()
        step.duration_ms = (step.completed_at - step.started_at) * 1000
        return step

    def _run_threat_intel(
        self,
        incident_data: Dict[str, Any],
        triage_data: Dict[str, Any],
    ) -> WorkflowStep:
        """Execute the Threat Intelligence Agent."""
        step = WorkflowStep(
            step_name="Threat Intelligence",
            agent_type="ThreatIntelAgent",
            status="running",
            started_at=time.time(),
        )

        try:
            from ai.agents.threat_intel_agent import ThreatIntelAgent

            agent = ThreatIntelAgent(llm_client=self.llm_client)
            ti_data = dict(incident_data)
            if "initial_evidence" not in ti_data:
                ti_data["initial_evidence"] = ti_data.get("evidence", [])
            if "triage_result" not in ti_data:
                ti_data["triage_result"] = triage_data

            ti_result = agent.enrich(ti_data)
            step.result = ti_result.to_dict()
            step.status = "completed"

            logger.info(
                "Threat Intel completed: %d findings",
                len(ti_result.findings),
            )

        except Exception as exc:
            step.status = "failed"
            step.error = str(exc)
            logger.error("Threat Intel failed: %s", exc)

        step.completed_at = time.time()
        step.duration_ms = (step.completed_at - step.started_at) * 1000
        return step

    def _generate_recommendations(
        self,
        triage_data: Optional[Dict[str, Any]],
        investigation_data: Optional[Dict[str, Any]],
        threat_intel_data: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Generate response recommendations from agent outputs.

        These are advisory only — they are NOT automatically executed.
        Human approval is required via the response gating flow:
            AI Recommendation → Policy Validation → Human Approval →
            Response Engine → Endpoint Agent
        """
        ALLOWED_ACTIONS = {"isolate_endpoint", "kill_process", "flag_for_review"}

        def _normalize_action(act_str: str) -> str:
            act_lower = (act_str or "").lower().strip()
            if act_lower in ALLOWED_ACTIONS:
                return act_lower
            if any(w in act_lower for w in ["isolate", "contain", "quarantine", "block_network"]):
                return "isolate_endpoint"
            if any(w in act_lower for w in ["kill", "terminate", "stop_process"]):
                return "kill_process"
            return "flag_for_review"

        recommendations: List[Dict[str, Any]] = []

        if not triage_data:
            return recommendations

        classification = triage_data.get("classification", "suspicious")

        # Collect actions from triage
        for action in triage_data.get("recommended_actions", []):
            recommendations.append({
                "source": "triage_agent",
                "action": _normalize_action(action.get("action", "")),
                "priority": action.get("priority", "medium"),
                "rationale": action.get("rationale", "Triage analysis recommended action"),
                "requires_approval": True,
                "requires_human_approval": True,
                "status": "recommended",
            })

        # Add investigation-derived recommendations
        if investigation_data:
            inv_classification = investigation_data.get("classification", "")
            if inv_classification in ("likely_malicious", "confirmed_malicious"):
                recommendations.append({
                    "source": "investigation_agent",
                    "action": "isolate_endpoint" if inv_classification == "confirmed_malicious" else "flag_for_review",
                    "priority": "high",
                    "rationale": f"Investigation classified incident as {inv_classification}",
                    "requires_approval": True,
                "requires_human_approval": True,
                    "status": "recommended",
                })

        # Severity-based baseline recommendations
        if classification in ("confirmed_malicious",):
            recommendations.append({
                "source": "workflow_policy",
                "action": "isolate_endpoint",
                "priority": "immediate",
                "rationale": "Confirmed malicious activity detected — isolation recommended",
                "requires_approval": True,
                "requires_human_approval": True,
                "status": "recommended",
            })
        elif classification in ("likely_malicious",):
            recommendations.append({
                "source": "workflow_policy",
                "action": "flag_for_review",
                "priority": "high",
                "rationale": "Likely malicious activity — analyst review recommended",
                "requires_human_approval": True,
                "status": "recommended",
            })

        return recommendations
