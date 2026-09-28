"""Incident management API routes.

Implements incident CRUD and AI triage/investigation triggers:
    GET  /incidents — List incidents
    GET  /incidents/{id} — Get incident detail
    POST /incidents/{id}/triage — Trigger AI triage
    POST /incidents/{id}/investigate — Trigger investigation
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisX.API.Incidents")

try:
    from fastapi import APIRouter, HTTPException, Query, Depends
    from pydantic import BaseModel, Field

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

    class APIRouter:  # type: ignore
        def post(self, *a, **kw):
            def d(f): return f
            return d

        def get(self, *a, **kw):
            def d(f): return f
            return d

    class BaseModel:  # type: ignore
        pass

    def Field(*a, **kw):  # type: ignore
        return None

    def Query(*a, **kw):  # type: ignore
        return None

    def Depends(*a, **kw):  # type: ignore
        return None

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code=500, detail=""):
            self.status_code = status_code
            self.detail = detail

from backend.api.auth import require_role, Role

router = APIRouter()


# ---------------------------------------------------------------------------
# In-memory store (replaced by database in production)
# ---------------------------------------------------------------------------

_incidents: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------

class IncidentSummary(BaseModel):
    """Compact incident summary for list views."""
    incident_id: str
    title: str
    severity: str
    status: str
    alert_count: int = 0
    is_multi_stage: bool = False
    created_at: str = ""


class TriageRequest(BaseModel):
    """Request to trigger AI triage on an incident."""
    provider: str = "mock"
    model: Optional[str] = None


class InvestigationRequest(BaseModel):
    """Request to trigger AI investigation on an incident."""
    provider: str = "mock"
    model: Optional[str] = None
    max_steps: int = 5


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """List incidents with optional filtering.

    Supports filtering by status and severity, with pagination.
    """
    incidents = list(_incidents.values())

    # Apply filters
    if status:
        incidents = [i for i in incidents if i.get("status") == status]
    if severity:
        incidents = [i for i in incidents if i.get("severity") == severity]

    # Sort by created_at descending
    incidents.sort(key=lambda i: i.get("created_at", ""), reverse=True)

    # Paginate
    total = len(incidents)
    incidents = incidents[offset:offset + limit]

    return {
        "incidents": incidents,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """Get detailed incident information including correlated alerts."""
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.post("/incidents/{incident_id}/triage")
async def triage_incident(
    incident_id: str,
    request: TriageRequest,
    _auth: Any = Depends(require_role(Role.ANALYST)),
) -> Dict[str, Any]:
    """Trigger AI triage on an incident.

    Uses the TriageAgent to analyze the incident and produce a
    classification, severity assessment, and recommended actions.

    The triage result is advisory — it does not automatically
    authorize any response actions.
    """
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        from ai.llm import LLMClient
        from ai.agents.triage_agent import TriageAgent

        # Build LLMClient with requested provider
        client = LLMClient.from_mock()  # Default to mock for safety
        agent = TriageAgent(llm_client=client)

        # Build triage input from incident
        triage_input = _build_triage_input(incident)
        result = agent.triage(triage_input)

        # Update incident with triage result
        incident["triage"] = result.to_dict()
        incident["status"] = "triaging"
        incident["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Record audit log
        try:
            from backend.api.services import get_services
            services = get_services()
            services.audit_store.add(
                action="incident_triage",
                user_id=getattr(_auth, "user_id", "analyst"),
                resource_type="incident",
                resource_id=incident_id,
                details={
                    "classification": result.classification,
                    "severity": result.severity,
                    "confidence": result.confidence,
                },
            )
        except Exception as audit_exc:
            logger.debug("Triage audit logging skipped: %s", audit_exc)

        logger.info(
            "Incident %s triaged: classification=%s, severity=%s, confidence=%.2f",
            incident_id, result.classification, result.severity, result.confidence,
        )

        return {
            "incident_id": incident_id,
            "triage_result": result.to_dict(),
            "status": "completed",
        }

    except Exception as exc:
        logger.error("Triage failed for incident %s: %s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"Triage failed: {exc}")


@router.post("/incidents/{incident_id}/investigate")
async def investigate_incident(
    incident_id: str,
    request: InvestigationRequest,
    _auth: Any = Depends(require_role(Role.ANALYST)),
) -> Dict[str, Any]:
    """Trigger AI investigation on an incident.

    Uses the InvestigationAgent to perform multi-step, evidence-grounded
    investigation using approved read-only tools.

    Investigation results are advisory — all response actions require
    human approval.
    """
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        from ai.llm import LLMClient
        from ai.agents.investigation_agent import InvestigationAgent

        client = LLMClient.from_mock()
        agent = InvestigationAgent(
            llm_client=client,
            max_steps=request.max_steps,
        )

        # Build investigation input from incident
        inv_input = _build_triage_input(incident)  # Same input structure
        result = agent.investigate(inv_input)

        # Update incident
        incident["investigation"] = result.to_dict()
        incident["status"] = "investigating"
        incident["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Record audit log and agent traces
        try:
            from backend.api.services import get_services
            services = get_services()
            services.audit_store.add(
                action="incident_investigation",
                user_id=getattr(_auth, "user_id", "analyst"),
                resource_type="incident",
                resource_id=incident_id,
                details={
                    "total_steps": result.total_steps,
                    "findings_count": len(result.findings),
                    "classification": result.classification,
                },
            )
            for step in result.steps:
                services.trace_store.add(
                    agent_type="InvestigationAgent",
                    investigation_id=f"INV-{incident_id}",
                    incident_id=incident_id,
                    model="mock",
                    provider="mock",
                    structured_output=step.to_dict() if hasattr(step, "to_dict") else {},
                )
        except Exception as audit_exc:
            logger.debug("Investigation audit logging skipped: %s", audit_exc)

        logger.info(
            "Incident %s investigated: classification=%s, steps=%d",
            incident_id, result.classification, result.total_steps,
        )

        return {
            "incident_id": incident_id,
            "investigation_result": result.to_dict(),
            "status": "completed",
        }

    except Exception as exc:
        logger.error("Investigation failed for incident %s: %s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_triage_input(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Build TriageAgent-compatible input from an incident dict."""
    alerts = incident.get("alerts", [])
    evidence = []
    for i, alert in enumerate(alerts):
        evidence.append({
            "id": f"EVT-{i + 1:06d}",
            "type": alert.get("event_type", "correlated_alert"),
            "description": (
                f"[{alert.get('severity', 'medium')}] {alert.get('title', 'Unknown alert')} "
                f"(rule={alert.get('rule_id', 'N/A')})"
            ),
        })

    if not evidence:
        evidence = [{
            "id": "EVT-000001",
            "type": "incident",
            "description": incident.get("description", "Security incident"),
        }]

    return {
        "alert": {
            "title": incident.get("title", "Security Incident"),
            "severity": incident.get("severity", "medium"),
            "source": "correlation_engine",
            "timestamp": incident.get("created_at", ""),
        },
        "context": {
            "hostname": (incident.get("affected_hosts") or ["unknown"])[0],
            "username": (incident.get("affected_users") or ["unknown"])[0],
            "ip_address": (incident.get("affected_ips") or ["0.0.0.0"])[0],
            "os": "unknown",
            "environment": "unknown",
            "asset_criticality": "unknown",
            "department": "unknown",
        },
        "evidence": evidence,
    }


def register_incident(incident_data: Dict[str, Any]) -> None:
    """Register an incident in the in-memory store (for development)."""
    incident_id = incident_data.get("incident_id")
    if incident_id:
        _incidents[incident_id] = incident_data
