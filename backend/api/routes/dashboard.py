"""Dashboard API routes.

Implements dashboard summary and data endpoints:
    GET /dashboard/summary — Overview statistics
    GET /dashboard/alerts — Recent alerts
    GET /dashboard/incidents — Active incidents
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisX.API.Dashboard")

try:
    from fastapi import APIRouter, Query, Depends
    from pydantic import BaseModel, Field

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

    class APIRouter:  # type: ignore
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

from backend.api.auth import require_role, Role

router = APIRouter()


# ---------------------------------------------------------------------------
# In-memory state (populated by detection/correlation engines)
# ---------------------------------------------------------------------------

_dashboard_state: Dict[str, Any] = {
    "total_events": 0,
    "total_alerts": 0,
    "total_incidents": 0,
    "active_incidents": 0,
    "alerts_by_severity": {},
    "alerts_by_rule": {},
    "recent_alerts": [],
    "recent_incidents": [],
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/dashboard/summary")
async def dashboard_summary(
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """Overview statistics for the SOC dashboard.

    Returns aggregate counts, severity distributions, and system health.
    """
    from backend.api.services import get_services
    services = get_services()

    events_total = max(_dashboard_state.get("total_events", 0), services.event_store.count)
    alerts_total = max(_dashboard_state.get("total_alerts", 0), services.alert_store.count)
    incidents_total = max(_dashboard_state.get("total_incidents", 0), services.incident_store.count)
    active_incidents = max(_dashboard_state.get("active_incidents", 0), services.incident_store.active_count)

    # Dynamic severity breakdown
    severity_counts = dict(_dashboard_state.get("alerts_by_severity", {}))
    if not severity_counts and services.alert_store.count > 0:
        for alert in services.alert_store.list_all():
            sev = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Dynamic rule breakdown
    rule_counts = dict(_dashboard_state.get("alerts_by_rule", {}))
    if not rule_counts and services.alert_store.count > 0:
        for alert in services.alert_store.list_all():
            rule_counts[alert.rule_id] = rule_counts.get(alert.rule_id, 0) + 1

    db_status = "connected" if services.is_db_available else "not_connected"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events": {
            "total": events_total,
            "last_24h": events_total if services.is_db_available else 0,
        },
        "alerts": {
            "total": alerts_total,
            "by_severity": severity_counts,
            "by_rule": rule_counts,
        },
        "incidents": {
            "total": incidents_total,
            "active": active_incidents,
        },
        "system": {
            "detection_rules": services.detection_engine.rule_count if hasattr(services, "detection_engine") else 10,
            "ai_agents": 3,  # triage, investigation, threat_intel
            "database": db_status,
            "training_status": "running_on_gpu",
            "audit_logs_recorded": services.audit_store.count if hasattr(services, "audit_store") else 0,
            "agent_traces_recorded": services.trace_store.count if hasattr(services, "trace_store") else 0,
        },
    }


@router.get("/dashboard/alerts")
async def dashboard_alerts(
    limit: int = 20,
    severity: Optional[str] = None,
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """Recent alerts for the dashboard.

    Returns the most recent alerts with optional severity filtering.
    """
    from backend.api.services import get_services
    services = get_services()

    alerts = list(_dashboard_state.get("recent_alerts", []))
    if not alerts and services.alert_store.count > 0:
        alerts = services.alert_store.to_dict_list(limit=100)

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]

    alerts = alerts[:limit]
    total = max(_dashboard_state.get("total_alerts", 0), services.alert_store.count)

    return {
        "alerts": alerts,
        "count": len(alerts),
        "total": total,
    }


@router.get("/dashboard/incidents")
async def dashboard_incidents(
    limit: int = 20,
    status: Optional[str] = None,
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """Active incidents for the dashboard.

    Returns current incidents with optional status filtering.
    """
    from backend.api.services import get_services
    services = get_services()

    incidents = list(_dashboard_state.get("recent_incidents", []))
    if not incidents and services.incident_store.count > 0:
        incidents = services.incident_store.to_dict_list(limit=100)

    if status:
        incidents = [i for i in incidents if i.get("status") == status]

    incidents = incidents[:limit]
    active_count = max(_dashboard_state.get("active_incidents", 0), services.incident_store.active_count)

    return {
        "incidents": incidents,
        "count": len(incidents),
        "active": active_count,
    }


@router.get("/dashboard/traces")
async def dashboard_traces(
    limit: int = 20,
    offset: int = 0,
    agent_type: Optional[str] = None,
    incident_id: Optional[str] = None,
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """Recent AI agent reasoning traces for audit and transparency."""
    from backend.api.services import get_services
    services = get_services()
    traces, total = services.trace_store.list_traces(
        limit=limit, offset=offset, agent_type=agent_type, incident_id=incident_id
    )
    return {
        "traces": traces,
        "count": len(traces),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/dashboard/audit-logs")
async def dashboard_audit_logs(
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    _auth: Any = Depends(require_role(Role.VIEWER)),
) -> Dict[str, Any]:
    """System audit log trail."""
    from backend.api.services import get_services
    services = get_services()
    logs, total = services.audit_store.list_logs(
        limit=limit, offset=offset, action=action, resource_type=resource_type
    )
    return {
        "audit_logs": logs,
        "count": len(logs),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# State update functions (called by detection/correlation engines)
# ---------------------------------------------------------------------------

def update_alert_stats(alert: Dict[str, Any]) -> None:
    """Update dashboard state with a new alert."""
    _dashboard_state["total_alerts"] += 1

    severity = alert.get("severity", "medium")
    _dashboard_state["alerts_by_severity"][severity] = \
        _dashboard_state["alerts_by_severity"].get(severity, 0) + 1

    rule_id = alert.get("rule_id", "unknown")
    _dashboard_state["alerts_by_rule"][rule_id] = \
        _dashboard_state["alerts_by_rule"].get(rule_id, 0) + 1

    _dashboard_state["recent_alerts"].insert(0, alert)
    _dashboard_state["recent_alerts"] = _dashboard_state["recent_alerts"][:100]


def update_incident_stats(incident: Dict[str, Any]) -> None:
    """Update dashboard state with a new incident."""
    _dashboard_state["total_incidents"] += 1
    _dashboard_state["active_incidents"] += 1

    _dashboard_state["recent_incidents"].insert(0, incident)
    _dashboard_state["recent_incidents"] = _dashboard_state["recent_incidents"][:50]


def update_event_count(count: int = 1) -> None:
    """Increment event counter."""
    _dashboard_state["total_events"] += count
