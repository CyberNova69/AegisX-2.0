"""Telemetry ingestion API routes.

Implements the contracted telemetry endpoints:
    POST /telemetry/ingest - Accept telemetry from endpoint agents

The ingestion route normalizes incoming events, runs them through the
detection engine, correlates alerts into incidents, persists results,
and updates dashboard state.

Pipeline:
    POST /telemetry/ingest -> CanonicalEvent -> EventProcessor ->
    NormalizedEvent -> DetectionEngine -> Alert(s) -> CorrelationEngine ->
    Incident(s) -> Persistence -> Dashboard Update
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisX.API.Telemetry")

try:
    from fastapi import APIRouter, HTTPException, Depends
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

    def Depends(*a, **kw):  # type: ignore
        return None

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code=500, detail=""):
            self.status_code = status_code
            self.detail = detail

router = APIRouter()


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class TelemetryEvent(BaseModel):
    """Incoming telemetry event from an endpoint agent."""
    event_type: str = Field(default="generic", description="Event type (process_creation, network_connection, etc.)")
    timestamp: Optional[str] = Field(default=None, description="ISO-8601 timestamp")
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    domain: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    raw: Dict[str, Any] = Field(default_factory=dict)


class TelemetryBatch(BaseModel):
    """Batch of telemetry events from an endpoint agent."""
    endpoint_id: Optional[str] = None
    events: List[TelemetryEvent] = Field(default_factory=list)


class IngestResponse(BaseModel):
    """Response from telemetry ingestion."""
    accepted: int = 0
    rejected: int = 0
    alerts_generated: int = 0
    incidents_created: int = 0
    event_ids: List[str] = Field(default_factory=list)


from backend.api.auth import require_role, Role

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/telemetry/ingest", response_model=IngestResponse)
async def ingest_telemetry(
    batch: TelemetryBatch,
    _auth: Any = Depends(require_role(Role.AGENT)),
) -> Dict[str, Any]:
    """Ingest telemetry events from endpoint agents.

    Full pipeline:
        Endpoint Agent -> POST /telemetry/ingest -> Normalization ->
        Detection -> Alert(s) -> Correlation -> Incident(s) ->
        Persistence -> Dashboard Update

    Returns ingestion results with generated alert and incident counts.
    """
    from ai.ingestion.types import CanonicalEvent, Format
    from ai.ingestion.processing import EventProcessor
    from backend.api.services import get_services
    from backend.api.routes.dashboard import update_alert_stats, update_incident_stats, update_event_count

    services = get_services()
    processor = EventProcessor()

    accepted = 0
    rejected = 0
    all_alerts = []
    event_ids: List[str] = []

    for i, event_data in enumerate(batch.events):
        event_id = f"tel-{uuid.uuid4().hex[:12]}"

        try:
            # Build CanonicalEvent from telemetry
            canonical = CanonicalEvent(
                event_id=event_id,
                source_name=f"endpoint:{batch.endpoint_id or 'unknown'}",
                source_format=Format.JSON,
                record_index=i,
                timestamp=event_data.timestamp or datetime.now(timezone.utc).isoformat(),
                event_type=event_data.event_type,
                hostname=event_data.hostname,
                username=event_data.username,
                source_ip=event_data.source_ip,
                dest_ip=event_data.dest_ip,
                domain=event_data.domain,
                process_name=event_data.process_name,
                command_line=event_data.command_line,
                file_path=event_data.file_path,
                file_hash=event_data.file_hash,
                port=event_data.port,
                dest_port=event_data.dest_port,
                protocol=event_data.protocol,
                severity=event_data.severity,
                status=event_data.status or event_data.attributes.get("status"),
                raw=event_data.raw,
                attributes=event_data.attributes,
            )

            # Process through normalization + validation + dedup
            outcome = processor.process_one(canonical)

            if outcome.status == "trusted":
                accepted += 1
                event_ids.append(event_id)

                # Persist normalized event into event store
                services.event_store.add(outcome.normalized)

                # Run through detection engine (application-level singleton)
                alerts = services.detection_engine.evaluate(outcome.normalized)
                all_alerts.extend(alerts)

                # Persist alerts and update dashboard
                services.alert_store.add_batch(alerts)
                for alert in alerts:
                    update_alert_stats({
                        "alert_id": alert.alert_id,
                        "title": alert.title,
                        "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                        "rule_id": alert.rule_id,
                        "rule_name": alert.rule_name,
                        "hostname": alert.hostname,
                        "username": alert.username,
                        "mitre_technique_id": alert.mitre_technique_id,
                        "timestamp": alert.timestamp,
                    })

            else:
                rejected += 1
                logger.debug(
                    "Event %s rejected: status=%s", event_id, outcome.status
                )

        except Exception as exc:
            rejected += 1
            logger.warning("Failed to process event %d: %s", i, exc)

    # Update event counter
    update_event_count(accepted)
    services.event_counter.increment(accepted)

    # Correlate accumulated alerts into incidents
    incidents_created = 0
    if all_alerts:
        incidents = services.correlation_engine.correlate(all_alerts)
        services.incident_store.add_batch(incidents)
        incidents_created = len(incidents)

        # Register incidents in the incidents route store and dashboard
        from backend.api.routes.incidents import register_incident
        for incident in incidents:
            inc_dict = incident.to_dict() if hasattr(incident, "to_dict") else {}
            register_incident(inc_dict)
            update_incident_stats(inc_dict)

        logger.info(
            "Telemetry batch processed: accepted=%d, rejected=%d, alerts=%d, incidents=%d",
            accepted, rejected, len(all_alerts), incidents_created,
        )

    return {
        "accepted": accepted,
        "rejected": rejected,
        "alerts_generated": len(all_alerts),
        "incidents_created": incidents_created,
        "event_ids": event_ids,
    }
