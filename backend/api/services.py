"""AegisX Application Services.

Provides application-level singleton services for the backend API.
These services maintain state across requests and provide the correct
lifecycle for detection engine, correlation engine, and data stores.

Usage:
    from backend.api.services import get_services
    services = get_services()
    alerts = services.detection_engine.evaluate(event)
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.detection.engine import DetectionEngine
from backend.correlation.engine import CorrelationEngine
from backend.detection.models import Alert
from backend.correlation.models import Incident

logger = logging.getLogger("AegisX.Services")


# ---------------------------------------------------------------------------
# Event Stores
# ---------------------------------------------------------------------------

def _extract_event_field(event: Any, field_name: str, default: Any = None) -> Any:
    """Extract a field from NormalizedEvent, CanonicalEvent, or dictionary."""
    if hasattr(event, "event"):  # NormalizedEvent wrapping CanonicalEvent
        val = getattr(event.event, field_name, None)
        if val is not None:
            return val
    if hasattr(event, field_name):
        val = getattr(event, field_name, None)
        if val is not None:
            return val
    if isinstance(event, dict):
        return event.get(field_name, default)
    return default


class InMemoryEventStore:
    """Thread-safe in-memory event store for development and testing."""

    def __init__(self):
        self._events: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def add(self, event: Any) -> None:
        with self._lock:
            eid = _extract_event_field(event, "event_id") or str(uuid.uuid4())
            self._events[eid] = event

    def add_batch(self, events: List[Any]) -> None:
        with self._lock:
            for e in events:
                eid = _extract_event_field(e, "event_id") or str(uuid.uuid4())
                self._events[eid] = e

    def get(self, event_id: str) -> Optional[Any]:
        with self._lock:
            return self._events.get(event_id)

    def list_recent(self, limit: int = 50) -> List[Any]:
        with self._lock:
            all_events = list(self._events.values())
            return all_events[-limit:]

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._events)


class PostgresEventStore(InMemoryEventStore):
    """PostgreSQL-backed event store with local memory cache fallback."""

    def __init__(self, db_pool: Any):
        super().__init__()
        self.db_pool = db_pool

    def add(self, event: Any) -> None:
        super().add(event)
        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            eid = _extract_event_field(event, "event_id")
            try:
                etype = _extract_event_field(event, "event_type", "generic")
                hostname = _extract_event_field(event, "hostname")
                username = _extract_event_field(event, "username")
                src_ip = _extract_event_field(event, "source_ip")
                dst_ip = _extract_event_field(event, "dest_ip")
                proc_name = _extract_event_field(event, "process_name")
                cmd_line = _extract_event_field(event, "command_line")
                file_path = _extract_event_field(event, "file_path")
                file_hash = _extract_event_field(event, "file_hash")
                port = _extract_event_field(event, "port")
                dest_port = _extract_event_field(event, "dest_port")
                protocol = _extract_event_field(event, "protocol")
                timestamp = _extract_event_field(event, "timestamp") or datetime.now(timezone.utc).isoformat()

                self.db_pool.execute_sync(
                    """
                    INSERT INTO events (
                        event_id, event_type, timestamp, hostname, username,
                        source_ip, dest_ip, process_name, command_line,
                        file_path, file_hash, port, dest_port, protocol
                    ) VALUES (
                        $1, $2, $3, $4, $5,
                        $6::inet, $7::inet, $8, $9,
                        $10, $11, $12, $13, $14
                    ) ON CONFLICT (event_id) DO NOTHING
                    """,
                    eid, etype, timestamp, hostname, username,
                    src_ip if src_ip else None, dst_ip if dst_ip else None, proc_name, cmd_line,
                    file_path, file_hash, port, dest_port, protocol,
                )

                if etype in ("process_creation", "process_start") and proc_name:
                    self.db_pool.execute_sync(
                        """
                        INSERT INTO processes (
                            event_id, process_name, command_line, file_path, file_hash, username, start_time
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                        """,
                        eid, proc_name, cmd_line, file_path, file_hash, username, timestamp,
                    )

                if etype in ("network_connection", "net_connect") and (src_ip or dst_ip):
                    self.db_pool.execute_sync(
                        """
                        INSERT INTO network_events (
                            event_id, source_ip, dest_ip, source_port, dest_port, protocol, timestamp
                        ) VALUES ($1, $2::inet, $3::inet, $4, $5, $6, $7)
                        """,
                        eid, src_ip if src_ip else None, dst_ip if dst_ip else None, port, dest_port, protocol, timestamp,
                    )
            except Exception as exc:
                logger.warning("PostgresEventStore failed to persist event %s: %s", eid, exc)

    def add_batch(self, events: List[Any]) -> None:
        for e in events:
            self.add(e)


EventStore = InMemoryEventStore


# ---------------------------------------------------------------------------
# Alert Stores
# ---------------------------------------------------------------------------

class InMemoryAlertStore:
    """Thread-safe in-memory alert store.

    Development-mode persistence for alerts. In production, this can
    be swapped for PostgresAlertStore.
    """

    def __init__(self):
        self._alerts: Dict[str, Alert] = {}
        self._lock = threading.Lock()

    def add(self, alert: Alert) -> None:
        with self._lock:
            self._alerts[alert.alert_id] = alert

    def add_batch(self, alerts: List[Alert]) -> None:
        with self._lock:
            for alert in alerts:
                self._alerts[alert.alert_id] = alert

    def get(self, alert_id: str) -> Optional[Alert]:
        with self._lock:
            return self._alerts.get(alert_id)

    def list_all(self) -> List[Alert]:
        """Return all stored alerts sorted by timestamp descending.

        Used by dashboard aggregation to compute severity and rule breakdowns.
        """
        with self._lock:
            all_alerts = list(self._alerts.values())
        all_alerts.sort(key=lambda a: a.timestamp or "", reverse=True)
        return all_alerts

    def list_recent(self, limit: int = 50) -> List[Alert]:
        with self._lock:
            all_alerts = list(self._alerts.values())
            all_alerts.sort(key=lambda a: a.timestamp or "", reverse=True)
            return all_alerts[:limit]

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def to_dict_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return serializable list of recent alerts."""
        recent = self.list_recent(limit)
        result = []
        for a in recent:
            result.append({
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "hostname": a.hostname,
                "username": a.username,
                "source_ip": a.source_ip,
                "mitre_technique_id": a.mitre_technique_id,
                "mitre_tactic": a.mitre_tactic,
                "timestamp": a.timestamp,
                "source_event_id": a.source_event_id,
            })
        return result


class PostgresAlertStore(InMemoryAlertStore):
    """PostgreSQL-backed alert store with local memory cache."""

    def __init__(self, db_pool: Any):
        super().__init__()
        self.db_pool = db_pool

    def add(self, alert: Alert) -> None:
        super().add(alert)
        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                sev_val = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
                evidence_json = json.dumps(getattr(alert, "evidence", {}) or {})
                self.db_pool.execute_sync(
                    """
                    INSERT INTO alerts (
                        alert_id, title, description, severity, status,
                        rule_id, rule_name, source_event_id, hostname, username,
                        source_ip, mitre_technique_id, mitre_technique_name,
                        mitre_tactic, evidence, match_details, confidence, created_at
                    ) VALUES (
                        $1, $2, $3, $4::alert_severity, $5::alert_status,
                        $6, $7, $8, $9, $10,
                        $11::inet, $12, $13,
                        $14, $15::jsonb, $16, $17, $18
                    ) ON CONFLICT (alert_id) DO NOTHING
                    """,
                    alert.alert_id,
                    alert.title,
                    getattr(alert, "description", "") or alert.title,
                    sev_val.lower() if sev_val.lower() in ("informational", "low", "medium", "high", "critical") else "medium",
                    "new",
                    alert.rule_id,
                    alert.rule_name,
                    getattr(alert, "source_event_id", None),
                    alert.hostname,
                    alert.username,
                    alert.source_ip if alert.source_ip else None,
                    getattr(alert, "mitre_technique_id", None),
                    getattr(alert, "mitre_technique_name", None),
                    getattr(alert, "mitre_tactic", None),
                    evidence_json,
                    getattr(alert, "match_details", ""),
                    float(getattr(alert, "confidence", 1.0) or 1.0),
                    getattr(alert, "timestamp", None) or datetime.now(timezone.utc).isoformat(),
                )
            except Exception as exc:
                logger.warning("PostgresAlertStore failed to persist alert %s: %s", alert.alert_id, exc)

    def add_batch(self, alerts: List[Alert]) -> None:
        for a in alerts:
            self.add(a)


AlertStore = InMemoryAlertStore


# ---------------------------------------------------------------------------
# Incident Stores
# ---------------------------------------------------------------------------

class InMemoryIncidentStore:
    """Thread-safe in-memory incident store.

    Development-mode persistence for incidents. In production, this can
    be swapped for PostgresIncidentStore.
    """

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        self._lock = threading.Lock()

    def add(self, incident: Incident) -> None:
        with self._lock:
            self._incidents[incident.incident_id] = incident

    def add_batch(self, incidents: List[Incident]) -> None:
        with self._lock:
            for incident in incidents:
                self._incidents[incident.incident_id] = incident

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return self._incidents.get(incident_id)

    def list_all(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple:
        """Return (incidents_list, total_count)."""
        with self._lock:
            all_incidents = list(self._incidents.values())

        if status:
            all_incidents = [i for i in all_incidents if i.status == status]
        if severity:
            all_incidents = [
                i for i in all_incidents
                if (i.severity.value if hasattr(i.severity, "value") else str(i.severity)) == severity
            ]

        all_incidents.sort(key=lambda i: i.created_at or "", reverse=True)
        total = len(all_incidents)
        return all_incidents[offset:offset + limit], total

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._incidents)

    @property
    def active_count(self) -> int:
        with self._lock:
            return sum(1 for i in self._incidents.values() if i.status in ("new", "triaging", "investigating"))

    def to_dict_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return serializable list of recent incidents."""
        incidents, _ = self.list_all(limit=limit)
        result = []
        for inc in incidents:
            result.append({
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
                "status": inc.status,
                "alert_count": inc.alert_count,
                "is_multi_stage": inc.is_multi_stage,
                "affected_hosts": inc.affected_hosts,
                "affected_users": inc.affected_users,
                "attack_stages": inc.attack_stages,
                "created_at": inc.created_at,
            })
        return result


class PostgresIncidentStore(InMemoryIncidentStore):
    """PostgreSQL-backed incident store with local memory cache."""

    def __init__(self, db_pool: Any):
        super().__init__()
        self.db_pool = db_pool

    def add(self, incident: Incident) -> None:
        super().add(incident)
        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                sev_val = incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity)
                self.db_pool.execute_sync(
                    """
                    INSERT INTO incidents (
                        incident_id, title, description, severity, status,
                        alert_count, affected_hosts, affected_users, affected_ips,
                        attack_stages, mitre_techniques, is_multi_stage,
                        first_seen, last_seen, correlation_method, correlation_window_minutes,
                        created_at
                    ) VALUES (
                        $1, $2, $3, $4::incident_severity, $5::incident_status,
                        $6, $7, $8, $9,
                        $10, $11, $12,
                        $13, $14, $15, $16,
                        $17
                    ) ON CONFLICT (incident_id) DO NOTHING
                    """,
                    incident.incident_id,
                    incident.title,
                    getattr(incident, "description", "") or incident.title,
                    sev_val.lower() if sev_val.lower() in ("low", "medium", "high", "critical") else "medium",
                    "new",
                    incident.alert_count,
                    incident.affected_hosts or [],
                    incident.affected_users or [],
                    getattr(incident, "affected_ips", []) or [],
                    incident.attack_stages or [],
                    incident.mitre_techniques or [],
                    incident.is_multi_stage,
                    getattr(incident, "first_seen", None),
                    getattr(incident, "last_seen", None),
                    getattr(incident, "correlation_method", "rule_based"),
                    getattr(incident, "correlation_window_minutes", 30),
                    getattr(incident, "created_at", None) or datetime.now(timezone.utc).isoformat(),
                )
                alert_ids = getattr(incident, "alert_ids", []) or []
                for aid in alert_ids:
                    self.db_pool.execute_sync(
                        """
                        INSERT INTO incident_events (incident_id, alert_id, added_at)
                        VALUES ($1, $2, NOW())
                        ON CONFLICT (incident_id, alert_id) DO NOTHING
                        """,
                        incident.incident_id,
                        aid,
                    )
            except Exception as exc:
                logger.warning("PostgresIncidentStore failed to persist incident %s: %s", incident.incident_id, exc)

    def add_batch(self, incidents: List[Incident]) -> None:
        for inc in incidents:
            self.add(inc)


IncidentStore = InMemoryIncidentStore


# ---------------------------------------------------------------------------
# Event Counter
# ---------------------------------------------------------------------------

class EventCounter:
    """Thread-safe event counter."""

    def __init__(self):
        self._count = 0
        self._lock = threading.Lock()

    def increment(self, n: int = 1) -> int:
        with self._lock:
            self._count += n
            return self._count

    @property
    def count(self) -> int:
        with self._lock:
            return self._count


# ---------------------------------------------------------------------------
# Audit Stores
# ---------------------------------------------------------------------------

class InMemoryAuditStore:
    """Thread-safe in-memory audit log store."""

    def __init__(self):
        self._logs: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def add(
        self,
        action: str,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        log_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            lid = log_id or f"log-{uuid.uuid4().hex[:12]}"
            entry = {
                "log_id": lid,
                "user_id": user_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": details or {},
                "ip_address": ip_address,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._logs.insert(0, entry)
            if len(self._logs) > 1000:
                self._logs = self._logs[:1000]
            return entry

    def list_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> tuple:
        with self._lock:
            filtered = list(self._logs)
        if action:
            filtered = [l for l in filtered if l.get("action") == action]
        if resource_type:
            filtered = [l for l in filtered if l.get("resource_type") == resource_type]
        total = len(filtered)
        return filtered[offset:offset + limit], total

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._logs)


class PostgresAuditStore(InMemoryAuditStore):
    """PostgreSQL-backed audit log store with local cache."""

    def __init__(self, db_pool: Any):
        super().__init__()
        self.db_pool = db_pool

    def add(
        self,
        action: str,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        log_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = super().add(action, user_id, resource_type, resource_id, details, ip_address, log_id)
        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                details_json = json.dumps(entry["details"])
                self.db_pool.execute_sync(
                    """
                    INSERT INTO audit_logs (
                        log_id, user_id, action, resource_type,
                        resource_id, details, ip_address, created_at
                    ) VALUES (
                        $1, $2, $3, $4,
                        $5, $6::jsonb, $7::inet, $8
                    ) ON CONFLICT (log_id) DO NOTHING
                    """,
                    entry["log_id"],
                    entry["user_id"],
                    entry["action"],
                    entry["resource_type"],
                    entry["resource_id"],
                    details_json,
                    entry["ip_address"],
                    entry["created_at"],
                )
            except Exception as exc:
                logger.warning("PostgresAuditStore failed to insert audit log: %s", exc)
        return entry


# ---------------------------------------------------------------------------
# Agent Trace Stores
# ---------------------------------------------------------------------------

class InMemoryTraceStore:
    """Thread-safe in-memory agent execution trace store."""

    def __init__(self):
        self._traces: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def add(
        self,
        agent_type: str,
        investigation_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        latency_ms: Optional[float] = None,
        request_prompt: Optional[str] = None,
        response_content: Optional[str] = None,
        structured_output: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            tid = trace_id or f"trc-{uuid.uuid4().hex[:12]}"
            entry = {
                "trace_id": tid,
                "agent_type": agent_type,
                "investigation_id": investigation_id,
                "incident_id": incident_id,
                "model": model or "mock",
                "provider": provider or "mock",
                "input_tokens": input_tokens or 0,
                "output_tokens": output_tokens or 0,
                "latency_ms": latency_ms or 0.0,
                "request_prompt": request_prompt or "",
                "response_content": response_content or "",
                "structured_output": structured_output or {},
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._traces.insert(0, entry)
            if len(self._traces) > 1000:
                self._traces = self._traces[:1000]
            return entry

    def list_traces(
        self,
        limit: int = 50,
        offset: int = 0,
        agent_type: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> tuple:
        with self._lock:
            filtered = list(self._traces)
        if agent_type:
            filtered = [t for t in filtered if t.get("agent_type") == agent_type]
        if incident_id:
            filtered = [t for t in filtered if t.get("incident_id") == incident_id]
        total = len(filtered)
        return filtered[offset:offset + limit], total

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._traces)


class PostgresTraceStore(InMemoryTraceStore):
    """PostgreSQL-backed agent trace store with local cache."""

    def __init__(self, db_pool: Any):
        super().__init__()
        self.db_pool = db_pool

    def add(
        self,
        agent_type: str,
        investigation_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        latency_ms: Optional[float] = None,
        request_prompt: Optional[str] = None,
        response_content: Optional[str] = None,
        structured_output: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = super().add(
            agent_type=agent_type,
            investigation_id=investigation_id,
            incident_id=incident_id,
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            request_prompt=request_prompt,
            response_content=response_content,
            structured_output=structured_output,
            trace_id=trace_id,
        )
        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                struct_json = json.dumps(entry["structured_output"])
                self.db_pool.execute_sync(
                    """
                    INSERT INTO agent_traces (
                        trace_id, agent_type, investigation_id, incident_id,
                        model, provider, input_tokens, output_tokens,
                        latency_ms, request_prompt, response_content, structured_output, created_at
                    ) VALUES (
                        $1, $2, $3, $4,
                        $5, $6, $7, $8,
                        $9, $10, $11, $12::jsonb, $13
                    ) ON CONFLICT (trace_id) DO NOTHING
                    """,
                    entry["trace_id"],
                    entry["agent_type"],
                    entry["investigation_id"],
                    entry["incident_id"],
                    entry["model"],
                    entry["provider"],
                    entry["input_tokens"],
                    entry["output_tokens"],
                    entry["latency_ms"],
                    entry["request_prompt"],
                    entry["response_content"],
                    struct_json,
                    entry["created_at"],
                )
            except Exception as exc:
                logger.warning("PostgresTraceStore failed to insert agent trace: %s", exc)
        return entry


# ---------------------------------------------------------------------------
# Application Services Container
# ---------------------------------------------------------------------------

class AppServices:
    """Application-level services container.

    Holds singleton instances of detection engine, correlation engine,
    and data stores. Dynamically activates PostgreSQL persistence when
    a connected database pool is available, or gracefully falls back
    to in-memory persistence.
    """

    def __init__(self, db_pool: Optional[Any] = None):
        self.detection_engine = DetectionEngine()
        self.correlation_engine = CorrelationEngine()
        self.event_counter = EventCounter()

        if db_pool is None:
            from backend.database.connection import get_db_pool
            db_pool = get_db_pool()
        self.db_pool = db_pool
        self._db_available = bool(self.db_pool and getattr(self.db_pool, "is_initialized", False))

        if self._db_available:
            self.event_store = PostgresEventStore(self.db_pool)
            self.alert_store = PostgresAlertStore(self.db_pool)
            self.incident_store = PostgresIncidentStore(self.db_pool)
            self.audit_store = PostgresAuditStore(self.db_pool)
            self.trace_store = PostgresTraceStore(self.db_pool)
        else:
            self.event_store = InMemoryEventStore()
            self.alert_store = InMemoryAlertStore()
            self.incident_store = InMemoryIncidentStore()
            self.audit_store = InMemoryAuditStore()
            self.trace_store = InMemoryTraceStore()

        logger.info(
            "AppServices initialized (db_available=%s): %d detection rules, correlation window=%d min",
            self._db_available,
            self.detection_engine.rule_count,
            self.correlation_engine.window_minutes
            if hasattr(self.correlation_engine, "window_minutes") else 30,
        )

    def configure_db(self, db_pool: Any) -> None:
        """Configure or switch database pool at runtime."""
        self.db_pool = db_pool
        self._db_available = bool(db_pool and getattr(db_pool, "is_initialized", False))
        if self._db_available:
            self.event_store = PostgresEventStore(db_pool)
            self.alert_store = PostgresAlertStore(db_pool)
            self.incident_store = PostgresIncidentStore(db_pool)
            self.audit_store = PostgresAuditStore(db_pool)
            self.trace_store = PostgresTraceStore(db_pool)
        else:
            self.event_store = InMemoryEventStore()
            self.alert_store = InMemoryAlertStore()
            self.incident_store = InMemoryIncidentStore()
            self.audit_store = InMemoryAuditStore()
            self.trace_store = InMemoryTraceStore()

    @property
    def is_db_available(self) -> bool:
        return self._db_available


# Module-level singleton
_services: Optional[AppServices] = None
_services_lock = threading.Lock()


def get_services() -> AppServices:
    """Get or create the application services singleton."""
    global _services
    if _services is None:
        with _services_lock:
            if _services is None:
                _services = AppServices()
    return _services


def reset_services() -> None:
    """Reset services (for testing)."""
    global _services
    with _services_lock:
        _services = None

