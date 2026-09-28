"""AegisX Database-Backed Investigation Tools.

Provides PostgreSQL/Repository-backed versions of the core investigation tools:
    - DBProcessActivityTool ('process_activity')
    - DBNetworkActivityTool ('network_activity')
    - DBAuthenticationTool  ('authentication')
    - DBFileActivityTool    ('file_activity')
    - DBRelatedAlertsTool   ('related_alerts')

Safety Invariants:
    - 100% read-only queries (SELECT only, no DDL/DML)
    - Fully parameterized queries (no SQL string formatting/injection)
    - Hard bounded result size (default 20, hard maximum 100)
    - Deterministic evidence ID generation (PROC-xxx, NET-xxx, AUTH-xxx, FILE-xxx, ALT-xxx)
    - Seamless fallback to synthetic telemetry fixtures when database is not connected
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ai.tools.base import BaseInvestigationTool, ToolResult
from ai.tools.synthetic_data import query_synthetic_telemetry

logger = logging.getLogger("AegisX.Tools.Database")

MAX_RESULT_LIMIT = 100
DEFAULT_RESULT_LIMIT = 20


class DBProcessActivityTool(BaseInvestigationTool):
    """Database-backed process execution tool querying the processes schema table."""

    def __init__(self, db_pool: Optional[Any] = None):
        self.db_pool = db_pool

    @property
    def name(self) -> str:
        return "process_activity"

    @property
    def description(self) -> str:
        return "Inspect process execution telemetry, parent/child relationships, command lines, and hashes via database query."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "username": {"type": "string", "description": "User context to query"},
                "process_name": {"type": "string", "description": "Process executable name filter"},
                "limit": {"type": "integer", "description": "Max results to return (max 100, default 20)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "processes": {"type": "array", "items": {"type": "object"}},
                "count": {"type": "integer"},
                "source": {"type": "string"},
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(
                success=False,
                tool_name=self.name,
                error="Invalid tool input: expected dictionary.",
            )

        limit = min(int(tool_input.get("limit", DEFAULT_RESULT_LIMIT)), MAX_RESULT_LIMIT)
        hostname = tool_input.get("hostname")
        username = tool_input.get("username")
        process_name = tool_input.get("process_name")

        # Check for active database pool
        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                query = """
                SELECT p.process_id, p.process_name, p.command_line, p.file_path,
                       p.file_hash, p.username, p.pid, p.parent_pid, p.start_time,
                       e.hostname
                FROM processes p
                LEFT JOIN events e ON p.event_id = e.event_id
                WHERE ($1::text IS NULL OR e.hostname ILIKE $1)
                  AND ($2::text IS NULL OR p.username ILIKE $2)
                  AND ($3::text IS NULL OR p.process_name ILIKE ('%' || $3 || '%'))
                ORDER BY p.start_time DESC
                LIMIT $4;
                """
                rows = self.db_pool.fetch_sync(query, hostname, username, process_name, limit)
                if rows:
                    records = []
                    for r in rows:
                        records.append({
                            "evidence_id": f"PROC-{str(r['process_id'])[:8].upper()}",
                            "process_id": str(r["process_id"]),
                            "process_name": r["process_name"],
                            "command_line": r["command_line"],
                            "file_path": r["file_path"],
                            "sha256": r["file_hash"],
                            "username": r["username"],
                            "hostname": r.get("hostname") or hostname or "unknown",
                            "pid": r["pid"],
                            "parent_pid": r["parent_pid"],
                            "timestamp": str(r["start_time"]) if r["start_time"] else None,
                        })
                    return ToolResult(
                        success=True,
                        tool_name=self.name,
                        data={"processes": records, "count": len(records), "source": "postgresql_runtime"},
                        evidence=records,
                        metadata={"query_params": tool_input, "bounded_limit": limit},
                    )
            except Exception as exc:
                logger.warning("DBProcessActivityTool database query failed: %s; falling back to synthetic", exc)

        # Clean fallback to synthetic fixtures
        events = query_synthetic_telemetry("process", tool_input)
        if process_name:
            events = [e for e in events if process_name.lower() in e.get("process_name", "").lower()]
        events = events[:limit]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"processes": events, "count": len(events), "source": "synthetic_fallback"},
            evidence=events,
            metadata={"query_params": tool_input, "bounded_limit": limit},
        )


class DBNetworkActivityTool(BaseInvestigationTool):
    """Database-backed network connection tool querying the network_events schema table."""

    def __init__(self, db_pool: Optional[Any] = None):
        self.db_pool = db_pool

    @property
    def name(self) -> str:
        return "network_activity"

    @property
    def description(self) -> str:
        return "Inspect outbound and inbound network connections, destinations, ports, and protocols via database query."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "dest_ip": {"type": "string", "description": "Destination IP address filter"},
                "dest_port": {"type": "integer", "description": "Destination port filter"},
                "limit": {"type": "integer", "description": "Max results to return (max 100, default 20)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "connections": {"type": "array", "items": {"type": "object"}},
                "count": {"type": "integer"},
                "source": {"type": "string"},
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(success=False, tool_name=self.name, error="Invalid input")

        limit = min(int(tool_input.get("limit", DEFAULT_RESULT_LIMIT)), MAX_RESULT_LIMIT)
        hostname = tool_input.get("hostname")
        dest_ip = tool_input.get("dest_ip")
        dest_port = tool_input.get("dest_port")

        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                query = """
                SELECT n.network_event_id, n.source_ip::text AS source_ip, n.dest_ip::text AS dest_ip,
                       n.source_port, n.dest_port, n.protocol, n.timestamp, e.hostname
                FROM network_events n
                LEFT JOIN events e ON n.event_id = e.event_id
                WHERE ($1::text IS NULL OR e.hostname ILIKE $1)
                  AND ($2::text IS NULL OR n.dest_ip::text = $2)
                  AND ($3::int IS NULL OR n.dest_port = $3)
                ORDER BY n.timestamp DESC
                LIMIT $4;
                """
                rows = self.db_pool.fetch_sync(query, hostname, dest_ip, dest_port, limit)
                if rows:
                    records = []
                    for r in rows:
                        records.append({
                            "evidence_id": f"NET-{str(r['network_event_id'])[:8].upper()}",
                            "network_event_id": str(r["network_event_id"]),
                            "source_ip": r["source_ip"],
                            "dest_ip": r["dest_ip"],
                            "source_port": r["source_port"],
                            "dest_port": r["dest_port"],
                            "protocol": r["protocol"],
                            "hostname": r.get("hostname") or hostname or "unknown",
                            "timestamp": str(r["timestamp"]) if r["timestamp"] else None,
                        })
                    return ToolResult(
                        success=True,
                        tool_name=self.name,
                        data={"connections": records, "count": len(records), "source": "postgresql_runtime"},
                        evidence=records,
                        metadata={"query_params": tool_input, "bounded_limit": limit},
                    )
            except Exception as exc:
                logger.warning("DBNetworkActivityTool database query failed: %s; falling back to synthetic", exc)

        events = query_synthetic_telemetry("network", tool_input)
        events = events[:limit]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"connections": events, "count": len(events), "source": "synthetic_fallback"},
            evidence=events,
            metadata={"query_params": tool_input, "bounded_limit": limit},
        )


class DBAuthenticationTool(BaseInvestigationTool):
    """Database-backed authentication event tool querying logon activity."""

    def __init__(self, db_pool: Optional[Any] = None):
        self.db_pool = db_pool

    @property
    def name(self) -> str:
        return "authentication"

    @property
    def description(self) -> str:
        return "Inspect authentication attempts, logon types, success/failure status, and source IPs via database query."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Account username to inspect"},
                "hostname": {"type": "string", "description": "Endpoint hostname filter"},
                "status": {"type": "string", "description": "Filter by 'success' or 'failure'"},
                "limit": {"type": "integer", "description": "Max results to return (max 100, default 20)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "events": {"type": "array", "items": {"type": "object"}},
                "count": {"type": "integer"},
                "source": {"type": "string"},
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(success=False, tool_name=self.name, error="Invalid input")

        limit = min(int(tool_input.get("limit", DEFAULT_RESULT_LIMIT)), MAX_RESULT_LIMIT)
        username = tool_input.get("username")
        hostname = tool_input.get("hostname")
        status_filter = tool_input.get("status")

        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                query = """
                SELECT event_id, event_type, hostname, username, source_ip::text AS source_ip,
                       severity::text AS severity, timestamp, raw, attributes
                FROM events
                WHERE event_type IN ('authentication', 'logon', 'auth')
                  AND ($1::text IS NULL OR username ILIKE $1)
                  AND ($2::text IS NULL OR hostname ILIKE $2)
                ORDER BY timestamp DESC
                LIMIT $3;
                """
                rows = self.db_pool.fetch_sync(query, username, hostname, limit)
                if rows:
                    records = []
                    for r in rows:
                        attrs = r.get("attributes") or {}
                        raw = r.get("raw") or {}
                        rec_status = attrs.get("status") or raw.get("status") or "success"
                        if status_filter and rec_status.lower() != status_filter.lower():
                            continue
                        records.append({
                            "evidence_id": f"AUTH-{str(r['event_id'])[:8].upper()}",
                            "event_id": str(r["event_id"]),
                            "username": r["username"],
                            "hostname": r["hostname"],
                            "source_ip": r["source_ip"],
                            "status": rec_status,
                            "timestamp": str(r["timestamp"]) if r["timestamp"] else None,
                        })
                    if records:
                        return ToolResult(
                            success=True,
                            tool_name=self.name,
                            data={"events": records, "count": len(records), "source": "postgresql_runtime"},
                            evidence=records,
                            metadata={"query_params": tool_input, "bounded_limit": limit},
                        )
            except Exception as exc:
                logger.warning("DBAuthenticationTool database query failed: %s; falling back to synthetic", exc)

        events = query_synthetic_telemetry("authentication", tool_input)
        events = events[:limit]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"events": events, "count": len(events), "source": "synthetic_fallback"},
            evidence=events,
            metadata={"query_params": tool_input, "bounded_limit": limit},
        )


class DBFileActivityTool(BaseInvestigationTool):
    """Database-backed file activity tool querying file modification events."""

    def __init__(self, db_pool: Optional[Any] = None):
        self.db_pool = db_pool

    @property
    def name(self) -> str:
        return "file_activity"

    @property
    def description(self) -> str:
        return "Inspect file modifications, creation, deletions, paths, and hashes via database query."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "file_path": {"type": "string", "description": "File path prefix or exact match"},
                "extension": {"type": "string", "description": "File extension filter (e.g. '.exe', '.locked')"},
                "limit": {"type": "integer", "description": "Max results to return (max 100, default 20)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "files": {"type": "array", "items": {"type": "object"}},
                "count": {"type": "integer"},
                "source": {"type": "string"},
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(success=False, tool_name=self.name, error="Invalid input")

        limit = min(int(tool_input.get("limit", DEFAULT_RESULT_LIMIT)), MAX_RESULT_LIMIT)
        hostname = tool_input.get("hostname")
        file_path = tool_input.get("file_path")
        extension = tool_input.get("extension")

        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                query = """
                SELECT event_id, event_type, hostname, username, file_path, file_hash, timestamp
                FROM events
                WHERE file_path IS NOT NULL
                  AND ($1::text IS NULL OR hostname ILIKE $1)
                  AND ($2::text IS NULL OR file_path ILIKE ('%' || $2 || '%'))
                  AND ($3::text IS NULL OR file_path ILIKE ('%' || $3))
                ORDER BY timestamp DESC
                LIMIT $4;
                """
                rows = self.db_pool.fetch_sync(query, hostname, file_path, extension, limit)
                if rows:
                    records = []
                    for r in rows:
                        records.append({
                            "evidence_id": f"FILE-{str(r['event_id'])[:8].upper()}",
                            "event_id": str(r["event_id"]),
                            "file_path": r["file_path"],
                            "file_hash": r["file_hash"],
                            "hostname": r["hostname"],
                            "username": r["username"],
                            "timestamp": str(r["timestamp"]) if r["timestamp"] else None,
                        })
                    return ToolResult(
                        success=True,
                        tool_name=self.name,
                        data={"files": records, "count": len(records), "source": "postgresql_runtime"},
                        evidence=records,
                        metadata={"query_params": tool_input, "bounded_limit": limit},
                    )
            except Exception as exc:
                logger.warning("DBFileActivityTool database query failed: %s; falling back to synthetic", exc)

        events = query_synthetic_telemetry("file", tool_input)
        events = events[:limit]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"files": events, "count": len(events), "source": "synthetic_fallback"},
            evidence=events,
            metadata={"query_params": tool_input, "bounded_limit": limit},
        )


class DBRelatedAlertsTool(BaseInvestigationTool):
    """Database-backed alert correlation tool querying the alerts schema table."""

    def __init__(self, db_pool: Optional[Any] = None):
        self.db_pool = db_pool

    @property
    def name(self) -> str:
        return "related_alerts"

    @property
    def description(self) -> str:
        return "Query past alerts associated with a hostname, username, or MITRE technique ID from the alerts store."

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target endpoint hostname"},
                "username": {"type": "string", "description": "Target username"},
                "mitre_technique_id": {"type": "string", "description": "MITRE ATT&CK technique filter"},
                "limit": {"type": "integer", "description": "Max results to return (max 100, default 20)"},
            },
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "alerts": {"type": "array", "items": {"type": "object"}},
                "count": {"type": "integer"},
                "source": {"type": "string"},
            },
        }

    def execute(self, tool_input: Dict[str, Any]) -> ToolResult:
        if not isinstance(tool_input, dict):
            return ToolResult(success=False, tool_name=self.name, error="Invalid input")

        limit = min(int(tool_input.get("limit", DEFAULT_RESULT_LIMIT)), MAX_RESULT_LIMIT)
        hostname = tool_input.get("hostname")
        username = tool_input.get("username")
        mitre_tech = tool_input.get("mitre_technique_id")

        if self.db_pool and getattr(self.db_pool, "is_initialized", False):
            try:
                query = """
                SELECT alert_id, title, severity::text AS severity, rule_id, rule_name,
                       hostname, username, mitre_technique_id, mitre_technique_name, created_at
                FROM alerts
                WHERE ($1::text IS NULL OR hostname ILIKE $1)
                  AND ($2::text IS NULL OR username ILIKE $2)
                  AND ($3::text IS NULL OR mitre_technique_id ILIKE $3)
                ORDER BY created_at DESC
                LIMIT $4;
                """
                rows = self.db_pool.fetch_sync(query, hostname, username, mitre_tech, limit)
                if rows:
                    records = []
                    for r in rows:
                        records.append({
                            "evidence_id": f"ALT-{str(r['alert_id'])[:8].upper()}",
                            "alert_id": str(r["alert_id"]),
                            "title": r["title"],
                            "severity": r["severity"],
                            "rule_id": r["rule_id"],
                            "rule_name": r["rule_name"],
                            "hostname": r["hostname"],
                            "username": r["username"],
                            "mitre_technique_id": r["mitre_technique_id"],
                            "mitre_technique_name": r["mitre_technique_name"],
                            "created_at": str(r["created_at"]) if r["created_at"] else None,
                        })
                    return ToolResult(
                        success=True,
                        tool_name=self.name,
                        data={"alerts": records, "count": len(records), "source": "postgresql_runtime"},
                        evidence=records,
                        metadata={"query_params": tool_input, "bounded_limit": limit},
                    )
            except Exception as exc:
                logger.warning("DBRelatedAlertsTool database query failed: %s; falling back to synthetic", exc)

        events = query_synthetic_telemetry("alerts", tool_input)
        events = events[:limit]

        return ToolResult(
            success=True,
            tool_name=self.name,
            data={"alerts": events, "count": len(events), "source": "synthetic_fallback"},
            evidence=events,
            metadata={"query_params": tool_input, "bounded_limit": limit},
        )
