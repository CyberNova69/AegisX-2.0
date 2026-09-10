"""Core types for the AegisX external dataset ingestion foundation.

Phase 1 scope: source discovery -> format detection -> parsing -> canonical event.
This module defines the canonical AegisX event model that all downstream
components (detection, correlation, AI triage, investigation, RAG, evaluation)
are expected to consume.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Format(str, Enum):
    """Supported source formats. Excel/Parquet require optional dependencies."""

    CSV = "csv"
    JSON = "json"
    JSONL = "jsonl"
    XML = "xml"
    EXCEL = "excel"
    PARQUET = "parquet"
    TEXT_LOG = "text_log"
    UNKNOWN = "unknown"


# Canonical event categories. These align with the evidence `type` enum used by
# the existing synthetic dataset (process_creation, network_connection, ...).
EVENT_TYPES = (
    "authentication",
    "network_connection",
    "dns_query",
    "process_creation",
    "file_modification",
    "registry_modification",
    "email",
    "web_request",
    "generic",
    "raw",
)

# Severity vocabulary, kept consistent with the synthetic alert schema.
SEVERITIES = ("informational", "low", "medium", "high", "critical")


@dataclass
class CanonicalEvent:
    """A normalized security event.

    The flat canonical fields (host, user, ips, process, file, ...) are filled by
    best-effort field discovery in `canonicalize.map_record`. `raw` always retains
    the original record, and `attributes` captures any extra normalized fields.
    """

    event_id: str
    source_name: str
    source_format: Format
    record_index: int = 0

    timestamp: Optional[str] = None          # ISO-8601 UTC
    event_type: str = "generic"

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
    status: Optional[object] = None

    raw: Dict[str, Any] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "event_id": self.event_id,
            "source_name": self.source_name,
            "source_format": self.source_format.value,
            "record_index": self.record_index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "hostname": self.hostname,
            "username": self.username,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "domain": self.domain,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "port": self.port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "severity": self.severity,
            "status": self.status,
            "attributes": self.attributes,
            "raw": self.raw,
        }
        return out

    def normalize(self) -> Dict[str, Any]:
        """Convenience alias returning the canonical view as a plain dict."""
        return self.to_dict()

    def validate(self) -> List[str]:
        """Light structural validation. Returns a list of human-readable issues."""
        issues: List[str] = []
        if not self.event_id:
            issues.append("missing event_id")
        if self.source_format == Format.UNKNOWN:
            issues.append("unknown source format")
        if self.event_type not in EVENT_TYPES:
            issues.append(f"unrecognized event_type: {self.event_type}")
        if self.severity and self.severity not in SEVERITIES:
            issues.append(f"unrecognized severity: {self.severity}")
        return issues

    def to_alert_input(self) -> Dict[str, Any]:
        """Bridge to the existing synthetic alert schema for downstream consumption.

        This is a FORMAT bridge only (raw -> canonical -> alert-shaped dict). It is
        intentionally NOT a detector: classification/severity are left for the
        detection/correlation layer. It exists so the canonical event can be fed
        into TriageAgent for testing the ingestion -> AI boundary.
        """
        title = self.attributes.get("title") or _derive_title(self)
        context = {
            "hostname": self.hostname or "unknown",
            "username": self.username or "unknown",
            "ip_address": self.source_ip or self.dest_ip or "0.0.0.0",
            "os": "unknown",
            "environment": "unknown",
            "asset_criticality": "unknown",
            "department": "unknown",
        }
        # The existing dataset JSON schema requires evidence IDs matching
        # EVT-<3..6 digits>. Preserve the external event_id in the canonical
        # object/raw record, and expose a deterministic schema-compatible ID here.
        evidence = [{
            "id": f"EVT-{self.record_index + 1:06d}",
            "type": self.event_type if self.event_type in (
                "process_creation", "network_connection", "file_modification",
                "registry_modification", "authentication", "dns_query", "email",
            ) else "process_creation",
            "description": self.attributes.get("description") or self.raw_description(),
        }]
        return {
            "alert": {
                "title": title,
                "severity": self.severity or "medium",
                "source": self.source_name,
                "timestamp": self.timestamp or "",
            },
            "context": context,
            "evidence": evidence,
        }

    def raw_description(self) -> str:
        parts = [f"source={self.source_name}"]
        if self.event_type:
            parts.append(f"type={self.event_type}")
        if self.hostname:
            parts.append(f"host={self.hostname}")
        if self.username:
            parts.append(f"user={self.username}")
        if self.source_ip:
            parts.append(f"src_ip={self.source_ip}")
        if self.process_name:
            parts.append(f"process={self.process_name}")
        return "; ".join(parts)


_TITLE_HINTS = {
    "authentication": "Authentication event",
    "network_connection": "Network connection observed",
    "dns_query": "DNS query observed",
    "process_creation": "Process execution observed",
    "file_modification": "File modification observed",
    "registry_modification": "Registry modification observed",
    "email": "Email event observed",
    "web_request": "Web request observed",
}


def _derive_title(event: "CanonicalEvent") -> str:
    return _TITLE_HINTS.get(event.event_type, "Security event")


# Loose indicators used during field discovery (see canonicalize.py).
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
FILE_EXT_RE = re.compile(r"\.[a-z0-9]{1,6}$", re.I)
