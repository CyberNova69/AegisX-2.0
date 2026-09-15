"""Field-level normalization for DatasetRecord.

Extends concepts from ai/ingestion/normalize.py but operates on DatasetRecord
which includes labels, flow features, and enrichment fields.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Optional

from ..core.types import DatasetRecord, Severity


# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------

def normalize_ip(value: Optional[str]) -> Optional[str]:
    """Normalize an IP address string. Returns None for unparseable values."""
    if value is None:
        return None
    value = value.strip()
    if not value or value in ("-", "N/A", "n/a", "none", "None", ""):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        # Try stripping leading zeros (e.g. "010.000.001.001")
        try:
            parts = value.split(".")
            if len(parts) == 4:
                cleaned = ".".join(str(int(p)) for p in parts)
                return str(ipaddress.ip_address(cleaned))
        except (ValueError, TypeError):
            pass
        return None


def normalize_port(value) -> Optional[int]:
    """Normalize a port number. Returns None for invalid values."""
    if value is None:
        return None
    try:
        port = int(float(str(value)))
        if 0 <= port <= 65535:
            return port
        return None
    except (ValueError, TypeError):
        return None


def normalize_protocol(value: Optional[str]) -> Optional[str]:
    """Normalize protocol names to lowercase canonical form."""
    if value is None:
        return None
    value = str(value).strip().lower()
    protocol_map = {
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "igmp": "igmp",
        "6": "tcp",
        "17": "udp",
        "1": "icmp",
        "0": "hopopt",
        "http": "http",
        "https": "https",
        "dns": "dns",
        "tls": "tls",
        "ssh": "ssh",
        "ftp": "ftp",
        "smtp": "smtp",
    }
    return protocol_map.get(value, value if value else None)


def normalize_timestamp(value: Optional[str]) -> Optional[str]:
    """Normalize timestamps to ISO-8601 UTC format."""
    if value is None:
        return None
    value = str(value).strip()
    if not value or value in ("-", "N/A", "n/a", "none", "None"):
        return None

    # Already ISO-8601
    if "T" in value and (value.endswith("Z") or "+" in value[10:]):
        return value

    # Common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    # Unix epoch (seconds or milliseconds)
    try:
        ts = float(value)
        if ts > 1e12:  # Milliseconds
            ts /= 1000
        if 0 < ts < 2e10:  # Reasonable range
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        pass

    return None


def normalize_severity(value: Optional[str]) -> Optional[Severity]:
    """Map various severity representations to the AegisX Severity enum."""
    if value is None:
        return None
    value = str(value).strip().lower()

    mapping = {
        "informational": Severity.INFORMATIONAL,
        "info": Severity.INFORMATIONAL,
        "0": Severity.INFORMATIONAL,
        "low": Severity.LOW,
        "1": Severity.LOW,
        "medium": Severity.MEDIUM,
        "med": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "2": Severity.MEDIUM,
        "high": Severity.HIGH,
        "3": Severity.HIGH,
        "critical": Severity.CRITICAL,
        "crit": Severity.CRITICAL,
        "4": Severity.CRITICAL,
        "urgent": Severity.CRITICAL,
    }
    return mapping.get(value)


def normalize_whitespace(value: Optional[str]) -> Optional[str]:
    """Collapse and strip whitespace."""
    if value is None:
        return None
    return re.sub(r"\s+", " ", str(value)).strip() or None


def normalize_hash(value: Optional[str]) -> Optional[str]:
    """Normalize a file hash (lowercase hex, validate length)."""
    if value is None:
        return None
    value = str(value).strip().lower()
    if not re.match(r"^[0-9a-f]+$", value):
        return None
    if len(value) in (32, 40, 64):  # MD5, SHA-1, SHA-256
        return value
    return None


# ---------------------------------------------------------------------------
# Record Normalizer
# ---------------------------------------------------------------------------

class RecordNormalizer:
    """Apply deterministic field normalization to DatasetRecord instances."""

    def normalize(self, record: DatasetRecord) -> DatasetRecord:
        """Normalize a record in-place and track actions."""
        actions: List[str] = []

        # IP addresses
        for field_name in ("src_ip", "dst_ip"):
            original = getattr(record, field_name)
            if original is not None:
                normalized = normalize_ip(original)
                if normalized != original:
                    setattr(record, field_name, normalized)
                    actions.append(f"{field_name}: normalized IP")

        # Ports
        for field_name in ("src_port", "dst_port"):
            original = getattr(record, field_name)
            if original is not None:
                normalized = normalize_port(original)
                if normalized != original:
                    setattr(record, field_name, normalized)
                    actions.append(f"{field_name}: normalized port")

        # Protocol
        if record.protocol is not None:
            original = record.protocol
            normalized = normalize_protocol(original)
            if normalized != original:
                record.protocol = normalized
                actions.append("protocol: normalized")

        # Timestamp
        if record.timestamp is not None:
            original = record.timestamp
            normalized = normalize_timestamp(original)
            if normalized != original:
                record.timestamp = normalized
                actions.append("timestamp: normalized to ISO-8601 UTC")

        # Severity
        if record.severity is not None and isinstance(record.severity, str):
            normalized = normalize_severity(record.severity)
            if normalized is not None:
                record.severity = normalized
                actions.append("severity: normalized")

        # String fields — whitespace normalization
        for field_name in ("hostname", "username", "process_name", "command_line",
                           "file_path", "source_label"):
            original = getattr(record, field_name)
            if original is not None:
                normalized = normalize_whitespace(original)
                if normalized != original:
                    setattr(record, field_name, normalized)
                    actions.append(f"{field_name}: normalized whitespace")

        # File hash
        if record.file_hash is not None:
            original = record.file_hash
            normalized = normalize_hash(original)
            if normalized != original:
                record.file_hash = normalized
                actions.append("file_hash: normalized")

        # Numeric coercion for flow fields
        for field_name in ("bytes_sent", "bytes_recv", "packets_sent", "packets_recv"):
            original = getattr(record, field_name)
            if original is not None and not isinstance(original, int):
                try:
                    coerced = int(float(str(original)))
                    if coerced >= 0:
                        setattr(record, field_name, coerced)
                        actions.append(f"{field_name}: coerced to int")
                except (ValueError, TypeError):
                    setattr(record, field_name, None)
                    actions.append(f"{field_name}: invalid, set to None")

        if record.duration is not None and not isinstance(record.duration, (int, float)):
            try:
                record.duration = float(str(record.duration))
                actions.append("duration: coerced to float")
            except (ValueError, TypeError):
                record.duration = None
                actions.append("duration: invalid, set to None")

        record.normalization_actions.extend(actions)
        from ..core.types import RecordStatus
        if record.status == RecordStatus.RAW:
            record.status = RecordStatus.NORMALIZED
        return record
