"""Value normalization helpers for canonical events.

Pure stdlib. Deterministic. No network, no locale-dependent parsing.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from typing import Optional


# Common timestamp formats. Most-specific first when ambiguity matters.
_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",      # 2026-09-04T12:00:00.123Z
    "%Y-%m-%dT%H:%M:%SZ",        # 2026-09-04T12:00:00Z
    "%Y-%m-%dT%H:%M:%S.%f",      # 2026-09-04T12:00:00.123
    "%Y-%m-%dT%H:%M:%S",         # 2026-09-04T12:00:00
    "%Y-%m-%d %H:%M:%S.%f",      # 2026-09-04 12:00:00.123
    "%Y-%m-%d %H:%M:%S",         # 2026-09-04 12:00:00
    "%Y/%m/%d %H:%M:%S",         # 2026/09/04 12:00:00
    "%d/%b/%Y:%H:%M:%S",         # 04/Sep/2026:12:00:00 (some syslog variants)
    "%b %d %H:%M:%S",            # Sep  4 12:00:00 (syslog, year implicit)
    "%Y-%m-%d",                  # 2026-09-04
    "%m/%d/%Y %H:%M:%S",         # 09/04/2026 12:00:00
    "%m/%d/%Y",                  # 09/04/2026
    "%d-%b-%Y %H:%M:%S",         # 04-Sep-2026 12:00:00
]


def normalize_timestamp(value: object) -> Optional[str]:
    """Best-effort conversion of an arbitrary timestamp into ISO-8601 UTC string.

    Handles: ISO-8601 (with/without Z and fractional seconds), a set of common
    datetime formats, and epoch seconds/milliseconds (int/float/str). Returns None
    if the value cannot be parsed. Never raises.
    """
    if value is None or value == "":
        return None

    # Epoch (int / float / numeric string)
    if isinstance(value, (int, float)):
        return _epoch_to_iso(float(value))
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.lstrip("-").replace(".", "", 1).isdigit():
            try:
                return _epoch_to_iso(float(s))
            except (ValueError, OverflowError):
                pass
        # ISO with possible trailing Z -> replace with +00:00 for fromisoformat
        iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
        try:
            dt = _dt.datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_dt.timezone.utc)
            return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
        for fmt in _TS_FORMATS:
            try:
                dt = _dt.datetime.strptime(s, fmt)
                return dt.replace(tzinfo=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
    return None


def _epoch_to_iso(epoch: float) -> Optional[str]:
    """Convert epoch seconds or milliseconds to ISO-8601 UTC."""
    # Heuristic: millisecond epochs are >= 1e11 (year ~1973 in ms).
    if epoch >= 1e11:
        epoch /= 1000.0
    try:
        dt = _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return None


def normalize_severity(value: object) -> Optional[str]:
    """Map free-text severity to the canonical vocabulary (or None)."""
    if value is None:
        return None
    s = str(value).strip().lower()
    mapping = {
        "info": "informational", "informational": "informational",
        "debug": "informational", "trace": "informational",
        "low": "low", "medium": "medium", "med": "medium",
        "high": "high", "hi": "high",
        "critical": "critical", "crit": "critical", "fatal": "critical",
        "warn": "medium", "warning": "medium",
        "error": "high", "err": "high",
    }
    return mapping.get(s)


def normalize_ip(value: object) -> Optional[str]:
    """Canonicalize a valid IPv4 or IPv6 address; return None if invalid.

    `ipaddress` is standard library. It handles compressed/expanded IPv6 forms
    deterministically and never performs a DNS/network lookup.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def is_valid_ip(value: object) -> bool:
    """True only for a populated, syntactically valid IPv4 or IPv6 address."""
    return normalize_ip(value) is not None


def normalize_hash(value: object) -> Optional[str]:
    """Canonicalize explicitly mapped hash values; preserve unrecognized values.

    The caller knows the field represents a hash. Hexadecimal MD5/SHA-1/SHA-256
    values are lowercased. Other values return their whitespace-normalized string
    so validation can explicitly mark them invalid rather than silently removing
    evidence from the event.
    """
    if value is None:
        return None
    cleaned = normalize_whitespace(str(value))
    return cleaned.lower() or None


def hash_algorithm(value: object) -> Optional[str]:
    """Return md5/sha1/sha256 for a valid hex hash, otherwise None."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]+", value):
        return None
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))


def normalize_protocol(value: object) -> Optional[str]:
    """Normalize known protocol spelling/case; keep unknown values for validation."""
    if value is None:
        return None
    cleaned = normalize_whitespace(str(value)).lower()
    return cleaned or None


def normalize_status(value: object) -> Optional[object]:
    """Safely normalize known boolean/status terms without coercing bare numbers.

    Numeric 1/0 can mean a code, count, or boolean. This method therefore only
    normalizes string values when the source field is semantically mapped as
    status/action/result, and returns other values unchanged.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return value
    cleaned = normalize_whitespace(value).lower()
    mapping = {
        "true": True, "false": False, "yes": True, "no": False,
        "success": "success", "successful": "success", "succeeded": "success",
        "failure": "failure", "failed": "failure", "fail": "failure",
    }
    return mapping.get(cleaned, cleaned or None)


def normalize_whitespace(value: str) -> str:
    """Trim and collapse internal whitespace without changing semantic case."""
    return " ".join(value.strip().split())


def normalize_hostname(value: object) -> Optional[str]:
    """Normalize DNS/endpoint hostname casing and surrounding whitespace."""
    if value is None:
        return None
    cleaned = normalize_whitespace(str(value))
    return cleaned.lower() or None


def normalize_domain(value: object) -> Optional[str]:
    """Normalize a domain name conservatively; no DNS lookup or guessing."""
    if value is None:
        return None
    cleaned = normalize_whitespace(str(value)).rstrip(".").lower()
    return cleaned or None
