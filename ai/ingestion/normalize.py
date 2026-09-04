"""Value normalization helpers for canonical events.

Pure stdlib. Deterministic. No network, no locale-dependent parsing.
"""

from __future__ import annotations

import datetime as _dt
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
    """Return the value if it looks like an IPv4 address, else None."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    parts = s.split(".")
    if len(parts) != 4:
        return None
    try:
        return s if all(0 <= int(p) <= 255 for p in parts) else None
    except ValueError:
        return None


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
