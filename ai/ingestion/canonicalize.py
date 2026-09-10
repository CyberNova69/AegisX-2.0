"""Canonicalization: map raw record fields -> canonical AegisX event fields.

This is the "field discovery + canonical mapping" step. It is rule-based and
deterministic (no LLM), so it is cheap, CPU-friendly, and reproducible. The
mapping is keyed on normalized field names, so `SourceIP`, `source_ip`, and
`src-ip` all resolve to the same canonical field.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .normalize import normalize_ip, normalize_severity, normalize_timestamp
from .types import CanonicalEvent, EVENT_TYPES, Format

# Normalized-key -> canonical field. Keys are matched after normalization
# (lower-cased, separators stripped), so variants collapse together.
_FIELD_MAP: Dict[str, str] = {
    # timestamp
    "timestamp": "timestamp", "time": "timestamp", "datetime": "timestamp",
    "date": "timestamp", "ts": "timestamp", "eventtime": "timestamp",
    "logtime": "timestamp", "timegenerated": "timestamp", "occurrencetime": "timestamp",
    "created": "timestamp", "createdat": "timestamp", "createtime": "timestamp",
    # host / user
    "host": "hostname", "hostname": "hostname", "computer": "hostname",
    "computername": "hostname", "host_name": "hostname", "system": "hostname",
    "device": "hostname", "devicehostname": "hostname", "workstation": "hostname",
    "endpoint": "hostname", "src_host": "hostname", "srchost": "hostname",
    "dest_host": "hostname", "dsthost": "hostname",
    "user": "username", "username": "username", "user_name": "username",
    "account": "username", "accountname": "username", "account_name": "username",
    "subjectuser": "username", "userid": "username", "login": "username",
    "logonuser": "username", "targetuser": "username", "targetusername": "username",
    # ip
    "srcip": "source_ip", "sourceip": "source_ip", "src_ip": "source_ip",
    "source_ip": "source_ip", "sourceipaddress": "source_ip", "clientip": "source_ip",
    "client_ip": "source_ip", "ip": "source_ip", "ipaddress": "source_ip",
    "ip_address": "source_ip", "srcipaddr": "source_ip", "remoteaddress": "source_ip",
    "remote_address": "source_ip", "srcaddr": "source_ip",
    "dstip": "dest_ip", "destip": "dest_ip", "dst_ip": "dest_ip",
    "dest_ip": "dest_ip", "destinationip": "dest_ip", "destination_ip": "dest_ip",
    "dstipaddress": "dest_ip", "serverip": "dest_ip", "server_ip": "dest_ip",
    "dstaddr": "dest_ip", "targetip": "dest_ip",
    # domain / network
    "domain": "domain", "dns": "domain", "hostname2": "domain",
    "urlhost": "domain", "fqdn": "domain", "domainname": "domain",
    "querieddomain": "domain", "requestdomain": "domain", "query": "domain",
    # process
    "process": "process_name", "processname": "process_name",
    "process_name": "process_name", "image": "process_name",
    "imagename": "process_name", "proc": "process_name", "procname": "process_name",
    "processimage": "process_name",
    "command": "command_line", "cmd": "command_line", "commandline": "command_line",
    "command_line": "command_line", "cmdline": "command_line",
    "parentcommandline": "command_line",
    # file
    "file": "file_path", "filepath": "file_path", "file_path": "file_path",
    "path": "file_path", "filename": "file_path", "targetfilename": "file_path",
    "fullpath": "file_path", "filepath2": "file_path",
    "hash": "file_hash", "sha256": "file_hash", "sha1": "file_hash",
    "md5": "file_hash", "filehash": "file_hash", "file_hash": "file_hash",
    "hashvalue": "file_hash", "imphash": "file_hash",
    # network / port / severity / status
    "port": "port", "srcport": "port", "sourceport": "port",
    "dstport": "dest_port", "destinationport": "dest_port", "dest_port": "dest_port",
    "protocol": "protocol", "proto": "protocol", "transport": "protocol",
    "severity": "severity", "level": "severity", "loglevel": "severity",
    "eventlevel": "severity", "priority": "severity",
    "status": "status", "result": "status", "outcome": "status",
    "success": "status", "issuccess": "status",
    # event type hint
    "eventtype": "_event_type", "event_type": "_event_type",
    "action": "_event_type", "operation": "_event_type",
    "eventaction": "_event_type", "activity": "_event_type",
}

_AUTH_TOKENS = ("logon", "login", "auth", "authentication", "credential", "password", "kerberos")
_FILE_TOKENS = ("created", "modified", "written", "dropped", "deleted", "renamed", "file")
_REG_TOKENS = ("registry", "regkey", "regadd", "reg query")
_WEB_TOKENS = ("http", "url", "request", "uri", "useragent")


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


def _flatten(raw: Any, prefix: str = "", depth: int = 0) -> Dict[str, Any]:
    """Flatten nested dict/list structures into dotted keys for field discovery."""
    out: Dict[str, Any] = {}
    if depth > 4:
        return out
    if isinstance(raw, dict):
        for k, v in raw.items():
            nk = f"{prefix}{k}"
            if isinstance(v, (dict, list)):
                out.update(_flatten(v, f"{nk}.", depth + 1))
            else:
                out[nk] = v
    elif isinstance(raw, list):
        for i, v in enumerate(raw):
            out.update(_flatten(v, f"{prefix}{i}.", depth + 1))
    else:
        out[prefix.rstrip(".")] = raw
    return out


def _coerce_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        return v.strip() or None
    return str(v)


def infer_event_type(flat: Dict[str, Any]) -> str:
    """Best-effort event category from normalized field presence + hints."""
    hint = str(flat.get("_event_type", "")).lower()
    joined = " ".join(str(v).lower() for v in flat.values())
    has_src = any(flat.get(k) for k in ("source_ip", "dest_ip"))
    has_proc = any(flat.get(k) for k in ("process_name", "command_line"))
    has_file = flat.get("file_path") is not None or any(t in joined for t in _FILE_TOKENS)
    has_domain = flat.get("domain") is not None

    if hint in EVENT_TYPES:
        return hint
    if has_proc:
        return "process_creation"
    if has_src:
        return "network_connection"
    if has_domain:
        return "dns_query"
    if any(tok in joined for tok in _AUTH_TOKENS):
        return "authentication"
    if any(tok in joined for tok in _REG_TOKENS):
        return "registry_modification"
    if has_file:
        return "file_modification"
    if any(tok in joined for tok in _WEB_TOKENS):
        return "web_request"
    return "generic"


def map_record(raw: Dict[str, Any], source_name: str, record_index: int,
               source_format: Format, event_id: str) -> CanonicalEvent:
    """Map a single raw record to a CanonicalEvent."""
    flat = _flatten(raw)
    attrs: Dict[str, Any] = {}
    mapped: Dict[str, Any] = {}

    for key, value in flat.items():
        nk = _norm_key(key)
        canonical = _FIELD_MAP.get(nk)
        if canonical:
            # Prefer first non-empty value for each canonical field.
            if mapped.get(canonical) in (None, ""):
                mapped[canonical] = value
        else:
            if value not in (None, ""):
                attrs[key] = value

    # Pull typed fields out of the generic map.
    ts_raw = mapped.get("timestamp")
    severity_raw = mapped.get("severity")
    source_ip_raw = mapped.get("source_ip")
    dest_ip_raw = mapped.get("dest_ip")
    source_ip = normalize_ip(source_ip_raw)
    dest_ip = normalize_ip(dest_ip_raw)
    # Preserve explicitly mapped but invalid typed values for Task 2 validation.
    # They must not quietly disappear during Task 1 field mapping.
    if source_ip_raw not in (None, "") and source_ip is None:
        attrs["_invalid_source_ip"] = source_ip_raw
    if dest_ip_raw not in (None, "") and dest_ip is None:
        attrs["_invalid_dest_ip"] = dest_ip_raw
    raw_port = mapped.get("port")
    raw_dest_port = mapped.get("dest_port")
    port = _to_int(raw_port)
    dest_port = _to_int(raw_dest_port)
    if raw_port not in (None, "") and port is None:
        attrs["_invalid_port"] = raw_port
    if raw_dest_port not in (None, "") and dest_port is None:
        attrs["_invalid_dest_port"] = raw_dest_port

    event = CanonicalEvent(
        event_id=event_id,
        source_name=source_name,
        source_format=source_format,
        record_index=record_index,
        timestamp=normalize_timestamp(ts_raw),
        event_type=infer_event_type(mapped),
        hostname=_coerce_str(mapped.get("hostname")),
        username=_coerce_str(mapped.get("username")),
        source_ip=source_ip,
        dest_ip=dest_ip,
        domain=_coerce_str(mapped.get("domain")),
        process_name=_coerce_str(mapped.get("process_name")),
        command_line=_coerce_str(mapped.get("command_line")),
        file_path=_coerce_str(mapped.get("file_path")),
        file_hash=_coerce_str(mapped.get("file_hash")),
        port=port,
        dest_port=dest_port,
        protocol=_coerce_str(mapped.get("protocol")),
        severity=normalize_severity(severity_raw),
        status=mapped.get("status"),
        raw=raw,
        attributes=attrs,
    )
    return event


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return None
