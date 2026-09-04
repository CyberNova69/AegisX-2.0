#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX Dataset Template System v0.5
===================================

Upgrades the 150 v0.4 template families with:
1. Polymorphic Linguistic Rendering (4 analytical reasoning styles for rationale, varied finding phrasing)
2. Realistic Benign Distractor Telemetry (browser, OS maintenance, Kerberos auth, cloud sync)
3. Controlled Telemetry Noise & Dynamic Pacing (non-uniform time gaps, diverse ports, process context)
4. Anti-Keyword Shortcut Protection (decouples predictive keywords across multiple classes)
5. Strict Template-Family Isolation across Train (120), Validation (15), Test (15)

Preserves exact backwards compatibility with v0.4 schema and template specs.
"""

import copy
import hashlib
import json
import random
from typing import Any

# Import template specs from v0.4
import templates_v04

EXTERNAL_IPS = templates_v04.EXTERNAL_IPS
SUSPICIOUS_DOMAINS = templates_v04.SUSPICIOUS_DOMAINS
BENIGN_DOMAINS = [
    "clients2.google.com",
    "login.microsoftonline.com",
    "update.microsoft.com",
    "edge.activity.windows.com",
    "ocsp.digicert.com",
    "cdn.office.net",
    "ctldl.windowsupdate.com",
    "archive.ubuntu.com",
    "cdn.redhat.com",
]

# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _f(desc: str, refs: list[str], sev: str = "medium") -> dict:
    return {"description": desc, "evidence_refs": refs, "severity": sev}

def _act(act: str, prio: str = "medium", rat: str = "") -> dict:
    return {"action": act, "priority": prio, "rationale": rat}

def _m(tid: str, name: str, tactic: str, refs: list[str]) -> dict:
    return {"technique_id": tid, "technique_name": name, "tactic": tactic, "evidence_refs": refs}

def _format_str(s: str, rep: dict[str, str]) -> str:
    for k, v in rep.items():
        s = s.replace(k, str(v))
    return s

def _format_obj(obj: Any, rep: dict[str, str]) -> Any:
    if isinstance(obj, str):
        return _format_str(obj, rep)
    elif isinstance(obj, dict):
        return {_format_str(k, rep): _format_obj(v, rep) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_format_obj(x, rep) for x in obj]
    return obj

# ---------------------------------------------------------------------------
# Linguistic Polymorphism Engine (Part 5)
# ---------------------------------------------------------------------------

def render_polymorphic_rationale(base_rat: str, cls: str, borderline: Any, style_idx: int, rep: dict[str, str]) -> str:
    """Generates 4 distinct analytical reasoning frameworks for the rationale."""
    formatted_base = _format_str(base_rat, rep)
    
    if style_idx == 0:
        # Style 0: Evidentiary-Deductive Framework
        lead_ins = [
            "Forensic correlation of endpoint telemetry and authentication artifacts confirms that ",
            "Analysis of chronological event logs and system telemetry demonstrates that ",
            "Technical evaluation of observed process execution and network activity indicates that ",
            "Corroborating indicators across endpoint and perimeter data sources establish that ",
        ]
        lead_h = int(hashlib.md5(formatted_base.encode("utf-8")).hexdigest()[:8], 16)
        lead = lead_ins[lead_h % len(lead_ins)]
        return f"{lead}{formatted_base[0].lower() + formatted_base[1:] if formatted_base else ''}"

    elif style_idx == 1:
        # Style 1: Threat-Hypothesis Evaluation Framework (competing hypotheses)
        if cls in ("likely_malicious", "confirmed_malicious"):
            return (
                f"Evaluation of competing hypotheses: While administrative maintenance was considered, "
                f"the presence of unauthorized artifacts refutes benign operational intent. Specifically, {formatted_base}"
            )
        elif cls == "benign":
            return (
                f"Operational baseline assessment: Activity was evaluated for potential unauthorized abuse. "
                f"Verified parameters and identity context corroborate legitimate administrative execution: {formatted_base}"
            )
        elif cls == "suspicious":
            return (
                f"Hypothesis evaluation remains inconclusive: Observed indicators deviate significantly from normal baseline, "
                f"yet direct malicious payload execution is not conclusively demonstrated: {formatted_base}"
            )
        else: # insufficient_evidence
            return (
                f"Indeterminate telemetry hypothesis: Available logs lack required contextual telemetry to validate authorization "
                f"or confirm malice. Follow-up investigation required: {formatted_base}"
            )

    elif style_idx == 2:
        # Style 2: SOC Clinical Analyst Framework (high signal-to-noise density)
        trailers = [
            " Observed tactics align directly with recognized operational tradecraft.",
            " Triage priority is assigned in accordance with observed asset criticality and execution context.",
            " Analysis establishes high confidence in the designated triage determination.",
            " Finding is substantiated by multiple independent telemetry log streams.",
        ]
        trailer_h = int(hashlib.md5(formatted_base.encode("utf-8")).hexdigest()[:8], 16)
        trailer = trailers[trailer_h % len(trailers)]
        return f"SOC Incident Assessment: {formatted_base}{trailer}"

    else:
        # Style 3: Forensic Chronology Framework
        return f"Timeline reconstruction: Systematic event progression indicates that {formatted_base[0].lower() + formatted_base[1:] if formatted_base else ''}"


def render_polymorphic_finding_description(desc: str, style_idx: int, rep: dict[str, str]) -> str:
    """Varies finding phrasing structure deterministically."""
    formatted = _format_str(desc, rep)
    if style_idx == 0:
        return formatted
    elif style_idx == 1:
        if not formatted.startswith("Detected:") and not formatted.startswith("Observed:"):
            return f"Detected: {formatted}"
        return formatted
    elif style_idx == 2:
        if not formatted.startswith("Forensic artifact confirms"):
            return f"Forensic artifact confirms: {formatted[0].lower() + formatted[1:] if formatted else ''}"
        return formatted
    else:
        return formatted

# ---------------------------------------------------------------------------
# Benign Distractor Telemetry Engine (Part 6)
# ---------------------------------------------------------------------------

def generate_benign_distractor(gen, ctx: dict, os_fam: str, ref_timestamp: str, distractor_id: str) -> dict:
    """Generates a realistic background enterprise telemetry event.
    Must NOT be cited in malicious findings."""
    rng = gen.rng
    distractor_types = [
        "browser_network", "os_servicing", "kerberos_auth", "dns_lookup", 
        "cloud_sync", "canary_verification", "av_update"
    ]
    chosen_type = rng.choice(distractor_types)

    # Offset timestamp slightly (-30s to +45s) from reference
    from datetime import datetime, timedelta, timezone
    try:
        dt = datetime.fromisoformat(ref_timestamp)
    except Exception:
        dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    delta_s = rng.randint(15, 75)
    event_dt = dt + timedelta(seconds=delta_s)
    event_ts = event_dt.isoformat()

    benign_domain = rng.choice(BENIGN_DOMAINS)
    host = ctx["hostname"]
    user = ctx["username"]

    if chosen_type == "browser_network":
        proc = "msedge.exe" if os_fam == "Windows" else "firefox"
        return {
            "id": distractor_id,
            "type": "network_connection",
            "description": f"Standard outbound HTTPS session by {proc} to {benign_domain} on {host}",
            "timestamp": event_ts,
            "raw_data": {
                "process": proc,
                "dest_domain": benign_domain,
                "dest_port": 443,
                "protocol": "TCP",
                "direction": "outbound",
            }
        }
    elif chosen_type == "os_servicing":
        proc = "tiworker.exe" if os_fam == "Windows" else "systemd-resolved"
        desc = "Windows Component Servicing routine maintenance check" if os_fam == "Windows" else "systemd-resolved internal cache refresh"
        return {
            "id": distractor_id,
            "type": "process_creation",
            "description": f"Routine OS background service {proc} initiated ({desc}) on {host}",
            "timestamp": event_ts,
            "raw_data": {
                "process": proc,
                "command_line": f"{proc} --service-check",
                "user": "SYSTEM" if os_fam == "Windows" else "root",
                "pid": rng.randint(1000, 9999),
            }
        }
    elif chosen_type == "kerberos_auth":
        logon_type = 3 if os_fam == "Windows" else "PAM"
        # Alternate phrasing for failed login vs failed logon
        auth_phrase = "Routine Kerberos ticket-granting service renewal" if rng.random() < 0.6 else "Temporary failed login attempt prior to successful session logon"
        return {
            "id": distractor_id,
            "type": "authentication",
            "description": f"{auth_phrase} for user {user} on {host}",
            "timestamp": event_ts,
            "raw_data": {
                "user": user,
                "logon_type": logon_type,
                "auth_package": "Kerberos",
                "status": "success",
            }
        }
    elif chosen_type == "dns_lookup":
        return {
            "id": distractor_id,
            "type": "dns_query",
            "description": f"Standard DNS query resolved for {benign_domain} from {host}",
            "timestamp": event_ts,
            "raw_data": {
                "query": benign_domain,
                "record_type": "A",
                "status": "NOERROR",
            }
        }
    elif chosen_type == "canary_verification":
        # Decouples 'ransomware' keyword by demonstrating anti-ransomware canary telemetry in background
        return {
            "id": distractor_id,
            "type": "file_modification",
            "description": f"Routine canary file integrity verification for ransomware protection agent on {host}",
            "timestamp": event_ts,
            "raw_data": {
                "path": "C:\\ProgramData\\SecurityAgent\\canary.dat" if os_fam == "Windows" else "/var/log/canary.log",
                "action": "verify",
                "component": "anti_ransomware_monitor",
            }
        }
    elif chosen_type == "av_update":
        # Decouples 'malicious' and 'attack' keywords by demonstrating defensive signature updates
        return {
            "id": distractor_id,
            "type": "process_creation",
            "description": f"Security agent signature update verified against known malicious threat patterns and attack vectors on {host}",
            "timestamp": event_ts,
            "raw_data": {
                "process": "MpSigStub.exe" if os_fam == "Windows" else "freshclam",
                "command_line": "MpSigStub.exe /update-signatures",
                "status": "up_to_date",
            }
        }
    else: # cloud_sync
        proc = "OneDrive.exe" if os_fam == "Windows" else "nextcloud"
        return {
            "id": distractor_id,
            "type": "network_connection",
            "description": f"Background cloud synchronization heartbeat by {proc} on {host}",
            "timestamp": event_ts,
            "raw_data": {
                "process": proc,
                "dest_port": 443,
                "status": "established",
            }
        }

# ---------------------------------------------------------------------------
# Upgraded v0.5 Template Generator Function Factory
# ---------------------------------------------------------------------------

def make_generator_fn_v05(spec):
    tid, name, domain, task, cls, split, bl, os_fam, role, user, title, sev, rule, evts, findings, rat, mitre, actions, extra = spec

    def generator_fn(gen):
        gen.reset_evt_counter()
        ctx = gen.create_context(os_family=os_fam, role=role)
        if user:
            if user == "employee01":
                ctx["username"] = gen.rng.choice(["employee01", "employee02", "employee05", "employee10", "contractor01"])
            else:
                ctx["username"] = user

        num_evts = len(evts)
        
        # Dynamic pacing / non-uniform time sequence
        ts = gen.timestamp_sequence(num_evts)
        evt_ids = [gen.next_evt_id() for _ in range(num_evts)]
        ext_ip = gen.rng.choice(EXTERNAL_IPS)
        domain_val = gen.rng.choice(SUSPICIOUS_DOMAINS)
        enc_cmd = gen.encoded_command()
        clean_hash = gen.file_hash(malicious=False)
        mal_hash = gen.file_hash(malicious=True)
        pid_val = gen.rng.randint(1024, 65535)

        rep = {
            "{domain}": domain_val,
            "{ext_ip}": ext_ip,
            "{enc}": enc_cmd,
            "{enc_cmd}": enc_cmd,
            "{clean_hash}": clean_hash,
            "{mal_hash}": mal_hash,
            "{username}": ctx["username"],
            "{hostname}": ctx["hostname"],
            "{pid}": str(pid_val),
        }

        # Determine polymorphic style (0, 1, 2, 3) for this instance
        style_idx = gen.rng.randint(0, 3)

        # Build evidence
        evidence_list = []
        for i, (etype, edesc, eraw) in enumerate(evts):
            formatted_desc = _format_str(edesc, rep)
            if i == 0 and ctx["hostname"] not in formatted_desc:
                formatted_desc = f"{formatted_desc} on {ctx['hostname']}"
            elif i > 0 and gen.rng.random() < 0.35 and ctx["hostname"] not in formatted_desc:
                formatted_desc = f"{formatted_desc} (host: {ctx['hostname']})"

            if "failed logon" in formatted_desc and gen.rng.random() < 0.5:
                formatted_desc = formatted_desc.replace("failed logon", "failed login")

            if isinstance(eraw, str):
                formatted_raw_str = _format_str(eraw, rep)
                raw_data = json.loads(formatted_raw_str)
            else:
                raw_data = _format_obj(eraw, rep)
            evidence_list.append({
                "id": evt_ids[i],
                "type": etype,
                "description": formatted_desc,
                "timestamp": ts[i],
                "raw_data": raw_data,
            })

        # Inject Benign Distractor Telemetry (Part 6)
        # Injects in ~30% of records; distractor ID is NEVER referenced in malicious findings
        has_distractor = False
        if gen.rng.random() < 0.30:
            distractor_id = gen.next_evt_id()
            ref_ts = ts[-1] if ts else "2026-01-15T12:00:00+00:00"
            distractor_event = generate_benign_distractor(gen, ctx, os_fam, ref_ts, distractor_id)
            evidence_list.append(distractor_event)
            has_distractor = True

        # Ensure evidence items are strictly sorted by timestamp for chronological integrity
        evidence_list.sort(key=lambda e: e.get("timestamp", ""))

        # Build findings (using polymorphic finding descriptions)
        finding_list = []
        for fdesc, frefs, fsev in findings:
            resolved_refs = [evt_ids[int(r.split("-")[1]) - 1] for r in frefs]
            f_desc_poly = render_polymorphic_finding_description(fdesc, style_idx, rep)
            finding_list.append(_f(f_desc_poly, resolved_refs, fsev))

        # Build actions
        action_list = []
        for aact, aprio, arat in actions:
            action_list.append(_act(_format_str(aact, rep), aprio, _format_str(arat, rep)))

        # Build mitre
        mitre_list = []
        for mtid, mname, mtactic, mrefs in mitre:
            resolved_refs = [evt_ids[int(r.split("-")[1]) - 1] for r in mrefs]
            mitre_list.append(_m(mtid, mname, mtactic, resolved_refs))

        # Polymorphic Rationale (Part 5)
        poly_rationale = render_polymorphic_rationale(rat, cls, bl, style_idx, rep)

        output_dict = {
            "classification": cls,
            "confidence": gen.confidence_for_classification(cls),
            "findings": finding_list,
            "rationale": poly_rationale,
            "recommended_actions": action_list,
        }
        if mitre_list:
            output_dict["mitre_techniques"] = mitre_list
        if extra:
            output_dict["additional_evidence_needed"] = [_format_str(x, rep) for x in extra]

        source_val = "EDR" if os_fam == "Windows" else "SIEM"
        inc_id = f"ALT-{gen.rng.randint(10000, 99999)}"

        # Natural alert title variants
        title_base = _format_str(title, rep)
        title_variants = [
            f"{title_base} [{inc_id}]",
            f"{title_base} on {ctx['hostname']} ({inc_id})",
            f"SOC Alert: {title_base} [{inc_id}]",
            f"{title_base} - {ctx['department']} ({inc_id})",
            f"Security Detection {inc_id}: {title_base}",
            f"{title_base} ({ctx['username']}) [{inc_id}]",
        ]
        chosen_title = gen.rng.choice(title_variants)

        return {
            "task": task,
            "input": {
                "alert": {
                    "title": chosen_title,
                    "severity": sev,
                    "source": source_val,
                    "timestamp": evidence_list[0]["timestamp"] if evidence_list else ts[0],
                    "rule_name": rule,
                    "rule_id": gen.rule_id(),
                },
                "context": ctx,
                "evidence": evidence_list,
            },
            "output": output_dict,
        }

    return generator_fn

# ---------------------------------------------------------------------------
# Export ALL_TEMPLATES for v0.5
# ---------------------------------------------------------------------------

TEMPLATES_V05 = []
for spec in templates_v04.ALL_SPECS:
    tid, name, domain, task, cls, split, bl, os_fam = spec[:8]
    TEMPLATES_V05.append({
        "id": tid,
        "name": name,
        "domain": domain,
        "task": task,
        "classification": cls,
        "split": split,
        "borderline": bl,
        "os_family": os_fam,
        "fn": make_generator_fn_v05(spec),
    })

print(f"Total template families registered in templates_v05: {len(TEMPLATES_V05)}")
