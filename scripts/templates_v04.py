# -*- coding: utf-8 -*-
"""
AegisX Template Registry v0.4
==============================
Contains exactly 150 distinct template families across 18 security domains:
- 30 benign (20.0%)
- 30 suspicious (20.0%)
- 30 likely_malicious (20.0%)
- 30 confirmed_malicious (20.0%)
- 30 insufficient_evidence (20.0%)
Total = 150 templates.

Operating System distribution:
- 105 Windows (70.0%)
- 45 Linux (30.0%)

Split distribution:
- Train: 120 templates (80.0%, 24 per class, 84 Windows / 36 Linux)
- Validation: 15 templates (10.0%, 3 per class, 11 Windows / 4 Linux)
- Test: 15 templates (10.0%, 3 per class, 10 Windows / 5 Linux)

Zero template overlap between splits:
Templates(Train) ∩ Templates(Val) = ∅
Templates(Train) ∩ Templates(Test) = ∅
Templates(Val) ∩ Templates(Test) = ∅
"""

import json
from typing import Any
from specs_chunk1 import CHUNK_1
from specs_chunk2 import CHUNK_2
from specs_chunk3 import CHUNK_3
from specs_chunk4_v04 import CHUNK_4
from specs_chunk5_v04 import CHUNK_5

ALL_SPECS = CHUNK_1 + CHUNK_2 + CHUNK_3 + CHUNK_4 + CHUNK_5

EXTERNAL_IPS = [
    "203.0.113.10", "203.0.113.25", "203.0.113.99", "198.51.100.15",
    "198.51.100.42", "185.220.101.33", "91.234.56.78", "45.33.32.156",
    "194.26.29.112", "185.190.140.22", "195.123.245.8", "192.0.2.77",
    "198.18.0.15", "203.0.113.140", "198.51.100.99"
]

SUSPICIOUS_DOMAINS = [
    "update-service-cdn.xyz", "secure-login-verify.top", "cloud-sync-backup.ru",
    "microsoft-update-center.tk", "office365-verify.pw", "corp-vpn-access.cc",
    "security-patch-update.ga", "api-telemetry-metrics.cc", "system-diagnostic-cache.biz",
    "fast-content-deliver.net", "global-telemetry-relay.info", "external-auth-validate.org"
]

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

def make_generator_fn(spec):
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

        # Build evidence
        evidence_list = []
        for i, (etype, edesc, eraw) in enumerate(evts):
            formatted_desc = _format_str(edesc, rep)
            # Ensure host and process context are grounded across instances
            if i == 0 and ctx["hostname"] not in formatted_desc:
                formatted_desc = f"{formatted_desc} on {ctx['hostname']}"
            elif i > 0 and gen.rng.random() < 0.35 and ctx["hostname"] not in formatted_desc:
                formatted_desc = f"{formatted_desc} (host: {ctx['hostname']})"

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

        # Build findings
        finding_list = []
        for fdesc, frefs, fsev in findings:
            resolved_refs = [evt_ids[int(r.split("-")[1]) - 1] for r in frefs]
            finding_list.append(_f(_format_str(fdesc, rep), resolved_refs, fsev))

        # Build actions
        action_list = []
        for aact, aprio, arat in actions:
            action_list.append(_act(_format_str(aact, rep), aprio, _format_str(arat, rep)))

        # Build mitre
        mitre_list = []
        for mtid, mname, mtactic, mrefs in mitre:
            resolved_refs = [evt_ids[int(r.split("-")[1]) - 1] for r in mrefs]
            mitre_list.append(_m(mtid, mname, mtactic, resolved_refs))

        output_dict = {
            "classification": cls,
            "confidence": gen.confidence_for_classification(cls),
            "findings": finding_list,
            "rationale": _format_str(rat, rep),
            "recommended_actions": action_list,
        }
        if mitre_list:
            output_dict["mitre_techniques"] = mitre_list
        if extra:
            output_dict["additional_evidence_needed"] = [_format_str(x, rep) for x in extra]

        source_val = "EDR" if os_fam == "Windows" else "SIEM"
        inc_id = f"ALT-{gen.rng.randint(10000, 99999)}"

        # Varied, natural SOC alert titles with distinct incident identifiers
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
                    "timestamp": ts[0],
                    "rule_name": rule,
                    "rule_id": gen.rule_id(),
                },
                "context": ctx,
                "evidence": evidence_list,
            },
            "output": output_dict,
        }

    return generator_fn

TEMPLATES = []
for spec in ALL_SPECS:
    tid, name, domain, task, cls, split, bl, os_fam = spec[:8]
    TEMPLATES.append({
        "id": tid,
        "name": name,
        "domain": domain,
        "task": task,
        "classification": cls,
        "split": split,
        "borderline": bl,
        "os_family": os_fam,
        "fn": make_generator_fn(spec),
    })

print(f"Total template families registered in templates_v04: {len(TEMPLATES)}")
