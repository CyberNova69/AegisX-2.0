# -*- coding: utf-8 -*-
"""
AegisX Template Registry v0.3
==============================
Contains exactly 85 distinct template families across 12 domains:
- 17 benign
- 17 suspicious
- 17 likely_malicious
- 17 confirmed_malicious
- 17 insufficient_evidence
Total = 85 templates.

Split distribution:
- Train: 68 templates (80.0%)
- Validation: 9 templates (10.6%)
- Test: 8 templates (9.4%)
"""

import json
from typing import Callable, Any
from generate_dataset_v03 import EXTERNAL_IPS, SUSPICIOUS_DOMAINS
from specs_chunk1 import CHUNK_1
from specs_chunk2 import CHUNK_2
from specs_chunk3 import CHUNK_3

ALL_SPECS = CHUNK_1 + CHUNK_2 + CHUNK_3

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
            # For standard user roles, allow dynamic user selection from role pool if generic employee
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
            elif i > 0 and gen.rng.random() < 0.3 and ctx["hostname"] not in formatted_desc:
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

print(f"Total template families registered in templates_v03: {len(TEMPLATES)}")