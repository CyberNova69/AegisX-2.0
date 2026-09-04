#!/usr/bin/env python3
"""
AegisX Template Builder (v0.3)
Combines Chunk 1, 2, and 3, validates all metrics, and generates `scripts/templates_v03.py`.
"""

import json
from collections import Counter
from pathlib import Path

# Import the 3 specification chunks
from specs_chunk1 import CHUNK_1
from specs_chunk2 import CHUNK_2
from specs_chunk3 import CHUNK_3

ALL_SPECS = CHUNK_1 + CHUNK_2 + CHUNK_3

def validate_specs():
    print(f"Total templates in spec: {len(ALL_SPECS)}")
    assert len(ALL_SPECS) == 85, f"Expected 85 templates, got {len(ALL_SPECS)}"

    # Check unique IDs
    ids = [s[0] for s in ALL_SPECS]
    assert len(ids) == len(set(ids)), "Duplicate template IDs detected!"

    # Check classifications
    cls_counts = Counter(s[4] for s in ALL_SPECS)
    print("Classifications:", dict(cls_counts))
    for c in ["benign", "suspicious", "likely_malicious", "confirmed_malicious", "insufficient_evidence"]:
        assert cls_counts[c] == 17, f"Expected 17 for {c}, got {cls_counts[c]}"

    # Check splits
    split_counts = Counter(s[5] for s in ALL_SPECS)
    print("Splits:", dict(split_counts))
    assert split_counts["train"] == 68, f"Expected 68 train, got {split_counts['train']}"
    assert split_counts["val"] == 9, f"Expected 9 val, got {split_counts['val']}"
    assert split_counts["test"] == 8, f"Expected 8 test, got {split_counts['test']}"

    # Check borderline
    bl_count = sum(1 for s in ALL_SPECS if s[6] is not None)
    print(f"Borderline templates: {bl_count}")
    assert bl_count >= 30, f"Expected >= 30 borderline templates, got {bl_count}"

    # Check OS distribution
    os_counts = Counter(s[7] for s in ALL_SPECS)
    print("OS counts:", dict(os_counts))
    assert os_counts["Windows"] >= 50, "Expected >= 50 Windows templates"
    assert os_counts["Linux"] >= 15, "Expected >= 15 Linux templates"

    print("All specification checks PASSED!\n")

def generate_code():
    out_file = Path(__file__).resolve().parent / "templates_v03.py"
    lines = [
        '# -*- coding: utf-8 -*-',
        '"""',
        'AegisX Template Registry v0.3',
        '==============================',
        'Contains exactly 85 distinct template families across 12 domains:',
        '- 17 benign',
        '- 17 suspicious',
        '- 17 likely_malicious',
        '- 17 confirmed_malicious',
        '- 17 insufficient_evidence',
        'Total = 85 templates.',
        '"""',
        '',
        'from typing import Callable, Any',
        '',
        'TEMPLATES = []',
        '',
        'def register_template(tid, name, domain, task, classification, split, borderline, os_family):',
        '    def decorator(fn: Callable[[Any], dict]):',
        '        TEMPLATES.append({',
        '            "id": tid,',
        '            "name": name,',
        '            "domain": domain,',
        '            "task": task,',
        '            "classification": classification,',
        '            "split": split,',
        '            "borderline": borderline,',
        '            "os_family": os_family,',
        '            "fn": fn,',
        '        })',
        '        return fn',
        '    return decorator',
        '',
        'def _f(desc: str, refs: list[str], sev: str = "medium") -> dict:',
        '    return {"description": desc, "evidence_refs": refs, "severity": sev}',
        '',
        'def _act(act: str, prio: str = "medium", rat: str = "") -> dict:',
        '    return {"action": act, "priority": prio, "rationale": rat}',
        '',
        'def _m(tid: str, name: str, tactic: str, refs: list[str]) -> dict:',
        '    return {"technique_id": tid, "technique_name": name, "tactic": tactic, "evidence_refs": refs}',
        '',
    ]

    for spec in ALL_SPECS:
        tid, name, domain, task, cls, split, bl, os_fam, role, user, title, sev, rule, evts, findings, rat, mitre, actions, extra = spec

        bl_str = f'"{bl}"' if bl else 'None'
        lines.append(f'@register_template("{tid}", "{name}", "{domain}", "{task}", "{cls}", "{split}", {bl_str}, "{os_fam}")')
        fn_name = f"_tf_{tid.replace('-', '_').lower()}"
        lines.append(f'def {fn_name}(gen):')
        lines.append('    gen.reset_evt_counter()')
        lines.append(f'    ctx = gen.create_context(os_family="{os_fam}", role="{role}")')
        if user:
            lines.append(f'    ctx["username"] = "{user}"')
        
        num_evts = len(evts)
        lines.append(f'    ts = gen.timestamp_sequence({num_evts})')
        evt_ids = [f"e{i+1}" for i in range(num_evts)]
        lines.append(f'    {", ".join(evt_ids)} = {", ".join(["gen.next_evt_id()"] * num_evts)}')
        lines.append('    ext_ip = gen.rng.choice(EXTERNAL_IPS)')
        lines.append('    domain = gen.rng.choice(SUSPICIOUS_DOMAINS)')
        lines.append('    enc_cmd = gen.encoded_command()')
        lines.append('    clean_hash = gen.file_hash(malicious=False)')
        lines.append('    mal_hash = gen.file_hash(malicious=True)')
        lines.append('    hostname = ctx["hostname"]')
        lines.append('    username = ctx["username"]')
        lines.append('')

        # Build evidence items
        evt_items = []
        for i, (etype, edesc, eraw) in enumerate(evts):
            eid_var = evt_ids[i]
            # Replace format strings in description
            desc_expr = f'f"{edesc}"'.replace("{domain}", '{domain}').replace("{ext_ip}", '{ext_ip}').replace("{username}", '{username}').replace("{hostname}", '{hostname}')
            raw_expr = f'json.loads(f"""{eraw}""".replace("{{domain}}", domain).replace("{{ext_ip}}", ext_ip).replace("{{enc}}", enc_cmd).replace("{{clean_hash}}", clean_hash).replace("{{mal_hash}}", mal_hash).replace("{{username}}", username).replace("{{hostname}}", hostname))'
            evt_items.append(f'{{"id": {eid_var}, "type": "{etype}", "description": {desc_expr}, "timestamp": ts[{i}], "raw_data": {raw_expr}}}')

        lines.append('    evidence_list = [')
        for item in evt_items:
            lines.append(f'        {item},')
        lines.append('    ]')
        lines.append('')

        # Build findings
        finding_items = []
        for fdesc, frefs, fsev in findings:
            # Map ref names like EVT-001 to e1, e2
            ref_vars = [f'e{int(r.split("-")[1])}' for r in frefs]
            fdesc_expr = f'f"{fdesc}"'.replace("{domain}", '{domain}').replace("{ext_ip}", '{ext_ip}').replace("{username}", '{username}').replace("{hostname}", '{hostname}')
            finding_items.append(f'_f({fdesc_expr}, [{", ".join(ref_vars)}], "{fsev}")')

        # Build actions
        act_items = []
        for aact, aprio, arat in actions:
            act_expr = f'f"{aact}"'.replace("{domain}", '{domain}').replace("{ext_ip}", '{ext_ip}').replace("{username}", '{username}').replace("{hostname}", '{hostname}')
            arat_expr = f'f"{arat}"'.replace("{domain}", '{domain}').replace("{ext_ip}", '{ext_ip}').replace("{username}", '{username}').replace("{hostname}", '{hostname}')
            act_items.append(f'_act({act_expr}, "{aprio}", {arat_expr})')

        # Build mitre
        mitre_items = []
        for mtid, mname, mtactic, mrefs in mitre:
            ref_vars = [f'e{int(r.split("-")[1])}' for r in mrefs]
            mitre_items.append(f'_m("{mtid}", "{mname}", "{mtactic}", [{", ".join(ref_vars)}])')

        # Build output structure
        lines.append('    output_dict = {')
        lines.append(f'        "classification": "{cls}",')
        lines.append(f'        "confidence": gen.confidence_for_classification("{cls}"),')
        lines.append(f'        "findings": [{", ".join(finding_items)}],')
        rat_expr = f'f"{rat}"'.replace("{domain}", '{domain}').replace("{ext_ip}", '{ext_ip}').replace("{username}", '{username}').replace("{hostname}", '{hostname}')
        lines.append(f'        "rationale": {rat_expr},')
        if mitre_items:
            lines.append(f'        "mitre_techniques": [{", ".join(mitre_items)}],')
        lines.append(f'        "recommended_actions": [{", ".join(act_items)}],')
        if extra:
            extra_items = [f'"{x}"' for x in extra]
            lines.append(f'        "additional_evidence_needed": [{", ".join(extra_items)}],')
        lines.append('    }')
        lines.append('')

        # Build complete record
        title_expr = f'f"{title}"'.replace("{domain}", '{domain}').replace("{ext_ip}", '{ext_ip}').replace("{username}", '{username}').replace("{hostname}", '{hostname}')
        lines.append('    return {')
        lines.append(f'        "task": "{task}",')
        lines.append('        "input": {')
        lines.append(f'            "alert": {{"title": {title_expr}, "severity": "{sev}", "source": "EDR" if "{os_fam}" == "Windows" else "SIEM", "timestamp": ts[0], "rule_name": "{rule}", "rule_id": gen.rule_id()}},')
        lines.append('            "context": ctx,')
        lines.append('            "evidence": evidence_list,')
        lines.append('        },')
        lines.append('        "output": output_dict,')
        lines.append('    }')
        lines.append('')

    lines.append('import json')
    lines.append('from generate_dataset_v03 import EXTERNAL_IPS, SUSPICIOUS_DOMAINS')
    lines.append('print(f"Total template families registered: {len(TEMPLATES)}")')

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Wrote {len(ALL_SPECS)} templates to {out_file} successfully!")

if __name__ == "__main__":
    validate_specs()
    generate_code()
