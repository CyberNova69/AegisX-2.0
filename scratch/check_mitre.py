import json
import sys
sys.path.insert(0, 'scripts')
import templates_v04

with open('datasets/metadata/mitre_reference.json') as f:
    ref = {t['technique_id']: t for t in json.load(f)}

print("Checking MITRE references in ALL 150 templates:")
invalid_count = 0
for s in templates_v04.ALL_SPECS:
    tid = s[0]
    mitre = s[16]
    for m in mitre:
        mtid, mname, mtactic, refs = m
        if mtid not in ref:
            print(f"[{tid}] Invalid technique_id: {mtid} ({mname})")
            invalid_count += 1
        else:
            expected = ref[mtid]
            if mname != expected['technique_name']:
                print(f"[{tid}] Name mismatch for {mtid}: '{mname}' != '{expected['technique_name']}'")
                invalid_count += 1
            if mtactic != expected['tactic']:
                print(f"[{tid}] Tactic mismatch for {mtid}: '{mtactic}' != '{expected['tactic']}'")
                invalid_count += 1

print(f"Total invalid entries: {invalid_count}")
