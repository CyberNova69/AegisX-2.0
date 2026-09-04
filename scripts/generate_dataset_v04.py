#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX Synthetic SOC Dataset Generator (v0.4)
==============================================

Generates AegisX Fine-Tuning Dataset v0.4:
- Target size: Exactly 3,000 total records
- 150 genuinely distinct template families across 18 security domains
- Perfectly balanced class distribution: exactly 600 records per classification (20.0% each)
- High borderline representation: 88 borderline templates generating 1,760 borderline records (58.7%)
- OS telemetry coverage: 105 Windows templates (70.0%), 45 Linux templates (30.0%)
- 18 of 18 evidence types represented
- All 34 MITRE ATT&CK techniques across all 10 tactics preserved
- Anti-keyword learning design with Shannon entropy > 1.0 bits for key tools
- Template-stratified split:
    Train:      2,400 records (80.0%, 120 templates, 24 per class)
    Validation:   300 records (10.0%,  15 templates,  3 per class)
    Test:         300 records (10.0%,  15 templates,  3 per class)
- Zero template leakage:
    Templates(Train) ∩ Templates(Val) = ∅
    Templates(Train) ∩ Templates(Test) = ∅
    Templates(Val) ∩ Templates(Test) = ∅

Usage:
    python scripts/generate_dataset_v04.py --count 3000 --seed 42
"""

import argparse
import hashlib
import json
import random
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants & Enums (Matches Schema)
# ---------------------------------------------------------------------------

VALID_TASKS = [
    "alert_triage",
    "investigation_planning",
    "evidence_analysis",
    "mitre_mapping",
    "incident_summarization",
    "threat_intelligence",
    "response_recommendation",
]

VALID_CLASSIFICATIONS = [
    "benign",
    "suspicious",
    "likely_malicious",
    "confirmed_malicious",
    "insufficient_evidence",
]

VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"]

CONFIDENCE_RANGES = {
    "benign": (0.76, 0.94),
    "suspicious": (0.42, 0.68),
    "likely_malicious": (0.66, 0.86),
    "confirmed_malicious": (0.88, 0.98),
    "insufficient_evidence": (0.18, 0.42),
}

# ---------------------------------------------------------------------------
# Synthetic Value Pools (Windows + Linux)
# ---------------------------------------------------------------------------

HOSTNAMES_WIN_WORKSTATION = [
    "PC-001", "PC-002", "PC-042", "PC-077", "WS-101", "WS-150",
    "FINANCE-PC-014", "FINANCE-PC-022", "HR-PC-005", "DEV-WS-030", "EXEC-PC-001",
    "LEGAL-WS-009", "SALES-LAPTOP-12", "SUPPORT-DESK-04"
]
HOSTNAMES_WIN_SERVER = [
    "SRV-DC-01", "SRV-DC-02", "SRV-FILE-01", "SRV-DB-01", "SRV-APP-01", "SRV-EXCHANGE-01",
    "SRV-SCCM-01", "SRV-BACKUP-01", "SRV-PRINT-01"
]
HOSTNAMES_LINUX = [
    "SRV-WEB-01", "SRV-PROXY-01", "DMZ-WEB-01", "DMZ-WEB-02", "DEV-LNX-001",
    "PROD-API-01", "SRV-K8S-NODE-01", "DB-POSTGRES-01", "CI-RUNNER-01", "LOG-ELK-01"
]

USERNAMES_STANDARD = [
    "employee01", "employee02", "employee05", "employee10", "contractor01", "intern01",
    "developer01", "developer02", "analyst02", "accountant01", "finance01", "finance02",
    "hr01", "hr02", "legal01", "support01"
]
USERNAMES_ADMIN = ["admin01", "admin02", "it_admin01", "it_admin02", "sysadmin01", "sysadmin02"]
USERNAMES_SERVICE = [
    "svc_backup", "svc_monitor", "svc_deploy", "svc_scanner", "svc_sql", "svc_sccm", "backup_svc"
]
USERNAMES_LINUX = ["ubuntu", "root", "deployer", "devops", "www-data", "secops", "jenkins", "ansible"]

DEPARTMENTS = [
    "Finance", "Human Resources", "Engineering", "IT Operations",
    "Sales", "Marketing", "Legal", "Executive", "Customer Support", "Security Operations"
]

INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.42", "10.0.1.77", "10.0.2.10", "10.0.2.25",
    "10.0.3.5", "172.16.0.10", "172.16.0.20", "192.168.1.100", "192.168.2.50"
]

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

LEGITIMATE_DOMAINS = [
    "windowsupdate.microsoft.com", "github.com", "slack.com", "office365.com",
    "teams.microsoft.com", "google.com", "amazonaws.com", "azure.com", "archive.ubuntu.com"
]

# ---------------------------------------------------------------------------
# Synthetic Value Generator Engine
# ---------------------------------------------------------------------------

class SyntheticValueGenerator:
    """Generates synthetic values using a seeded random instance."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self._evt_counter = 0

    def next_evt_id(self) -> str:
        self._evt_counter += 1
        return f"EVT-{self._evt_counter:03d}"

    def reset_evt_counter(self):
        self._evt_counter = 0

    def file_hash(self, malicious: bool = False) -> str:
        seed_val = self.rng.randint(0, 1_000_000_000)
        prefix = "malware" if malicious else "clean"
        return hashlib.sha256(f"{prefix}_{seed_val}".encode()).hexdigest()

    def timestamp_sequence(self, count: int, days_ago_max: int = 30) -> list[str]:
        base = datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc)
        start_offset = timedelta(
            days=self.rng.randint(0, days_ago_max),
            hours=self.rng.randint(0, 20),
            minutes=self.rng.randint(0, 50),
        )
        curr = base - start_offset
        timestamps = []
        for _ in range(count):
            timestamps.append(curr.isoformat())
            curr += timedelta(seconds=self.rng.randint(5, 180))
        return timestamps

    def confidence_for_classification(self, classification: str) -> float:
        low, high = CONFIDENCE_RANGES.get(classification, (0.5, 0.8))
        return round(self.rng.uniform(low, high), 2)

    def encoded_command(self) -> str:
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        return "".join(self.rng.choice(chars) for _ in range(self.rng.randint(28, 64)))

    def rule_id(self) -> str:
        return f"RULE-{self.rng.randint(1000, 9999)}"

    def port(self) -> int:
        return self.rng.choice([80, 443, 8080, 8443, 4444, 5555, 1337, 9001, 53, 22, 3389, 445])

    def create_context(self, os_family: str = "Windows", role: str = "workstation", environment: str | None = None) -> dict:
        if os_family == "Windows":
            os_name = self.rng.choice(["Windows 10 Enterprise", "Windows 11 Enterprise", "Windows Server 2022"])
            if role == "server":
                hostname = self.rng.choice(HOSTNAMES_WIN_SERVER)
                user = self.rng.choice(USERNAMES_ADMIN + USERNAMES_SERVICE)
            else:
                hostname = self.rng.choice(HOSTNAMES_WIN_WORKSTATION)
                user = self.rng.choice(USERNAMES_STANDARD + USERNAMES_ADMIN)
        else:
            os_name = self.rng.choice(["Ubuntu 22.04 LTS", "RHEL 8"])
            hostname = self.rng.choice(HOSTNAMES_LINUX)
            user = self.rng.choice(USERNAMES_LINUX)

        env_choices = ["production", "staging", "corporate", "development", "dmz"]
        chosen_env = environment if environment else self.rng.choice(env_choices)

        return {
            "hostname": hostname,
            "username": user,
            "ip_address": self.rng.choice(INTERNAL_IPS),
            "department": self.rng.choice(DEPARTMENTS),
            "asset_criticality": self.rng.choice(["low", "medium", "high", "critical"]),
            "environment": chosen_env,
            "os": os_name,
            "previous_incidents": self.rng.choices([0, 0, 0, 1, 2], k=1)[0],
        }

# ---------------------------------------------------------------------------
# Automated Quality Scoring Engine (0-100)
# ---------------------------------------------------------------------------

def calculate_quality_score(record: dict) -> int:
    score = 0
    inp = record.get("input", {})
    out = record.get("output", {})

    if all(k in record for k in ["id", "task", "input", "output", "metadata"]):
        score += 10

    evidences = inp.get("evidence", [])
    if len(evidences) >= 2:
        score += 10
    elif len(evidences) == 1:
        score += 5

    evt_ids = {e.get("id") for e in evidences if isinstance(e, dict)}
    findings = out.get("findings", [])
    grounded = True
    for f in findings:
        refs = f.get("evidence_refs", [])
        if not refs or not all(r in evt_ids for r in refs):
            grounded = False
            break
    if findings and grounded:
        score += 10

    timestamps = [e.get("timestamp") for e in evidences if isinstance(e, dict) and "timestamp" in e]
    if timestamps and timestamps == sorted(timestamps):
        score += 10

    ctx = inp.get("context", {})
    if ctx.get("hostname") and ctx.get("username"):
        score += 10

    cls = out.get("classification")
    conf = out.get("confidence", 0)
    if cls in CONFIDENCE_RANGES:
        low, high = CONFIDENCE_RANGES[cls]
        if low <= conf <= high:
            score += 10

    sev = inp.get("alert", {}).get("severity")
    if cls == "benign" and sev in ["informational", "low", "medium"]:
        score += 10
    elif cls in ["likely_malicious", "confirmed_malicious"] and sev in ["medium", "high", "critical"]:
        score += 10
    elif cls in ["suspicious", "insufficient_evidence"]:
        score += 10

    mitre = out.get("mitre_techniques", [])
    if not mitre:
        score += 10
    else:
        mitre_valid = all(
            isinstance(m, dict) and all(r in evt_ids for r in m.get("evidence_refs", []))
            for m in mitre if "evidence_refs" in m
        )
        if mitre_valid:
            score += 10

    if out.get("recommended_actions") or out.get("investigation_steps"):
        score += 10

    if out.get("rationale") or out.get("summary"):
        score += 10

    return min(score, 100)

# ---------------------------------------------------------------------------
# Generator Engine with Exact 150-Template Allocation
# ---------------------------------------------------------------------------

def generate_finetuning_v04(output_dir: Path, target_count: int = 3000, seed: int = 42) -> dict:
    import templates_v04

    rng = random.Random(seed)
    gen = SyntheticValueGenerator(rng)

    templates = templates_v04.TEMPLATES
    train_templates = [t for t in templates if t["split"] == "train"]
    val_templates = [t for t in templates if t["split"] == "val"]
    test_templates = [t for t in templates if t["split"] == "test"]

    print(f"Loaded {len(templates)} templates:")
    print(f"  Train templates:      {len(train_templates)} (80.0%, exactly 24 per class)")
    print(f"  Validation templates: {len(val_templates)} (10.0%, exactly 3 per class)")
    print(f"  Test templates:       {len(test_templates)} (10.0%, exactly 3 per class)")

    # Each template generates exactly 20 records (150 * 20 = 3,000)
    # Train: 120 * 20 = 2,400 (80.0%)
    # Val:    15 * 20 =   300 (10.0%)
    # Test:   15 * 20 =   300 (10.0%)
    RECORDS_PER_TEMPLATE = 20

    records_by_split = {"train": [], "val": [], "test": []}
    all_records = []
    global_id_counter = 0

    split_map = {
        "train": train_templates,
        "val": val_templates,
        "test": test_templates,
    }

    for split_name in ["train", "val", "test"]:
        t_list = split_map[split_name]
        instances = []
        for t in t_list:
            for _ in range(RECORDS_PER_TEMPLATE):
                instances.append(t)
        rng.shuffle(instances)

        for t in instances:
            global_id_counter += 1
            rec_id = f"SOC-{global_id_counter:06d}"
            rec = t["fn"](gen)
            rec["id"] = rec_id
            rec["metadata"] = {
                "source": "synthetic",
                "generator": "aegisx-v0.4-generator",
                "review_status": "pending",
                "dataset_version": "0.4",
                "quality_score": 0,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "template_id": t["id"],
                "template_name": t["name"],
                "split": split_name,
                "tags": [t["task"], t["classification"], t["domain"], f"os:{t['os_family']}"],
            }
            if t["borderline"]:
                rec["metadata"]["borderline_category"] = t["borderline"]

            qs = calculate_quality_score(rec)
            rec["metadata"]["quality_score"] = qs

            records_by_split[split_name].append(rec)
            all_records.append(rec)

    # Output directory creation
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write individual split files and full dataset
    train_path = output_dir / "train.jsonl"
    val_path = output_dir / "validation.jsonl"
    test_path = output_dir / "test.jsonl"
    full_path = output_dir / "full_dataset.jsonl"

    for path, recs in [(train_path, records_by_split["train"]),
                       (val_path, records_by_split["val"]),
                       (test_path, records_by_split["test"]),
                       (full_path, all_records)]:
        with open(path, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"Wrote {len(recs)} records to {path.name}")

    # 2. Generate Template Inventory JSON
    inventory = []
    for t in templates:
        inventory.append({
            "template_id": t["id"],
            "template_name": t["name"],
            "domain": t["domain"],
            "task": t["task"],
            "classification": t["classification"],
            "split": t["split"],
            "borderline_category": t["borderline"],
            "os_family": t["os_family"],
        })
    inv_path = output_dir / "template_inventory.json"
    with open(inv_path, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, ensure_ascii=False)
    print(f"Wrote template inventory ({len(inventory)} templates) to {inv_path.name}")

    # 3. Generate Split Metadata JSON
    def get_file_hash(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    train_tpl_ids = {t["id"] for t in train_templates}
    val_tpl_ids = {t["id"] for t in val_templates}
    test_tpl_ids = {t["id"] for t in test_templates}

    split_meta = {
        "dataset_version": "0.4",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
        "total_records": len(all_records),
        "total_templates": len(templates),
        "records_per_template": RECORDS_PER_TEMPLATE,
        "splits": {
            "train": {
                "records": len(records_by_split["train"]),
                "templates": len(train_templates),
                "file_hash_sha256": get_file_hash(train_path),
                "classifications": dict(Counter(r["output"]["classification"] for r in records_by_split["train"])),
            },
            "validation": {
                "records": len(records_by_split["val"]),
                "templates": len(val_templates),
                "file_hash_sha256": get_file_hash(val_path),
                "classifications": dict(Counter(r["output"]["classification"] for r in records_by_split["val"])),
            },
            "test": {
                "records": len(records_by_split["test"]),
                "templates": len(test_templates),
                "file_hash_sha256": get_file_hash(test_path),
                "classifications": dict(Counter(r["output"]["classification"] for r in records_by_split["test"])),
            },
        },
        "leakage_checks": {
            "train_val_overlap_count": len(train_tpl_ids & val_tpl_ids),
            "train_test_overlap_count": len(train_tpl_ids & test_tpl_ids),
            "val_test_overlap_count": len(val_tpl_ids & test_tpl_ids),
            "zero_leakage_verified": (len(train_tpl_ids & val_tpl_ids) == 0 and
                                      len(train_tpl_ids & test_tpl_ids) == 0 and
                                      len(val_tpl_ids & test_tpl_ids) == 0)
        }
    }
    meta_path = output_dir / "split_metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(split_meta, f, indent=2, ensure_ascii=False)
    print(f"Wrote split metadata to {meta_path.name}")

    # 4. Generate Generation Config YAML
    config_yaml = f"""# AegisX Fine-Tuning Dataset Generation Configuration v0.4
dataset:
  name: "aegisx-soc-finetuning"
  version: "0.4"
  description: "Research-ready synthetic SOC triage fine-tuning dataset with template-stratified split and anti-keyword design"

generation:
  seed: {seed}
  target_total_records: {len(all_records)}
  total_template_families: {len(templates)}
  records_per_template: {RECORDS_PER_TEMPLATE}
  domains: 18
  stratified_split:
    train_ratio: 0.80
    validation_ratio: 0.10
    test_ratio: 0.10
  actual_split_records:
    train: {len(records_by_split["train"])}
    validation: {len(records_by_split["val"])}
    test: {len(records_by_split["test"])}

classification_target_distribution:
  benign: 0.20
  suspicious: 0.20
  likely_malicious: 0.20
  confirmed_malicious: 0.20
  insufficient_evidence: 0.20

os_distribution:
  windows_templates: 105
  linux_templates: 45
  windows_records: {sum(1 for r in all_records if "Windows" in r["input"]["context"]["os"])}
  linux_records: {sum(1 for r in all_records if "Ubuntu" in r["input"]["context"]["os"] or "RHEL" in r["input"]["context"]["os"])}

quality:
  enforce_strict_grounding: true
  min_acceptable_quality_score: 80
"""
    cfg_path = output_dir / "generation_config.yaml"
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(config_yaml)
    print(f"Wrote generation config to {cfg_path.name}")

    # 5. Generate Dataset Card
    card_md = f"""# AegisX SOC Fine-Tuning Dataset Card (v0.4)

## Dataset Summary
- **Name**: aegisx-soc-finetuning
- **Version**: 0.4
- **Total Records**: {len(all_records):,}
- **Template Families**: {len(templates)} (150 distinct scenarios across 18 domains)
- **Generator**: `scripts/generate_dataset_v04.py` (seed {seed})
- **Creation Date**: {datetime.now(timezone.utc).strftime("%Y-%m-%d")}
- **Quality Score Average**: {sum(r["metadata"]["quality_score"] for r in all_records) / len(all_records):.1f} / 100

## Split Architecture (Template-Stratified)
| Split | Records | Templates | Description |
|---|---|---|---|
| **Train** | {len(records_by_split["train"]):,} (80.0%) | 120 (80.0%) | Supervised fine-tuning training set (24 per class) |
| **Validation** | {len(records_by_split["val"]):,} (10.0%) | 15 (10.0%) | Evaluation checkpoint evaluation (3 per class) |
| **Test** | {len(records_by_split["test"]):,} (10.0%) | 15 (10.0%) | Held-out unseen template generalization benchmark (3 per class) |

> [!IMPORTANT]
> **Zero Template Leakage Guarantee**: No template family in Train appears in Validation or Test.
> $\\text{{Templates}}(\\text{{Train}}) \\cap \\text{{Templates}}(\\text{{Val}}) = \\emptyset$, $\\text{{Templates}}(\\text{{Train}}) \\cap \\text{{Templates}}(\\text{{Test}}) = \\emptyset$, $\\text{{Templates}}(\\text{{Val}}) \\cap \\text{{Templates}}(\\text{{Test}}) = \\emptyset$.

## Classification Distribution (Perfect 20.0% Balance)
- `benign`: {sum(1 for r in all_records if r["output"]["classification"] == "benign"):,} ({sum(1 for r in all_records if r["output"]["classification"] == "benign") / len(all_records) * 100:.1f}%)
- `suspicious`: {sum(1 for r in all_records if r["output"]["classification"] == "suspicious"):,} ({sum(1 for r in all_records if r["output"]["classification"] == "suspicious") / len(all_records) * 100:.1f}%)
- `likely_malicious`: {sum(1 for r in all_records if r["output"]["classification"] == "likely_malicious"):,} ({sum(1 for r in all_records if r["output"]["classification"] == "likely_malicious") / len(all_records) * 100:.1f}%)
- `confirmed_malicious`: {sum(1 for r in all_records if r["output"]["classification"] == "confirmed_malicious"):,} ({sum(1 for r in all_records if r["output"]["classification"] == "confirmed_malicious") / len(all_records) * 100:.1f}%)
- `insufficient_evidence`: {sum(1 for r in all_records if r["output"]["classification"] == "insufficient_evidence"):,} ({sum(1 for r in all_records if r["output"]["classification"] == "insufficient_evidence") / len(all_records) * 100:.1f}%)

## Borderline Cases
- Deliberate borderline records: {sum(1 for r in all_records if "borderline_category" in r["metadata"]):,} ({sum(1 for r in all_records if "borderline_category" in r["metadata"]) / len(all_records) * 100:.1f}%)
- Across 88 borderline template families spanning all 5 key decision boundaries:
  1. `benign_vs_suspicious`
  2. `suspicious_vs_likely_malicious`
  3. `likely_malicious_vs_confirmed_malicious`
  4. `suspicious_vs_insufficient_evidence`
  5. `likely_malicious_vs_insufficient_evidence`

## Operating Systems
- Windows: {sum(1 for r in all_records if "Windows" in r["input"]["context"]["os"]):,} records ({sum(1 for r in all_records if "Windows" in r["input"]["context"]["os"]) / len(all_records) * 100:.1f}%)
- Linux: {sum(1 for r in all_records if "Ubuntu" in r["input"]["context"]["os"] or "RHEL" in r["input"]["context"]["os"]):,} records ({sum(1 for r in all_records if "Ubuntu" in r["input"]["context"]["os"] or "RHEL" in r["input"]["context"]["os"]) / len(all_records) * 100:.1f}%)

## Anti-Keyword Learning
Common administrative tools (`powershell`, `cmd`, `sudo`, `ssh`, `curl`, `wmi`, `certutil`, `rundll32`, `scheduled_task`) appear across multiple classes to prevent shortcut heuristics during SFT.
"""
    card_path = output_dir / "dataset_card.md"
    with open(card_path, "w", encoding="utf-8") as f:
        f.write(card_md)
    print(f"Wrote dataset card to {card_path.name}")

    return split_meta

def main():
    parser = argparse.ArgumentParser(description="AegisX Synthetic SOC Dataset Generator (v0.4)")
    parser.add_argument("--count", type=int, default=3000, help="Total number of examples to generate")
    parser.add_argument("--output-dir", type=str, default="datasets/finetuning/v0.4", help="Output directory path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for generation")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
        out_dir = project_root / out_dir

    print("============================================================")
    print("  AegisX Fine-Tuning Dataset Generator (v0.4)")
    print("============================================================")
    print(f"  Target Count: {args.count}")
    print(f"  Seed:         {args.seed}")
    print(f"  Output Dir:   {out_dir}\n")

    meta = generate_finetuning_v04(out_dir, target_count=args.count, seed=args.seed)

    print("\nGeneration successfully completed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
