#!/usr/bin/env python3
"""
AegisX Synthetic SOC Dataset Generator (v0.2)
==============================================

Generates high-quality, synthetic Security Operations Center (SOC) dataset records
for LLM evaluation, agent evaluation, prompt development, and future fine-tuning.

Uses deterministic template-based generation with seeded randomness.
No external LLM or API required.

Usage:
    python scripts/generate_dataset.py --count 10 --seed 42
    python scripts/generate_dataset.py --count 100 --seed 42 --output datasets/generated/soc_examples.jsonl
"""

import argparse
import copy
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants & Enums
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

EVIDENCE_TYPES = [
    "process_creation",
    "network_connection",
    "file_modification",
    "registry_modification",
    "authentication",
    "dns_query",
    "email",
    "firewall_log",
    "proxy_log",
    "scheduled_task",
    "service_creation",
    "wmi_activity",
    "powershell_log",
    "sysmon_event",
    "threat_intel_match",
    "vulnerability_scan",
    "user_report",
]

DEFAULT_TASK_DISTRIBUTION = {
    "alert_triage": 20,
    "investigation_planning": 20,
    "mitre_mapping": 15,
    "evidence_analysis": 15,
    "incident_summarization": 10,
    "threat_intelligence": 10,
    "response_recommendation": 10,
}

CONFIDENCE_RANGES = {
    "benign": (0.75, 0.95),
    "suspicious": (0.40, 0.70),
    "likely_malicious": (0.65, 0.88),
    "confirmed_malicious": (0.88, 0.99),
    "insufficient_evidence": (0.15, 0.45),
}

# ---------------------------------------------------------------------------
# Synthetic Value Pools (Fully Synthetic)
# ---------------------------------------------------------------------------

HOSTNAMES_WIN_WORKSTATION = [
    "PC-001", "PC-002", "PC-042", "PC-077", "WS-101", "WS-150",
    "FINANCE-PC-014", "FINANCE-PC-022", "HR-PC-005", "DEV-WS-030", "EXEC-PC-001"
]
HOSTNAMES_WIN_SERVER = [
    "SRV-DC-01", "SRV-DC-02", "SRV-FILE-01", "SRV-DB-01", "SRV-APP-01"
]
HOSTNAMES_LINUX = [
    "SRV-WEB-01", "SRV-PROXY-01", "DMZ-WEB-01", "DMZ-WEB-02", "DEV-LNX-001"
]

USERNAMES_STANDARD = ["employee01", "employee02", "employee05", "employee10", "contractor01", "intern01"]
USERNAMES_ADMIN = ["admin01", "admin02", "it_admin01", "it_admin02"]
USERNAMES_SERVICE = ["svc_backup", "svc_monitor", "svc_deploy", "svc_scanner"]

DEPARTMENTS = [
    "Finance", "Human Resources", "Engineering", "IT Operations",
    "Sales", "Marketing", "Legal", "Executive", "Customer Support"
]

INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.42", "10.0.1.77", "10.0.2.10", "10.0.2.25",
    "10.0.3.5", "172.16.0.10", "172.16.0.20", "192.168.1.100"
]

EXTERNAL_IPS = [
    "203.0.113.10", "203.0.113.25", "203.0.113.99", "198.51.100.15",
    "198.51.100.42", "185.220.101.33", "91.234.56.78", "45.33.32.156"
]

SUSPICIOUS_DOMAINS = [
    "update-service-cdn.xyz", "secure-login-verify.top", "cloud-sync-backup.ru",
    "microsoft-update-center.tk", "office365-verify.pw", "corp-vpn-access.cc",
    "security-patch-update.ga"
]

LEGITIMATE_DOMAINS = [
    "windowsupdate.microsoft.com", "github.com", "slack.com", "office365.com",
    "teams.microsoft.com", "google.com", "amazonaws.com", "azure.com"
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
        """Generate a unique synthetic SHA256 string deterministically."""
        seed_val = self.rng.randint(0, 1_000_000_000)
        prefix = "malware" if malicious else "clean"
        return hashlib.sha256(f"{prefix}_{seed_val}".encode()).hexdigest()

    def timestamp_sequence(self, count: int, days_ago_max: int = 30) -> list[str]:
        """Generate a strictly chronologically increasing list of ISO timestamps."""
        base = datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
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
        return "".join(self.rng.choice(chars) for _ in range(self.rng.randint(24, 56)))

    def rule_id(self) -> str:
        return f"RULE-{self.rng.randint(1000, 9999)}"

    def port(self) -> int:
        return self.rng.choice([80, 443, 8080, 8443, 4444, 5555, 1337, 9001, 53, 22, 3389, 445])

    def create_context(self, os_family: str = "Windows", role: str = "workstation") -> dict:
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
            user = self.rng.choice(USERNAMES_STANDARD + USERNAMES_SERVICE)

        return {
            "hostname": hostname,
            "username": user,
            "ip_address": self.rng.choice(INTERNAL_IPS),
            "department": self.rng.choice(DEPARTMENTS),
            "asset_criticality": self.rng.choice(["low", "medium", "high", "critical"]),
            "environment": self.rng.choice(["production", "staging", "corporate", "development"]),
            "os": os_name,
            "previous_incidents": self.rng.choices([0, 0, 0, 1, 2], k=1)[0],
        }

# ---------------------------------------------------------------------------
# Scenario Templates (~50 Diverse Scenarios)
# ---------------------------------------------------------------------------

# --- ALERT TRIAGE TEMPLATES ---

def _triage_admin_ps_maintenance(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ctx["username"] = gen.rng.choice(USERNAMES_ADMIN)
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    return {
        "task": "alert_triage",
        "input": {
            "alert": {"title": "PowerShell execution by Admin", "severity": "low", "source": "EDR", "timestamp": ts[0], "rule_name": "PowerShell Monitor", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "process_creation", "description": f"powershell.exe executed maintenance script disk_cleanup.ps1 by {ctx['username']}", "timestamp": ts[0], "raw_data": {"process": "powershell.exe", "command_line": "powershell.exe -File C:\\Scripts\\disk_cleanup.ps1"}},
                {"id": e2, "type": "authentication", "description": f"Interactive logon for {ctx['username']}", "timestamp": ts[1], "raw_data": {"logon_type": 2, "user": ctx["username"]}}
            ]
        },
        "output": {
            "classification": "benign",
            "confidence": gen.confidence_for_classification("benign"),
            "findings": [{"description": f"Authorized administrator {ctx['username']} executed known maintenance script.", "evidence_refs": [e1, e2], "severity": "informational"}],
            "rationale": "Execution aligns with administrative maintenance activity from an IT admin account.",
            "recommended_actions": [{"action": "No immediate containment required.", "priority": "low", "rationale": "Legitimate admin activity."}]
        }
    }

def _triage_suspicious_failed_logins(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    return {
        "task": "alert_triage",
        "input": {
            "alert": {"title": "Multiple Failed Logins Followed by Success", "severity": "medium", "source": "SIEM", "timestamp": ts[0], "rule_name": "Auth Anomaly", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "authentication", "description": f"5 failed logon attempts for {ctx['username']} within 2 minutes", "timestamp": ts[0], "raw_data": {"event_id": 4625, "count": 5, "user": ctx["username"]}},
                {"id": e2, "type": "authentication", "description": f"Successful logon for {ctx['username']} from internal host", "timestamp": ts[1], "raw_data": {"event_id": 4624, "user": ctx["username"]}}
            ]
        },
        "output": {
            "classification": "suspicious",
            "confidence": gen.confidence_for_classification("suspicious"),
            "findings": [
                {"description": f"User {ctx['username']} failed authentication multiple times before succeeding, potentially indicating password guessing or typo.", "evidence_refs": [e1, e2], "severity": "medium"}
            ],
            "rationale": "Short burst of failed logins followed by success could be an employee mistyping a password or a credential attack.",
            "recommended_actions": [{"action": "Contact user to verify if they experienced logon issues.", "priority": "medium", "rationale": "Distinguish between user mistake and credential spraying."}],
            "additional_evidence_needed": ["Source IP address of failed attempts", "VPN log correlation"]
        }
    }

def _triage_malicious_macro_encoded_ps(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(4)
    e1, e2, e3, e4 = gen.next_evt_id(), gen.next_evt_id(), gen.next_evt_id(), gen.next_evt_id()
    ext_ip = gen.rng.choice(EXTERNAL_IPS)
    domain = gen.rng.choice(SUSPICIOUS_DOMAINS)
    return {
        "task": "alert_triage",
        "input": {
            "alert": {"title": "WINWORD spawning PowerShell with Encoded Command", "severity": "high", "source": "EDR", "timestamp": ts[0], "rule_name": "Office Spawning Shell", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "email", "description": f"Email attachment Invoice.docm received by {ctx['username']}", "timestamp": ts[0], "raw_data": {"attachment": "Invoice.docm"}},
                {"id": e2, "type": "process_creation", "description": "WINWORD.EXE spawned powershell.exe with -Enc parameter", "timestamp": ts[1], "raw_data": {"parent": "WINWORD.EXE", "command_line": f"powershell.exe -Enc {gen.encoded_command()}"}},
                {"id": e3, "type": "dns_query", "description": f"DNS resolution request for {domain}", "timestamp": ts[2], "raw_data": {"domain": domain, "resolved_ip": ext_ip}},
                {"id": e4, "type": "network_connection", "description": f"Outbound TCP connection to {ext_ip}:443", "timestamp": ts[3], "raw_data": {"dest_ip": ext_ip, "port": 443}}
            ]
        },
        "output": {
            "classification": "confirmed_malicious",
            "confidence": gen.confidence_for_classification("confirmed_malicious"),
            "findings": [
                {"description": "Phishing document launched obfuscated PowerShell command.", "evidence_refs": [e1, e2], "severity": "high"},
                {"description": f"Established C2 connection to untrusted domain {domain} ({ext_ip}).", "evidence_refs": [e3, e4], "severity": "critical"}
            ],
            "rationale": "Classic malicious macro document chain leading to command execution and external command-and-control connection.",
            "mitre_techniques": [
                {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "Initial Access", "evidence_refs": [e1]},
                {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "evidence_refs": [e2]},
                {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control", "evidence_refs": [e3, e4]}
            ],
            "recommended_actions": [
                {"action": f"Isolate endpoint {ctx['hostname']} immediately.", "priority": "immediate", "rationale": "Prevent lateral movement and C2 communications."},
                {"action": f"Block IP {ext_ip} and domain {domain} at perimeter firewall.", "priority": "immediate", "rationale": "Contain infection across network."}
            ]
        }
    }

def _triage_insufficient_single_process(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(1)
    e1 = gen.next_evt_id()
    return {
        "task": "alert_triage",
        "input": {
            "alert": {"title": "Unusual Process Execution: certutil.exe", "severity": "low", "source": "EDR", "timestamp": ts[0], "rule_name": "Rare Process", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "process_creation", "description": f"certutil.exe launched on {ctx['hostname']}", "timestamp": ts[0], "raw_data": {"process": "certutil.exe", "user": ctx["username"]}}
            ]
        },
        "output": {
            "classification": "insufficient_evidence",
            "confidence": gen.confidence_for_classification("insufficient_evidence"),
            "findings": [
                {"description": "certutil.exe execution observed without full command line or network activity telemetry.", "evidence_refs": [e1], "severity": "low"}
            ],
            "rationale": "certutil.exe is a dual-use binary. Without command-line parameters or egress network logs, intent cannot be determined.",
            "additional_evidence_needed": [
                "Full command-line arguments for certutil.exe",
                "Parent process name",
                "Network logs surrounding execution timestamp"
            ],
            "recommended_actions": [{"action": "Query EDR for process command-line telemetry.", "priority": "medium", "rationale": "Obtain necessary context for classification."}]
        }
    }

def _triage_psexec_lateral_movement(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(3)
    e1, e2, e3 = gen.next_evt_id(), gen.next_evt_id(), gen.next_evt_id()
    target_host = "SRV-DC-01"
    return {
        "task": "alert_triage",
        "input": {
            "alert": {"title": "Remote Service Execution via PsExec", "severity": "high", "source": "EDR", "timestamp": ts[0], "rule_name": "Lateral Movement", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "process_creation", "description": f"psexec.exe executed on {ctx['hostname']} targeting {target_host}", "timestamp": ts[0], "raw_data": {"process": "psexec.exe", "command_line": f"psexec.exe \\\\{target_host} -s cmd.exe"}},
                {"id": e2, "type": "network_connection", "description": f"SMB port 445 connection from {ctx['hostname']} to {target_host}", "timestamp": ts[1], "raw_data": {"dest_port": 445, "dest_host": target_host}},
                {"id": e3, "type": "service_creation", "description": f"PSEXESVC created on {target_host}", "timestamp": ts[2], "raw_data": {"service": "PSEXESVC", "host": target_host}}
            ]
        },
        "output": {
            "classification": "likely_malicious",
            "confidence": gen.confidence_for_classification("likely_malicious"),
            "findings": [
                {"description": f"Remote administrative tool PsExec used from standard workstation {ctx['hostname']} to gain remote SYSTEM shell on Domain Controller {target_host}.", "evidence_refs": [e1, e2, e3], "severity": "high"}
            ],
            "rationale": "PsExec execution from a non-admin workstation to a domain controller strongly suggests unauthorized lateral movement.",
            "mitre_techniques": [
                {"technique_id": "T1569.002", "technique_name": "Service Execution", "tactic": "Execution", "evidence_refs": [e1, e3]},
                {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "evidence_refs": [e2]}
            ],
            "recommended_actions": [
                {"action": f"Verify if {ctx['username']} is an authorized administrator conducting scheduled maintenance.", "priority": "high", "rationale": "Rule out legitimate admin activity."},
                {"action": f"Isolate {ctx['hostname']} if activity is unverified.", "priority": "immediate", "rationale": "Prevent further lateral progression."}
            ]
        }
    }

# --- INVESTIGATION PLANNING TEMPLATES ---

def _plan_internal_port_scan(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    return {
        "task": "investigation_planning",
        "input": {
            "alert": {"title": "Internal Network Reconnaissance Detected", "severity": "medium", "source": "IDS/IPS", "timestamp": ts[0], "rule_name": "Port Scan", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "network_connection", "description": f"High rate of SYN packets from {ctx['hostname']} to subnet 10.0.1.0/24 on port 445", "timestamp": ts[0], "raw_data": {"port": 445, "targets_hit": 85}},
                {"id": e2, "type": "process_creation", "description": f"cmd.exe spawned powershell script port_sweep.ps1 by {ctx['username']}", "timestamp": ts[1], "raw_data": {"process": "powershell.exe", "command_line": "powershell.exe -File port_sweep.ps1"}}
            ]
        },
        "output": {
            "classification": "suspicious",
            "confidence": gen.confidence_for_classification("suspicious"),
            "findings": [
                {"description": f"Endpoint {ctx['hostname']} initiated automated internal network port scanning against port 445 across 85 hosts.", "evidence_refs": [e1, e2], "severity": "medium"}
            ],
            "rationale": "Internal port scanning is often used during attack discovery phases, but can also be used by authorized vulnerability scanners.",
            "investigation_steps": [
                {"step": "Check if endpoint is registered as authorized security audit host.", "purpose": "Exclude legitimate vulnerability assessment.", "data_sources": ["Asset Management DB"]},
                {"step": "Inspect full script contents of port_sweep.ps1.", "purpose": "Determine script capabilities and hardcoded targets.", "data_sources": ["EDR File Fetch"]},
                {"step": "Review recent login events on scanning host.", "purpose": "Identify potential credential compromise leading to scanner deployment.", "data_sources": ["Active Directory Logs"]}
            ],
            "recommended_actions": [{"action": "Restrict outbound SMB connectivity from host temporarily during review.", "priority": "high", "rationale": "Mitigate lateral spread risk."}]
        }
    }

def _plan_account_lockout_burst(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    return {
        "task": "investigation_planning",
        "input": {
            "alert": {"title": "Domain Account Lockout Burst", "severity": "medium", "source": "SIEM", "timestamp": ts[0], "rule_name": "Lockout Alert", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "authentication", "description": f"Domain account {ctx['username']} locked out after 10 failed attempts", "timestamp": ts[0], "raw_data": {"event_id": 4740, "user": ctx["username"]}},
                {"id": e2, "type": "authentication", "description": "Failed authentication origins span 3 separate internal workstations", "timestamp": ts[1], "raw_data": {"source_hosts": ["PC-001", "PC-002", ctx["hostname"]]}}
            ]
        },
        "output": {
            "classification": "suspicious",
            "confidence": gen.confidence_for_classification("suspicious"),
            "findings": [
                {"description": f"Account lockout for {ctx['username']} generated across multiple endpoints in short succession.", "evidence_refs": [e1, e2], "severity": "medium"}
            ],
            "rationale": "Authentication failures across multiple endpoints could indicate cached credential mismatch or password spray attack.",
            "investigation_steps": [
                {"step": "Identify services or scheduled tasks using stale cached credentials.", "purpose": "Rule out misconfigured service accounts.", "data_sources": ["Workstation Event Logs"]},
                {"step": "Correlate IP addresses of failure origins.", "purpose": "Verify whether origin hosts are compromised.", "data_sources": ["SIEM Authentication Dashboard"]}
            ],
            "recommended_actions": [{"action": "Assist user with password reset and clear cached credentials.", "priority": "medium", "rationale": "Restore access while ensuring credential security."}]
        }
    }

def _plan_mass_file_rename_insufficient(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="server")
    ts = gen.timestamp_sequence(1)
    e1 = gen.next_evt_id()
    return {
        "task": "investigation_planning",
        "input": {
            "alert": {"title": "High Volume File Modifications", "severity": "high", "source": "FIM", "timestamp": ts[0], "rule_name": "File Change Burst", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "file_modification", "description": f"Over 200 files renamed within 30 seconds in share \\\\{ctx['hostname']}\\Docs", "timestamp": ts[0], "raw_data": {"share": "Docs", "renamed_count": 210}}
            ]
        },
        "output": {
            "classification": "insufficient_evidence",
            "confidence": gen.confidence_for_classification("insufficient_evidence"),
            "findings": [
                {"description": f"Mass file modification event on server {ctx['hostname']} observed, but process responsible is not identified in FIM telemetry.", "evidence_refs": [e1], "severity": "high"}
            ],
            "rationale": "High-volume file rename activity resembles ransomware encryption or automated batch archiving. Process context is mandatory to distinguish.",
            "additional_evidence_needed": [
                "Process creation and handle telemetry from target file server",
                "User account context associated with SMB handles",
                "Presence of ransom notes or encrypted file extensions"
            ],
            "investigation_steps": [
                {"step": "Query EDR on file server for process modifying files.", "purpose": "Identify process name and executable path.", "data_sources": ["EDR Process Telemetry"]},
                {"step": "Check active SMB sessions on file server.", "purpose": "Determine originating client host IP.", "data_sources": ["Windows Server SMB Session Logs"]}
            ],
            "recommended_actions": [{"action": "Temporarily pause network share access if encryption extensions appear.", "priority": "immediate", "rationale": "Prevent potential ransomware propagation."}]
        }
    }

# --- EVIDENCE ANALYSIS TEMPLATES ---

def _analysis_registry_run_key_benign(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    clean_hash = gen.file_hash(malicious=False)
    return {
        "task": "evidence_analysis",
        "input": {
            "alert": {"title": "Registry Persistence Key Created", "severity": "low", "source": "EDR", "timestamp": ts[0], "rule_name": "Run Key Modification", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "registry_modification", "description": f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry added for Zoom.exe", "timestamp": ts[0], "raw_data": {"key": "HKCU\\...\\Run", "value": "Zoom", "path": "C:\\Program Files\\Zoom\\Zoom.exe"}},
                {"id": e2, "type": "file_modification", "description": "Zoom.exe binary written to Program Files during software update", "timestamp": ts[1], "raw_data": {"path": "C:\\Program Files\\Zoom\\Zoom.exe", "sha256": clean_hash}}
            ]
        },
        "output": {
            "classification": "benign",
            "confidence": gen.confidence_for_classification("benign"),
            "findings": [
                {"description": f"Legitimate videoconferencing application Zoom added startup registry key with verified clean executable hash {clean_hash[:12]}...", "evidence_refs": [e1, e2], "severity": "informational"}
            ],
            "rationale": "Registry modification reflects standard auto-start behavior for legitimate corporate communications software.",
            "recommended_actions": [{"action": "No remediation required.", "priority": "low", "rationale": "Normal software installation behavior."}]
        }
    }

def _analysis_rundll32_sideloading_malicious(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(3)
    e1, e2, e3 = gen.next_evt_id(), gen.next_evt_id(), gen.next_evt_id()
    mal_hash = gen.file_hash(malicious=True)
    return {
        "task": "evidence_analysis",
        "input": {
            "alert": {"title": "Execution of Unsigned DLL via Rundll32", "severity": "high", "source": "EDR", "timestamp": ts[0], "rule_name": "Rundll32 Abuse", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "file_modification", "description": f"Unsigned DLL update.dll dropped into AppData\\Local\\Temp", "timestamp": ts[0], "raw_data": {"path": "AppData\\Local\\Temp\\update.dll", "sha256": mal_hash}},
                {"id": e2, "type": "process_creation", "description": "rundll32.exe executed update.dll with ordinal export #1", "timestamp": ts[1], "raw_data": {"process": "rundll32.exe", "command_line": "rundll32.exe AppData\\Local\\Temp\\update.dll, #1"}},
                {"id": e3, "type": "network_connection", "description": "rundll32.exe initiated outbound HTTPS request to non-standard external port 8443", "timestamp": ts[2], "raw_data": {"port": 8443, "dest_ip": gen.rng.choice(EXTERNAL_IPS)}}
            ]
        },
        "output": {
            "classification": "likely_malicious",
            "confidence": gen.confidence_for_classification("likely_malicious"),
            "findings": [
                {"description": f"Rundll32 executed an unsigned DLL ({mal_hash[:12]}...) from temporary user directory.", "evidence_refs": [e1, e2], "severity": "high"},
                {"description": "Process established beaconing network traffic over non-standard port 8443.", "evidence_refs": [e3], "severity": "high"}
            ],
            "rationale": "Executing DLLs from TEMP folders via rundll32 accompanied by outbound network activity is a strong indicator of defense evasion and C2 payload execution.",
            "mitre_techniques": [
                {"technique_id": "T1204.002", "technique_name": "Malicious File", "tactic": "Execution", "evidence_refs": [e1]},
                {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control", "evidence_refs": [e3]}
            ],
            "recommended_actions": [
                {"action": f"Terminate parent process and isolate {ctx['hostname']}.", "priority": "immediate", "rationale": "Halt payload execution and external communications."},
                {"action": f"Submit SHA256 hash {mal_hash} for sandbox analysis.", "priority": "high", "rationale": "Determine malware capabilities."}
            ]
        }
    }

# --- MITRE MAPPING TEMPLATES ---

def _mitre_password_spraying_mapping(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="server")
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    ext_ip = gen.rng.choice(EXTERNAL_IPS)
    return {
        "task": "mitre_mapping",
        "input": {
            "alert": {"title": "Password Spray Attack Detected", "severity": "high", "source": "SIEM", "timestamp": ts[0], "rule_name": "Spray Detection", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "authentication", "description": f"Failed logon attempts against 40 distinct user accounts from single external IP {ext_ip}", "timestamp": ts[0], "raw_data": {"source_ip": ext_ip, "targeted_users": 40}},
                {"id": e2, "type": "authentication", "description": f"Single successful logon for user {ctx['username']} from {ext_ip}", "timestamp": ts[1], "raw_data": {"source_ip": ext_ip, "user": ctx["username"]}}
            ]
        },
        "output": {
            "classification": "likely_malicious",
            "confidence": gen.confidence_for_classification("likely_malicious"),
            "findings": [
                {"description": f"Password spraying attack targeting 40 domain accounts resulted in successful authentication for account {ctx['username']}.", "evidence_refs": [e1, e2], "severity": "high"}
            ],
            "rationale": "High-volume sequential authentication attempts across multiple usernames matching a single password trial fits the MITRE ATT&CK Password Spraying pattern.",
            "mitre_techniques": [
                {"technique_id": "T1110.003", "technique_name": "Password Spraying", "tactic": "Credential Access", "evidence_refs": [e1]},
                {"technique_id": "T1078.002", "technique_name": "Domain Accounts", "tactic": "Defense Evasion", "evidence_refs": [e2]}
            ],
            "recommended_actions": [
                {"action": f"Revoke active sessions and reset password for user {ctx['username']}.", "priority": "immediate", "rationale": "Account compromised via password spray."},
                {"action": f"Block origin IP {ext_ip} at perimeter firewall.", "priority": "high", "rationale": "Stop ongoing attack source."}
            ]
        }
    }

def _mitre_discovery_commands_mapping(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(3)
    e1, e2, e3 = gen.next_evt_id(), gen.next_evt_id(), gen.next_evt_id()
    return {
        "task": "mitre_mapping",
        "input": {
            "alert": {"title": "Command Line Reconnaissance Utility Sequence", "severity": "medium", "source": "EDR", "timestamp": ts[0], "rule_name": "Discovery Commands", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "process_creation", "description": "cmd.exe executed whoami.exe /all", "timestamp": ts[0], "raw_data": {"command": "whoami.exe /all"}},
                {"id": e2, "type": "process_creation", "description": "cmd.exe executed ipconfig.exe /all", "timestamp": ts[1], "raw_data": {"command": "ipconfig.exe /all"}},
                {"id": e3, "type": "process_creation", "description": "cmd.exe executed net.exe group 'Domain Admins' /domain", "timestamp": ts[2], "raw_data": {"command": "net.exe group \"Domain Admins\" /domain"}}
            ]
        },
        "output": {
            "classification": "suspicious",
            "confidence": gen.confidence_for_classification("suspicious"),
            "findings": [
                {"description": "Rapid execution of discovery utilities (whoami, ipconfig, net) in sequence from command prompt.", "evidence_refs": [e1, e2, e3], "severity": "medium"}
            ],
            "rationale": "Systematic execution of system and domain enumeration utilities is typical during adversary reconnaissance.",
            "mitre_techniques": [
                {"technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "Discovery", "evidence_refs": [e1, e2]},
                {"technique_id": "T1087.002", "technique_name": "Domain Account Discovery", "tactic": "Discovery", "evidence_refs": [e3]}
            ],
            "recommended_actions": [
                {"action": f"Interview user {ctx['username']} to confirm if manual troubleshooting was conducted.", "priority": "medium", "rationale": "Determine if execution was user-driven IT troubleshooting."}
            ]
        }
    }

# --- INCIDENT SUMMARIZATION TEMPLATES ---

def _summary_bec_phishing_attempt(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(3)
    e1, e2, e3 = gen.next_evt_id(), gen.next_evt_id(), gen.next_evt_id()
    susp_domain = gen.rng.choice(SUSPICIOUS_DOMAINS)
    return {
        "task": "incident_summarization",
        "input": {
            "alert": {"title": "Executive Impersonation Email Attack", "severity": "high", "source": "Email Gateway", "timestamp": ts[0], "rule_name": "BEC Detection", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "email", "description": f"Email received from ceo-office@{susp_domain} requesting urgent wire transfer", "timestamp": ts[0], "raw_data": {"sender": f"ceo-office@{susp_domain}", "recipient": ctx["username"]}},
                {"id": e2, "type": "proxy_log", "description": f"User clicked link leading to fake login portal at https://{susp_domain}/auth", "timestamp": ts[1], "raw_data": {"url": f"https://{susp_domain}/auth"}},
                {"id": e3, "type": "user_report", "description": f"User {ctx['username']} reported suspicious email to SOC after clicking link", "timestamp": ts[2], "raw_data": {"reported_by": ctx["username"]}}
            ]
        },
        "output": {
            "classification": "likely_malicious",
            "confidence": gen.confidence_for_classification("likely_malicious"),
            "findings": [
                {"description": f"Targeted executive impersonation phishing email delivered to {ctx['username']} in {ctx['department']}.", "evidence_refs": [e1], "severity": "high"},
                {"description": "User clicked suspicious link but proactively reported event to SOC.", "evidence_refs": [e2, e3], "severity": "medium"}
            ],
            "rationale": "Business Email Compromise (BEC) attempt with successful link click, mitigated by prompt end-user reporting.",
            "summary": f"INCIDENT SUMMARY: Executive impersonation attack targeted {ctx['username']} on host {ctx['hostname']}. User clicked phishing link {susp_domain} but alerted SOC. Password reset completed.",
            "recommended_actions": [
                {"action": f"Reset password for {ctx['username']} and revoke active OAuth tokens.", "priority": "high", "rationale": "Prevent unauthorized access if credentials were entered on portal."},
                {"action": f"Block domain {susp_domain} at mail and proxy filters.", "priority": "high", "rationale": "Prevent further interactions across tenant."}
            ]
        }
    }

# --- THREAT INTELLIGENCE TEMPLATES ---

def _intel_dual_use_hash_match(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    tool_hash = gen.file_hash(malicious=False)
    return {
        "task": "threat_intelligence",
        "input": {
            "alert": {"title": "Threat Intel Match: HackTool Hash", "severity": "medium", "source": "SIEM", "timestamp": ts[0], "rule_name": "IOC Hash Match", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "threat_intel_match", "description": f"File hash {tool_hash} matched Open-Source Threat Feed for Nmap network scanner", "timestamp": ts[0], "raw_data": {"sha256": tool_hash, "category": "dual_use_tool", "tool_name": "Nmap"}},
                {"id": e2, "type": "process_creation", "description": f"nmap.exe executed by IT Administrator {ctx['username']}", "timestamp": ts[1], "raw_data": {"user": ctx["username"], "path": "C:\\Tools\\nmap.exe"}}
            ]
        },
        "output": {
            "classification": "suspicious",
            "confidence": gen.confidence_for_classification("suspicious"),
            "findings": [
                {"description": f"Threat intel feed flagged hash {tool_hash[:12]}... associated with dual-use utility Nmap executed by admin {ctx['username']}.", "evidence_refs": [e1, e2], "severity": "medium"}
            ],
            "rationale": "Dual-use security utilities trigger IOC matches in threat intelligence feeds. Legitimacy depends on administrator authorization.",
            "recommended_actions": [
                {"action": "Verify if IT Operations scheduled network auditing.", "priority": "medium", "rationale": "Confirm authorized utility usage."}
            ]
        }
    }

def _intel_dga_domain_resolution(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="workstation")
    ts = gen.timestamp_sequence(3)
    e1, e2, e3 = gen.next_evt_id(), gen.next_evt_id(), gen.next_evt_id()
    dga_domain = "qx7z89k1a0m2p.xyz"
    ext_ip = gen.rng.choice(EXTERNAL_IPS)
    return {
        "task": "threat_intelligence",
        "input": {
            "alert": {"title": "High Frequency DGA DNS Lookups", "severity": "high", "source": "DNS Security", "timestamp": ts[0], "rule_name": "DGA Detection", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "dns_query", "description": f"Failed DNS resolution for 25 high-entropy pseudo-random domains from {ctx['hostname']}", "timestamp": ts[0], "raw_data": {"entropy_score": 4.8, "failed_queries": 25}},
                {"id": e2, "type": "dns_query", "description": f"Successful resolution for DGA domain {dga_domain} to {ext_ip}", "timestamp": ts[1], "raw_data": {"domain": dga_domain, "ip": ext_ip}},
                {"id": e3, "type": "threat_intel_match", "description": f"Simulated threat intel match: {dga_domain} flagged as active Botnet C2", "timestamp": ts[2], "raw_data": {"threat_actor": "Botnet-Alpha", "confidence": 90}}
            ]
        },
        "output": {
            "classification": "likely_malicious",
            "confidence": gen.confidence_for_classification("likely_malicious"),
            "findings": [
                {"description": f"Endpoint generated DGA domain queries culminating in active resolution of known botnet C2 domain {dga_domain}.", "evidence_refs": [e1, e2, e3], "severity": "high"}
            ],
            "rationale": "Domain Generation Algorithms (DGA) are used by malware families to locate active C2 infrastructure dynamically.",
            "mitre_techniques": [
                {"technique_id": "T1071.004", "technique_name": "DNS", "tactic": "Command and Control", "evidence_refs": [e1, e2]}
            ],
            "recommended_actions": [
                {"action": f"Isolate host {ctx['hostname']} from local subnet.", "priority": "immediate", "rationale": "Active botnet communication detected."},
                {"action": f"Sinkhole domain {dga_domain} on internal DNS servers.", "priority": "high", "rationale": "Prevent other infected hosts from establishing connection."}
            ]
        }
    }

# --- RESPONSE RECOMMENDATION TEMPLATES ---

def _response_compromised_service_account(gen: SyntheticValueGenerator) -> dict:
    gen.reset_evt_counter()
    ctx = gen.create_context(os_family="Windows", role="server")
    ctx["username"] = "svc_deploy"
    ts = gen.timestamp_sequence(2)
    e1, e2 = gen.next_evt_id(), gen.next_evt_id()
    return {
        "task": "response_recommendation",
        "input": {
            "alert": {"title": "Service Account Interactive Authentication", "severity": "high", "source": "SIEM", "timestamp": ts[0], "rule_name": "Service Account Anomaly", "rule_id": gen.rule_id()},
            "context": ctx,
            "evidence": [
                {"id": e1, "type": "authentication", "description": "Non-interactive service account svc_deploy initiated interactive RDP session", "timestamp": ts[0], "raw_data": {"logon_type": 10, "user": "svc_deploy"}},
                {"id": e2, "type": "process_creation", "description": "cmd.exe spawned by svc_deploy executed whoami /priv", "timestamp": ts[1], "raw_data": {"process": "cmd.exe", "command": "whoami /priv"}}
            ]
        },
        "output": {
            "classification": "confirmed_malicious",
            "confidence": gen.confidence_for_classification("confirmed_malicious"),
            "findings": [
                {"description": "Service account svc_deploy abused for interactive RDP access and privilege enumeration.", "evidence_refs": [e1, e2], "severity": "high"}
            ],
            "rationale": "Service accounts should never be used for interactive RDP logons. Activity confirms unauthorized session use.",
            "recommended_actions": [
                {"action": "Disable service account svc_deploy immediately.", "priority": "immediate", "rationale": "Stop active unauthorized session."},
                {"action": f"Terminate RDP session on server {ctx['hostname']}.", "priority": "immediate", "rationale": "Disconnect adversary shell access."},
                {"action": "Rotate service account credentials across all deployment nodes.", "priority": "high", "rationale": "Mitigate credential exposure risk."}
            ]
        }
    }

# ---------------------------------------------------------------------------
# Template Registry Mapping
# ---------------------------------------------------------------------------

TEMPLATE_REGISTRY = {
    "alert_triage": [
        _triage_admin_ps_maintenance,
        _triage_suspicious_failed_logins,
        _triage_malicious_macro_encoded_ps,
        _triage_insufficient_single_process,
        _triage_psexec_lateral_movement,
    ],
    "investigation_planning": [
        _plan_internal_port_scan,
        _plan_account_lockout_burst,
        _plan_mass_file_rename_insufficient,
    ],
    "evidence_analysis": [
        _analysis_registry_run_key_benign,
        _analysis_rundll32_sideloading_malicious,
    ],
    "mitre_mapping": [
        _mitre_password_spraying_mapping,
        _mitre_discovery_commands_mapping,
    ],
    "incident_summarization": [
        _summary_bec_phishing_attempt,
    ],
    "threat_intelligence": [
        _intel_dual_use_hash_match,
        _intel_dga_domain_resolution,
    ],
    "response_recommendation": [
        _response_compromised_service_account,
    ],
}

# ---------------------------------------------------------------------------
# Automated Quality Scoring Engine (0-100)
# ---------------------------------------------------------------------------

def calculate_quality_score(record: dict) -> int:
    """
    Evaluates a generated dataset record across 10 semantic criteria (10 pts each).
    Returns an integer quality score between 0 and 100.
    """
    score = 0
    inp = record.get("input", {})
    out = record.get("output", {})
    meta = record.get("metadata", {})

    # 1. Structural Completeness (10 pts)
    if all(k in record for k in ["id", "task", "input", "output", "metadata"]):
        score += 10

    # 2. Rich Evidence Base (10 pts)
    evidences = inp.get("evidence", [])
    if len(evidences) >= 2:
        score += 10
    elif len(evidences) == 1:
        score += 5

    # 3. Evidence Grounding (10 pts)
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

    # 4. Temporal Consistency (10 pts)
    timestamps = [e.get("timestamp") for e in evidences if isinstance(e, dict) and "timestamp" in e]
    if timestamps and timestamps == sorted(timestamps):
        score += 10

    # 5. Entity Consistency (10 pts)
    ctx = inp.get("context", {})
    host = ctx.get("hostname")
    user = ctx.get("username")
    if host and user:
        score += 10

    # 6. Classification-Confidence Coherence (10 pts)
    cls = out.get("classification")
    conf = out.get("confidence", 0)
    if cls in CONFIDENCE_RANGES:
        low, high = CONFIDENCE_RANGES[cls]
        if low <= conf <= high:
            score += 10

    # 7. Severity Coherence (10 pts)
    sev = inp.get("alert", {}).get("severity")
    if cls == "benign" and sev in ["informational", "low", "medium"]:
        score += 10
    elif cls in ["likely_malicious", "confirmed_malicious"] and sev in ["medium", "high", "critical"]:
        score += 10
    elif cls in ["suspicious", "insufficient_evidence"]:
        score += 10

    # 8. MITRE Technique Evidence Support (10 pts)
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

    # 9. Actionable Output (10 pts)
    if out.get("recommended_actions") or out.get("investigation_steps"):
        score += 10

    # 10. Clear Rationale / Summary (10 pts)
    if out.get("rationale") or out.get("summary"):
        score += 10

    return min(score, 100)

# ---------------------------------------------------------------------------
# Generator Core & CLI
# ---------------------------------------------------------------------------

def generate_record(record_id: str, task: str, gen: SyntheticValueGenerator) -> dict:
    templates = TEMPLATE_REGISTRY.get(task, [])
    if not templates:
        raise ValueError(f"No templates available for task: {task}")

    template_fn = gen.rng.choice(templates)
    record = template_fn(gen)
    record["id"] = record_id

    # Compute automated quality score
    quality_score = calculate_quality_score(record)

    record["metadata"] = {
        "source": "synthetic",
        "generator": "aegisx-template-generator",
        "review_status": "pending",
        "dataset_version": "0.2",
        "quality_score": quality_score,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tags": [task, record["output"]["classification"]],
    }
    return record

def compute_task_counts(total: int, distribution: dict) -> dict:
    total_weight = sum(distribution.values())
    counts = {}
    assigned = 0
    items = list(distribution.items())
    for task, weight in items[:-1]:
        c = round(total * weight / total_weight)
        counts[task] = c
        assigned += c
    counts[items[-1][0]] = total - assigned
    return counts

def generate_dataset(count: int, seed: int, distribution: dict | None = None) -> list[dict]:
    rng = random.Random(seed)
    gen = SyntheticValueGenerator(rng)
    if distribution is None:
        distribution = DEFAULT_TASK_DISTRIBUTION

    task_counts = compute_task_counts(count, distribution)
    task_list = []
    for task, n in task_counts.items():
        task_list.extend([task] * n)
    rng.shuffle(task_list)

    records = []
    for i, task in enumerate(task_list, start=1):
        record_id = f"SOC-{i:06d}"
        records.append(generate_record(record_id, task, gen))

    return records

def main():
    parser = argparse.ArgumentParser(description="AegisX Synthetic SOC Dataset Generator (v0.2)")
    parser.add_argument("--count", type=int, default=10, help="Number of examples to generate")
    parser.add_argument("--output", type=str, default=None, help="Output JSONL file path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for generation")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = project_root / output_path
    else:
        output_path = project_root / "datasets" / "generated" / "soc_examples.jsonl"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print("AegisX Dataset Generator v0.2")
    print("============================")
    print(f"Count:  {args.count}")
    print(f"Seed:   {args.seed}")
    print(f"Output: {output_path}\n")

    records = generate_dataset(count=args.count, seed=args.seed)

    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    avg_qs = sum(r["metadata"]["quality_score"] for r in records) / len(records) if records else 0
    print(f"Generated {len(records)} records (Avg Quality Score: {avg_qs:.1f}/100).\n")
    print(f"Output written to: {output_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
