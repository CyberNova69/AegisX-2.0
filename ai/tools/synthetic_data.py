"""
AegisX Synthetic Telemetry Store
==================================

Deterministic synthetic investigation telemetry for 10 standard SOC scenarios.
All data is purely synthetic and safe. Contains no real employee endpoints,
no real network telemetry, and executes no external commands.
"""

from typing import Any, Dict, List, Optional

SYNTHETIC_SCENARIOS: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # Scenario 1: Benign PowerShell (IT administrator maintenance)
    # Expected: benign
    # -------------------------------------------------------------------------
    "benign_powershell": {
        "scenario_id": "SOC-INV-001",
        "title": "Scheduled Health Check PowerShell Script",
        "description": "IT administrator maintenance running scheduled health monitoring script.",
        "expected_conclusion": "benign",
        "expected_severity": "low",
        "alert": {
            "id": "ALT-INV-001",
            "title": "PowerShell Execution with Service Query Parameters",
            "severity": "low",
            "source": "EDR",
            "rule_id": "RULE-PS-001",
            "timestamp": "2026-02-10T14:00:00Z",
        },
        "context": {
            "hostname": "SRV-OPS-01",
            "username": "it_admin_sarah",
            "department": "Information Technology",
            "os": "Windows Server 2022",
            "asset_criticality": "high",
            "ip_address": "10.0.10.15",
            "environment": "production",
        },
        "initial_evidence": [
            {
                "id": "EVT-001",
                "type": "process_creation",
                "description": "powershell.exe executed with script Get-HealthStatus.ps1",
                "timestamp": "2026-02-10T14:00:00Z",
                "raw_data": {"command": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Get-HealthStatus.ps1"},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-001",
                    "process_id": 4128,
                    "process_name": "powershell.exe",
                    "parent_process": "taskeng.exe (PID: 1044)",
                    "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Get-HealthStatus.ps1",
                    "user": "DOMAIN\\it_admin_sarah",
                    "timestamp": "2026-02-10T14:00:00Z",
                    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "description": "Scheduled task spawned PowerShell to execute signed IT health script.",
                }
            ],
            "network": [
                {
                    "id": "NET-001",
                    "source_endpoint": "SRV-OPS-01 (10.0.10.15)",
                    "destination_ip": "10.0.10.2",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "timestamp": "2026-02-10T14:00:05Z",
                    "process": "powershell.exe",
                    "connection_status": "established",
                    "description": "Outbound HTTPS connection to internal IT monitoring collector.",
                }
            ],
            "auth": [
                {
                    "id": "AUTH-001",
                    "username": "it_admin_sarah",
                    "source_ip": "10.0.10.15",
                    "destination_endpoint": "SRV-OPS-01",
                    "event_type": "scheduled_task_logon",
                    "success": True,
                    "timestamp": "2026-02-10T13:59:58Z",
                    "failure_count": 0,
                    "description": "Batch logon for scheduled task using service credentials.",
                }
            ],
            "file": [
                {
                    "id": "FILE-001",
                    "path": "C:\\Scripts\\Logs\\health_report_20260210.log",
                    "operation": "file_created",
                    "process": "powershell.exe",
                    "user": "DOMAIN\\it_admin_sarah",
                    "timestamp": "2026-02-10T14:00:10Z",
                    "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "description": "Created health report text log file in standard logs directory.",
                }
            ],
            "alerts": [
                {
                    "id": "ALT-CORR-001",
                    "title": "Scheduled Task Triggered: IT Maintenance",
                    "severity": "informational",
                    "endpoint": "SRV-OPS-01",
                    "user": "it_admin_sarah",
                    "timestamp": "2026-02-10T13:59:55Z",
                    "correlation_id": "CORR-MAINT-01",
                    "description": "Known daily maintenance window task executed as planned.",
                }
            ],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 2: Suspicious PowerShell (Encoded command, no C2)
    # Expected: suspicious
    # -------------------------------------------------------------------------
    "suspicious_powershell": {
        "scenario_id": "SOC-INV-002",
        "title": "Encoded PowerShell Command by Local User",
        "description": "Base64 encoded PowerShell executed from developer terminal; no network C2 detected.",
        "expected_conclusion": "suspicious",
        "expected_severity": "medium",
        "alert": {
            "id": "ALT-INV-002",
            "title": "Obfuscated PowerShell Invocation via -EncodedCommand",
            "severity": "medium",
            "source": "SIEM",
            "rule_id": "RULE-PS-002",
            "timestamp": "2026-02-11T09:15:00Z",
        },
        "context": {
            "hostname": "WS-DEV-09",
            "username": "dev_user_alex",
            "department": "Engineering",
            "os": "Windows 11 Enterprise",
            "asset_criticality": "medium",
            "ip_address": "192.168.4.88",
            "environment": "development",
        },
        "initial_evidence": [
            {
                "id": "EVT-002",
                "type": "process_creation",
                "description": "powershell.exe spawned with Base64 encoded payload",
                "timestamp": "2026-02-11T09:15:00Z",
                "raw_data": {"command": "powershell.exe -Enc V3JpdGUtSG9zdCAiVGVzdGluZyBCdWlsZCI="},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-002",
                    "process_id": 8812,
                    "process_name": "powershell.exe",
                    "parent_process": "cmd.exe (PID: 7420)",
                    "command_line": "powershell.exe -Enc V3JpdGUtSG9zdCAiVGVzdGluZyBCdWlsZCI=",
                    "user": "DOMAIN\\dev_user_alex",
                    "timestamp": "2026-02-11T09:15:00Z",
                    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "description": "Decodes to: Write-Host 'Testing Build'. Spawned from interactive developer command prompt.",
                }
            ],
            "network": [
                {
                    "id": "NET-002",
                    "source_endpoint": "WS-DEV-09 (192.168.4.88)",
                    "destination_ip": "127.0.0.1",
                    "destination_port": 8080,
                    "protocol": "TCP",
                    "timestamp": "2026-02-11T09:15:02Z",
                    "process": "powershell.exe",
                    "connection_status": "closed",
                    "description": "Local loopback connection check to developer test port; no external traffic.",
                }
            ],
            "auth": [
                {
                    "id": "AUTH-002",
                    "username": "dev_user_alex",
                    "source_ip": "192.168.4.88",
                    "destination_endpoint": "WS-DEV-09",
                    "event_type": "interactive_logon",
                    "success": True,
                    "timestamp": "2026-02-11T09:00:00Z",
                    "failure_count": 0,
                    "description": "Standard interactive local login during regular business hours.",
                }
            ],
            "file": [
                {
                    "id": "FILE-002",
                    "path": "C:\\Users\\dev_user_alex\\AppData\\Local\\Temp\\build_test.tmp",
                    "operation": "file_created",
                    "process": "powershell.exe",
                    "user": "DOMAIN\\dev_user_alex",
                    "timestamp": "2026-02-11T09:15:01Z",
                    "hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "description": "Temporary text artifact written to local user temp folder.",
                }
            ],
            "alerts": [],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 3: Malicious PowerShell (Word -> PS -> C2 -> payload drop)
    # Expected: confirmed_malicious
    # -------------------------------------------------------------------------
    "malicious_powershell": {
        "scenario_id": "SOC-INV-003",
        "title": "Phishing Word Document Spawning C2 Beacon",
        "description": "WINWORD.EXE launched obfuscated PowerShell downloading and dropping second-stage payload from external C2.",
        "expected_conclusion": "confirmed_malicious",
        "expected_severity": "critical",
        "alert": {
            "id": "ALT-INV-003",
            "title": "Office Application Spawning Script Interpreter",
            "severity": "critical",
            "source": "EDR",
            "rule_id": "RULE-EDR-WINWORD-PS",
            "timestamp": "2026-02-12T11:20:00Z",
        },
        "context": {
            "hostname": "FIN-W10-04",
            "username": "clerk_emily",
            "department": "Finance",
            "os": "Windows 10 Pro",
            "asset_criticality": "high",
            "ip_address": "172.16.20.44",
            "environment": "production",
        },
        "initial_evidence": [
            {
                "id": "EVT-003",
                "type": "process_creation",
                "description": "WINWORD.EXE spawned powershell.exe with hidden window flag",
                "timestamp": "2026-02-12T11:20:00Z",
                "raw_data": {"command": "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoA"},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-003",
                    "process_id": 9210,
                    "process_name": "powershell.exe",
                    "parent_process": "WINWORD.EXE (PID: 3412)",
                    "command_line": "powershell.exe -WindowStyle Hidden -Enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoA...",
                    "user": "DOMAIN\\clerk_emily",
                    "timestamp": "2026-02-12T11:20:01Z",
                    "hash": "7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7",
                    "description": "Macro in Invoice_2026.docm spawned PowerShell with download-cradle payload.",
                }
            ],
            "network": [
                {
                    "id": "NET-003",
                    "source_endpoint": "FIN-W10-04 (172.16.20.44)",
                    "destination_ip": "198.51.100.200",
                    "destination_port": 4444,
                    "protocol": "TCP",
                    "timestamp": "2026-02-12T11:20:05Z",
                    "process": "powershell.exe",
                    "connection_status": "established",
                    "description": "Outbound connection to known untrusted external IP on non-standard port 4444.",
                }
            ],
            "auth": [
                {
                    "id": "AUTH-003",
                    "username": "clerk_emily",
                    "source_ip": "172.16.20.44",
                    "destination_endpoint": "FIN-W10-04",
                    "event_type": "interactive_logon",
                    "success": True,
                    "timestamp": "2026-02-12T08:30:00Z",
                    "failure_count": 0,
                    "description": "Standard user session active when malicious attachment opened.",
                }
            ],
            "file": [
                {
                    "id": "FILE-003",
                    "path": "C:\\Users\\clerk_emily\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.vbs",
                    "operation": "file_created",
                    "process": "powershell.exe",
                    "user": "DOMAIN\\clerk_emily",
                    "timestamp": "2026-02-12T11:20:12Z",
                    "hash": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                    "description": "Persistence mechanism established by writing VBScript to user Startup folder.",
                }
            ],
            "alerts": [
                {
                    "id": "ALT-CORR-003",
                    "title": "Known Malicious IP Connection Observed",
                    "severity": "high",
                    "endpoint": "FIN-W10-04",
                    "user": "clerk_emily",
                    "timestamp": "2026-02-12T11:20:06Z",
                    "correlation_id": "CORR-MAL-99",
                    "description": "Firewall alert for outbound traffic to threat-listed IP 198.51.100.200.",
                }
            ],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 4: Suspicious Login (Off-hours, new source IP)
    # Expected: suspicious
    # -------------------------------------------------------------------------
    "suspicious_login": {
        "scenario_id": "SOC-INV-004",
        "title": "Anomalous Off-Hours Login from Foreign IP",
        "description": "User logged in at 03:00 AM from a previously unseen external IP address.",
        "expected_conclusion": "suspicious",
        "expected_severity": "medium",
        "alert": {
            "id": "ALT-INV-004",
            "title": "Anomalous Geolocation and Off-Hours Authentication",
            "severity": "medium",
            "source": "IAM",
            "rule_id": "RULE-IAM-GEO-01",
            "timestamp": "2026-02-13T03:12:00Z",
        },
        "context": {
            "hostname": "VPN-GW-01",
            "username": "accountant_bob",
            "department": "Accounting",
            "os": "Linux / PAM",
            "asset_criticality": "high",
            "ip_address": "203.0.113.88",
            "environment": "dmz",
        },
        "initial_evidence": [
            {
                "id": "EVT-004",
                "type": "authentication",
                "description": "Successful VPN login for accountant_bob from unusual IP 203.0.113.88 at 03:12 UTC",
                "timestamp": "2026-02-13T03:12:00Z",
                "raw_data": {"user": "accountant_bob", "src_ip": "203.0.113.88", "method": "MFA_Push"},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-004",
                    "process_id": 1140,
                    "process_name": "openvpn",
                    "parent_process": "systemd (PID: 1)",
                    "command_line": "/usr/sbin/openvpn --config /etc/openvpn/server.conf",
                    "user": "root",
                    "timestamp": "2026-02-13T03:12:00Z",
                    "hash": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                    "description": "VPN daemon session allocated for user.",
                }
            ],
            "network": [
                {
                    "id": "NET-004",
                    "source_endpoint": "203.0.113.88",
                    "destination_ip": "10.0.0.1",
                    "destination_port": 1194,
                    "protocol": "UDP",
                    "timestamp": "2026-02-13T03:11:58Z",
                    "process": "openvpn",
                    "connection_status": "active",
                    "description": "Inbound tunnel traffic from external IP.",
                }
            ],
            "auth": [
                {
                    "id": "AUTH-004",
                    "username": "accountant_bob",
                    "source_ip": "203.0.113.88",
                    "destination_endpoint": "VPN-GW-01",
                    "event_type": "vpn_login",
                    "success": True,
                    "timestamp": "2026-02-13T03:12:00Z",
                    "failure_count": 0,
                    "description": "Single successful login attempt with approved mobile MFA token, but foreign origin.",
                }
            ],
            "file": [],
            "alerts": [
                {
                    "id": "ALT-CORR-004",
                    "title": "First Time Country Connection for User",
                    "severity": "low",
                    "endpoint": "VPN-GW-01",
                    "user": "accountant_bob",
                    "timestamp": "2026-02-13T03:12:01Z",
                    "correlation_id": "CORR-GEO-02",
                    "description": "User never connected from this regional IP block before.",
                }
            ],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 5: Brute-Force Authentication (50 failures followed by success)
    # Expected: likely_malicious
    # -------------------------------------------------------------------------
    "brute_force_authentication": {
        "scenario_id": "SOC-INV-005",
        "title": "Password Spray / Brute Force on SSH Service",
        "description": "52 failed password attempts within 3 minutes followed by successful login.",
        "expected_conclusion": "likely_malicious",
        "expected_severity": "high",
        "alert": {
            "id": "ALT-INV-005",
            "title": "Multiple Failed Authentication Threshold Exceeded",
            "severity": "high",
            "source": "SIEM",
            "rule_id": "RULE-AUTH-BRUTE-01",
            "timestamp": "2026-02-14T01:45:00Z",
        },
        "context": {
            "hostname": "LNX-BASTION-01",
            "username": "admin",
            "department": "Infrastructure",
            "os": "Debian 12",
            "asset_criticality": "critical",
            "ip_address": "192.0.2.15",
            "environment": "dmz",
        },
        "initial_evidence": [
            {
                "id": "EVT-005",
                "type": "authentication",
                "description": "Rapid succession of 52 failed SSH logins from 198.51.100.77",
                "timestamp": "2026-02-14T01:45:00Z",
                "raw_data": {"service": "sshd", "failed_attempts": 52, "src_ip": "198.51.100.77"},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-005",
                    "process_id": 6192,
                    "process_name": "sshd",
                    "parent_process": "systemd (PID: 1)",
                    "command_line": "sshd: admin [priv]",
                    "user": "root",
                    "timestamp": "2026-02-14T01:45:15Z",
                    "hash": "887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99",
                    "description": "Interactive SSH session opened following sustained dictionary attack.",
                }
            ],
            "network": [
                {
                    "id": "NET-005",
                    "source_endpoint": "198.51.100.77",
                    "destination_ip": "192.0.2.15",
                    "destination_port": 22,
                    "protocol": "TCP",
                    "timestamp": "2026-02-14T01:45:10Z",
                    "process": "sshd",
                    "connection_status": "established",
                    "description": "Persistent TCP connection on port 22 from attack source.",
                }
            ],
            "auth": [
                {
                    "id": "AUTH-005",
                    "username": "admin",
                    "source_ip": "198.51.100.77",
                    "destination_endpoint": "LNX-BASTION-01",
                    "event_type": "ssh_login",
                    "success": True,
                    "timestamp": "2026-02-14T01:45:14Z",
                    "failure_count": 52,
                    "description": "52 failed password attempts recorded immediately prior to single successful authentication.",
                }
            ],
            "file": [
                {
                    "id": "FILE-005",
                    "path": "/home/admin/.ssh/authorized_keys",
                    "operation": "file_modified",
                    "process": "sshd",
                    "user": "admin",
                    "timestamp": "2026-02-14T01:45:30Z",
                    "hash": "33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122",
                    "description": "Attacker appended new RSA public key to authorized_keys for backdoor persistence.",
                }
            ],
            "alerts": [
                {
                    "id": "ALT-CORR-005",
                    "title": "Brute Force Attack Detected by IDS",
                    "severity": "high",
                    "endpoint": "LNX-BASTION-01",
                    "user": "admin",
                    "timestamp": "2026-02-14T01:44:50Z",
                    "correlation_id": "CORR-BF-77",
                    "description": "Suricata alert for SSH password brute force signature.",
                }
            ],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 6: Suspicious Process Chain (rundll32 -> regsvr32)
    # Expected: suspicious
    # -------------------------------------------------------------------------
    "suspicious_process_chain": {
        "scenario_id": "SOC-INV-006",
        "title": "Unusual LOLBIN Execution Chain (rundll32 -> regsvr32)",
        "description": "rundll32 spawned regsvr32 with uncommon DLL registration parameters.",
        "expected_conclusion": "suspicious",
        "expected_severity": "medium",
        "alert": {
            "id": "ALT-INV-006",
            "title": "Suspicious Native Windows Binary Spawning Regsvr32",
            "severity": "medium",
            "source": "EDR",
            "rule_id": "RULE-EDR-LOLBIN-01",
            "timestamp": "2026-02-15T16:00:00Z",
        },
        "context": {
            "hostname": "WS-HR-03",
            "username": "hr_recruiter_linda",
            "department": "Human Resources",
            "os": "Windows 10 Enterprise",
            "asset_criticality": "medium",
            "ip_address": "10.5.20.12",
            "environment": "production",
        },
        "initial_evidence": [
            {
                "id": "EVT-006",
                "type": "process_creation",
                "description": "rundll32.exe spawned regsvr32.exe /s /u custom_helper.dll",
                "timestamp": "2026-02-15T16:00:00Z",
                "raw_data": {"parent": "rundll32.exe", "child": "regsvr32.exe"},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-006",
                    "process_id": 5532,
                    "process_name": "regsvr32.exe",
                    "parent_process": "rundll32.exe (PID: 4410)",
                    "command_line": "regsvr32.exe /s /u C:\\ProgramData\\custom_helper.dll",
                    "user": "DOMAIN\\hr_recruiter_linda",
                    "timestamp": "2026-02-15T16:00:01Z",
                    "hash": "cc22110099887766554433221100ffeeddccbbaa99887766554433221100ffee",
                    "description": "regsvr32 silently unregistering a dynamic library in ProgramData.",
                }
            ],
            "network": [],
            "auth": [
                {
                    "id": "AUTH-006",
                    "username": "hr_recruiter_linda",
                    "source_ip": "10.5.20.12",
                    "destination_endpoint": "WS-HR-03",
                    "event_type": "interactive_logon",
                    "success": True,
                    "timestamp": "2026-02-15T09:00:00Z",
                    "failure_count": 0,
                    "description": "Local workstation session.",
                }
            ],
            "file": [
                {
                    "id": "FILE-006",
                    "path": "C:\\ProgramData\\custom_helper.dll",
                    "operation": "file_modified",
                    "process": "rundll32.exe",
                    "user": "DOMAIN\\hr_recruiter_linda",
                    "timestamp": "2026-02-15T15:59:50Z",
                    "hash": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                    "description": "DLL dropped into public ProgramData path.",
                }
            ],
            "alerts": [],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 7: Suspicious Outbound Connection (Beaconing)
    # Expected: likely_malicious
    # -------------------------------------------------------------------------
    "suspicious_outbound_connection": {
        "scenario_id": "SOC-INV-007",
        "title": "Periodic HTTPS Beaconing to Uncategorized Domain",
        "description": "Workstation establishing recurring outbound connections at strict 60-second intervals.",
        "expected_conclusion": "likely_malicious",
        "expected_severity": "high",
        "alert": {
            "id": "ALT-INV-007",
            "title": "Network Beaconing Pattern Detected by NTA",
            "severity": "high",
            "source": "Zeek/NTA",
            "rule_id": "RULE-NET-BEACON-01",
            "timestamp": "2026-02-16T18:00:00Z",
        },
        "context": {
            "hostname": "WS-RND-11",
            "username": "engineer_chen",
            "department": "R&D",
            "os": "Ubuntu 22.04 LTS",
            "asset_criticality": "high",
            "ip_address": "10.8.0.45",
            "environment": "production",
        },
        "initial_evidence": [
            {
                "id": "EVT-007",
                "type": "network_connection",
                "description": "120 periodic HTTPS connections to 198.51.100.99 with exact 60s jitter-free intervals",
                "timestamp": "2026-02-16T18:00:00Z",
                "raw_data": {"dest_ip": "198.51.100.99", "interval_sec": 60, "total_beacons": 120},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-007",
                    "process_id": 8102,
                    "process_name": "cron_sync",
                    "parent_process": "sh (PID: 8099)",
                    "command_line": "/tmp/.hidden/cron_sync --daemon",
                    "user": "engineer_chen",
                    "timestamp": "2026-02-16T16:00:00Z",
                    "hash": "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
                    "description": "Masquerading ELF binary executing out of hidden directory in /tmp.",
                }
            ],
            "network": [
                {
                    "id": "NET-007",
                    "source_endpoint": "WS-RND-11 (10.8.0.45)",
                    "destination_ip": "198.51.100.99",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "timestamp": "2026-02-16T18:00:00Z",
                    "process": "cron_sync",
                    "connection_status": "established",
                    "description": "C2 heartbeat beacon containing 256-byte encrypted check-in payload.",
                }
            ],
            "auth": [],
            "file": [
                {
                    "id": "FILE-007",
                    "path": "/tmp/.hidden/cron_sync",
                    "operation": "file_created",
                    "process": "curl",
                    "user": "engineer_chen",
                    "timestamp": "2026-02-16T15:59:40Z",
                    "hash": "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
                    "description": "Hidden executable payload fetched via curl.",
                }
            ],
            "alerts": [
                {
                    "id": "ALT-CORR-007",
                    "title": "Low Reputation External Destination",
                    "severity": "medium",
                    "endpoint": "WS-RND-11",
                    "user": "engineer_chen",
                    "timestamp": "2026-02-16T16:01:00Z",
                    "correlation_id": "CORR-REP-44",
                    "description": "Destination IP recently registered in bulletproof hosting ASN.",
                }
            ],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 8: Suspicious File Activity (Temporary executable creation)
    # Expected: suspicious
    # -------------------------------------------------------------------------
    "suspicious_file_activity": {
        "scenario_id": "SOC-INV-008",
        "title": "Executable Written to User AppData Temp",
        "description": "Browser process downloaded and wrote a standalone binary to AppData\\Local\\Temp.",
        "expected_conclusion": "suspicious",
        "expected_severity": "medium",
        "alert": {
            "id": "ALT-INV-008",
            "title": "Executable File Dropped in Temporary Path",
            "severity": "medium",
            "source": "Antivirus",
            "rule_id": "RULE-AV-TEMP-EXE",
            "timestamp": "2026-02-17T10:45:00Z",
        },
        "context": {
            "hostname": "WS-SALES-02",
            "username": "rep_mark",
            "department": "Sales",
            "os": "Windows 11 Home",
            "asset_criticality": "low",
            "ip_address": "192.168.1.105",
            "environment": "production",
        },
        "initial_evidence": [
            {
                "id": "EVT-008",
                "type": "file_creation",
                "description": "setup_patch_x86.exe written to C:\\Users\\rep_mark\\AppData\\Local\\Temp",
                "timestamp": "2026-02-17T10:45:00Z",
                "raw_data": {"path": "C:\\Users\\rep_mark\\AppData\\Local\\Temp\\setup_patch_x86.exe"},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-008",
                    "process_id": 4910,
                    "process_name": "chrome.exe",
                    "parent_process": "explorer.exe (PID: 2100)",
                    "command_line": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
                    "user": "DOMAIN\\rep_mark",
                    "timestamp": "2026-02-17T10:44:50Z",
                    "hash": "aabb00112233445566778899aabb00112233445566778899aabb001122334455",
                    "description": "Chrome browser triggered direct binary download from external vendor site.",
                }
            ],
            "network": [
                {
                    "id": "NET-008",
                    "source_endpoint": "WS-SALES-02 (192.168.1.105)",
                    "destination_ip": "198.51.100.50",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "timestamp": "2026-02-17T10:44:55Z",
                    "process": "chrome.exe",
                    "connection_status": "closed",
                    "description": "Completed HTTPS download of setup executable.",
                }
            ],
            "auth": [],
            "file": [
                {
                    "id": "FILE-008",
                    "path": "C:\\Users\\rep_mark\\AppData\\Local\\Temp\\setup_patch_x86.exe",
                    "operation": "file_created",
                    "process": "chrome.exe",
                    "user": "DOMAIN\\rep_mark",
                    "timestamp": "2026-02-17T10:45:00Z",
                    "hash": "7788990011223344556677889900112233445566778899001122334455667788",
                    "description": "Unsigned binary sitting in temp directory; not yet executed.",
                }
            ],
            "alerts": [],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 9: Multi-Stage Attack (Process + Network + File)
    # Expected: confirmed_malicious
    # -------------------------------------------------------------------------
    "multi_stage_attack": {
        "scenario_id": "SOC-INV-009",
        "title": "Multi-Stage Ransomware Intrusion",
        "description": "Macro exploit followed by PowerShell C2 communication, staging, and mass file encryption.",
        "expected_conclusion": "confirmed_malicious",
        "expected_severity": "critical",
        "alert": {
            "id": "ALT-INV-009",
            "title": "High-Volume Rapid File Renaming with Ransom Extension",
            "severity": "critical",
            "source": "EDR",
            "rule_id": "RULE-RANSOM-STG-01",
            "timestamp": "2026-02-18T22:30:00Z",
        },
        "context": {
            "hostname": "FILE-SRV-CORP",
            "username": "svc_storage",
            "department": "Infrastructure",
            "os": "Windows Server 2019",
            "asset_criticality": "critical",
            "ip_address": "10.100.1.10",
            "environment": "production",
        },
        "initial_evidence": [
            {
                "id": "EVT-009",
                "type": "file_modification",
                "description": "Over 2,000 files modified and renamed with .aegiscry extension",
                "timestamp": "2026-02-18T22:30:00Z",
                "raw_data": {"extension": ".aegiscry", "modified_count": 2150},
            }
        ],
        "telemetry": {
            "process": [
                {
                    "id": "PROC-009",
                    "process_id": 9940,
                    "process_name": "vssadmin.exe",
                    "parent_process": "powershell.exe (PID: 9912)",
                    "command_line": "vssadmin.exe delete shadows /all /quiet",
                    "user": "NT AUTHORITY\\SYSTEM",
                    "timestamp": "2026-02-18T22:28:10Z",
                    "hash": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "description": "Adversary deleted volume shadow copies to prevent recovery prior to encryption.",
                }
            ],
            "network": [
                {
                    "id": "NET-009",
                    "source_endpoint": "FILE-SRV-CORP (10.100.1.10)",
                    "destination_ip": "198.51.100.250",
                    "destination_port": 8443,
                    "protocol": "TCP",
                    "timestamp": "2026-02-18T22:25:00Z",
                    "process": "powershell.exe",
                    "connection_status": "established",
                    "description": "Pre-encryption exfiltration of 500 MB data archive to external C2 server.",
                }
            ],
            "auth": [
                {
                    "id": "AUTH-009",
                    "username": "svc_storage",
                    "source_ip": "10.100.1.55",
                    "destination_endpoint": "FILE-SRV-CORP",
                    "event_type": "lateral_movement_wmi",
                    "success": True,
                    "timestamp": "2026-02-18T22:20:00Z",
                    "failure_count": 0,
                    "description": "Compromised service account utilized for lateral movement via WMI from workstation.",
                }
            ],
            "file": [
                {
                    "id": "FILE-009",
                    "path": "D:\\Shared\\HOW_TO_DECRYPT.txt",
                    "operation": "file_created",
                    "process": "powershell.exe",
                    "user": "NT AUTHORITY\\SYSTEM",
                    "timestamp": "2026-02-18T22:30:05Z",
                    "hash": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                    "description": "Ransom note placed in every encrypted file share directory.",
                }
            ],
            "alerts": [
                {
                    "id": "ALT-CORR-009",
                    "title": "Volume Shadow Copy Deletion Detected",
                    "severity": "critical",
                    "endpoint": "FILE-SRV-CORP",
                    "user": "SYSTEM",
                    "timestamp": "2026-02-18T22:28:12Z",
                    "correlation_id": "CORR-VSS-DEL",
                    "description": "Critical anti-recovery behavior observed immediately before file renaming surge.",
                }
            ],
        },
    },

    # -------------------------------------------------------------------------
    # Scenario 10: Insufficient Evidence (Truncated / missing data)
    # Expected: insufficient_evidence
    # -------------------------------------------------------------------------
    "insufficient_evidence": {
        "scenario_id": "SOC-INV-010",
        "title": "Truncated Syslog Event with Incomplete Context",
        "description": "Single fragmented syslog message mentioning certutil with zero process arguments or destination IP.",
        "expected_conclusion": "insufficient_evidence",
        "expected_severity": "low",
        "alert": {
            "id": "ALT-INV-010",
            "title": "Malformed Log Event: Missing Process Telemetry",
            "severity": "low",
            "source": "Syslog",
            "rule_id": "RULE-LOG-CORRUPT",
            "timestamp": "2026-02-19T05:00:00Z",
        },
        "context": {
            "hostname": "UNKNOWN-HOST",
            "username": "unknown_user",
            "department": "Unknown",
            "os": "Unknown",
            "asset_criticality": "low",
            "ip_address": "0.0.0.0",
            "environment": "unknown",
        },
        "initial_evidence": [
            {
                "id": "EVT-010",
                "type": "log_fragment",
                "description": "certutil.exe appeared in fragmented buffer without arguments or timestamp",
                "timestamp": "2026-02-19T05:00:00Z",
                "raw_data": {"fragment": "certutil [TRUNCATED]"},
            }
        ],
        "telemetry": {
            "process": [],
            "network": [],
            "auth": [],
            "file": [],
            "alerts": [],
        },
    },
}

def get_scenario(scenario_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve full synthetic investigation scenario by key name."""
    return SYNTHETIC_SCENARIOS.get(scenario_name)

def list_scenarios() -> List[Dict[str, str]]:
    """Return summary list of all available synthetic investigation scenarios."""
    summaries = []
    for key, data in SYNTHETIC_SCENARIOS.items():
        summaries.append({
            "key": key,
            "id": data["scenario_id"],
            "title": data["title"],
            "expected_conclusion": data["expected_conclusion"],
            "expected_severity": data["expected_severity"],
        })
    return summaries

def query_synthetic_telemetry(
    telemetry_type: str,
    query_params: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Safe deterministic query engine over synthetic telemetry records.
    Filters by hostname, username, process_name, or scenario key.
    """
    results = []
    scenario_key = query_params.get("scenario")
    hostname = query_params.get("hostname")
    username = query_params.get("username")

    target_scenarios = (
        [SYNTHETIC_SCENARIOS[scenario_key]]
        if scenario_key and scenario_key in SYNTHETIC_SCENARIOS
        else SYNTHETIC_SCENARIOS.values()
    )

    for scn in target_scenarios:
        # Match by hostname if specified
        if hostname and scn.get("context", {}).get("hostname") != hostname:
            continue
        # Match by username if specified
        if username and scn.get("context", {}).get("username") != username:
            continue

        items = scn.get("telemetry", {}).get(telemetry_type, [])
        results.extend(items)

    return results
