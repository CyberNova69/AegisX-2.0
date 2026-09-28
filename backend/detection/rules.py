"""Detection rules for the AegisX SOC detection engine.

Each rule is a deterministic condition function that inspects a NormalizedEvent
and returns match information. Rules cover the 12 controlled SOC lab scenarios
specified in the AegisX architecture, plus hard-negative exclusions.

Rules are organized by MITRE ATT&CK tactic and map to specific technique IDs.
No LLM is used in this layer — all detection is pattern-based and auditable.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import AlertSeverity, DetectionRule, DetectionType

# Type alias for rule condition functions.
# A condition receives an event dict (NormalizedEvent.event.to_dict()) and
# returns (matched: bool, details: str, evidence: dict).
RuleCondition = Callable[[Dict[str, Any]], Tuple[bool, str, Dict[str, Any]]]


# ---------------------------------------------------------------------------
# Suspicious pattern libraries (deterministic, no LLM)
# ---------------------------------------------------------------------------

# PowerShell patterns indicating potential malicious use
SUSPICIOUS_PS_PATTERNS = [
    re.compile(r"-(?:enc|encodedcommand)\b", re.IGNORECASE),
    re.compile(r"(?:invoke-expression|iex)\b", re.IGNORECASE),
    re.compile(r"(?:downloadstring|downloadfile|webclient)\b", re.IGNORECASE),
    re.compile(r"(?:net\.webclient|system\.net\.webclient)", re.IGNORECASE),
    re.compile(r"-(?:nop|noprofile|noninteractive|windowstyle\s+hidden)", re.IGNORECASE),
    re.compile(r"(?:bypass|unrestricted).*executionpolicy", re.IGNORECASE),
    re.compile(r"executionpolicy.*(?:bypass|unrestricted)", re.IGNORECASE),
    re.compile(r"(?:frombase64string|tobase64string)\b", re.IGNORECASE),
    re.compile(r"(?:start-process|invoke-webrequest|invoke-restmethod)\b", re.IGNORECASE),
    re.compile(r"\$(?:env:temp|env:appdata).*\\.*\.(?:exe|dll|ps1|bat|vbs)", re.IGNORECASE),
]

# Benign PowerShell administration patterns (hard negatives)
BENIGN_PS_PATTERNS = [
    re.compile(r"get-service\b", re.IGNORECASE),
    re.compile(r"get-process\b", re.IGNORECASE),
    re.compile(r"get-eventlog\b", re.IGNORECASE),
    re.compile(r"get-wmiobject\b", re.IGNORECASE),
    re.compile(r"get-childitem\b", re.IGNORECASE),
    re.compile(r"set-executionpolicy\s+(?:restricted|allsigned)\b", re.IGNORECASE),
    re.compile(r"update-help\b", re.IGNORECASE),
    re.compile(r"get-windowsfeature\b", re.IGNORECASE),
]

# Known suspicious outbound ports/indicators
SUSPICIOUS_PORTS = {4444, 5555, 8888, 1234, 31337, 6667, 6697, 9001, 9050, 9150}

# Common ransomware file extensions
RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".crypto", ".enc",
    ".locky", ".cerber", ".zepto", ".odin", ".thor",
    ".aaa", ".abc", ".zzz", ".micro", ".xyz",
}

# Persistence mechanisms via scheduled tasks
PERSISTENCE_COMMANDS = [
    re.compile(r"schtasks\s+/create\b", re.IGNORECASE),
    re.compile(r"at\s+\d{1,2}:\d{2}", re.IGNORECASE),
    re.compile(r"register-scheduledjob\b", re.IGNORECASE),
    re.compile(r"new-scheduledtask\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Condition functions
# ---------------------------------------------------------------------------

def _condition_suspicious_powershell(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect suspicious PowerShell execution patterns."""
    cmd = (event.get("command_line") or "").strip()
    proc = (event.get("process_name") or "").lower()

    if not cmd:
        return False, "", {}

    # Must involve PowerShell
    is_ps = "powershell" in proc or "pwsh" in proc or "powershell" in cmd.lower()
    if not is_ps:
        return False, "", {}

    # Check for benign patterns first (hard-negative suppression)
    for bp in BENIGN_PS_PATTERNS:
        if bp.search(cmd):
            # Only suppress if NO suspicious pattern also matches
            has_suspicious = any(sp.search(cmd) for sp in SUSPICIOUS_PS_PATTERNS)
            if not has_suspicious:
                return False, "", {}

    # Check for suspicious patterns
    matched_patterns = []
    for sp in SUSPICIOUS_PS_PATTERNS:
        if sp.search(cmd):
            matched_patterns.append(sp.pattern)

    if matched_patterns:
        return (
            True,
            f"Suspicious PowerShell: {len(matched_patterns)} pattern(s) matched",
            {"matched_patterns": matched_patterns, "command_line": cmd[:500]},
        )

    return False, "", {}


def _condition_brute_force_auth(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect brute-force authentication patterns.

    Looks for failed authentication events. In a real deployment, the
    engine would aggregate multiple events over a time window. For
    single-event detection, we flag individual failed logins from
    anomalous sources as suspicious.
    """
    event_type = event.get("event_type", "")
    if event_type != "authentication":
        return False, "", {}

    attrs = event.get("attributes", {})
    status = event.get("status") or attrs.get("status")
    if isinstance(status, str):
        status = status.lower()

    failure_reason = str(attrs.get("failure_reason", "")).lower()
    login_type = str(attrs.get("login_type", "")).lower()

    # Check for authentication failure indicators
    is_failure = (
        status in ("failure", "failed", "denied", "rejected", "error")
        or "fail" in failure_reason
        or "invalid" in failure_reason
        or "wrong password" in failure_reason
        or "account locked" in failure_reason
    )

    if is_failure:
        return (
            True,
            f"Authentication failure detected (status={status})",
            {
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "status": status,
                "failure_reason": failure_reason,
                "login_type": login_type,
            },
        )

    return False, "", {}


def _condition_scheduled_task_persistence(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect persistence via scheduled tasks / at jobs."""
    cmd = (event.get("command_line") or "").strip()
    if not cmd:
        return False, "", {}

    for pattern in PERSISTENCE_COMMANDS:
        if pattern.search(cmd):
            return (
                True,
                f"Scheduled task persistence detected",
                {"command_line": cmd[:500], "pattern": pattern.pattern},
            )

    return False, "", {}


def _condition_office_spawn_shell(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect Office application spawning a shell (macro/exploit chain).

    Looks for process creation events where the parent is an Office app
    and the child is a shell or scripting engine.
    """
    proc = (event.get("process_name") or "").lower()
    cmd = (event.get("command_line") or "").lower()
    attrs = event.get("attributes", {})
    parent = str(attrs.get("parent_process") or attrs.get("parent_process_name") or event.get("parent_process", "")).lower()

    office_procs = {"winword", "excel", "powerpnt", "outlook", "msaccess"}
    shell_procs = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
                   "wscript", "wscript.exe", "cscript", "cscript.exe", "mshta", "mshta.exe"}

    parent_is_office = any(op in parent for op in office_procs)
    child_is_shell = proc in shell_procs or any(sp in cmd for sp in shell_procs)

    if parent_is_office and child_is_shell:
        return (
            True,
            f"Office application ({parent}) spawned shell ({proc})",
            {"parent_process": parent, "child_process": proc, "command_line": cmd[:500]},
        )

    return False, "", {}


def _condition_suspicious_outbound(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect suspicious outbound network connections."""
    event_type = event.get("event_type", "")
    if event_type != "network_connection":
        return False, "", {}

    dest_port = event.get("dest_port") or event.get("port")
    dest_ip = event.get("dest_ip", "")

    if dest_port is not None and int(dest_port) in SUSPICIOUS_PORTS:
        return (
            True,
            f"Suspicious outbound connection to port {dest_port}",
            {"dest_ip": dest_ip, "dest_port": dest_port, "source_ip": event.get("source_ip")},
        )

    return False, "", {}


def _condition_ransomware_file_mod(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect ransomware-like mass file modification patterns."""
    event_type = event.get("event_type", "")
    if event_type != "file_modification":
        return False, "", {}

    file_path = (event.get("file_path") or "").lower()

    for ext in RANSOMWARE_EXTENSIONS:
        if file_path.endswith(ext):
            return (
                True,
                f"Ransomware-like file extension detected: {ext}",
                {"file_path": file_path, "extension": ext},
            )

    # Check for ransom note indicators
    basename = file_path.split("\\")[-1].split("/")[-1]
    ransom_indicators = {"readme.txt", "how_to_decrypt.txt", "decrypt_instructions.txt",
                         "ransom_note.txt", "restore_files.txt", "help_decrypt.html"}
    if basename in ransom_indicators:
        return (
            True,
            f"Possible ransom note detected: {basename}",
            {"file_path": file_path, "indicator": basename},
        )

    return False, "", {}


def _condition_suspicious_login_anomaly(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect anomalous login patterns (off-hours, unusual source, etc.)."""
    event_type = event.get("event_type", "")
    if event_type != "authentication":
        return False, "", {}

    attrs = event.get("attributes", {})
    status = event.get("status")
    if isinstance(status, str):
        status = status.lower()

    # Must be a successful login to be an anomaly (failures are caught by brute-force rule)
    if status not in ("success", "successful", None):
        return False, "", {}

    # Check for anomaly indicators in attributes
    is_anomalous = False
    reasons = []

    if attrs.get("off_hours"):
        is_anomalous = True
        reasons.append("off-hours login")
    if attrs.get("new_source_ip"):
        is_anomalous = True
        reasons.append("previously unseen source IP")
    if attrs.get("impossible_travel"):
        is_anomalous = True
        reasons.append("impossible travel detected")
    if attrs.get("service_account_interactive"):
        is_anomalous = True
        reasons.append("service account used interactively")

    # Check login type anomalies
    login_type = str(attrs.get("login_type", "")).lower()
    if login_type in ("remote_interactive", "rdp") and attrs.get("external_source"):
        is_anomalous = True
        reasons.append(f"external {login_type} login")

    if is_anomalous:
        return (
            True,
            f"Login anomaly: {', '.join(reasons)}",
            {
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "reasons": reasons,
                "login_type": login_type,
            },
        )

    return False, "", {}


def _condition_suspicious_dns(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect suspicious DNS queries (DGA-like, known malicious TLDs)."""
    event_type = event.get("event_type", "")
    if event_type != "dns_query":
        return False, "", {}

    domain = (event.get("domain") or "").lower()
    if not domain:
        return False, "", {}

    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc"}
    reasons = []

    # Check for suspicious TLDs
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            reasons.append(f"suspicious TLD: {tld}")
            break

    # Check for very long domain names (potential DGA)
    parts = domain.split(".")
    if parts and len(parts[0]) > 30:
        reasons.append(f"unusually long subdomain ({len(parts[0])} chars)")

    # Check for high entropy (many consonant clusters, potential DGA)
    if parts and len(parts[0]) > 10:
        vowels = sum(1 for c in parts[0] if c in "aeiou")
        consonants = sum(1 for c in parts[0] if c.isalpha() and c not in "aeiou")
        if consonants > 0 and vowels / max(consonants, 1) < 0.2:
            reasons.append("high-entropy domain (potential DGA)")

    if reasons:
        return (
            True,
            f"Suspicious DNS query: {', '.join(reasons)}",
            {"domain": domain, "reasons": reasons, "hostname": event.get("hostname")},
        )

    return False, "", {}


def _condition_registry_persistence(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect persistence via registry modification."""
    event_type = event.get("event_type", "")
    if event_type != "registry_modification":
        return False, "", {}

    attrs = event.get("attributes", {})
    reg_path = str(attrs.get("registry_path", "") or event.get("file_path", "")).lower()

    persistence_keys = [
        r"software\microsoft\windows\currentversion\run",
        r"software\microsoft\windows\currentversion\runonce",
        r"software\microsoft\windows nt\currentversion\winlogon",
        r"software\microsoft\windows\currentversion\explorer\shell folders",
        r"system\currentcontrolset\services",
    ]

    for key in persistence_keys:
        if key in reg_path:
            return (
                True,
                f"Registry persistence detected: {key}",
                {"registry_path": reg_path, "process_name": event.get("process_name")},
            )

    return False, "", {}


def _condition_malicious_document(event: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Detect malicious document simulation indicators."""
    proc = (event.get("process_name") or "").lower()
    cmd = (event.get("command_line") or "").lower()
    file_path = (event.get("file_path") or "").lower()

    # Look for document-related process spawning unexpected children
    doc_extensions = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".pdf"}
    has_doc = any(file_path.endswith(ext) for ext in doc_extensions)

    # Macro / embedded content execution indicators
    macro_indicators = [
        re.compile(r"wmic\s+process\s+call\s+create", re.IGNORECASE),
        re.compile(r"certutil.*-urlcache", re.IGNORECASE),
        re.compile(r"bitsadmin.*/(transfer|download)", re.IGNORECASE),
        re.compile(r"mshta\s+(?:http|javascript)", re.IGNORECASE),
        re.compile(r"regsvr32\s+/s\s+/n\s+/u\s+/i:", re.IGNORECASE),
    ]

    if cmd:
        for indicator in macro_indicators:
            if indicator.search(cmd):
                return (
                    True,
                    f"Malicious document execution pattern detected",
                    {"command_line": cmd[:500], "file_path": file_path, "process": proc},
                )

    return False, "", {}


# ---------------------------------------------------------------------------
# Exclusion (hard-negative) conditions
# ---------------------------------------------------------------------------

def _exclusion_authorized_scanner(event: Dict[str, Any]) -> bool:
    """Suppress alerts for known authorized security scanners."""
    attrs = event.get("attributes", {})
    username = (event.get("username") or "").lower()
    proc = (event.get("process_name") or "").lower()
    hostname = (event.get("hostname") or "").lower()

    # Check explicit authorized scanner tags
    if attrs.get("authorized_scanner"):
        return True
    if attrs.get("security_scan"):
        return True

    # Known scanner process names
    scanner_procs = {"nessus", "openvas", "qualys", "nmap", "nikto", "burpsuite",
                     "zap", "acunetix", "nexpose"}
    if proc in scanner_procs:
        return True

    # Known scanner service accounts
    if username.startswith("svc_scan") or username.startswith("svc_security"):
        return True

    return False


def _exclusion_approved_deployment(event: Dict[str, Any]) -> bool:
    """Suppress alerts for approved IT deployment activity."""
    attrs = event.get("attributes", {})
    username = (event.get("username") or "").lower()

    if attrs.get("approved_deployment"):
        return True
    if attrs.get("change_ticket"):
        return True

    # Known deployment service accounts
    if username.startswith("svc_deploy") or username.startswith("svc_sccm"):
        return True

    return False


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

# Condition-to-exclusion mapping
EXCLUSION_FUNCTIONS = {
    "authorized_scanner": _exclusion_authorized_scanner,
    "approved_deployment": _exclusion_approved_deployment,
}


# Master rule definitions
DETECTION_RULES: List[Tuple[DetectionRule, RuleCondition]] = [
    # --- Scenario 1: Suspicious PowerShell ---
    (
        DetectionRule(
            rule_id="AX-RULE-001",
            name="Suspicious PowerShell Execution",
            description="Detects PowerShell with obfuscation, download cradles, or encoded commands",
            severity=AlertSeverity.HIGH,
            detection_type=DetectionType.RULE,
            mitre_technique_id="T1059.001",
            mitre_technique_name="Command and Scripting Interpreter: PowerShell",
            mitre_tactic="execution",
            tags=["powershell", "execution", "obfuscation"],
            exclude_tags=["authorized_scanner", "approved_deployment"],
        ),
        _condition_suspicious_powershell,
    ),

    # --- Scenario 3: Brute-Force Authentication ---
    (
        DetectionRule(
            rule_id="AX-RULE-002",
            name="Authentication Failure",
            description="Detects failed authentication attempts indicating potential brute-force",
            severity=AlertSeverity.MEDIUM,
            detection_type=DetectionType.RULE,
            mitre_technique_id="T1110",
            mitre_technique_name="Brute Force",
            mitre_tactic="credential_access",
            tags=["brute_force", "authentication", "credential_access"],
        ),
        _condition_brute_force_auth,
    ),

    # --- Scenario 4: Suspicious Login Anomaly ---
    (
        DetectionRule(
            rule_id="AX-RULE-003",
            name="Login Anomaly Detected",
            description="Detects anomalous login patterns (off-hours, impossible travel, etc.)",
            severity=AlertSeverity.MEDIUM,
            detection_type=DetectionType.BEHAVIORAL,
            mitre_technique_id="T1078",
            mitre_technique_name="Valid Accounts",
            mitre_tactic="initial_access",
            tags=["anomaly", "authentication", "behavioral"],
        ),
        _condition_suspicious_login_anomaly,
    ),

    # --- Scenario 5: Scheduled Task Persistence ---
    (
        DetectionRule(
            rule_id="AX-RULE-004",
            name="Scheduled Task Persistence",
            description="Detects persistence mechanisms via scheduled tasks",
            severity=AlertSeverity.HIGH,
            detection_type=DetectionType.RULE,
            mitre_technique_id="T1053.005",
            mitre_technique_name="Scheduled Task/Job: Scheduled Task",
            mitre_tactic="persistence",
            tags=["persistence", "scheduled_task"],
            exclude_tags=["approved_deployment"],
        ),
        _condition_scheduled_task_persistence,
    ),

    # --- Scenario 6: Office → PowerShell Chain ---
    (
        DetectionRule(
            rule_id="AX-RULE-005",
            name="Office Application Spawns Shell",
            description="Detects Office applications spawning command shells (macro/exploit chain)",
            severity=AlertSeverity.CRITICAL,
            detection_type=DetectionType.RULE,
            mitre_technique_id="T1204.002",
            mitre_technique_name="User Execution: Malicious File",
            mitre_tactic="execution",
            tags=["macro", "office", "initial_access"],
        ),
        _condition_office_spawn_shell,
    ),

    # --- Scenario 7: Suspicious Outbound Connection ---
    (
        DetectionRule(
            rule_id="AX-RULE-006",
            name="Suspicious Outbound Connection",
            description="Detects outbound connections to known suspicious ports",
            severity=AlertSeverity.HIGH,
            detection_type=DetectionType.IOC,
            mitre_technique_id="T1571",
            mitre_technique_name="Non-Standard Port",
            mitre_tactic="command_and_control",
            tags=["c2", "network", "exfiltration"],
            exclude_tags=["authorized_scanner"],
        ),
        _condition_suspicious_outbound,
    ),

    # --- Scenario 8: Ransomware-like File Modification ---
    (
        DetectionRule(
            rule_id="AX-RULE-007",
            name="Ransomware-like File Modification",
            description="Detects file modifications with known ransomware extensions or ransom notes",
            severity=AlertSeverity.CRITICAL,
            detection_type=DetectionType.BEHAVIORAL,
            mitre_technique_id="T1486",
            mitre_technique_name="Data Encrypted for Impact",
            mitre_tactic="impact",
            tags=["ransomware", "encryption", "impact"],
        ),
        _condition_ransomware_file_mod,
    ),

    # --- Suspicious DNS ---
    (
        DetectionRule(
            rule_id="AX-RULE-008",
            name="Suspicious DNS Query",
            description="Detects DNS queries to suspicious TLDs or DGA-like domains",
            severity=AlertSeverity.MEDIUM,
            detection_type=DetectionType.IOC,
            mitre_technique_id="T1071.004",
            mitre_technique_name="Application Layer Protocol: DNS",
            mitre_tactic="command_and_control",
            tags=["dns", "dga", "c2"],
        ),
        _condition_suspicious_dns,
    ),

    # --- Registry Persistence ---
    (
        DetectionRule(
            rule_id="AX-RULE-009",
            name="Registry Persistence",
            description="Detects modifications to known registry persistence locations",
            severity=AlertSeverity.HIGH,
            detection_type=DetectionType.RULE,
            mitre_technique_id="T1547.001",
            mitre_technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
            mitre_tactic="persistence",
            tags=["persistence", "registry"],
            exclude_tags=["approved_deployment"],
        ),
        _condition_registry_persistence,
    ),

    # --- Malicious Document ---
    (
        DetectionRule(
            rule_id="AX-RULE-010",
            name="Malicious Document Execution",
            description="Detects document-based execution patterns (macro, embedded content)",
            severity=AlertSeverity.HIGH,
            detection_type=DetectionType.RULE,
            mitre_technique_id="T1204.002",
            mitre_technique_name="User Execution: Malicious File",
            mitre_tactic="execution",
            tags=["document", "macro", "execution"],
        ),
        _condition_malicious_document,
    ),
]


def get_all_rules() -> List[Tuple[DetectionRule, RuleCondition]]:
    """Return all registered detection rules and their conditions."""
    return list(DETECTION_RULES)


def get_exclusion_fn(tag: str):
    """Return the exclusion function for a given tag, or None."""
    return EXCLUSION_FUNCTIONS.get(tag)
