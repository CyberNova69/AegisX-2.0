"""
AegisX Synthetic Threat Intelligence Store
===========================================

Deterministic synthetic threat intelligence indicators, threat actor profiles,
malware families, and reputation scores.
Correlates directly with the 10 AegisX SOC investigation scenarios.
100% synthetic, offline, and safe.
"""

from typing import Any, Dict, List, Optional

SYNTHETIC_THREAT_INTEL_DB: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # Network Indicators (IP Addresses & Domains)
    # -------------------------------------------------------------------------
    "198.51.100.200": {
        "indicator": "198.51.100.200",
        "indicator_type": "ip",
        "reputation": "malicious",
        "confidence": 0.96,
        "threat_actor": "FIN7",
        "malware_family": "Cobalt Strike",
        "asn": "AS64500 (Bulletproof Hosting)",
        "country": "Unknown",
        "associated_ports": [4444, 8080],
        "mitre_techniques": ["T1071.001", "T1059.001"],
        "description": "Known Cobalt Strike Command and Control (C2) server used in financial phishing campaigns.",
        "tags": ["c2", "cobalt_strike", "fin7", "phishing_drop"],
    },
    "198.51.100.77": {
        "indicator": "198.51.100.77",
        "indicator_type": "ip",
        "reputation": "malicious",
        "confidence": 0.90,
        "threat_actor": "Unknown / Botnet",
        "malware_family": "SSH-Bruter",
        "asn": "AS64512 (Automated Scanning Network)",
        "country": "Unknown",
        "associated_ports": [22],
        "mitre_techniques": ["T1110.001", "T1078"],
        "description": "Active SSH brute force and dictionary spray node observed scanning cloud bastions.",
        "tags": ["brute_force", "ssh_scan", "credential_access"],
    },
    "198.51.100.99": {
        "indicator": "198.51.100.99",
        "indicator_type": "ip",
        "reputation": "malicious",
        "confidence": 0.92,
        "threat_actor": "LNX-Botnet-Group",
        "malware_family": "Mirai/Gafgyt Variant",
        "asn": "AS64501 (High-Risk Hosting)",
        "country": "Unknown",
        "associated_ports": [443, 8443],
        "mitre_techniques": ["T1071.001", "T1053.003"],
        "description": "Linux ELF botnet heartbeat receiver accepting periodic 60-second beacon check-ins.",
        "tags": ["beaconing", "botnet", "c2", "linux"],
    },
    "198.51.100.250": {
        "indicator": "198.51.100.250",
        "indicator_type": "ip",
        "reputation": "malicious",
        "confidence": 0.98,
        "threat_actor": "LockBit Gang",
        "malware_family": "LockBit 3.0",
        "asn": "AS64520 (Compromised Cloud Infrastructure)",
        "country": "Unknown",
        "associated_ports": [8443],
        "mitre_techniques": ["T1486", "T1490", "T1048"],
        "description": "Exfiltration endpoint and key-exchange server used prior to enterprise ransomware deployment.",
        "tags": ["ransomware", "lockbit", "exfiltration", "critical"],
    },
    "198.51.100.50": {
        "indicator": "198.51.100.50",
        "indicator_type": "ip",
        "reputation": "suspicious",
        "confidence": 0.72,
        "threat_actor": "Unknown",
        "malware_family": "Unsigned Dropper",
        "asn": "AS64505 (Commercial Content Delivery)",
        "country": "Unknown",
        "associated_ports": [80, 443],
        "mitre_techniques": ["T1204.002"],
        "description": "Host distributing unsigned executables via fake software updates; observed serving temp binaries.",
        "tags": ["drive_by_download", "suspicious_host", "unsigned_binary"],
    },
    "203.0.113.88": {
        "indicator": "203.0.113.88",
        "indicator_type": "ip",
        "reputation": "suspicious",
        "confidence": 0.68,
        "threat_actor": "Anonymization Network",
        "malware_family": "Tor / Commercial VPN",
        "asn": "AS64550 (VPN Service Provider)",
        "country": "Switzerland",
        "associated_ports": [1194, 443],
        "mitre_techniques": ["T1078.002"],
        "description": "Commercial VPN exit node associated with unauthorized off-hours access and proxy evasions.",
        "tags": ["vpn_exit", "proxy", "anomalous_geo"],
    },
    "10.0.10.2": {
        "indicator": "10.0.10.2",
        "indicator_type": "ip",
        "reputation": "benign",
        "confidence": 0.99,
        "threat_actor": "None (Internal)",
        "malware_family": "None",
        "asn": "Private RFC 1918",
        "country": "Internal",
        "associated_ports": [443],
        "mitre_techniques": [],
        "description": "Authorized internal enterprise monitoring and IT inventory collection server.",
        "tags": ["internal", "whitelisted", "it_infrastructure"],
    },
    "127.0.0.1": {
        "indicator": "127.0.0.1",
        "indicator_type": "ip",
        "reputation": "benign",
        "confidence": 1.0,
        "threat_actor": "None",
        "malware_family": "None",
        "asn": "Loopback",
        "country": "Local",
        "associated_ports": [8080],
        "mitre_techniques": [],
        "description": "Local host loopback interface used for software debugging and development.",
        "tags": ["loopback", "safe", "local"],
    },

    # -------------------------------------------------------------------------
    # File Hash Indicators (SHA-256)
    # -------------------------------------------------------------------------
    "7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7": {
        "indicator": "7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7",
        "indicator_type": "hash",
        "reputation": "malicious",
        "confidence": 0.98,
        "threat_actor": "FIN7",
        "malware_family": "Invoice-Macro-Dropper",
        "mitre_techniques": ["T1566.001", "T1059.001"],
        "description": "Malicious macro document payload that spawns hidden PowerShell to download second-stage C2.",
        "tags": ["dropper", "macro", "maldoc", "fin7"],
    },
    "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a": {
        "indicator": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "indicator_type": "hash",
        "reputation": "malicious",
        "confidence": 0.95,
        "threat_actor": "FIN7",
        "malware_family": "Updater-VBS-Backdoor",
        "mitre_techniques": ["T1547.001", "T1059.005"],
        "description": "Persistence VBScript dropped into the user Startup directory to maintain boot persistence.",
        "tags": ["persistence", "vbscript", "startup"],
    },
    "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344": {
        "indicator": "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
        "indicator_type": "hash",
        "reputation": "malicious",
        "confidence": 0.94,
        "threat_actor": "LNX-Botnet-Group",
        "malware_family": "CronSync-ELF-Backdoor",
        "mitre_techniques": ["T1053.003", "T1071.001"],
        "description": "Hidden Linux executable executing from /tmp disguised as a cron synchronizer.",
        "tags": ["backdoor", "elf", "linux", "hidden_binary"],
    },
    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd": {
        "indicator": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "indicator_type": "hash",
        "reputation": "malicious",
        "confidence": 0.99,
        "threat_actor": "LockBit Gang",
        "malware_family": "LockBit Ransom Note",
        "mitre_techniques": ["T1486"],
        "description": "Cryptographic signature of LockBit HOW_TO_DECRYPT.txt ransom demand instructions.",
        "tags": ["ransom_note", "lockbit", "extortion"],
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "indicator_type": "hash",
        "reputation": "benign",
        "confidence": 1.0,
        "threat_actor": "Microsoft Corporation",
        "malware_family": "None",
        "mitre_techniques": [],
        "description": "Standard signed system executable or zero-length reference hash.",
        "tags": ["system_binary", "whitelisted", "microsoft"],
    },
}

def get_threat_intel(indicator: str, indicator_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve structured threat intelligence for a specific IP, domain, or hash."""
    clean_key = indicator.strip().lower()
    for key, data in SYNTHETIC_THREAT_INTEL_DB.items():
        if key.lower() == clean_key:
            if indicator_type and data.get("indicator_type") != indicator_type:
                continue
            return dict(data)
    return None

def list_all_threat_intel() -> List[Dict[str, Any]]:
    """Return all records in the synthetic threat intelligence database."""
    return [dict(v) for v in SYNTHETIC_THREAT_INTEL_DB.values()]

def search_threat_intel(query: str) -> List[Dict[str, Any]]:
    """Perform basic text search across indicator, malware family, threat actor, and tags."""
    q = query.strip().lower()
    matches = []
    for item in SYNTHETIC_THREAT_INTEL_DB.values():
        haystack = " ".join([
            item.get("indicator", ""),
            item.get("threat_actor", ""),
            item.get("malware_family", ""),
            item.get("description", ""),
            " ".join(item.get("tags", [])),
        ]).lower()
        if q in haystack:
            matches.append(dict(item))
    return matches
