"""Post-validation enrichment for DatasetRecord.

Adds MITRE ATT&CK technique tags, kill chain phase mapping, and
threat category enrichment using local reference data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.types import AttackCategory, DatasetRecord, RecordStatus, Severity


# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MITRE_REFERENCE_PATH = PROJECT_ROOT / "datasets" / "metadata" / "mitre_reference.json"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Enricher
# ---------------------------------------------------------------------------

class MITREEnricher:
    """Enrich records with MITRE ATT&CK technique and tactic information.

    Uses the local mitre_reference.json from datasets/metadata/.
    """

    def __init__(self, reference_path: Optional[Path] = None):
        self._reference_path = reference_path or MITRE_REFERENCE_PATH
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._keyword_map: Dict[str, str] = {}  # keyword -> technique_id
        self._loaded = False

    def _load(self) -> None:
        """Load the MITRE reference data."""
        if self._loaded:
            return
        if self._reference_path.exists():
            with open(self._reference_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                techniques = data.get("techniques", data)
                if isinstance(techniques, list):
                    for t in techniques:
                        tid = t.get("id", t.get("technique_id", ""))
                        if tid:
                            self._techniques[tid] = t
                elif isinstance(techniques, dict):
                    self._techniques = techniques
        self._build_keyword_map()
        self._loaded = True

    def _build_keyword_map(self) -> None:
        """Build a keyword → technique_id map for fuzzy matching."""
        # Map attack categories to likely MITRE techniques
        category_technique_map = {
            "ddos": "T1498",          # Network Denial of Service
            "dos": "T1499",           # Endpoint Denial of Service
            "brute_force": "T1110",   # Brute Force
            "port_scan": "T1046",     # Network Service Scanning
            "reconnaissance": "T1595", # Active Scanning
            "infiltration": "T1071",   # Application Layer Protocol
            "web_attack": "T1190",     # Exploit Public-Facing Application
            "malware": "T1059",        # Command and Scripting Interpreter
            "exploit": "T1203",        # Exploitation for Client Execution
            "backdoor": "T1547",       # Boot or Logon Autostart Execution
            "botnet": "T1071",         # Application Layer Protocol
            "shellcode": "T1055",      # Process Injection
            "worm": "T1091",           # Replication Through Removable Media
            "fuzzers": "T1595",        # Active Scanning
        }
        self._keyword_map = category_technique_map

    def enrich(self, record: DatasetRecord) -> DatasetRecord:
        """Enrich a record with MITRE ATT&CK information."""
        self._load()

        # Try direct technique ID mapping from attack_category
        if record.attack_category and record.attack_category != AttackCategory.NONE:
            category_key = record.attack_category.value
            technique_id = self._keyword_map.get(category_key)
            if technique_id:
                record.mitre_technique_id = technique_id
                technique_data = self._techniques.get(technique_id, {})
                record.mitre_technique_name = technique_data.get(
                    "name", technique_data.get("technique_name", ""))
                record.mitre_tactic = technique_data.get(
                    "tactic", technique_data.get("kill_chain_phase", ""))
                record.enrichment_tags["mitre_source"] = "category_mapping"

        return record


# ---------------------------------------------------------------------------
# Severity Estimator
# ---------------------------------------------------------------------------

class SeverityEstimator:
    """Estimate severity from attack category when not provided by source."""

    CATEGORY_SEVERITY_MAP = {
        AttackCategory.NONE: Severity.INFORMATIONAL,
        AttackCategory.PORT_SCAN: Severity.LOW,
        AttackCategory.RECONNAISSANCE: Severity.LOW,
        AttackCategory.FUZZERS: Severity.LOW,
        AttackCategory.ANALYSIS: Severity.LOW,
        AttackCategory.BRUTE_FORCE: Severity.MEDIUM,
        AttackCategory.DOS: Severity.MEDIUM,
        AttackCategory.DDOS: Severity.HIGH,
        AttackCategory.WEB_ATTACK: Severity.HIGH,
        AttackCategory.INFILTRATION: Severity.HIGH,
        AttackCategory.BOTNET: Severity.HIGH,
        AttackCategory.EXPLOIT: Severity.HIGH,
        AttackCategory.MALWARE: Severity.CRITICAL,
        AttackCategory.BACKDOOR: Severity.CRITICAL,
        AttackCategory.SHELLCODE: Severity.CRITICAL,
        AttackCategory.WORM: Severity.CRITICAL,
        AttackCategory.GENERIC_ATTACK: Severity.MEDIUM,
        AttackCategory.OTHER: Severity.MEDIUM,
    }

    def estimate(self, record: DatasetRecord) -> DatasetRecord:
        """Estimate severity if not already set."""
        if record.severity is None and record.attack_category is not None:
            estimated = self.CATEGORY_SEVERITY_MAP.get(
                record.attack_category, Severity.MEDIUM)
            record.severity = estimated
            record.enrichment_tags["severity_source"] = "estimated_from_category"
        return record


# ---------------------------------------------------------------------------
# Kill Chain Phase Mapper
# ---------------------------------------------------------------------------

class KillChainMapper:
    """Map attack categories to Cyber Kill Chain phases."""

    CATEGORY_PHASE_MAP = {
        AttackCategory.RECONNAISSANCE: "reconnaissance",
        AttackCategory.PORT_SCAN: "reconnaissance",
        AttackCategory.FUZZERS: "weaponization",
        AttackCategory.WEB_ATTACK: "exploitation",
        AttackCategory.EXPLOIT: "exploitation",
        AttackCategory.SHELLCODE: "exploitation",
        AttackCategory.MALWARE: "installation",
        AttackCategory.BACKDOOR: "installation",
        AttackCategory.BOTNET: "command_and_control",
        AttackCategory.INFILTRATION: "actions_on_objectives",
        AttackCategory.WORM: "actions_on_objectives",
        AttackCategory.DOS: "actions_on_objectives",
        AttackCategory.DDOS: "actions_on_objectives",
        AttackCategory.BRUTE_FORCE: "exploitation",
    }

    def map_phase(self, record: DatasetRecord) -> DatasetRecord:
        """Add kill chain phase to enrichment tags."""
        if record.attack_category and record.attack_category != AttackCategory.NONE:
            phase = self.CATEGORY_PHASE_MAP.get(record.attack_category)
            if phase:
                record.enrichment_tags["kill_chain_phase"] = phase
        return record


# ---------------------------------------------------------------------------
# Composite Enricher
# ---------------------------------------------------------------------------

class RecordEnricher:
    """Composite enricher that applies all enrichment steps."""

    def __init__(
        self,
        mitre_enabled: bool = True,
        severity_estimation: bool = True,
        kill_chain_mapping: bool = True,
        mitre_reference_path: Optional[Path] = None,
    ):
        self._enrichers: List = []
        if mitre_enabled:
            self._enrichers.append(MITREEnricher(mitre_reference_path))
        if severity_estimation:
            self._enrichers.append(SeverityEstimator())
        if kill_chain_mapping:
            self._enrichers.append(KillChainMapper())

    def enrich(self, record: DatasetRecord) -> DatasetRecord:
        """Apply all enrichment steps to a record."""
        for enricher in self._enrichers:
            if hasattr(enricher, "enrich"):
                enricher.enrich(record)
            elif hasattr(enricher, "estimate"):
                enricher.estimate(record)
            elif hasattr(enricher, "map_phase"):
                enricher.map_phase(record)

        if record.status == RecordStatus.VALIDATED:
            record.status = RecordStatus.ENRICHED

        return record
