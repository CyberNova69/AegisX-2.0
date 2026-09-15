"""Label harmonization: map heterogeneous source labels to AegisX taxonomy.

Each external dataset uses its own label scheme. This module provides
configurable per-source mappings that produce a unified Classification
(benign/malicious/suspicious/insufficient_evidence) plus an AttackCategory.

Label maps are loaded from YAML files in configs/label_maps/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.types import (
    AttackCategory,
    Classification,
    DatasetRecord,
    DatasetSourceType,
    HarmonizationStatus,
    RecordStatus,
    Severity,
)


# ---------------------------------------------------------------------------
# Default label maps (built-in fallbacks)
# ---------------------------------------------------------------------------

# CICIDS-2017/2018 label → (classification, attack_category)
CICIDS_LABEL_MAP: Dict[str, Tuple[Classification, AttackCategory]] = {
    # Benign
    "BENIGN": (Classification.BENIGN, AttackCategory.NONE),
    "Benign": (Classification.BENIGN, AttackCategory.NONE),
    "benign": (Classification.BENIGN, AttackCategory.NONE),
    # DDoS
    "DDoS": (Classification.MALICIOUS, AttackCategory.DDOS),
    "ddos": (Classification.MALICIOUS, AttackCategory.DDOS),
    # DoS variants
    "DoS Hulk": (Classification.MALICIOUS, AttackCategory.DOS),
    "DoS GoldenEye": (Classification.MALICIOUS, AttackCategory.DOS),
    "DoS slowloris": (Classification.MALICIOUS, AttackCategory.DOS),
    "DoS Slowhttptest": (Classification.MALICIOUS, AttackCategory.DOS),
    # Brute force
    "FTP-Patator": (Classification.MALICIOUS, AttackCategory.BRUTE_FORCE),
    "SSH-Patator": (Classification.MALICIOUS, AttackCategory.BRUTE_FORCE),
    "Brute Force": (Classification.MALICIOUS, AttackCategory.BRUTE_FORCE),
    # Web attacks
    "Web Attack – Brute Force": (Classification.MALICIOUS, AttackCategory.WEB_ATTACK),
    "Web Attack – XSS": (Classification.MALICIOUS, AttackCategory.WEB_ATTACK),
    "Web Attack – Sql Injection": (Classification.MALICIOUS, AttackCategory.WEB_ATTACK),
    "Web Attack  Brute Force": (Classification.MALICIOUS, AttackCategory.WEB_ATTACK),
    "Web Attack  XSS": (Classification.MALICIOUS, AttackCategory.WEB_ATTACK),
    "Web Attack  Sql Injection": (Classification.MALICIOUS, AttackCategory.WEB_ATTACK),
    # Other
    "Infiltration": (Classification.MALICIOUS, AttackCategory.INFILTRATION),
    "Bot": (Classification.MALICIOUS, AttackCategory.BOTNET),
    "PortScan": (Classification.SUSPICIOUS, AttackCategory.PORT_SCAN),
    "Heartbleed": (Classification.MALICIOUS, AttackCategory.EXPLOIT),
}

# UNSW-NB15 label → (classification, attack_category)
UNSW_NB15_LABEL_MAP: Dict[str, Tuple[Classification, AttackCategory]] = {
    "Normal": (Classification.BENIGN, AttackCategory.NONE),
    "normal": (Classification.BENIGN, AttackCategory.NONE),
    "0": (Classification.BENIGN, AttackCategory.NONE),
    "Fuzzers": (Classification.SUSPICIOUS, AttackCategory.FUZZERS),
    "Analysis": (Classification.SUSPICIOUS, AttackCategory.ANALYSIS),
    "Backdoor": (Classification.MALICIOUS, AttackCategory.BACKDOOR),
    "Backdoors": (Classification.MALICIOUS, AttackCategory.BACKDOOR),
    "DoS": (Classification.MALICIOUS, AttackCategory.DOS),
    "Exploits": (Classification.MALICIOUS, AttackCategory.EXPLOIT),
    "Generic": (Classification.MALICIOUS, AttackCategory.GENERIC_ATTACK),
    "Reconnaissance": (Classification.SUSPICIOUS, AttackCategory.RECONNAISSANCE),
    "Shellcode": (Classification.MALICIOUS, AttackCategory.SHELLCODE),
    "Worms": (Classification.MALICIOUS, AttackCategory.WORM),
}

# CTU-13 label → (classification, attack_category)
CTU_13_LABEL_MAP: Dict[str, Tuple[Classification, AttackCategory]] = {
    "Normal": (Classification.BENIGN, AttackCategory.NONE),
    "Botnet": (Classification.MALICIOUS, AttackCategory.BOTNET),
    "Background": (Classification.BENIGN, AttackCategory.NONE),
    "normal": (Classification.BENIGN, AttackCategory.NONE),
    "botnet": (Classification.MALICIOUS, AttackCategory.BOTNET),
    "background": (Classification.BENIGN, AttackCategory.NONE),
}

# EMBER label → (classification, attack_category)
EMBER_LABEL_MAP: Dict[str, Tuple[Classification, AttackCategory]] = {
    "0": (Classification.BENIGN, AttackCategory.NONE),
    "benign": (Classification.BENIGN, AttackCategory.NONE),
    "1": (Classification.MALICIOUS, AttackCategory.MALWARE),
    "malware": (Classification.MALICIOUS, AttackCategory.MALWARE),
    "malicious": (Classification.MALICIOUS, AttackCategory.MALWARE),
    "-1": (Classification.INSUFFICIENT_EVIDENCE, AttackCategory.OTHER),
    "unknown": (Classification.INSUFFICIENT_EVIDENCE, AttackCategory.OTHER),
}

# AegisX SOC (v0.4) label → (classification, attack_category)
# These are trusted labels from the existing AegisX cybersecurity dataset.
AEGISX_SOC_LABEL_MAP: Dict[str, Tuple[Classification, AttackCategory]] = {
    "benign": (Classification.BENIGN, AttackCategory.NONE),
    "suspicious": (Classification.SUSPICIOUS, AttackCategory.OTHER),
    "likely_malicious": (Classification.LIKELY_MALICIOUS, AttackCategory.OTHER),
    "confirmed_malicious": (Classification.CONFIRMED_MALICIOUS, AttackCategory.OTHER),
    "insufficient_evidence": (Classification.INSUFFICIENT_EVIDENCE, AttackCategory.OTHER),
}

# Master map of all built-in label maps
BUILTIN_LABEL_MAPS: Dict[str, Dict[str, Tuple[Classification, AttackCategory]]] = {
    DatasetSourceType.CICIDS_2017.value: CICIDS_LABEL_MAP,
    DatasetSourceType.CICIDS_2018.value: CICIDS_LABEL_MAP,
    DatasetSourceType.UNSW_NB15.value: UNSW_NB15_LABEL_MAP,
    DatasetSourceType.CTU_13.value: CTU_13_LABEL_MAP,
    DatasetSourceType.EMBER.value: EMBER_LABEL_MAP,
    "aegisx_soc": AEGISX_SOC_LABEL_MAP,
}


# ---------------------------------------------------------------------------
# Label Map Loader
# ---------------------------------------------------------------------------

def load_label_map_from_yaml(path: Path) -> Dict[str, Tuple[Classification, AttackCategory]]:
    """Load a label mapping from a YAML file.

    Expected format:
        labels:
          "BENIGN":
            classification: "benign"
            attack_category: "none"
          "DDoS":
            classification: "malicious"
            attack_category: "ddos"
    """
    label_map: Dict[str, Tuple[Classification, AttackCategory]] = {}

    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except ImportError:
        # Basic fallback: read key-value pairs
        data = _basic_label_yaml_parse(path)

    if not isinstance(data, dict):
        return label_map

    labels = data.get("labels", data)
    if isinstance(labels, dict):
        for source_label, mapping in labels.items():
            if isinstance(mapping, dict):
                cls_str = mapping.get("classification", "suspicious")
                cat_str = mapping.get("attack_category", "other")
                try:
                    classification = Classification(cls_str)
                except ValueError:
                    classification = Classification.SUSPICIOUS
                try:
                    attack_category = AttackCategory(cat_str)
                except ValueError:
                    attack_category = AttackCategory.OTHER
                label_map[str(source_label)] = (classification, attack_category)
            elif isinstance(mapping, str):
                # Simple format: "source_label": "classification"
                try:
                    classification = Classification(mapping)
                    label_map[str(source_label)] = (classification, AttackCategory.OTHER)
                except ValueError:
                    pass

    return label_map


def _basic_label_yaml_parse(path: Path) -> Dict[str, Any]:
    """Minimal YAML parser for label map files."""
    data: Dict[str, Any] = {"labels": {}}
    current_label = None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.rstrip()
            if not stripped or stripped.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            content = stripped.lstrip()

            if ":" in content:
                key, _, value = content.partition(":")
                key = key.strip().strip('"').strip("'")
                value = value.strip().strip('"').strip("'")

                if indent <= 2 and key == "labels":
                    continue
                elif indent <= 4 and not value:
                    current_label = key
                    data["labels"][current_label] = {}
                elif indent > 4 and current_label:
                    data["labels"][current_label][key] = value

    return data


# ---------------------------------------------------------------------------
# Label Harmonizer
# ---------------------------------------------------------------------------

class LabelHarmonizer:
    """Map heterogeneous source labels to unified AegisX taxonomy.

    Uses built-in maps with optional YAML overrides from configs/label_maps/.
    """

    def __init__(self, label_maps_dir: Optional[Path] = None):
        self._maps: Dict[str, Dict[str, Tuple[Classification, AttackCategory]]] = {}
        self._maps.update(BUILTIN_LABEL_MAPS)

        # Load YAML overrides if directory exists
        if label_maps_dir and label_maps_dir.exists():
            for yaml_file in sorted(label_maps_dir.glob("*.yaml")):
                source_name = yaml_file.stem
                yaml_map = load_label_map_from_yaml(yaml_file)
                if yaml_map:
                    # YAML overrides merge on top of built-in
                    if source_name in self._maps:
                        self._maps[source_name].update(yaml_map)
                    else:
                        self._maps[source_name] = yaml_map

    def harmonize(self, record: DatasetRecord) -> DatasetRecord:
        """Map the source label to AegisX classification and attack category."""
        if record.source_label is None:
            record.classification = Classification.INSUFFICIENT_EVIDENCE
            record.attack_category = AttackCategory.OTHER
            record.enrichment_tags["harmonization"] = HarmonizationStatus.NO_LABEL.value
            if record.status in (RecordStatus.ENRICHED, RecordStatus.VALIDATED):
                record.status = RecordStatus.HARMONIZED
            return record

        # Resolve source key for label map lookup
        source_key = record.source.value if hasattr(record.source, 'value') else str(record.source)
        label_map = self._maps.get(source_key, {})

        # Try exact match first
        mapping = label_map.get(record.source_label)
        match_type = HarmonizationStatus.MAPPED

        # Try case-insensitive match
        if mapping is None:
            for key, value in label_map.items():
                if key.lower() == record.source_label.lower():
                    mapping = value
                    match_type = HarmonizationStatus.MAPPED
                    break

        # Try partial/contains match — flag as AMBIGUOUS
        if mapping is None:
            label_lower = record.source_label.lower()
            for key, value in label_map.items():
                if key.lower() in label_lower or label_lower in key.lower():
                    mapping = value
                    match_type = HarmonizationStatus.AMBIGUOUS
                    break

        if mapping and match_type == HarmonizationStatus.MAPPED:
            # Deterministic match — trusted
            record.classification, record.attack_category = mapping
            record.enrichment_tags["harmonization"] = HarmonizationStatus.MAPPED.value
        elif mapping and match_type == HarmonizationStatus.AMBIGUOUS:
            # Fuzzy match — needs review, may be wrong
            record.classification = Classification.REVIEW_REQUIRED
            record.attack_category = AttackCategory.OTHER
            record.confidence = 0.2
            record.enrichment_tags["harmonization"] = HarmonizationStatus.AMBIGUOUS.value
            record.enrichment_tags["ambiguous_label"] = record.source_label
            record.enrichment_tags["ambiguous_match_key"] = str(next(
                (k for k in label_map if k.lower() in record.source_label.lower()
                 or record.source_label.lower() in k.lower()), None
            ))
            if record.status in (RecordStatus.ENRICHED, RecordStatus.VALIDATED):
                record.status = RecordStatus.REVIEW_REQUIRED
        else:
            # No mapping found — unknown label, requires human review
            record.classification = Classification.REVIEW_REQUIRED
            record.attack_category = AttackCategory.OTHER
            record.confidence = 0.0
            record.enrichment_tags["harmonization"] = HarmonizationStatus.UNKNOWN.value
            record.enrichment_tags["unmapped_label"] = record.source_label
            if record.status in (RecordStatus.ENRICHED, RecordStatus.VALIDATED):
                record.status = RecordStatus.REVIEW_REQUIRED

        # Only set HARMONIZED for deterministic mappings
        if match_type == HarmonizationStatus.MAPPED:
            if record.status in (RecordStatus.ENRICHED, RecordStatus.VALIDATED):
                record.status = RecordStatus.HARMONIZED

        return record

    def get_map(self, source) -> Dict[str, Tuple[Classification, AttackCategory]]:
        """Get the label map for a specific source."""
        key = source.value if hasattr(source, 'value') else str(source)
        return self._maps.get(key, {})

    def add_mapping(self, source: str, source_label: str,
                    classification: Classification,
                    attack_category: AttackCategory) -> None:
        """Add or override a single label mapping."""
        if source not in self._maps:
            self._maps[source] = {}
        self._maps[source][source_label] = (classification, attack_category)
