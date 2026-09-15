"""MITRE ATT&CK STIX/JSON connector.

Downloads and parses the Enterprise ATT&CK matrix for technique
descriptions, tactic mapping, and enrichment data.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..core.types import DatasetRecord, DatasetSourceType
from .base import DatasetSource


# MITRE ATT&CK STIX URLs
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class MITREAttackSource(DatasetSource):
    """MITRE ATT&CK Enterprise matrix connector.

    Parses ATT&CK techniques from the STIX JSON bundle.
    This is primarily used for enrichment data, not training records.

    Usage:
        source = MITREAttackSource()
        techniques = source.load_techniques(Path("enterprise-attack.json"))
    """

    source_type = DatasetSourceType.MITRE_ATTACK
    description = "MITRE ATT&CK Enterprise Matrix"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._techniques: Dict[str, Dict[str, Any]] = {}

    def parse(self, path: Path, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        """Parse MITRE ATT&CK data as records (one per technique).

        Useful for creating technique-aware training data.
        """
        techniques = self.load_techniques(path)
        count = 0

        for technique_id, technique in techniques.items():
            if limit and count >= limit:
                return

            record = DatasetRecord(
                record_id=f"mitre-{technique_id}-{count:04d}",
                source=self.source_type,
                source_file=path.name,
                record_index=count,
            )

            record.mitre_technique_id = technique_id
            record.mitre_technique_name = technique.get("name", "")
            record.mitre_tactic = technique.get("tactic", "")
            record.source_label = "malicious"  # All ATT&CK techniques are adversary behavior

            record.enrichment_tags = {
                "description": technique.get("description", ""),
                "platforms": technique.get("platforms", []),
                "data_sources": technique.get("data_sources", []),
                "detection": technique.get("detection", ""),
                "url": technique.get("url", ""),
            }

            record.raw = technique
            yield record
            count += 1

    def load_techniques(self, path: Path) -> Dict[str, Dict[str, Any]]:
        """Load techniques from a STIX JSON file or local reference.

        Returns dict of technique_id -> technique_data.
        """
        if self._techniques:
            return self._techniques

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Handle STIX bundle format
        if isinstance(data, dict) and "objects" in data:
            self._techniques = self._parse_stix_bundle(data)
        # Handle our local mitre_reference.json format
        elif isinstance(data, dict) and "techniques" in data:
            techniques = data["techniques"]
            if isinstance(techniques, list):
                for t in techniques:
                    tid = t.get("id", t.get("technique_id", ""))
                    if tid:
                        self._techniques[tid] = t
            elif isinstance(techniques, dict):
                self._techniques = techniques
        # Handle flat dict of techniques
        elif isinstance(data, dict):
            self._techniques = data

        return self._techniques

    def _parse_stix_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Parse a MITRE ATT&CK STIX 2.0 bundle."""
        techniques: Dict[str, Dict[str, Any]] = {}

        for obj in bundle.get("objects", []):
            obj_type = obj.get("type", "")

            if obj_type == "attack-pattern":
                # Extract technique ID from external_references
                technique_id = ""
                url = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id", "")
                        url = ref.get("url", "")
                        break

                if technique_id:
                    # Extract kill chain phases (tactics)
                    tactics = []
                    for phase in obj.get("kill_chain_phases", []):
                        if phase.get("kill_chain_name") == "mitre-attack":
                            tactics.append(phase.get("phase_name", ""))

                    # Extract platforms
                    platforms = obj.get("x_mitre_platforms", [])

                    # Extract data sources
                    data_sources = obj.get("x_mitre_data_sources", [])

                    techniques[technique_id] = {
                        "id": technique_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactic": ", ".join(tactics) if tactics else "",
                        "tactics": tactics,
                        "platforms": platforms,
                        "data_sources": data_sources,
                        "detection": obj.get("x_mitre_detection", ""),
                        "url": url,
                        "created": obj.get("created", ""),
                        "modified": obj.get("modified", ""),
                    }

        return techniques

    def download_attack_data(self, dest: Optional[Path] = None) -> Path:
        """Download the latest Enterprise ATT&CK STIX bundle."""
        return self.download(ATTACK_STIX_URL, dest)
