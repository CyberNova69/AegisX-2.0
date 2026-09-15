"""Tests for source identifier scalability (P1 fix).

Verifies that DatasetRecord.source can be any string, not just
DatasetSourceType enum values. Existing enum sources remain backward-compatible.
"""

import json
import pytest

from aegisx_data.core.types import (
    Classification, DatasetRecord, DatasetSourceType, RecordStatus,
)
from aegisx_data.processing.label_harmonizer import LabelHarmonizer


class TestSourceScalability:
    """Tests for string-based source identifiers."""

    def test_arbitrary_source_string(self):
        """DatasetRecord accepts any string as source."""
        r = DatasetRecord(
            record_id="ext-001",
            source="my_custom_nids_dataset_v3",
        )
        assert r.source == "my_custom_nids_dataset_v3"

    def test_existing_enum_sources_backward_compatible(self):
        """Existing DatasetSourceType enum values still work."""
        r = DatasetRecord(
            record_id="ext-002",
            source=DatasetSourceType.CICIDS_2017,
        )
        # DatasetSourceType inherits from str, so string comparison works
        assert r.source == "cicids_2017"
        assert r.source == DatasetSourceType.CICIDS_2017

    def test_300_sources(self):
        """300 unique source strings can be used without enum changes."""
        records = []
        for i in range(300):
            r = DatasetRecord(
                record_id=f"ext-{i:04d}",
                source=f"external_dataset_{i:04d}",
            )
            records.append(r)

        assert len(records) == 300
        sources = {r.source for r in records}
        assert len(sources) == 300

    def test_to_dict_with_string_source(self):
        """to_dict works correctly with plain string source."""
        r = DatasetRecord(
            record_id="ext-003",
            source="kaggle_malware_2024",
        )
        d = r.to_dict()
        assert d["source"] == "kaggle_malware_2024"

    def test_from_dict_with_unknown_source(self):
        """from_dict accepts source strings not in DatasetSourceType."""
        d = {
            "record_id": "ext-004",
            "source": "custom_honeypot_v2",
        }
        r = DatasetRecord.from_dict(d)
        assert r.record_id == "ext-004"
        assert r.source == "custom_honeypot_v2"

    def test_from_dict_with_known_source(self):
        """from_dict converts known source strings to DatasetSourceType."""
        d = {
            "record_id": "ext-005",
            "source": "cicids_2017",
        }
        r = DatasetRecord.from_dict(d)
        assert r.source == DatasetSourceType.CICIDS_2017

    def test_roundtrip_string_source(self):
        """String source survives to_dict → from_dict roundtrip."""
        r1 = DatasetRecord(
            record_id="ext-006",
            source="shodan_scan_results",
            classification=Classification.SUSPICIOUS,
        )
        d = r1.to_dict()
        r2 = DatasetRecord.from_dict(d)
        assert r2.source == "shodan_scan_results"
        assert r2.classification == Classification.SUSPICIOUS

    def test_harmonizer_with_string_source(self):
        """LabelHarmonizer works with arbitrary string source IDs."""
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="ext-007",
            source="unknown_dataset_xyz",
            source_label="SomeAttackLabel",
            status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        # Unknown source + unknown label = REVIEW_REQUIRED (not crash)
        assert r.classification == Classification.REVIEW_REQUIRED

    def test_source_deterministic(self):
        """Same source string always produces same record."""
        r1 = DatasetRecord(record_id="x", source="dataset_abc")
        r2 = DatasetRecord(record_id="x", source="dataset_abc")
        assert r1.source == r2.source
        assert r1.to_dict()["source"] == r2.to_dict()["source"]

    def test_aegisx_soc_enum_value(self):
        """New AEGISX_SOC enum value is accessible."""
        assert DatasetSourceType.AEGISX_SOC.value == "aegisx_soc"
        r = DatasetRecord(
            record_id="soc-001",
            source=DatasetSourceType.AEGISX_SOC,
        )
        assert r.source == "aegisx_soc"
