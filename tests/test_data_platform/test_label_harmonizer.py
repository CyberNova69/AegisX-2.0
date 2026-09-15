"""Tests for the label harmonizer."""

import pytest
from aegisx_data.processing.label_harmonizer import LabelHarmonizer
from aegisx_data.core.types import (
    AttackCategory, Classification, DatasetRecord, DatasetSourceType, RecordStatus,
)


class TestLabelHarmonizer:
    def test_cicids_benign(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            source_label="BENIGN", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.BENIGN
        assert r.attack_category == AttackCategory.NONE

    def test_cicids_ddos(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            source_label="DDoS", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.MALICIOUS
        assert r.attack_category == AttackCategory.DDOS

    def test_unsw_normal(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.UNSW_NB15,
            source_label="Normal", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.BENIGN

    def test_unsw_exploits(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.UNSW_NB15,
            source_label="Exploits", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.MALICIOUS
        assert r.attack_category == AttackCategory.EXPLOIT

    def test_ctu_botnet(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CTU_13,
            source_label="Botnet", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.MALICIOUS
        assert r.attack_category == AttackCategory.BOTNET

    def test_ember_malware(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.EMBER,
            source_label="malware", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.MALICIOUS
        assert r.attack_category == AttackCategory.MALWARE

    def test_unknown_label(self):
        """Unknown labels must NOT silently become SUSPICIOUS (P0 fix).

        They must become REVIEW_REQUIRED with confidence=0.0 and
        harmonization status 'unknown'.
        """
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            source_label="CompletelyUnknownAttack", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.REVIEW_REQUIRED
        assert r.confidence == 0.0
        assert r.enrichment_tags["harmonization"] == "unknown"
        assert r.enrichment_tags["unmapped_label"] == "CompletelyUnknownAttack"
        assert r.status == RecordStatus.REVIEW_REQUIRED

    def test_no_source_label(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            source_label=None, status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.INSUFFICIENT_EVIDENCE

    def test_case_insensitive_match(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            source_label="benign", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.BENIGN

    def test_updates_status(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            source_label="BENIGN", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.status == RecordStatus.HARMONIZED


class TestAegisXSOCLabelMap:
    """Tests for the aegisx_soc built-in label map (P0 fix).

    Verifies that the 5 known SOC labels map deterministically
    and that unknown SOC labels still produce REVIEW_REQUIRED.
    """

    def test_soc_benign(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="soc1", source="aegisx_soc",
            source_label="benign", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.BENIGN
        assert r.attack_category == AttackCategory.NONE
        assert r.enrichment_tags["harmonization"] == "mapped"
        assert r.status == RecordStatus.HARMONIZED

    def test_soc_suspicious(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="soc2", source="aegisx_soc",
            source_label="suspicious", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.SUSPICIOUS
        assert r.enrichment_tags["harmonization"] == "mapped"

    def test_soc_likely_malicious(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="soc3", source="aegisx_soc",
            source_label="likely_malicious", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.LIKELY_MALICIOUS
        assert r.enrichment_tags["harmonization"] == "mapped"

    def test_soc_confirmed_malicious(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="soc4", source="aegisx_soc",
            source_label="confirmed_malicious", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.CONFIRMED_MALICIOUS
        assert r.enrichment_tags["harmonization"] == "mapped"

    def test_soc_insufficient_evidence(self):
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="soc5", source="aegisx_soc",
            source_label="insufficient_evidence", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.INSUFFICIENT_EVIDENCE
        assert r.enrichment_tags["harmonization"] == "mapped"

    def test_soc_source_label_preserved(self):
        """Original source_label must survive harmonization."""
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="soc6", source="aegisx_soc",
            source_label="confirmed_malicious", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.source_label == "confirmed_malicious"

    def test_soc_unknown_label_still_review_required(self):
        """An unknown label from aegisx_soc must still become REVIEW_REQUIRED."""
        harmonizer = LabelHarmonizer()
        r = DatasetRecord(
            record_id="soc7", source="aegisx_soc",
            source_label="never_seen_before", status=RecordStatus.VALIDATED,
        )
        harmonizer.harmonize(r)
        assert r.classification == Classification.REVIEW_REQUIRED
        assert r.confidence == 0.0
        assert r.enrichment_tags["harmonization"] == "unknown"

    def test_soc_no_review_required_for_known_labels(self):
        """None of the 5 known SOC labels should produce REVIEW_REQUIRED."""
        harmonizer = LabelHarmonizer()
        known_labels = ["benign", "suspicious", "likely_malicious",
                        "confirmed_malicious", "insufficient_evidence"]
        for label in known_labels:
            r = DatasetRecord(
                record_id=f"soc-{label}", source="aegisx_soc",
                source_label=label, status=RecordStatus.VALIDATED,
            )
            harmonizer.harmonize(r)
            assert r.classification != Classification.REVIEW_REQUIRED, (
                f"Label '{label}' incorrectly mapped to REVIEW_REQUIRED"
            )

