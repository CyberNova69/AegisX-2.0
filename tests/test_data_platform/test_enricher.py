"""Tests for the enricher."""

import pytest
from aegisx_data.processing.enricher import (
    RecordEnricher, MITREEnricher, SeverityEstimator, KillChainMapper,
)
from aegisx_data.core.types import (
    AttackCategory, DatasetRecord, DatasetSourceType, RecordStatus, Severity,
)


class TestSeverityEstimator:
    def test_estimates_severity_from_category(self):
        estimator = SeverityEstimator()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            attack_category=AttackCategory.DDOS,
        )
        estimator.estimate(r)
        assert r.severity == Severity.HIGH

    def test_does_not_overwrite_existing(self):
        estimator = SeverityEstimator()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            attack_category=AttackCategory.DDOS,
            severity=Severity.LOW,
        )
        estimator.estimate(r)
        assert r.severity == Severity.LOW  # Not overwritten


class TestKillChainMapper:
    def test_maps_recon(self):
        mapper = KillChainMapper()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            attack_category=AttackCategory.RECONNAISSANCE,
        )
        mapper.map_phase(r)
        assert r.enrichment_tags.get("kill_chain_phase") == "reconnaissance"

    def test_maps_malware(self):
        mapper = KillChainMapper()
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            attack_category=AttackCategory.MALWARE,
        )
        mapper.map_phase(r)
        assert r.enrichment_tags.get("kill_chain_phase") == "installation"


class TestRecordEnricher:
    def test_composite_enrichment(self):
        enricher = RecordEnricher(mitre_enabled=False)
        r = DatasetRecord(
            record_id="t1", source=DatasetSourceType.CICIDS_2017,
            attack_category=AttackCategory.BRUTE_FORCE,
            status=RecordStatus.VALIDATED,
        )
        enricher.enrich(r)
        assert r.severity == Severity.MEDIUM
        assert r.enrichment_tags.get("kill_chain_phase") == "exploitation"
        assert r.status == RecordStatus.ENRICHED
