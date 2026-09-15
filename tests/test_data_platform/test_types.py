"""Tests for core types."""

import json
import pytest
from aegisx_data.core.types import (
    AttackCategory,
    Classification,
    DatasetRecord,
    DatasetSourceType,
    ModelArtifact,
    ModelLifecycle,
    QualityReport,
    RecordStatus,
    RunStatus,
    Severity,
    TrainingRun,
)


class TestDatasetRecord:
    """Tests for DatasetRecord dataclass."""

    def _make_record(self, **kwargs):
        defaults = {
            "record_id": "test-001",
            "source": DatasetSourceType.CICIDS_2017,
        }
        defaults.update(kwargs)
        return DatasetRecord(**defaults)

    def test_default_creation(self):
        r = self._make_record()
        assert r.record_id == "test-001"
        assert r.source == DatasetSourceType.CICIDS_2017
        assert r.status == RecordStatus.RAW
        assert r.confidence == 1.0
        assert r.raw == {}

    def test_network_fields(self):
        r = self._make_record(
            src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=12345, dst_port=80,
            protocol="tcp", duration=1.5,
            bytes_sent=1024, bytes_recv=2048,
        )
        assert r.src_ip == "192.168.1.1"
        assert r.dst_port == 80
        assert r.bytes_sent == 1024

    def test_to_dict_roundtrip(self):
        r = self._make_record(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            source_label="DDoS",
            classification=Classification.MALICIOUS,
            attack_category=AttackCategory.DDOS,
            severity=Severity.HIGH,
        )
        d = r.to_dict()
        assert d["record_id"] == "test-001"
        assert d["classification"] == "malicious"
        assert d["attack_category"] == "ddos"

        # Roundtrip
        r2 = DatasetRecord.from_dict(d)
        assert r2.record_id == "test-001"
        assert r2.classification == Classification.MALICIOUS
        assert r2.attack_category == AttackCategory.DDOS

    def test_compute_fingerprint(self):
        r = self._make_record(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1234, dst_port=80,
        )
        fp = r.compute_fingerprint()
        assert len(fp) == 64  # SHA-256 hex
        assert r.fingerprint == fp

        # Same data = same fingerprint
        r2 = self._make_record(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1234, dst_port=80,
        )
        assert r2.compute_fingerprint() == fp

    def test_from_dict_handles_missing_fields(self):
        d = {"record_id": "test-002", "source": "cicids_2017"}
        r = DatasetRecord.from_dict(d)
        assert r.record_id == "test-002"
        assert r.src_ip is None
        assert r.classification is None


class TestTrainingRun:
    def test_creation_and_roundtrip(self):
        run = TrainingRun(
            run_id="run_001",
            dataset_version="1.0",
            base_model="qwen2.5-7b",
            config={"lr": 0.0002},
        )
        d = run.to_dict()
        assert d["run_id"] == "run_001"
        assert d["status"] == "pending"

        run2 = TrainingRun.from_dict(d)
        assert run2.run_id == "run_001"
        assert run2.status == RunStatus.PENDING
        assert run2.config["lr"] == 0.0002


class TestModelArtifact:
    def test_creation_and_roundtrip(self):
        artifact = ModelArtifact(
            model_id="model-001",
            run_id="run-001",
            base_model="qwen2.5-7b",
            lifecycle=ModelLifecycle.EVALUATED,
            eval_metrics={"accuracy": 0.85},
        )
        d = artifact.to_dict()
        assert d["lifecycle"] == "evaluated"

        a2 = ModelArtifact.from_dict(d)
        assert a2.lifecycle == ModelLifecycle.EVALUATED
        assert a2.eval_metrics["accuracy"] == 0.85


class TestQualityReport:
    def test_to_dict(self):
        report = QualityReport(
            dataset_version="1.0",
            total_records=100,
            valid_records=95,
            overall_quality_score=0.82,
        )
        d = report.to_dict()
        assert d["total_records"] == 100
        assert d["overall_quality_score"] == 0.82


class TestEnums:
    def test_classification_values(self):
        assert Classification.BENIGN.value == "benign"
        assert Classification.MALICIOUS.value == "malicious"

    def test_severity_order(self):
        severities = [s.value for s in Severity]
        assert "informational" in severities
        assert "critical" in severities

    def test_dataset_source_types(self):
        assert DatasetSourceType.CICIDS_2017.value == "cicids_2017"
        assert DatasetSourceType.EMBER.value == "ember"
