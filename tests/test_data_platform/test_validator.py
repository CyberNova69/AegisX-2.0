"""Tests for the validator."""

import pytest
from aegisx_data.processing.validator import RecordValidator
from aegisx_data.core.types import (
    DatasetRecord, DatasetSourceType, RecordStatus, Classification,
)


class TestRecordValidator:
    def _make_valid_record(self):
        return DatasetRecord(
            record_id="test-001",
            source=DatasetSourceType.CICIDS_2017,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="tcp",
            source_label="BENIGN",
            timestamp="2024-01-15T12:00:00Z",
            status=RecordStatus.NORMALIZED,
        )

    def test_valid_record(self):
        r = self._make_valid_record()
        validator = RecordValidator()
        issues = validator.validate(r)

        errors = [i for i in issues if i.severity == "error"]
        assert len(errors) == 0
        assert r.status == RecordStatus.VALIDATED

    def test_invalid_ip(self):
        r = self._make_valid_record()
        r.src_ip = "999.999.999.999"
        validator = RecordValidator()
        issues = validator.validate(r)

        assert any(i.code == "invalid_ip" for i in issues)
        assert r.status == RecordStatus.REJECTED

    def test_invalid_port(self):
        r = self._make_valid_record()
        r.src_port = 70000
        validator = RecordValidator()
        issues = validator.validate(r)

        assert any(i.code == "invalid_port" for i in issues)

    def test_missing_record_id(self):
        r = DatasetRecord(record_id="", source=DatasetSourceType.CICIDS_2017)
        validator = RecordValidator()
        issues = validator.validate(r)

        assert any(i.code == "missing_record_id" for i in issues)

    def test_invalid_confidence(self):
        r = self._make_valid_record()
        r.confidence = 1.5
        validator = RecordValidator()
        issues = validator.validate(r)

        assert any(i.code == "invalid_confidence" for i in issues)

    def test_warning_no_timestamp(self):
        r = self._make_valid_record()
        r.timestamp = None
        validator = RecordValidator()
        issues = validator.validate(r)

        warnings = [i for i in issues if i.severity == "warning"]
        assert any(i.code == "missing_timestamp" for i in warnings)
        # Should still be valid (warnings don't reject)
        assert r.status == RecordStatus.VALIDATED

    def test_is_valid(self):
        r = self._make_valid_record()
        validator = RecordValidator()
        assert validator.is_valid(r)
