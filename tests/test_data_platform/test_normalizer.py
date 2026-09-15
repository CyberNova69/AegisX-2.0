"""Tests for the normalizer."""

import pytest
from aegisx_data.processing.normalizer import (
    RecordNormalizer,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_timestamp,
    normalize_severity,
    normalize_whitespace,
    normalize_hash,
)
from aegisx_data.core.types import DatasetRecord, DatasetSourceType, RecordStatus, Severity


class TestNormalizeIP:
    def test_valid_ipv4(self):
        assert normalize_ip("192.168.1.1") == "192.168.1.1"

    def test_leading_zeros(self):
        assert normalize_ip("010.000.001.001") == "10.0.1.1"

    def test_whitespace(self):
        assert normalize_ip("  10.0.0.1  ") == "10.0.0.1"

    def test_none(self):
        assert normalize_ip(None) is None

    def test_empty(self):
        assert normalize_ip("") is None

    def test_na(self):
        assert normalize_ip("N/A") is None

    def test_invalid(self):
        assert normalize_ip("not-an-ip") is None


class TestNormalizePort:
    def test_valid_int(self):
        assert normalize_port(80) == 80

    def test_string(self):
        assert normalize_port("443") == 443

    def test_float_string(self):
        assert normalize_port("80.0") == 80

    def test_out_of_range(self):
        assert normalize_port(70000) is None

    def test_none(self):
        assert normalize_port(None) is None


class TestNormalizeProtocol:
    def test_uppercase(self):
        assert normalize_protocol("TCP") == "tcp"

    def test_numeric_tcp(self):
        assert normalize_protocol("6") == "tcp"

    def test_numeric_udp(self):
        assert normalize_protocol("17") == "udp"

    def test_none(self):
        assert normalize_protocol(None) is None


class TestNormalizeTimestamp:
    def test_iso_passthrough(self):
        ts = "2024-01-15T12:00:00Z"
        assert normalize_timestamp(ts) == ts

    def test_standard_format(self):
        result = normalize_timestamp("2024-01-15 12:00:00")
        assert result is not None
        assert "2024-01-15" in result

    def test_unix_epoch(self):
        result = normalize_timestamp("1705312800")
        assert result is not None

    def test_none(self):
        assert normalize_timestamp(None) is None


class TestNormalizeSeverity:
    def test_named(self):
        assert normalize_severity("high") == Severity.HIGH

    def test_numeric(self):
        assert normalize_severity("4") == Severity.CRITICAL

    def test_alias(self):
        assert normalize_severity("crit") == Severity.CRITICAL

    def test_none(self):
        assert normalize_severity(None) is None


class TestNormalizeWhitespace:
    def test_collapse(self):
        assert normalize_whitespace("  hello   world  ") == "hello world"

    def test_none(self):
        assert normalize_whitespace(None) is None


class TestNormalizeHash:
    def test_sha256(self):
        h = "a" * 64
        assert normalize_hash(h) == h

    def test_md5(self):
        h = "b" * 32
        assert normalize_hash(h) == h

    def test_uppercase(self):
        h = "A" * 64
        assert normalize_hash(h) == "a" * 64

    def test_invalid(self):
        assert normalize_hash("not-a-hash") is None


class TestRecordNormalizer:
    def test_normalizes_record(self):
        r = DatasetRecord(
            record_id="test-001",
            source=DatasetSourceType.CICIDS_2017,
            src_ip="010.000.001.001",
            protocol="TCP",
            src_port=80,
        )
        normalizer = RecordNormalizer()
        normalizer.normalize(r)

        assert r.src_ip == "10.0.1.1"
        assert r.protocol == "tcp"
        assert r.status == RecordStatus.NORMALIZED

    def test_tracks_actions(self):
        r = DatasetRecord(
            record_id="test-002",
            source=DatasetSourceType.CICIDS_2017,
            protocol="6",
        )
        normalizer = RecordNormalizer()
        normalizer.normalize(r)

        assert len(r.normalization_actions) > 0
        assert any("protocol" in a for a in r.normalization_actions)
