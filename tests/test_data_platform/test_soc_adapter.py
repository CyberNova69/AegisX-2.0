"""Tests for the SOC v0.4 → DatasetRecord adapter (P1 fix).

Verifies deterministic conversion, provenance preservation, and
classification mapping.
"""

import json
import pytest
from pathlib import Path

from aegisx_data.adapters.soc_adapter import SOCRecordAdapter
from aegisx_data.core.types import (
    Classification, DatasetRecord, DatasetSourceType, Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_soc_record(**overrides):
    """Create a minimal v0.4 SOC record."""
    base = {
        "task": "triage",
        "input": {
            "alert": {
                "title": "DDoS Attack Detected",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.50",
                "source_port": 54321,
                "destination_port": 80,
                "protocol": "tcp",
                "timestamp": "2024-01-15T12:00:00Z",
            },
            "context": {
                "hostname": "web-server-01",
                "username": "admin",
            },
        },
        "output": {
            "classification": "malicious",
            "severity": "high",
            "confidence": 0.95,
            "summary": "DDoS attack from internal network",
        },
        "id": "soc-test-001",
        "metadata": {
            "source_file": "test_alerts.jsonl",
            "template": "ddos_template",
        },
    }
    base.update(overrides)
    return base


class TestSOCRecordAdapter:
    """Tests for SOCRecordAdapter."""

    def test_basic_conversion(self):
        """A standard v0.4 record converts to DatasetRecord."""
        adapter = SOCRecordAdapter()
        soc = _make_soc_record()
        record = adapter.convert(soc)

        assert record is not None
        assert isinstance(record, DatasetRecord)
        assert record.record_id == "soc-test-001"

    def test_network_fields_mapped(self):
        """Network fields from the alert are correctly mapped."""
        adapter = SOCRecordAdapter()
        record = adapter.convert(_make_soc_record())

        assert record.src_ip == "192.168.1.100"
        assert record.dst_ip == "10.0.0.50"
        assert record.src_port == 54321
        assert record.dst_port == 80
        assert record.protocol == "tcp"
        assert record.timestamp == "2024-01-15T12:00:00Z"

    def test_context_fields_mapped(self):
        """Endpoint context fields are mapped."""
        adapter = SOCRecordAdapter()
        record = adapter.convert(_make_soc_record())

        assert record.hostname == "web-server-01"
        assert record.username == "admin"

    def test_classification_mapping(self):
        """SOC output classification maps to AegisX Classification enum."""
        adapter = SOCRecordAdapter()

        for soc_cls, expected in [
            ("malicious", Classification.MALICIOUS),
            ("benign", Classification.BENIGN),
            ("suspicious", Classification.SUSPICIOUS),
            ("insufficient_evidence", Classification.INSUFFICIENT_EVIDENCE),
        ]:
            soc = _make_soc_record()
            soc["output"]["classification"] = soc_cls
            record = adapter.convert(soc)
            assert record.classification == expected, \
                f"Expected {expected} for '{soc_cls}', got {record.classification}"

    def test_severity_mapping(self):
        """SOC output severity maps to AegisX Severity enum."""
        adapter = SOCRecordAdapter()

        for sev_str, expected in [
            ("high", Severity.HIGH),
            ("critical", Severity.CRITICAL),
            ("low", Severity.LOW),
        ]:
            soc = _make_soc_record()
            soc["output"]["severity"] = sev_str
            record = adapter.convert(soc)
            assert record.severity == expected

    def test_provenance_preserved(self):
        """Full provenance must survive the conversion."""
        adapter = SOCRecordAdapter()
        soc = _make_soc_record()
        record = adapter.convert(soc)

        # Raw original record preserved
        assert record.raw == soc

        # SOC task preserved
        assert record.enrichment_tags["soc_task"] == "triage"

        # SOC metadata preserved
        assert record.enrichment_tags["soc_metadata"]["template"] == "ddos_template"

        # Adapter version tracked
        assert record.enrichment_tags["adapter"] == "soc_v04"
        assert record.enrichment_tags["adapter_version"] == "1.0"

    def test_source_label_preserved(self):
        """Original SOC classification stored as source_label."""
        adapter = SOCRecordAdapter()
        record = adapter.convert(_make_soc_record())
        assert record.source_label == "malicious"

    def test_source_id(self):
        """Source ID is aegisx_soc."""
        adapter = SOCRecordAdapter()
        record = adapter.convert(_make_soc_record())
        assert record.source == DatasetSourceType.AEGISX_SOC.value
        assert record.source == "aegisx_soc"

    def test_string_input_handling(self):
        """Adapter handles string input/output fields gracefully."""
        soc = _make_soc_record()
        soc["input"] = "raw alert text"
        soc["output"] = '{"classification": "benign"}'

        adapter = SOCRecordAdapter()
        record = adapter.convert(soc)
        assert record is not None
        assert record.classification == Classification.BENIGN

    def test_missing_fields_handled(self):
        """Records with missing fields still convert (with None values)."""
        soc = {
            "task": "investigation",
            "input": {},
            "output": {},
            "id": "soc-minimal-001",
        }
        adapter = SOCRecordAdapter()
        record = adapter.convert(soc)

        assert record is not None
        assert record.record_id == "soc-minimal-001"
        assert record.src_ip is None
        assert record.classification is None
        assert record.enrichment_tags["soc_task"] == "investigation"

    def test_batch_conversion(self):
        """Batch conversion processes multiple records."""
        adapter = SOCRecordAdapter()
        socs = [_make_soc_record(id=f"soc-batch-{i}") for i in range(10)]
        records = adapter.convert_batch(socs)
        assert len(records) == 10

    def test_from_jsonl(self, tmp_path):
        """JSONL streaming produces correct records."""
        socs = [_make_soc_record(id=f"soc-jsonl-{i}") for i in range(5)]
        jsonl_file = tmp_path / "soc.jsonl"
        with open(jsonl_file, "w", encoding="utf-8") as f:
            for s in socs:
                f.write(json.dumps(s) + "\n")

        adapter = SOCRecordAdapter()
        records = list(adapter.from_jsonl(jsonl_file))
        assert len(records) == 5
        assert all(r.source_file == "soc.jsonl" for r in records)

    def test_confidence_preserved(self):
        """SOC confidence value is preserved."""
        adapter = SOCRecordAdapter()
        record = adapter.convert(_make_soc_record())
        assert record.confidence == 0.95
