"""Tests for the deduplicator."""

import pytest
from aegisx_data.processing.deduplicator import RecordDeduplicator
from aegisx_data.core.types import DatasetRecord, DatasetSourceType, RecordStatus


class TestRecordDeduplicator:
    def _make_record(self, record_id, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                     src_port=1234, source_label="BENIGN"):
        return DatasetRecord(
            record_id=record_id,
            source=DatasetSourceType.CICIDS_2017,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            source_label=source_label,
        )

    def test_unique_records(self):
        dedup = RecordDeduplicator()
        r1 = self._make_record("r1", src_ip="10.0.0.1")
        r2 = self._make_record("r2", src_ip="10.0.0.2")

        assert dedup.check(r1) is None  # unique
        assert dedup.check(r2) is None  # unique
        assert dedup.duplicates_found == 0

    def test_exact_duplicate(self):
        dedup = RecordDeduplicator()
        r1 = self._make_record("r1")
        r2 = self._make_record("r2")  # Same data, different ID

        assert dedup.check(r1) is None
        result = dedup.check(r2)
        assert result == "r1"  # duplicate of r1
        assert dedup.duplicates_found == 1
        assert r2.status == RecordStatus.DUPLICATE

    def test_near_duplicate_strategy(self):
        dedup = RecordDeduplicator(strategy="near")
        # Near dedup ignores timestamps and byte counts
        r1 = self._make_record("r1")
        r1.timestamp = "2024-01-01T00:00:00Z"
        r1.bytes_sent = 1000

        r2 = self._make_record("r2")
        r2.timestamp = "2024-01-02T00:00:00Z"  # Different timestamp
        r2.bytes_sent = 2000  # Different bytes

        assert dedup.check(r1) is None
        assert dedup.check(r2) == "r1"  # near duplicate

    def test_max_fingerprints(self):
        dedup = RecordDeduplicator(max_fingerprints=2)
        r1 = self._make_record("r1", src_ip="1.1.1.1")
        r2 = self._make_record("r2", src_ip="2.2.2.2")
        r3 = self._make_record("r3", src_ip="3.3.3.3")

        assert dedup.check(r1) is None
        assert dedup.check(r2) is None
        assert dedup.check(r3) is None  # Evicts r1

        # r1's fingerprint was evicted
        r1_dup = self._make_record("r1_dup", src_ip="1.1.1.1")
        assert dedup.check(r1_dup) is None  # Not detected as dup

    def test_deduplicate_stream(self):
        dedup = RecordDeduplicator()
        records = [
            self._make_record("r1", src_ip="10.0.0.1"),
            self._make_record("r2", src_ip="10.0.0.2"),
            self._make_record("r3", src_ip="10.0.0.1"),  # duplicate of r1
        ]
        unique = list(dedup.deduplicate(iter(records)))
        assert len(unique) == 2
        assert unique[0].record_id == "r1"
        assert unique[1].record_id == "r2"

    def test_stats(self):
        dedup = RecordDeduplicator()
        r1 = self._make_record("r1")
        r2 = self._make_record("r2")
        dedup.check(r1)
        dedup.check(r2)
        stats = dedup.stats()
        assert stats["unique_fingerprints"] == 1
        assert stats["duplicates_found"] == 1

    def test_reset(self):
        dedup = RecordDeduplicator()
        r1 = self._make_record("r1")
        dedup.check(r1)
        dedup.reset()
        assert len(dedup._seen) == 0
        assert dedup.duplicates_found == 0
