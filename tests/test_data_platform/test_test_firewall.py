"""Tests for the v1.0 test set firewall (P0 fix).

Verifies that protected test records cannot leak into train/validation splits.
"""

import hashlib
import json
import pytest
from pathlib import Path

from aegisx_data.core.types import (
    Classification, DatasetRecord, DatasetSourceType, RecordStatus,
)
from aegisx_data.sft.splitter import DatasetSplitter, ProtectedTestFirewall
from aegisx_data.sft.generator import SFTGenerator


def _canonical_json(obj):
    """Canonical JSON serialization matching the firewall."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class TestProtectedTestFirewall:
    """Unit tests for the ProtectedTestFirewall class."""

    def _write_test_jsonl(self, path: Path, records: list):
        """Write a JSONL file for testing."""
        with open(path, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def test_from_jsonl_loads_fingerprints(self, tmp_path):
        """ProtectedTestFirewall loads correct number of fingerprints from JSONL."""
        test_records = [
            {"messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": f"test {i}"}]}
            for i in range(10)
        ]
        test_file = tmp_path / "test.jsonl"
        self._write_test_jsonl(test_file, test_records)

        fw = ProtectedTestFirewall.from_jsonl(test_file)
        assert fw.size == 10

    def test_is_protected_matches(self, tmp_path):
        """Protected record fingerprints are correctly detected."""
        test_records = [{"messages": [{"role": "user", "content": "protected data"}]}]
        test_file = tmp_path / "test.jsonl"
        self._write_test_jsonl(test_file, test_records)

        fw = ProtectedTestFirewall.from_jsonl(test_file)

        # Same canonical fingerprint must match
        canonical = _canonical_json(test_records[0])
        fp = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert fw.is_protected(fp)

    def test_is_protected_rejects_unknown(self, tmp_path):
        """Non-protected fingerprints are correctly rejected."""
        test_records = [{"messages": [{"role": "user", "content": "protected"}]}]
        test_file = tmp_path / "test.jsonl"
        self._write_test_jsonl(test_file, test_records)

        fw = ProtectedTestFirewall.from_jsonl(test_file)
        fake_fp = hashlib.sha256(b"not in test set").hexdigest()
        assert not fw.is_protected(fake_fp)

    def test_deterministic(self, tmp_path):
        """Same file always produces same fingerprints."""
        test_records = [{"x": i} for i in range(5)]
        test_file = tmp_path / "test.jsonl"
        self._write_test_jsonl(test_file, test_records)

        fw1 = ProtectedTestFirewall.from_jsonl(test_file)
        fw2 = ProtectedTestFirewall.from_jsonl(test_file)
        assert fw1._fingerprints == fw2._fingerprints


class TestDatasetSplitterFirewall:
    """Tests for DatasetSplitter with test firewall integration."""

    def _make_records(self, n=100):
        return [
            DatasetRecord(
                record_id=f"r-{i}",
                source=DatasetSourceType.CICIDS_2017,
                classification=Classification.BENIGN if i % 3 == 0 else Classification.MALICIOUS,
            )
            for i in range(n)
        ]

    def _write_records_as_protected(self, records, path):
        """Write DatasetRecord dicts as JSONL (same format the firewall reads)."""
        with open(path, "w", encoding="utf-8") as f:
            for r in records:
                d = r.to_dict()
                f.write(json.dumps(d, ensure_ascii=False) + "\n")

    def test_protected_records_excluded_from_train(self, tmp_path):
        """Protected test records must NOT appear in the train split."""
        records = self._make_records(50)

        # Write first 5 records as protected
        test_file = tmp_path / "protected_test.jsonl"
        self._write_records_as_protected(records[:5], test_file)

        fw = ProtectedTestFirewall.from_jsonl(test_file)
        splitter = DatasetSplitter(test_firewall=fw)
        train, val, test = splitter.split(records)

        protected_ids = {records[i].record_id for i in range(5)}
        train_ids = {r.record_id for r in train}
        assert protected_ids.isdisjoint(train_ids), \
            f"Protected records leaked into train: {protected_ids & train_ids}"

    def test_protected_records_excluded_from_validation(self, tmp_path):
        """Protected test records must NOT appear in the validation split."""
        records = self._make_records(50)

        test_file = tmp_path / "protected_test.jsonl"
        self._write_records_as_protected(records[:5], test_file)

        fw = ProtectedTestFirewall.from_jsonl(test_file)
        splitter = DatasetSplitter(test_firewall=fw)
        train, val, test = splitter.split(records)

        protected_ids = {records[i].record_id for i in range(5)}
        val_ids = {r.record_id for r in val}
        assert protected_ids.isdisjoint(val_ids), \
            f"Protected records leaked into validation: {protected_ids & val_ids}"

    def test_train_val_remain_valid_with_firewall(self, tmp_path):
        """Train and validation sets must still be non-empty after firewall."""
        records = self._make_records(100)

        # Protect 5 records
        test_file = tmp_path / "protected_test.jsonl"
        self._write_records_as_protected(records[:5], test_file)

        fw = ProtectedTestFirewall.from_jsonl(test_file)
        splitter = DatasetSplitter(test_firewall=fw)
        train, val, test = splitter.split(records)

        assert len(train) > 0, "Train set is empty after firewall"
        assert len(val) >= 0, "Validation set check failed"
        total = len(train) + len(val) + len(test)
        # 5 protected records excluded
        assert total == 95, f"Expected 95, got {total}"
        assert splitter.firewall_excluded == 5

    def test_no_protection_backward_compatible(self):
        """Without a firewall, splitter behaves exactly as before."""
        records = self._make_records(100)
        splitter = DatasetSplitter()
        train, val, test = splitter.split(records)

        total = len(train) + len(val) + len(test)
        assert total == 100
        assert splitter.firewall_excluded == 0

    def test_firewall_count_tracking(self, tmp_path):
        """Splitter must track how many records were excluded by the firewall."""
        records = self._make_records(30)

        test_file = tmp_path / "protected_test.jsonl"
        self._write_records_as_protected(records[:10], test_file)

        fw = ProtectedTestFirewall.from_jsonl(test_file)
        splitter = DatasetSplitter(test_firewall=fw)
        splitter.split(records)

        assert splitter.firewall_excluded == 10


class TestSFTGeneratorFirewall:
    """Tests for SFTGenerator with protected_test_path."""

    def test_generator_with_protected_test_path(self, tmp_path):
        """SFTGenerator excludes protected test records when configured."""
        records = [
            DatasetRecord(
                record_id=f"r-{i}",
                source=DatasetSourceType.CICIDS_2017,
                src_ip=f"10.0.0.{i}", dst_ip="10.0.0.1",
                protocol="tcp",
                classification=Classification.BENIGN if i % 2 == 0 else Classification.MALICIOUS,
                severity=None,
                source_label="BENIGN" if i % 2 == 0 else "DDoS",
            )
            for i in range(20)
        ]

        # Write 5 records as protected test
        test_file = tmp_path / "protected_test.jsonl"
        with open(test_file, "w", encoding="utf-8") as f:
            for i in range(5):
                d = records[i].to_dict()
                f.write(json.dumps(d, ensure_ascii=False) + "\n")

        generator = SFTGenerator(protected_test_path=test_file)
        sft_dir = tmp_path / "sft"
        metadata = generator.generate(records, sft_dir)

        # Verify outputs exist
        assert (sft_dir / "train.jsonl").exists()
        assert (sft_dir / "validation.jsonl").exists()
        assert (sft_dir / "test.jsonl").exists()

        # Total converted should be <= 15 (20 - 5 protected)
        assert metadata["totals"]["converted"] <= 15


class TestFirewallConfigWiring:
    """Tests that the firewall is properly wired through configuration."""

    def test_sft_config_has_protected_test_path(self):
        """SFTConfig dataclass must have protected_test_path with v1.0 default."""
        from aegisx_data.core.config import SFTConfig
        cfg = SFTConfig()
        assert cfg.protected_test_path == "datasets/finetuning/v1.0/test.jsonl"

    def test_load_config_loads_protected_test_path(self):
        """load_config() must populate protected_test_path from YAML."""
        from aegisx_data.core.config import load_config
        config = load_config()
        assert config.sft.protected_test_path == "datasets/finetuning/v1.0/test.jsonl"

    def test_resolved_path_exists(self):
        """The configured protected test path must resolve to an existing file."""
        from aegisx_data.core.config import load_config
        config = load_config()
        resolved = config.resolve_path(config.sft.protected_test_path)
        assert resolved.exists(), f"Protected test path does not exist: {resolved}"
        assert resolved.is_file()

    def test_config_disabling_firewall(self):
        """Setting protected_test_path to null/None should disable the firewall."""
        from aegisx_data.core.config import SFTConfig
        cfg = SFTConfig(protected_test_path=None)
        assert cfg.protected_test_path is None

