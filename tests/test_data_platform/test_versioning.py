"""Tests for the versioning system."""

import json
import pytest
import tempfile
from pathlib import Path
from aegisx_data.versioning.manager import VersionManager
from aegisx_data.versioning.manifest import VersionManifest
from aegisx_data.core.types import (
    Classification, DatasetRecord, DatasetSourceType,
)


class TestVersionManifest:
    def test_to_dict(self):
        m = VersionManifest(
            version="1.0", record_count=100,
            quality_score=0.85, sources=["cicids"],
        )
        d = m.to_dict()
        assert d["version"] == "1.0"
        assert d["record_count"] == 100
        assert d["schema_version"] == "1.0"

    def test_save_and_load(self, tmp_path):
        m = VersionManifest(
            version="2.0", record_count=200,
            sources=["cicids", "unsw_nb15"],
        )
        path = tmp_path / "manifest.json"
        m.save(path)

        loaded = VersionManifest.load(path)
        assert loaded.version == "2.0"
        assert loaded.record_count == 200
        assert loaded.sources == ["cicids", "unsw_nb15"]


class TestVersionManager:
    def _make_records(self, n=10):
        records = []
        for i in range(n):
            records.append(DatasetRecord(
                record_id=f"r-{i}",
                source=DatasetSourceType.CICIDS_2017,
                classification=Classification.BENIGN if i % 2 == 0 else Classification.MALICIOUS,
                src_ip=f"10.0.0.{i}",
            ))
        return records

    def test_create_version(self, tmp_path):
        vm = VersionManager(tmp_path / "versions")
        records = self._make_records(10)
        manifest = vm.create_version("1.0", records, sources=["cicids"])

        assert manifest.version == "1.0"
        assert manifest.record_count == 10
        assert (tmp_path / "versions" / "v1.0" / "data.jsonl").exists()
        assert (tmp_path / "versions" / "v1.0" / "manifest.json").exists()

    def test_duplicate_version_raises(self, tmp_path):
        vm = VersionManager(tmp_path / "versions")
        records = self._make_records(5)
        vm.create_version("1.0", records)

        with pytest.raises(ValueError, match="already exists"):
            vm.create_version("1.0", records)

    def test_load_version(self, tmp_path):
        vm = VersionManager(tmp_path / "versions")
        records = self._make_records(5)
        vm.create_version("1.0", records)

        loaded_records, loaded_manifest = vm.load_version("1.0")
        assert len(loaded_records) == 5
        assert loaded_manifest.version == "1.0"

    def test_list_versions(self, tmp_path):
        vm = VersionManager(tmp_path / "versions")
        vm.create_version("1.0", self._make_records(5))
        vm.create_version("2.0", self._make_records(10))

        versions = vm.list_versions()
        assert len(versions) == 2
        assert versions[0].version == "1.0"
        assert versions[1].version == "2.0"

    def test_verify_integrity(self, tmp_path):
        vm = VersionManager(tmp_path / "versions")
        vm.create_version("1.0", self._make_records(5))

        results = vm.verify_integrity("1.0")
        assert results["data.jsonl"] is True

    def test_diff_versions(self, tmp_path):
        vm = VersionManager(tmp_path / "versions")

        records_a = self._make_records(5)
        records_b = self._make_records(8)

        vm.create_version("1.0", records_a)
        vm.create_version("2.0", records_b)

        diff = vm.diff_versions("1.0", "2.0")
        assert diff["records_a"] == 5
        assert diff["records_b"] == 8

    def test_delete_version(self, tmp_path):
        vm = VersionManager(tmp_path / "versions")
        vm.create_version("1.0", self._make_records(5))

        vm.delete_version("1.0")
        assert not (tmp_path / "versions" / "v1.0").exists()
