"""Integration test: full pipeline from records to SFT output."""

import json
import pytest
from pathlib import Path
from aegisx_data.core.types import (
    Classification, DatasetRecord, DatasetSourceType, RecordStatus,
)
from aegisx_data.processing.pipeline import ProcessingPipeline, build_pipeline
from aegisx_data.quality.analyzer import DatasetQualityAnalyzer
from aegisx_data.versioning.manager import VersionManager
from aegisx_data.sft.generator import SFTGenerator


class TestPipelineIntegration:
    """End-to-end test: create mock records → process → analyze → version → SFT."""

    def _make_mock_cicids_records(self, n=50):
        """Create mock CICIDS-format records."""
        records = []
        labels = ["BENIGN", "DDoS", "DoS Hulk", "PortScan", "FTP-Patator"]
        for i in range(n):
            label = labels[i % len(labels)]
            records.append(DatasetRecord(
                record_id=f"cicids-mock-{i:06d}",
                source=DatasetSourceType.CICIDS_2017,
                source_file="mock_data.csv",
                record_index=i,
                src_ip=f"192.168.1.{i % 256}",
                dst_ip=f"10.0.0.{i % 256}",
                src_port=1024 + i,
                dst_port=80 if label == "BENIGN" else 443,
                protocol="tcp",
                timestamp=f"2024-01-15T{12 + i % 12:02d}:00:00Z",
                duration=float(i * 0.1),
                bytes_sent=i * 100,
                bytes_recv=i * 50,
                source_label=label,
                status=RecordStatus.RAW,
            ))
        return records

    def test_full_pipeline(self, tmp_path):
        """Test the complete pipeline: process → quality → version → SFT."""
        # Step 1: Create mock records
        records = self._make_mock_cicids_records(50)

        # Step 2: Process through pipeline
        pipeline = build_pipeline(dedup_strategy="exact", mitre_enabled=False)
        processed, report = pipeline.process_all(iter(records))

        assert report.output_records > 0
        assert report.rejected == 0
        assert all(r.classification is not None for r in processed)
        assert all(r.status == RecordStatus.HARMONIZED for r in processed)

        # Verify classification distribution matches expected labels
        classifications = [r.classification.value for r in processed]
        assert "benign" in classifications
        assert "malicious" in classifications

        # Step 3: Quality analysis
        analyzer = DatasetQualityAnalyzer()
        quality_report = analyzer.analyze(processed, version="test")
        assert quality_report.total_records == len(processed)
        assert quality_report.overall_quality_score > 0

        # Step 4: Create version
        vm = VersionManager(tmp_path / "versions")
        manifest = vm.create_version(
            "1.0", processed,
            sources=["cicids_2017"],
            quality_score=quality_report.overall_quality_score,
        )
        assert manifest.record_count == len(processed)

        # Step 5: Load and verify version
        loaded_records, loaded_manifest = vm.load_version("1.0")
        assert len(loaded_records) == manifest.record_count

        # Step 6: Generate SFT dataset
        generator = SFTGenerator(
            train_ratio=0.8, val_ratio=0.1, test_ratio=0.1,
        )
        sft_dir = tmp_path / "sft"
        metadata = generator.generate(loaded_records, sft_dir)

        assert (sft_dir / "train.jsonl").exists()
        assert (sft_dir / "validation.jsonl").exists()
        assert (sft_dir / "test.jsonl").exists()
        assert metadata["totals"]["converted"] > 0

        # Step 7: Verify SFT format
        with open(sft_dir / "train.jsonl") as f:
            for line in f:
                example = json.loads(line)
                assert "messages" in example
                assert len(example["messages"]) == 3
                assert example["messages"][0]["role"] == "system"
                assert example["messages"][1]["role"] == "user"
                assert example["messages"][2]["role"] == "assistant"

                # Assistant response must be valid JSON
                response = json.loads(example["messages"][2]["content"])
                assert response["classification"] in [
                    "benign", "malicious", "suspicious", "insufficient_evidence"
                ]
                break  # Just check the first one

    def test_deduplication_in_pipeline(self, tmp_path):
        """Test that duplicates are properly removed."""
        # Create records with duplicates
        records = self._make_mock_cicids_records(20)
        # Duplicate the first 5
        duplicates = self._make_mock_cicids_records(5)
        for i, d in enumerate(duplicates):
            d.record_id = f"cicids-dup-{i:06d}"
        records.extend(duplicates)

        pipeline = build_pipeline(dedup_strategy="exact", mitre_enabled=False)
        processed, report = pipeline.process_all(iter(records))

        assert report.duplicates == 5
        assert report.output_records == 20

    def test_processing_report_completeness(self, tmp_path):
        """Test that the processing report has all expected fields."""
        records = self._make_mock_cicids_records(30)
        pipeline = build_pipeline(mitre_enabled=False)
        processed, report = pipeline.process_all(iter(records))

        d = report.to_dict()
        assert "input_records" in d
        assert "output_records" in d
        assert "rejected" in d
        assert "duplicates" in d
        assert "duration_seconds" in d
        assert "class_distribution" in d
        assert d["duration_seconds"] >= 0
