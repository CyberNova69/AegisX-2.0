"""Tests for the quality analyzer."""

import pytest
from aegisx_data.quality.analyzer import DatasetQualityAnalyzer
from aegisx_data.core.types import (
    Classification, DatasetRecord, DatasetSourceType, RecordStatus,
)


class TestDatasetQualityAnalyzer:
    def _make_records(self, n_benign=50, n_malicious=50):
        records = []
        for i in range(n_benign):
            records.append(DatasetRecord(
                record_id=f"b-{i}", source=DatasetSourceType.CICIDS_2017,
                classification=Classification.BENIGN,
                source_label="BENIGN",
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                timestamp="2024-01-15T12:00:00Z",
            ))
        for i in range(n_malicious):
            records.append(DatasetRecord(
                record_id=f"m-{i}", source=DatasetSourceType.CICIDS_2017,
                classification=Classification.MALICIOUS,
                source_label="DDoS",
                src_ip="10.0.0.3", dst_ip="10.0.0.4",
                timestamp="2024-01-15T12:00:00Z",
            ))
        return records

    def test_balanced_dataset(self):
        records = self._make_records(50, 50)
        analyzer = DatasetQualityAnalyzer()
        report = analyzer.analyze(records, version="test")

        assert report.total_records == 100
        assert report.class_balance_score > 0.9  # Nearly perfect balance
        assert report.overall_quality_score > 0.5

    def test_imbalanced_dataset(self):
        records = self._make_records(95, 5)
        analyzer = DatasetQualityAnalyzer()
        report = analyzer.analyze(records, version="test")

        assert report.class_balance_score < 0.5

    def test_empty_dataset(self):
        analyzer = DatasetQualityAnalyzer()
        report = analyzer.analyze([], version="empty")
        assert report.total_records == 0
        assert "empty" in report.issues[0].lower()

    def test_class_distribution(self):
        records = self._make_records(30, 70)
        analyzer = DatasetQualityAnalyzer()
        report = analyzer.analyze(records, version="test")

        assert report.class_distribution["benign"] == 30
        assert report.class_distribution["malicious"] == 70

    def test_completeness_scores(self):
        records = self._make_records(10, 10)
        analyzer = DatasetQualityAnalyzer()
        report = analyzer.analyze(records, version="test")

        assert report.completeness_scores["src_ip"] == 1.0
        assert report.completeness_scores["timestamp"] == 1.0
        assert report.completeness_scores["hostname"] == 0.0

    def test_recommendations_generated(self):
        records = self._make_records(50, 50)
        analyzer = DatasetQualityAnalyzer()
        report = analyzer.analyze(records, version="test")

        # Should generate at least one recommendation
        assert len(report.recommendations) > 0
