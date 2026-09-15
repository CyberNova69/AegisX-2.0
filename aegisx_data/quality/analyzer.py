"""Comprehensive dataset quality analysis.

Analyzes class distribution, feature completeness, label consistency,
duplicates, and computes an overall quality score. All analysis is
performed using stdlib only (no sklearn/numpy dependency).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Dict, List, Optional

from ..core.types import DatasetRecord, QualityReport


class DatasetQualityAnalyzer:
    """Analyze dataset quality and produce actionable reports."""

    # Fields to check for completeness
    COMPLETENESS_FIELDS = (
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "source_label", "classification", "severity",
        "hostname", "username", "process_name", "file_hash",
    )

    def analyze(self, records: List[DatasetRecord], version: str = "unknown") -> QualityReport:
        """Run full quality analysis on a list of records."""
        report = QualityReport(dataset_version=version)
        report.total_records = len(records)

        if not records:
            report.issues.append("Dataset is empty")
            return report

        # Count valid/invalid
        report.valid_records = sum(1 for r in records if r.status.value not in ("rejected",))
        report.invalid_records = report.total_records - report.valid_records

        # Duplicate count
        fingerprints = set()
        dupes = 0
        for r in records:
            if r.fingerprint:
                if r.fingerprint in fingerprints:
                    dupes += 1
                else:
                    fingerprints.add(r.fingerprint)
        report.duplicate_records = dupes

        # Class distribution
        report.class_distribution = self._class_distribution(records)

        # Class balance score
        report.class_balance_score = self._class_balance_score(report.class_distribution)

        # Feature completeness
        report.completeness_scores = self._completeness_scores(records)

        # Overall quality score (weighted composite)
        report.overall_quality_score = self._overall_score(report)

        # Generate issues and recommendations
        report.issues = self._identify_issues(report)
        report.recommendations = self._generate_recommendations(report)

        return report

    def _class_distribution(self, records: List[DatasetRecord]) -> Dict[str, int]:
        """Count records per classification."""
        dist: Dict[str, int] = Counter()
        for r in records:
            if r.classification:
                dist[r.classification.value] += 1
            else:
                dist["unlabeled"] += 1
        return dict(dist)

    def _class_balance_score(self, distribution: Dict[str, int]) -> float:
        """Compute class balance score using normalized entropy.

        1.0 = perfectly balanced, 0.0 = completely imbalanced.
        """
        counts = [v for v in distribution.values() if v > 0]
        if len(counts) <= 1:
            return 0.0

        total = sum(counts)
        if total == 0:
            return 0.0

        # Shannon entropy
        entropy = 0.0
        for count in counts:
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize by max possible entropy
        max_entropy = math.log2(len(counts))
        if max_entropy == 0:
            return 0.0

        return round(entropy / max_entropy, 4)

    def _completeness_scores(self, records: List[DatasetRecord]) -> Dict[str, float]:
        """Compute percentage of non-null values for each tracked field."""
        total = len(records)
        if total == 0:
            return {}

        scores: Dict[str, float] = {}
        for field_name in self.COMPLETENESS_FIELDS:
            non_null = sum(1 for r in records if getattr(r, field_name, None) is not None)
            scores[field_name] = round(non_null / total, 4)

        return scores

    def _overall_score(self, report: QualityReport) -> float:
        """Compute a weighted overall quality score [0.0, 1.0]."""
        scores = []

        # Validity rate (weight: 30%)
        if report.total_records > 0:
            validity_rate = report.valid_records / report.total_records
            scores.append(("validity", validity_rate, 0.30))

        # Class balance (weight: 20%)
        scores.append(("balance", report.class_balance_score, 0.20))

        # Completeness average (weight: 25%)
        if report.completeness_scores:
            avg_completeness = sum(report.completeness_scores.values()) / len(report.completeness_scores)
            scores.append(("completeness", avg_completeness, 0.25))

        # Duplicate ratio inverted (weight: 15%)
        if report.total_records > 0:
            dup_ratio = 1.0 - (report.duplicate_records / report.total_records)
            scores.append(("dedup", dup_ratio, 0.15))

        # Label coverage (weight: 10%)
        label_coverage = report.completeness_scores.get("source_label", 0.0)
        scores.append(("label_coverage", label_coverage, 0.10))

        # Weighted sum
        total_weight = sum(w for _, _, w in scores)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(s * w for _, s, w in scores)
        return round(weighted_sum / total_weight, 4)

    def _identify_issues(self, report: QualityReport) -> List[str]:
        """Identify quality issues."""
        issues = []

        if report.total_records == 0:
            issues.append("Dataset is empty")
            return issues

        # Class imbalance
        if report.class_balance_score < 0.3:
            issues.append(f"Severe class imbalance (balance score: {report.class_balance_score:.2f})")
        elif report.class_balance_score < 0.6:
            issues.append(f"Moderate class imbalance (balance score: {report.class_balance_score:.2f})")

        # Dominant class
        if report.class_distribution:
            total = sum(report.class_distribution.values())
            for cls, count in report.class_distribution.items():
                ratio = count / total if total > 0 else 0
                if ratio > 0.9:
                    issues.append(f"Class '{cls}' dominates with {ratio:.1%} of records")

        # High invalid rate
        invalid_rate = report.invalid_records / report.total_records
        if invalid_rate > 0.1:
            issues.append(f"High invalid record rate: {invalid_rate:.1%}")

        # High duplicate rate
        dup_rate = report.duplicate_records / report.total_records
        if dup_rate > 0.05:
            issues.append(f"Duplicate rate: {dup_rate:.1%}")

        # Low completeness fields
        for field, score in report.completeness_scores.items():
            if score < 0.5 and field in ("source_label", "classification"):
                issues.append(f"Low label completeness: {field} = {score:.1%}")

        return issues

    def _generate_recommendations(self, report: QualityReport) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        if report.class_balance_score < 0.5:
            recommendations.append(
                "Consider oversampling minority classes or undersampling majority classes "
                "during SFT generation to improve model performance on rare attack types."
            )

        if report.class_distribution.get("unlabeled", 0) > 0:
            total = sum(report.class_distribution.values())
            unlabeled_pct = report.class_distribution["unlabeled"] / total
            if unlabeled_pct > 0.1:
                recommendations.append(
                    f"{unlabeled_pct:.0%} of records are unlabeled. "
                    "Add label mappings for the source dataset or exclude unlabeled records."
                )

        if report.duplicate_records > 0:
            recommendations.append(
                "Run deduplication to remove duplicate records before SFT generation."
            )

        if report.overall_quality_score < 0.5:
            recommendations.append(
                "Overall quality score is low. Consider cleaning the dataset "
                "or combining with additional sources."
            )
        elif report.overall_quality_score >= 0.8:
            recommendations.append(
                "Dataset quality is good. Ready for SFT generation."
            )

        return recommendations
