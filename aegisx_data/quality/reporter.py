"""Quality report generation in JSON and Markdown formats."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..core.types import QualityReport


class QualityReporter:
    """Generate quality reports in multiple formats."""

    def to_json(self, report: QualityReport, path: Optional[Path] = None) -> str:
        """Serialize report to JSON string and optionally write to file."""
        json_str = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(json_str)
        return json_str

    def to_markdown(self, report: QualityReport, path: Optional[Path] = None) -> str:
        """Generate a Markdown quality report."""
        lines = [
            f"# Dataset Quality Report — {report.dataset_version}",
            "",
            f"> Analyzed at: {report.analyzed_at}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Records | {report.total_records:,} |",
            f"| Valid Records | {report.valid_records:,} |",
            f"| Invalid Records | {report.invalid_records:,} |",
            f"| Duplicate Records | {report.duplicate_records:,} |",
            f"| Overall Quality Score | {report.overall_quality_score:.2f} |",
            f"| Class Balance Score | {report.class_balance_score:.2f} |",
            "",
        ]

        # Class distribution
        if report.class_distribution:
            lines.append("## Class Distribution")
            lines.append("")
            lines.append("| Class | Count | Percentage |")
            lines.append("|-------|-------|------------|")
            total = sum(report.class_distribution.values())
            for cls, count in sorted(report.class_distribution.items(),
                                     key=lambda x: -x[1]):
                pct = (count / total * 100) if total > 0 else 0
                lines.append(f"| {cls} | {count:,} | {pct:.1f}% |")
            lines.append("")

        # Feature completeness
        if report.completeness_scores:
            lines.append("## Feature Completeness")
            lines.append("")
            lines.append("| Field | Completeness |")
            lines.append("|-------|-------------|")
            for field, score in sorted(report.completeness_scores.items(),
                                       key=lambda x: -x[1]):
                bar = "█" * int(score * 20) + "░" * (20 - int(score * 20))
                lines.append(f"| {field} | {bar} {score:.0%} |")
            lines.append("")

        # Issues
        if report.issues:
            lines.append("## Issues")
            lines.append("")
            for issue in report.issues:
                lines.append(f"- ⚠️ {issue}")
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for rec in report.recommendations:
                lines.append(f"- 💡 {rec}")
            lines.append("")

        md_str = "\n".join(lines)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(md_str)
        return md_str
