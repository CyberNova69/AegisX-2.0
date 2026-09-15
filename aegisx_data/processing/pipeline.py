"""Processing pipeline orchestrator.

Chains: normalize → validate → deduplicate → enrich → harmonize.
Streaming-capable (generator-based), consistent with ai/ingestion/pipeline.py.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from ..core.types import DatasetRecord, RecordStatus
from .deduplicator import RecordDeduplicator
from .enricher import RecordEnricher
from .label_harmonizer import LabelHarmonizer
from .normalizer import RecordNormalizer
from .validator import RecordValidator


# ---------------------------------------------------------------------------
# Processing report
# ---------------------------------------------------------------------------

@dataclass
class ProcessingReport:
    """Summary of a processing pipeline run."""
    input_records: int = 0
    normalized: int = 0
    validated: int = 0
    rejected: int = 0
    duplicates: int = 0
    enriched: int = 0
    harmonized: int = 0
    output_records: int = 0
    warnings: int = 0
    errors: int = 0
    duration_seconds: float = 0.0
    class_distribution: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "input_records": self.input_records,
            "normalized": self.normalized,
            "validated": self.validated,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "enriched": self.enriched,
            "harmonized": self.harmonized,
            "output_records": self.output_records,
            "warnings": self.warnings,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
            "class_distribution": self.class_distribution,
        }


# ---------------------------------------------------------------------------
# Processing pipeline
# ---------------------------------------------------------------------------

class ProcessingPipeline:
    """Orchestrates the full record processing chain.

    Parameters:
        normalizer: RecordNormalizer instance
        validator: RecordValidator instance
        deduplicator: RecordDeduplicator instance
        enricher: RecordEnricher instance (None to skip)
        harmonizer: LabelHarmonizer instance (None to skip)
    """

    def __init__(
        self,
        normalizer: Optional[RecordNormalizer] = None,
        validator: Optional[RecordValidator] = None,
        deduplicator: Optional[RecordDeduplicator] = None,
        enricher: Optional[RecordEnricher] = None,
        harmonizer: Optional[LabelHarmonizer] = None,
    ):
        self.normalizer = normalizer or RecordNormalizer()
        self.validator = validator or RecordValidator()
        self.deduplicator = deduplicator or RecordDeduplicator()
        self.enricher = enricher or RecordEnricher()
        self.harmonizer = harmonizer or LabelHarmonizer()

    def process_one(self, record: DatasetRecord) -> DatasetRecord:
        """Process a single record through all stages.

        Returns the record with updated status. Check record.status
        to determine if it was rejected or deduplicated.
        """
        # Stage 1: Normalize
        self.normalizer.normalize(record)

        # Stage 2: Validate
        issues = self.validator.validate(record)
        has_errors = any(i.severity == "error" for i in issues)
        if has_errors:
            return record  # status = REJECTED

        # Stage 3: Deduplicate
        duplicate_of = self.deduplicator.check(record)
        if duplicate_of is not None:
            return record  # status = DUPLICATE

        # Stage 4: Enrich
        if self.enricher:
            self.enricher.enrich(record)

        # Stage 5: Harmonize labels
        if self.harmonizer:
            self.harmonizer.harmonize(record)

        return record

    def process(self, records: Iterator[DatasetRecord]) -> Iterator[DatasetRecord]:
        """Stream records, yielding non-rejected, non-duplicate ones.

        REVIEW_REQUIRED records are yielded for visibility but should NOT be
        used as trusted SFT training examples without human review.
        """
        for record in records:
            processed = self.process_one(record)
            if processed.status not in (RecordStatus.REJECTED, RecordStatus.DUPLICATE):
                yield processed

    def process_all(
        self, records: Iterator[DatasetRecord]
    ) -> tuple[List[DatasetRecord], ProcessingReport]:
        """Process all records, collecting results and a report.

        For moderate-sized datasets. Use process() for streaming large datasets.
        """
        start_time = time.time()
        report = ProcessingReport()
        output: List[DatasetRecord] = []

        for record in records:
            report.input_records += 1
            processed = self.process_one(record)

            # Count by status
            if processed.status == RecordStatus.REJECTED:
                report.rejected += 1
                report.errors += len([
                    v for v in processed.validation_issues
                    if "[error]" in v.lower()
                ])
            elif processed.status == RecordStatus.DUPLICATE:
                report.duplicates += 1
            else:
                output.append(processed)
                report.output_records += 1

                # Track stage counts
                if any("normalized" in a.lower() for a in processed.normalization_actions):
                    report.normalized += 1
                else:
                    report.normalized += 1  # All records pass normalization

                report.validated += 1

                if processed.enrichment_tags:
                    report.enriched += 1
                if processed.classification is not None:
                    report.harmonized += 1
                    cls_name = processed.classification.value
                    report.class_distribution[cls_name] = \
                        report.class_distribution.get(cls_name, 0) + 1

            # Count warnings
            report.warnings += len([
                v for v in processed.validation_issues
                if "[warning]" in v.lower()
            ])

        report.duration_seconds = round(time.time() - start_time, 3)
        return output, report


# ---------------------------------------------------------------------------
# Pipeline builder (convenience factory)
# ---------------------------------------------------------------------------

def build_pipeline(
    dedup_strategy: str = "exact",
    validation_strict: bool = True,
    mitre_enabled: bool = True,
    label_maps_dir: Optional[Path] = None,
    max_dedup_window: Optional[int] = None,
) -> ProcessingPipeline:
    """Build a processing pipeline with common configuration."""
    return ProcessingPipeline(
        normalizer=RecordNormalizer(),
        validator=RecordValidator(strict=validation_strict),
        deduplicator=RecordDeduplicator(
            strategy=dedup_strategy,
            max_fingerprints=max_dedup_window,
        ),
        enricher=RecordEnricher(mitre_enabled=mitre_enabled),
        harmonizer=LabelHarmonizer(label_maps_dir=label_maps_dir),
    )
