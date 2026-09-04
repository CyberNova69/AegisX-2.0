"""AegisX external dataset ingestion foundation (Phase 1).

Scope: source discovery -> format detection -> parsing -> canonical event.

Public API:
    from ai.ingestion import IngestionPipeline, discover, detect_format
    from ai.ingestion.types import CanonicalEvent, Format
"""

from .types import CanonicalEvent, Format, EVENT_TYPES, SEVERITIES
from .discovery import discover, SourceFile
from .detection import detect_format
from .pipeline import IngestionPipeline, IngestionResult, FileResult
from .canonicalize import map_record, infer_event_type
from .config import load_config
from .processing import (
    EventNormalizer, EventValidator, EventDeduplicator, EventProcessor,
    NormalizedEvent, ValidationIssue, ProcessingOutcome, ProcessingReport,
)

__all__ = [
    "CanonicalEvent", "Format", "EVENT_TYPES", "SEVERITIES",
    "discover", "SourceFile", "detect_format",
    "IngestionPipeline", "IngestionResult", "FileResult",
    "map_record", "infer_event_type", "load_config",
    "EventNormalizer", "EventValidator", "EventDeduplicator", "EventProcessor",
    "NormalizedEvent", "ValidationIssue", "ProcessingOutcome", "ProcessingReport",
]
