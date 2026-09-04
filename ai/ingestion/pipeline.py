"""Ingestion pipeline: orchestrates discovery -> detection -> parsing -> canonicalize.

Designed to stream so it can handle very large inputs on a 16 GB / no-GPU box:
  * JSONL / CSV / XML / log parsers read incrementally
  * events are yielded one at a time via `ingest()`
  * `run()` collects into memory only for moderate inputs / tests

For millions of records, prefer `ingest()` and persist/forward events downstream
rather than `run()`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from .canonicalize import map_record
from .discovery import SourceFile, discover
from .parsers import get_parser
from .processing import EventProcessor, NormalizedEvent, ProcessingOutcome, ProcessingReport
from .types import CanonicalEvent, Format


@dataclass
class FileResult:
    path: str
    format: Format
    records: int = 0
    errors: int = 0
    skipped: bool = False
    skip_reason: Optional[str] = None


@dataclass
class IngestionResult:
    total_records: int = 0
    files_processed: int = 0
    errors: int = 0
    by_format: Dict[str, int] = field(default_factory=dict)
    file_results: List[FileResult] = field(default_factory=list)
    events: List[CanonicalEvent] = field(default_factory=list)
    duration_seconds: float = 0.0


class IngestionPipeline:
    def __init__(self, max_records: Optional[int] = None,
                 limit_per_file: Optional[int] = None):
        self.max_records = max_records
        self.limit_per_file = limit_per_file

    def ingest(self, input_path: str, recursive: bool = True) -> Iterator[CanonicalEvent]:
        """Stream canonical events from `input_path` (file or directory)."""
        sources = discover(input_path, recursive=recursive)
        total = 0
        for src in sources:
            parser = get_parser(src.format)
            if parser is None:
                continue
            stem = Path(src.path).stem
            count = 0
            for rec in parser.parse(src.path, limit=self.limit_per_file):
                event_id = f"{stem}-{count:06d}"
                try:
                    event = map_record(rec, stem, count, src.format, event_id)
                except Exception:
                    # The streaming API cannot return a summary object, so it
                    # retains parseable malformed input instead of silently
                    # dropping it; hard mapping failures are the sole skip case.
                    count += 1
                    continue
                count += 1
                total += 1
                yield event
                if self.max_records is not None and total >= self.max_records:
                    return

    def run(self, input_path: str, recursive: bool = True) -> IngestionResult:
        """Collect results into an IngestionResult (in-memory; for moderate inputs)."""
        result = IngestionResult()
        start = time.time()
        sources: List[SourceFile] = discover(input_path, recursive=recursive)
        for src in sources:
            fr = FileResult(path=src.path, format=src.format)
            parser = get_parser(src.format)
            if parser is None:
                fr.skipped = True
                fr.skip_reason = f"no parser for format {src.format.value}"
                result.file_results.append(fr)
                continue
            stem = Path(src.path).stem
            count = 0
            try:
                for rec in parser.parse(src.path, limit=self.limit_per_file):
                    # Tolerant parsers preserve malformed records and tag them
                    # explicitly; account for them rather than hiding bad input.
                    if isinstance(rec, dict) and rec.get("_parse_error"):
                        fr.errors += 1
                    try:
                        event = map_record(rec, stem, count, src.format, f"{stem}-{count:06d}")
                    except Exception:
                        fr.errors += 1
                        count += 1
                        continue
                    result.events.append(event)
                    fr.records += 1
                    count += 1
                    if self.max_records is not None and len(result.events) >= self.max_records:
                        break
            except Exception as exc:  # parser-level failure (e.g. unsupported dep)
                fr.errors += 1
                fr.skip_reason = str(exc)
            result.file_results.append(fr)
            result.total_records += fr.records
            result.errors += fr.errors
            result.by_format[src.format.value] = result.by_format.get(src.format.value, 0) + fr.records
            # `max_records` is global across every discovered source, not merely
            # a per-file cap. Stop the outer loop once the cap has been reached.
            if self.max_records is not None and len(result.events) >= self.max_records:
                break
        result.files_processed = sum(1 for f in result.file_results if not f.skipped)
        result.duration_seconds = round(time.time() - start, 3)
        return result

    def process_outcomes(self, input_path: str, recursive: bool = True,
                         processor: Optional[EventProcessor] = None) -> Iterator[ProcessingOutcome]:
        """Stream all processing outcomes, including duplicates/rejections for audit."""
        processor = processor or EventProcessor()
        yield from processor.process_outcomes(self.ingest(input_path, recursive=recursive))

    def process(self, input_path: str, recursive: bool = True,
                processor: Optional[EventProcessor] = None) -> Iterator[NormalizedEvent]:
        """Stream trusted normalized events only; use process_outcomes for audit."""
        processor = processor or EventProcessor()
        yield from processor.process(self.ingest(input_path, recursive=recursive))

    def run_processed(self, input_path: str, recursive: bool = True,
                      processor: Optional[EventProcessor] = None) -> tuple[List[NormalizedEvent], ProcessingReport, List[ProcessingOutcome]]:
        """Collect Task 2 results for moderate inputs/testing; preserves Task 1 run()."""
        processor = processor or EventProcessor()
        return processor.collect(self.ingest(input_path, recursive=recursive))
