#!/usr/bin/env python3
"""
AegisX — External Dataset Ingestion CLI (Phase 1)
=================================================

Discovers, detects, parses, and canonicalizes external security datasets into
AegisX canonical events. Stdlib-only; CPU-friendly; streams large files.

Usage:
    python scripts/ingest_dataset.py --input path/to/data_dir
    python scripts/ingest_dataset.py --input alert.csv --limit 100
    python scripts/ingest_dataset.py --input logs/ --json
    python scripts/ingest_dataset.py --input . --report reports/ingestion_report.json

The output is a list of canonical events (one JSON object per line when --json),
plus an optional summary report. This does NOT perform detection/correlation —
it produces normalized events for downstream components to consume.
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.ingestion import IngestionPipeline, EventDeduplicator, EventProcessor


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisX external dataset ingestion (Phase 1)")
    parser.add_argument("--input", required=True, help="File or directory to ingest")
    parser.add_argument("--limit", type=int, default=None, help="Max total events to emit")
    parser.add_argument("--limit-per-file", type=int, default=None, help="Max events per file")
    parser.add_argument("--no-recursive", action="store_true", help="Do not descend into subdirs")
    parser.add_argument("--json", action="store_true", help="Emit canonical events as JSONL")
    parser.add_argument("--trusted", action="store_true",
                        help="Run Task 2 normalization, validation and deduplication; emit trusted events only")
    parser.add_argument("--audit-json", action="store_true",
                        help="With --trusted, emit all audit outcomes as JSONL (trusted/rejected/duplicate)")
    parser.add_argument("--dedup-window", type=int, default=None,
                        help="Bound fingerprint memory to this many events; omitted means exact run-wide dedup")
    parser.add_argument("--report", default=None, help="Write JSON summary report to this path")
    args = parser.parse_args()

    pipeline = IngestionPipeline(max_records=args.limit, limit_per_file=args.limit_per_file)

    if args.trusted:
        processor = EventProcessor(deduplicator=EventDeduplicator(args.dedup_window))
        trusted, report, outcomes = pipeline.run_processed(
            args.input, recursive=not args.no_recursive, processor=processor
        )
        if args.audit_json:
            for outcome in outcomes:
                print(json.dumps(outcome.to_dict(), ensure_ascii=False))
        elif args.json:
            for ev in trusted:
                print(json.dumps(ev.to_dict(), ensure_ascii=False))
        else:
            for ev in trusted:
                event = ev.event
                print(f"{event.event_id}\t{event.source_format.value}\t{event.event_type}\t"
                      f"{event.timestamp or '-'}\t{event.hostname or '-'}\t{event.username or '-'}")
        print(f"\n[trusted-summary] {report.to_dict()}", file=sys.stderr)
        if args.report:
            payload = {"input": args.input, "processing": report.to_dict(),
                       "outcomes": [outcome.to_dict() for outcome in outcomes]}
            Path(args.report).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"[report] wrote {args.report}", file=sys.stderr)
        return 0

    result = pipeline.run(args.input, recursive=not args.no_recursive)

    if args.json:
        for ev in result.events:
            print(json.dumps(ev.to_dict(), ensure_ascii=False))
    else:
        for ev in result.events:
            print(f"{ev.event_id}\t{ev.source_format.value}\t{ev.event_type}\t"
                  f"{ev.timestamp or '-'}\t{ev.hostname or '-'}\t{ev.username or '-'}")

    print(f"\n[summary] files={result.files_processed} records={result.total_records} "
          f"errors={result.errors} formats={result.by_format} "
          f"time={result.duration_seconds}s", file=sys.stderr)

    if args.report:
        payload = {
            "input": args.input,
            "total_records": result.total_records,
            "files_processed": result.files_processed,
            "errors": result.errors,
            "by_format": result.by_format,
            "duration_seconds": result.duration_seconds,
            "files": [
                {
                    "path": fr.path,
                    "format": fr.format.value,
                    "records": fr.records,
                    "errors": fr.errors,
                    "skipped": fr.skipped,
                    "skip_reason": fr.skip_reason,
                }
                for fr in result.file_results
            ],
        }
        Path(args.report).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[report] wrote {args.report}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
