"""Exact and near-duplicate detection for DatasetRecord.

Design mirrors ai/ingestion/processing.py EventDeduplicator but operates on
the DatasetRecord type and supports both exact and near-duplicate strategies.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, Iterator, List, Optional

from ..core.types import DatasetRecord, RecordStatus


class RecordDeduplicator:
    """Deterministic deduplication over DatasetRecord instances.

    Strategies:
        - "exact": SHA-256 fingerprint over all canonical fields
        - "near": SHA-256 over a configurable subset of fields (e.g., ignore timestamps)

    Parameters:
        strategy: "exact" or "near"
        max_fingerprints: Optional bound on the fingerprint window (memory safety)
        near_fields: Fields to use for near-duplicate detection (default: network 5-tuple + label)
    """

    # Default fields for exact fingerprinting
    EXACT_FIELDS = (
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "timestamp", "source_label", "hostname", "username",
        "process_name", "command_line", "file_path", "file_hash",
        "duration", "bytes_sent", "bytes_recv", "packets_sent", "packets_recv",
    )

    # Default fields for near-duplicate detection (ignores timestamps, byte counts)
    NEAR_FIELDS = (
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "source_label", "hostname", "process_name", "file_hash",
    )

    def __init__(
        self,
        strategy: str = "exact",
        max_fingerprints: Optional[int] = None,
        near_fields: Optional[tuple] = None,
    ):
        if strategy not in ("exact", "near"):
            raise ValueError(f"Unknown dedup strategy: {strategy}")
        if max_fingerprints is not None and max_fingerprints < 1:
            raise ValueError("max_fingerprints must be positive or None")

        self.strategy = strategy
        self.max_fingerprints = max_fingerprints
        self.near_fields = near_fields or self.NEAR_FIELDS
        self._seen: Dict[str, str] = {}  # fingerprint -> first record_id
        self._order: List[str] = []
        self.evictions: int = 0
        self.duplicates_found: int = 0

    @property
    def _fields(self) -> tuple:
        """Fields used for fingerprinting based on strategy."""
        return self.EXACT_FIELDS if self.strategy == "exact" else self.near_fields

    def fingerprint(self, record: DatasetRecord) -> str:
        """Compute a SHA-256 fingerprint for a record."""
        payload = {}
        for field_name in self._fields:
            value = getattr(record, field_name, None)
            payload[field_name] = value

        encoded = json.dumps(
            payload, sort_keys=True, ensure_ascii=False,
            default=str, separators=(",", ":")
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def check(self, record: DatasetRecord) -> Optional[str]:
        """Check if a record is a duplicate.

        Returns the original record_id if duplicate, None if unique.
        Also updates the record's fingerprint and status.
        """
        fp = self.fingerprint(record)
        record.fingerprint = fp

        original_id = self._seen.get(fp)
        if original_id is not None:
            record.status = RecordStatus.DUPLICATE
            self.duplicates_found += 1
            return original_id

        # Register this record
        self._seen[fp] = record.record_id
        self._order.append(fp)

        # Evict oldest if window exceeded
        if self.max_fingerprints and len(self._order) > self.max_fingerprints:
            old_fp = self._order.pop(0)
            self._seen.pop(old_fp, None)
            self.evictions += 1

        return None

    def deduplicate(self, records: Iterator[DatasetRecord]) -> Iterator[DatasetRecord]:
        """Stream records, yielding only unique ones."""
        for record in records:
            if self.check(record) is None:
                yield record

    def reset(self) -> None:
        """Reset the deduplicator state."""
        self._seen.clear()
        self._order.clear()
        self.evictions = 0
        self.duplicates_found = 0

    def stats(self) -> Dict[str, int]:
        """Return deduplication statistics."""
        return {
            "unique_fingerprints": len(self._seen),
            "duplicates_found": self.duplicates_found,
            "evictions": self.evictions,
        }
