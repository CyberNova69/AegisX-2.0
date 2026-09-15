"""Generic CSV dataset loader with configurable column mapping.

For user-supplied datasets that don't have a dedicated connector.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from ..core.types import DatasetRecord, DatasetSourceType
from .base import DatasetSource


class CustomCSVSource(DatasetSource):
    """Generic CSV loader with configurable column mapping.

    Usage:
        mapping = {
            "source_ip_column": "src_ip",
            "dest_ip_column": "dst_ip",
            "label_column": "source_label",
        }
        source = CustomCSVSource(column_mapping=mapping)
        for record in source.parse(Path("data.csv")):
            print(record.src_ip, record.source_label)
    """

    source_type = DatasetSourceType.CUSTOM_CSV
    description = "Generic CSV Dataset"

    # Standard field names that map to DatasetRecord attributes
    KNOWN_FIELDS = {
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "timestamp", "duration", "bytes_sent", "bytes_recv",
        "packets_sent", "packets_recv", "hostname", "username",
        "process_name", "command_line", "file_path", "file_hash",
        "source_label",
    }

    def __init__(
        self,
        column_mapping: Optional[Dict[str, str]] = None,
        delimiter: str = ",",
        encoding: str = "utf-8",
        **kwargs,
    ):
        """
        Args:
            column_mapping: Dict mapping CSV column names → DatasetRecord field names
            delimiter: CSV delimiter (default: comma)
            encoding: File encoding (default: utf-8)
        """
        super().__init__(**kwargs)
        self.column_mapping = column_mapping or {}
        self.delimiter = delimiter
        self.encoding = encoding

    def parse(self, path: Path, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        if path.is_dir():
            yield from self._parse_directory(path, limit)
        else:
            yield from self._parse_file(path, limit)

    def _parse_directory(self, directory: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        total = 0
        for csv_file in sorted(directory.glob("*.csv")):
            remaining = (limit - total) if limit else None
            for record in self._parse_file(csv_file, remaining):
                yield record
                total += 1
                if limit and total >= limit:
                    return

    def _parse_file(self, filepath: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        count = 0
        with open(filepath, "r", encoding=self.encoding, errors="replace") as f:
            reader = csv.DictReader(f, delimiter=self.delimiter)
            if reader.fieldnames is None:
                return

            # Build effective column map: explicit mapping + auto-detection
            col_map = dict(self.column_mapping)

            # Auto-detect columns that match known field names
            for col in reader.fieldnames:
                col_lower = col.strip().lower().replace(" ", "_").replace("-", "_")
                if col not in col_map and col_lower in self.KNOWN_FIELDS:
                    col_map[col] = col_lower

            for row in reader:
                if limit and count >= limit:
                    return

                try:
                    record = self._row_to_record(row, col_map, filepath.name, count)
                    if record:
                        yield record
                        count += 1
                except Exception:
                    count += 1
                    continue

    def _row_to_record(
        self, row: Dict[str, str], col_map: Dict[str, str],
        filename: str, index: int
    ) -> Optional[DatasetRecord]:
        record = DatasetRecord(
            record_id=self._make_record_id(filename, index),
            source=self.source_type,
            source_file=filename,
            record_index=index,
        )

        for csv_col, record_field in col_map.items():
            value = row.get(csv_col, "").strip()
            if not value:
                continue

            if record_field in ("src_port", "dst_port", "bytes_sent", "bytes_recv",
                                "packets_sent", "packets_recv"):
                try:
                    setattr(record, record_field, int(float(value)))
                except (ValueError, TypeError):
                    pass
            elif record_field == "duration":
                try:
                    record.duration = float(value)
                except (ValueError, TypeError):
                    pass
            elif hasattr(record, record_field):
                setattr(record, record_field, value)

        record.raw = {k: v for k, v in row.items() if v and v.strip()}
        return record
