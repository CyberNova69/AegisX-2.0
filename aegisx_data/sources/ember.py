"""EMBER PE malware dataset connector.

Parses the Endgame Malware BEnchmark for Research (EMBER) dataset.
EMBER provides feature vectors extracted from PE files for malware
classification.

Reference: https://github.com/elastic/ember
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from ..core.types import DatasetRecord, DatasetSourceType
from .base import DatasetSource


class EMBERSource(DatasetSource):
    """EMBER PE malware dataset connector.

    EMBER uses JSONL format with pre-extracted features.

    Usage:
        source = EMBERSource()
        for record in source.parse(Path("ember2018/train_features_0.jsonl")):
            print(record.source_label)
    """

    source_type = DatasetSourceType.EMBER
    description = "EMBER PE Malware Feature Dataset"

    def parse(self, path: Path, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        if path.is_dir():
            yield from self._parse_directory(path, limit)
        else:
            yield from self._parse_file(path, limit)

    def _parse_directory(self, directory: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        total = 0
        for f in sorted(directory.iterdir()):
            if f.suffix in (".jsonl", ".json"):
                remaining = (limit - total) if limit else None
                for record in self._parse_file(f, remaining):
                    yield record
                    total += 1
                    if limit and total >= limit:
                        return

    def _parse_file(self, filepath: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        count = 0
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if limit and count >= limit:
                    return

                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    record = self._data_to_record(data, filepath.name, count)
                    if record:
                        yield record
                        count += 1
                except (json.JSONDecodeError, Exception):
                    count += 1
                    continue

    def _data_to_record(
        self, data: Dict[str, Any], filename: str, index: int
    ) -> Optional[DatasetRecord]:
        record = DatasetRecord(
            record_id=self._make_record_id(filename, index),
            source=self.source_type,
            source_file=filename,
            record_index=index,
        )

        # EMBER label: 0=benign, 1=malware, -1=unknown
        label = data.get("label", -1)
        if label == 0:
            record.source_label = "benign"
        elif label == 1:
            record.source_label = "malware"
        else:
            record.source_label = "unknown"

        # SHA-256 hash of the PE file
        sha256 = data.get("sha256")
        if sha256:
            record.file_hash = sha256.lower()

        # Extract PE metadata if available
        general_info = data.get("general", {})
        if isinstance(general_info, dict):
            record.file_path = general_info.get("filename")
            size = general_info.get("size")
            if size:
                record.enrichment_tags["pe_size"] = size
            has_debug = general_info.get("has_debug")
            if has_debug is not None:
                record.enrichment_tags["has_debug"] = has_debug

        # Extract header info
        header_info = data.get("header", {})
        if isinstance(header_info, dict):
            machine = header_info.get("machine")
            if machine:
                record.enrichment_tags["pe_machine"] = machine

        # Store feature summary (not full features — too large)
        feature_keys = [k for k in data.keys() if k not in ("label", "sha256")]
        record.enrichment_tags["ember_feature_keys"] = feature_keys

        record.raw = {"label": data.get("label"), "sha256": sha256}
        return record
