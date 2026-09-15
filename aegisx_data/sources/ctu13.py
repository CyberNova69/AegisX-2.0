"""CTU-13 Botnet dataset connector.

Parses NetFlow records from the Czech Technical University botnet traffic
capture dataset.

Reference: https://www.stratosphereips.org/datasets-ctu13
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..core.types import DatasetRecord, DatasetSourceType
from .base import DatasetSource


# CTU-13 NetFlow column mapping
CTU_COLUMNS = {
    "starttime": "timestamp",
    "dur": "duration",
    "proto": "protocol",
    "srcaddr": "src_ip",
    "sport": "src_port",
    "dir": "direction",
    "dstaddr": "dst_ip",
    "dport": "dst_port",
    "state": "state",
    "stos": "src_tos",
    "dtos": "dst_tos",
    "totpkts": "total_packets",
    "totbytes": "total_bytes",
    "srcbytes": "bytes_sent",
    "label": "label",
}


class CTU13Source(DatasetSource):
    """CTU-13 Botnet dataset connector.

    Usage:
        source = CTU13Source()
        for record in source.parse(Path("path/to/capture.binetflow")):
            print(record.source_label, record.src_ip)
    """

    source_type = DatasetSourceType.CTU_13
    description = "CTU-13 Botnet NetFlow Dataset"

    def parse(self, path: Path, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        """Parse CTU-13 NetFlow files (CSV/binetflow format)."""
        if path.is_dir():
            yield from self._parse_directory(path, limit)
        else:
            yield from self._parse_file(path, limit)

    def _parse_directory(self, directory: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        total = 0
        for f in sorted(directory.iterdir()):
            if f.suffix in (".csv", ".binetflow", ".tsv"):
                remaining = (limit - total) if limit else None
                for record in self._parse_file(f, remaining):
                    yield record
                    total += 1
                    if limit and total >= limit:
                        return

    def _parse_file(self, filepath: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        count = 0
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                return

            # Normalize columns
            col_map = {}
            for col in reader.fieldnames:
                normalized = CTU_COLUMNS.get(col.lower().strip())
                if normalized:
                    col_map[col] = normalized

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
        mapped: Dict[str, Any] = {}
        for original, canonical in col_map.items():
            value = row.get(original, "").strip()
            if value:
                mapped[canonical] = value

        record = DatasetRecord(
            record_id=self._make_record_id(filename, index),
            source=self.source_type,
            source_file=filename,
            record_index=index,
        )

        record.src_ip = mapped.get("src_ip")
        record.dst_ip = mapped.get("dst_ip")

        # CTU-13 ports can have hex values
        src_port = mapped.get("src_port")
        if src_port:
            try:
                record.src_port = int(src_port, 16) if src_port.startswith("0x") else int(src_port)
            except (ValueError, TypeError):
                pass

        dst_port = mapped.get("dst_port")
        if dst_port:
            try:
                record.dst_port = int(dst_port, 16) if dst_port.startswith("0x") else int(dst_port)
            except (ValueError, TypeError):
                pass

        record.protocol = mapped.get("protocol", "").lower() or None
        record.timestamp = mapped.get("timestamp")

        dur = mapped.get("duration")
        if dur:
            try:
                record.duration = float(dur)
            except (ValueError, TypeError):
                pass

        bytes_sent = mapped.get("bytes_sent")
        if bytes_sent:
            try:
                record.bytes_sent = int(bytes_sent)
            except (ValueError, TypeError):
                pass

        total_bytes = mapped.get("total_bytes")
        if total_bytes:
            try:
                total = int(total_bytes)
                record.bytes_recv = total - (record.bytes_sent or 0)
                if record.bytes_recv < 0:
                    record.bytes_recv = 0
            except (ValueError, TypeError):
                pass

        total_pkts = mapped.get("total_packets")
        if total_pkts:
            try:
                record.packets_sent = int(total_pkts)
            except (ValueError, TypeError):
                pass

        # Label: CTU-13 uses compound labels like "flow=From-Botnet"
        label = mapped.get("label", "")
        if label:
            # Simplify compound labels
            if "botnet" in label.lower():
                record.source_label = "Botnet"
            elif "normal" in label.lower():
                record.source_label = "Normal"
            elif "background" in label.lower():
                record.source_label = "Background"
            else:
                record.source_label = label

        record.raw = {k: v for k, v in row.items() if v and v.strip()}
        return record
