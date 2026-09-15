"""CICIDS-2017/2018 dataset connector.

Parses network flow records from the Canadian Institute for Cybersecurity
Intrusion Detection datasets (CSV format).

CICIDS-2017: ~2.8M records, 80 features, 15 attack categories
CICIDS-2018: ~16M records, 80 features, 7 attack categories

References:
  - https://www.unb.ca/cic/datasets/ids-2017.html
  - https://www.unb.ca/cic/datasets/ids-2018.html
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..core.types import DatasetRecord, DatasetSourceType
from .base import DatasetSource


# Column name normalization map (CICIDS CSVs have inconsistent naming)
COLUMN_ALIASES = {
    # Standard column names
    "flow id": "flow_id",
    " flow id": "flow_id",
    "source ip": "src_ip",
    " source ip": "src_ip",
    "src ip": "src_ip",
    "source port": "src_port",
    " source port": "src_port",
    "src port": "src_port",
    "destination ip": "dst_ip",
    " destination ip": "dst_ip",
    "dst ip": "dst_ip",
    "destination port": "dst_port",
    " destination port": "dst_port",
    "dst port": "dst_port",
    "protocol": "protocol",
    " protocol": "protocol",
    "timestamp": "timestamp",
    " timestamp": "timestamp",
    "flow duration": "duration",
    " flow duration": "duration",
    "total fwd packets": "packets_sent",
    " total fwd packets": "packets_sent",
    "total backward packets": "packets_recv",
    " total backward packets": "packets_recv",
    "total length of fwd packets": "bytes_sent",
    " total length of fwd packets": "bytes_sent",
    "total length of bwd packets": "bytes_recv",
    " total length of bwd packets": "bytes_recv",
    "fwd packets/s": "fwd_packets_per_sec",
    " fwd packets/s": "fwd_packets_per_sec",
    "bwd packets/s": "bwd_packets_per_sec",
    " bwd packets/s": "bwd_packets_per_sec",
    "label": "label",
    " label": "label",
}

# Protocol number → name
PROTOCOL_MAP = {
    "0": "hopopt",
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
}


class CICIDSSource(DatasetSource):
    """CICIDS-2017/2018 dataset connector.

    Parses CSV files with network flow features and attack labels.

    Usage:
        source = CICIDSSource(version="2017")
        for record in source.parse(Path("path/to/cicids.csv"), limit=1000):
            print(record.source_label, record.src_ip, record.dst_ip)
    """

    description = "Canadian Institute for Cybersecurity IDS Dataset"

    # Known download URLs for CICIDS-2017
    CICIDS_2017_FILES = [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    ]

    def __init__(self, version: str = "2017", **kwargs):
        super().__init__(**kwargs)
        self.version = version
        if version == "2017":
            self.source_type = DatasetSourceType.CICIDS_2017
        else:
            self.source_type = DatasetSourceType.CICIDS_2018

    def parse(self, path: Path, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        """Parse CICIDS CSV file(s).

        Args:
            path: Path to a single CSV file or directory of CSV files
            limit: Maximum number of records to yield
        """
        if path.is_dir():
            yield from self._parse_directory(path, limit)
        else:
            yield from self._parse_file(path, limit)

    def _parse_directory(self, directory: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        """Parse all CSV files in a directory."""
        total = 0
        for csv_file in sorted(directory.glob("*.csv")):
            remaining = (limit - total) if limit else None
            for record in self._parse_file(csv_file, remaining):
                yield record
                total += 1
                if limit and total >= limit:
                    return

    def _parse_file(self, filepath: Path, limit: Optional[int]) -> Iterator[DatasetRecord]:
        """Parse a single CICIDS CSV file."""
        count = 0

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            # Detect BOM
            first_bytes = f.read(3)
            if first_bytes != "\ufeff":
                f.seek(0)

            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                return

            # Normalize column names
            col_map = {}
            for col in reader.fieldnames:
                normalized = COLUMN_ALIASES.get(col.lower().strip(), None)
                if normalized:
                    col_map[col] = normalized

            for row in reader:
                if limit and count >= limit:
                    return

                try:
                    record = self._row_to_record(row, col_map, filepath.name, count)
                    if record is not None:
                        yield record
                        count += 1
                except Exception:
                    count += 1
                    continue

    def _row_to_record(
        self, row: Dict[str, str], col_map: Dict[str, str],
        filename: str, index: int
    ) -> Optional[DatasetRecord]:
        """Convert a CSV row to a DatasetRecord."""
        # Map columns
        mapped: Dict[str, Any] = {}
        for original_col, canonical_col in col_map.items():
            value = row.get(original_col, "").strip()
            if value and value not in ("", "NaN", "Infinity", "-Infinity", "nan", "inf"):
                mapped[canonical_col] = value

        record = DatasetRecord(
            record_id=self._make_record_id(filename, index),
            source=self.source_type,
            source_file=filename,
            record_index=index,
        )

        # Network flow fields
        record.src_ip = mapped.get("src_ip")
        record.dst_ip = mapped.get("dst_ip")
        record.src_port = _safe_int(mapped.get("src_port"))
        record.dst_port = _safe_int(mapped.get("dst_port"))
        record.timestamp = mapped.get("timestamp")

        # Protocol (CICIDS uses numeric protocol numbers)
        proto = mapped.get("protocol", "")
        record.protocol = PROTOCOL_MAP.get(proto, proto.lower() if proto else None)

        # Flow features
        record.duration = _safe_float(mapped.get("duration"))
        record.bytes_sent = _safe_int(mapped.get("bytes_sent"))
        record.bytes_recv = _safe_int(mapped.get("bytes_recv"))
        record.packets_sent = _safe_int(mapped.get("packets_sent"))
        record.packets_recv = _safe_int(mapped.get("packets_recv"))

        # Label
        record.source_label = mapped.get("label")

        # Preserve raw
        record.raw = {k: v for k, v in row.items() if v and v.strip()}

        return record

    def discover(self) -> List[Dict[str, Any]]:
        """List known CICIDS files."""
        return [{"name": f, "version": self.version} for f in self.CICIDS_2017_FILES]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(value: Optional[str]) -> Optional[int]:
    """Safely convert to int, handling floats and invalid values."""
    if value is None:
        return None
    try:
        return int(float(value))
    except (ValueError, TypeError, OverflowError):
        return None


def _safe_float(value: Optional[str]) -> Optional[float]:
    """Safely convert to float, handling invalid values."""
    if value is None:
        return None
    try:
        result = float(value)
        if result != result:  # NaN check
            return None
        return result
    except (ValueError, TypeError, OverflowError):
        return None
