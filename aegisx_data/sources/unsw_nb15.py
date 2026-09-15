"""UNSW-NB15 dataset connector.

Parses the 49-feature network flow records from the UNSW-NB15 dataset
created by the University of New South Wales.

Reference: https://research.unsw.edu.au/projects/unsw-nb15-dataset
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..core.types import DatasetRecord, DatasetSourceType
from .base import DatasetSource


# UNSW-NB15 column mapping
UNSW_COLUMNS = {
    "srcip": "src_ip",
    "sport": "src_port",
    "dstip": "dst_ip",
    "dsport": "dst_port",
    "proto": "protocol",
    "dur": "duration",
    "sbytes": "bytes_sent",
    "dbytes": "bytes_recv",
    "spkts": "packets_sent",
    "dpkts": "packets_recv",
    "stime": "timestamp",
    "ltime": "end_time",
    "attack_cat": "attack_category",
    "label": "label",
    "ct_srv_src": "ct_srv_src",
    "ct_srv_dst": "ct_srv_dst",
    "ct_dst_ltm": "ct_dst_ltm",
    "ct_src_ltm": "ct_src_ltm",
    "ct_src_dport_ltm": "ct_src_dport_ltm",
    "ct_dst_sport_ltm": "ct_dst_sport_ltm",
    "ct_dst_src_ltm": "ct_dst_src_ltm",
    "is_ftp_login": "is_ftp_login",
    "ct_ftp_cmd": "ct_ftp_cmd",
    "ct_flw_http_mthd": "ct_flw_http_mthd",
    "is_sm_ips_ports": "is_sm_ips_ports",
    "state": "state",
    "service": "service",
    "sttl": "src_ttl",
    "dttl": "dst_ttl",
    "sloss": "src_loss",
    "dloss": "dst_loss",
    "swin": "src_window",
    "dwin": "dst_window",
    "stcpb": "src_tcp_base",
    "dtcpb": "dst_tcp_base",
    "smean": "src_mean_pkt",
    "dmean": "dst_mean_pkt",
    "sinpkt": "src_inter_pkt",
    "dinpkt": "dst_inter_pkt",
    "sjit": "src_jitter",
    "djit": "dst_jitter",
    "tcprtt": "tcp_rtt",
    "synack": "syn_ack_time",
    "ackdat": "ack_dat_time",
    "trans_depth": "trans_depth",
    "response_body_len": "response_body_len",
}


class UNSWNB15Source(DatasetSource):
    """UNSW-NB15 dataset connector.

    Usage:
        source = UNSWNB15Source()
        for record in source.parse(Path("UNSW-NB15_1.csv"), limit=100):
            print(record.source_label, record.attack_category)
    """

    source_type = DatasetSourceType.UNSW_NB15
    description = "UNSW-NB15 Network Intrusion Dataset (49 features)"

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
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                return

            col_map = {}
            for col in reader.fieldnames:
                normalized = UNSW_COLUMNS.get(col.lower().strip())
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
            if value and value not in ("", " "):
                mapped[canonical] = value

        record = DatasetRecord(
            record_id=self._make_record_id(filename, index),
            source=self.source_type,
            source_file=filename,
            record_index=index,
        )

        # Network fields
        record.src_ip = mapped.get("src_ip")
        record.dst_ip = mapped.get("dst_ip")
        record.src_port = _safe_int(mapped.get("src_port"))
        record.dst_port = _safe_int(mapped.get("dst_port"))
        record.protocol = mapped.get("protocol", "").lower() or None
        record.duration = _safe_float(mapped.get("duration"))
        record.bytes_sent = _safe_int(mapped.get("bytes_sent"))
        record.bytes_recv = _safe_int(mapped.get("bytes_recv"))
        record.packets_sent = _safe_int(mapped.get("packets_sent"))
        record.packets_recv = _safe_int(mapped.get("packets_recv"))
        record.timestamp = mapped.get("timestamp")

        # Labels: UNSW-NB15 has both binary label and attack_cat
        label_val = mapped.get("label", "0")
        attack_cat = mapped.get("attack_category", "").strip()

        if label_val == "0" or (not attack_cat and label_val == "0"):
            record.source_label = "Normal"
        elif attack_cat:
            record.source_label = attack_cat
        else:
            record.source_label = "Normal" if label_val == "0" else "Attack"

        # Store extra features for potential use
        extra_features = {}
        for key in ("state", "service", "src_ttl", "dst_ttl", "tcp_rtt",
                     "src_jitter", "dst_jitter", "src_mean_pkt", "dst_mean_pkt",
                     "trans_depth", "response_body_len"):
            if key in mapped:
                extra_features[key] = mapped[key]
        if extra_features:
            record.enrichment_tags["unsw_features"] = extra_features

        record.raw = {k: v for k, v in row.items() if v and v.strip()}
        return record


def _safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(float(value))
    except (ValueError, TypeError, OverflowError):
        return None


def _safe_float(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    try:
        result = float(value)
        if result != result:
            return None
        return result
    except (ValueError, TypeError, OverflowError):
        return None
