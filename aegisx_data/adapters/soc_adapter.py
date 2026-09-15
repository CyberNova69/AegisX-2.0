"""Deterministic adapter: v0.4 SOC record → canonical DatasetRecord.

Converts the existing AegisX v0.4 SOC triage format:
    {task, input, output, id, metadata}

into the data platform's DatasetRecord.

This adapter is DETERMINISTIC and does NOT use an LLM.

Provenance is fully preserved:
- Original SOC record stored in DatasetRecord.raw
- Task type stored in enrichment_tags["soc_task"]
- SOC metadata stored in enrichment_tags["soc_metadata"]
- SOC record ID mapped to record_id
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional

from ..core.types import (
    AttackCategory,
    Classification,
    DatasetRecord,
    DatasetSourceType,
    Severity,
)


# ---------------------------------------------------------------------------
# Classification mapping: SOC output classification → AegisX Classification
# ---------------------------------------------------------------------------

_SOC_CLASSIFICATION_MAP = {
    "benign": Classification.BENIGN,
    "malicious": Classification.MALICIOUS,
    "suspicious": Classification.SUSPICIOUS,
    "likely_malicious": Classification.LIKELY_MALICIOUS,
    "confirmed_malicious": Classification.CONFIRMED_MALICIOUS,
    "insufficient_evidence": Classification.INSUFFICIENT_EVIDENCE,
}

_SOC_SEVERITY_MAP = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class SOCRecordAdapter:
    """Convert v0.4 SOC records to DatasetRecord.

    Usage:
        adapter = SOCRecordAdapter()

        # Single record
        record = adapter.convert(soc_record_dict)

        # Batch
        records = adapter.convert_batch(soc_records)

        # Streaming from JSONL
        for record in adapter.from_jsonl(Path("datasets/generated/soc_examples.jsonl")):
            ...
    """

    SOURCE_ID = DatasetSourceType.AEGISX_SOC.value  # "aegisx_soc"

    def convert(self, soc: Dict[str, Any], index: int = 0) -> Optional[DatasetRecord]:
        """Convert a single v0.4 SOC record to DatasetRecord.

        Args:
            soc: Dict with keys: task, input, output, id, metadata
            index: Record index for deterministic ID generation

        Returns:
            DatasetRecord or None if conversion fails
        """
        try:
            record_id = soc.get("id", f"soc-{index:08d}")
            task = soc.get("task", "unknown")
            input_data = soc.get("input", {})
            output_data = soc.get("output", {})
            metadata = soc.get("metadata", {})

            # Parse input structure
            alert = {}
            context = {}
            if isinstance(input_data, str):
                # Try parsing as JSON
                try:
                    input_data = json.loads(input_data)
                except (json.JSONDecodeError, TypeError):
                    input_data = {"raw_input": input_data}

            if isinstance(input_data, dict):
                alert = input_data.get("alert", input_data)
                context = input_data.get("context", {})

            # Parse output structure
            if isinstance(output_data, str):
                try:
                    output_data = json.loads(output_data)
                except (json.JSONDecodeError, TypeError):
                    output_data = {"raw_output": output_data}

            # Extract network fields from alert
            src_ip = alert.get("source_ip") or alert.get("src_ip")
            dst_ip = alert.get("destination_ip") or alert.get("dst_ip")
            src_port = _safe_int(alert.get("source_port") or alert.get("src_port"))
            dst_port = _safe_int(alert.get("destination_port") or alert.get("dst_port"))
            protocol = alert.get("protocol")
            timestamp = alert.get("timestamp")
            hostname = context.get("hostname") or alert.get("hostname")
            username = context.get("username") or alert.get("username")

            # Extract labels from output
            classification_str = None
            severity_str = None
            confidence = 1.0

            if isinstance(output_data, dict):
                classification_str = output_data.get("classification")
                severity_str = output_data.get("severity")
                if "confidence" in output_data:
                    try:
                        confidence = float(output_data["confidence"])
                    except (ValueError, TypeError):
                        confidence = 1.0

            # Map classification
            classification = None
            if classification_str:
                classification = _SOC_CLASSIFICATION_MAP.get(
                    classification_str.lower().strip()
                )

            # Map severity
            severity = None
            if severity_str:
                severity = _SOC_SEVERITY_MAP.get(
                    severity_str.lower().strip()
                )

            # Build the record
            record = DatasetRecord(
                record_id=str(record_id),
                source=self.SOURCE_ID,
                source_file=metadata.get("source_file", "soc_dataset"),
                record_index=index,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                hostname=hostname,
                username=username,
                source_label=classification_str,  # Original SOC classification is the "label"
                classification=classification,
                severity=severity,
                confidence=confidence,
                raw=soc,  # Full provenance
            )

            # Store SOC-specific provenance
            record.enrichment_tags["soc_task"] = task
            if metadata:
                record.enrichment_tags["soc_metadata"] = metadata
            record.enrichment_tags["adapter"] = "soc_v04"
            record.enrichment_tags["adapter_version"] = "1.0"

            return record

        except Exception:
            return None

    def convert_batch(self, records: List[Dict[str, Any]]) -> List[DatasetRecord]:
        """Convert a batch of v0.4 SOC records."""
        results = []
        for i, soc in enumerate(records):
            record = self.convert(soc, index=i)
            if record is not None:
                results.append(record)
        return results

    def from_jsonl(self, path) -> Iterator[DatasetRecord]:
        """Stream DatasetRecords from a v0.4 SOC JSONL file.

        Args:
            path: Path to JSONL file containing v0.4 SOC records
        """
        from pathlib import Path
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    soc = json.loads(line)
                    record = self.convert(soc, index=i)
                    if record is not None:
                        record.source_file = path.name
                        yield record
                except json.JSONDecodeError:
                    continue


def _safe_int(value) -> Optional[int]:
    """Safely convert a value to int."""
    if value is None:
        return None
    try:
        return int(float(str(value)))
    except (ValueError, TypeError):
        return None
