"""HuggingFace Datasets hub connector.

Loads cybersecurity datasets from HuggingFace Hub using the `datasets` library.
Falls back gracefully when the library is not installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from ..core.types import DatasetRecord, DatasetSourceType
from .base import DatasetSource


class HuggingFaceSource(DatasetSource):
    """HuggingFace Datasets hub connector.

    Usage:
        source = HuggingFaceSource(dataset_name="CyberPeace/IOCDetection")
        for record in source.parse(Path("."), limit=100):
            print(record.source_label)
    """

    source_type = DatasetSourceType.HUGGINGFACE
    description = "HuggingFace Datasets Hub"

    def __init__(
        self,
        dataset_name: str = "",
        split: str = "train",
        column_mapping: Optional[Dict[str, str]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.dataset_name = dataset_name
        self.split = split
        self.column_mapping = column_mapping or {}

    def parse(self, path: Path, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        """Load from HuggingFace Hub.

        The `path` argument is ignored for HF datasets; the dataset name
        is used instead. Pass path=Path(".") as a placeholder.

        Requires: pip install datasets
        """
        try:
            from datasets import load_dataset
        except ImportError:
            raise ImportError(
                "HuggingFace Datasets library is required. "
                "Install with: pip install datasets"
            )

        if not self.dataset_name:
            raise ValueError("dataset_name is required for HuggingFaceSource")

        # Load dataset
        ds = load_dataset(
            self.dataset_name,
            split=self.split,
            cache_dir=str(self.cache_dir) if self.cache_dir else None,
        )

        count = 0
        for i, item in enumerate(ds):
            if limit and count >= limit:
                return

            record = self._item_to_record(item, i)
            if record:
                yield record
                count += 1

    def _item_to_record(self, item: Dict[str, Any], index: int) -> Optional[DatasetRecord]:
        """Convert a HuggingFace dataset item to a DatasetRecord."""
        record = DatasetRecord(
            record_id=f"hf-{self.dataset_name.replace('/', '_')}-{index:08d}",
            source=self.source_type,
            source_file=self.dataset_name,
            record_index=index,
        )

        # Apply column mapping
        for hf_col, record_field in self.column_mapping.items():
            value = item.get(hf_col)
            if value is not None and hasattr(record, record_field):
                if record_field in ("src_port", "dst_port", "bytes_sent", "bytes_recv",
                                    "packets_sent", "packets_recv"):
                    try:
                        setattr(record, record_field, int(value))
                    except (ValueError, TypeError):
                        pass
                elif record_field == "duration":
                    try:
                        record.duration = float(value)
                    except (ValueError, TypeError):
                        pass
                else:
                    setattr(record, record_field, str(value))

        # Auto-detect label column
        if not record.source_label:
            for label_key in ("label", "Label", "labels", "target", "class", "category"):
                if label_key in item:
                    record.source_label = str(item[label_key])
                    break

        record.raw = {k: str(v) for k, v in item.items() if v is not None}
        return record
