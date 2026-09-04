"""Parquet parser (optional dependency: pyarrow)."""

from __future__ import annotations

from typing import Any, Dict, Iterator, Optional

from ..types import Format
from .base import BaseParser, MissingDependencyError


class ParquetParser(BaseParser):
    format = Format.PARQUET
    streaming = True

    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        try:
            import pyarrow.parquet as pq  # noqa: F401
        except ImportError as exc:
            raise MissingDependencyError("parquet", "pyarrow") from exc

        import pyarrow.parquet as pq
        parquet_file = pq.ParquetFile(path)
        count = 0
        # iter_batches avoids materializing an entire multi-million-row table.
        for batch in parquet_file.iter_batches(batch_size=4096):
            for row in batch.to_pylist():
                yield row
                count += 1
                if limit is not None and count >= limit:
                    return
