"""Excel parser (optional dependency: openpyxl)."""

from __future__ import annotations

from typing import Any, Dict, Iterator, Optional

from ..types import Format
from .base import BaseParser, MissingDependencyError


class ExcelParser(BaseParser):
    format = Format.EXCEL
    streaming = True

    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        try:
            import openpyxl  # noqa: F401
        except ImportError as exc:
            raise MissingDependencyError("excel", "openpyxl") from exc

        import openpyxl
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        for ws in wb.worksheets:
            rows = ws.iter_rows(values_only=True)
            try:
                header = [str(h) if h is not None else f"col{i}" for i, h in enumerate(next(rows))]
            except StopIteration:
                continue
            for i, row in enumerate(rows):
                if all(c is None for c in row):
                    continue
                rec = {header[j]: row[j] for j in range(min(len(header), len(row)))}
                yield rec
                if limit is not None and i + 1 >= limit:
                    return
