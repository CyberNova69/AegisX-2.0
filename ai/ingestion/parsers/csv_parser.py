"""CSV / TSV parser. Streams row-by-row using the stdlib csv module.

Delimiter is auto-detected via csv.Sniffer with a comma fallback so both .csv
and .tsv are handled by the same parser.
"""

from __future__ import annotations

import csv
from typing import Any, Dict, Iterator, Optional

from ..types import Format
from .base import BaseParser


class CsvParser(BaseParser):
    format = Format.CSV
    streaming = True

    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            sample = fh.read(4096)
            fh.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=[",", "\t", ";", "|"])
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(fh, dialect=dialect)
            for i, row in enumerate(reader):
                # Normalize empty strings to None for cleaner canonicalization.
                clean = {k: (v if v != "" else None) for k, v in row.items()}
                yield clean
                if limit is not None and i + 1 >= limit:
                    return
