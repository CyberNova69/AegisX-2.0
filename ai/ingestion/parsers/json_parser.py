"""JSON parser. Streams nothing (loads the whole document)."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, Optional

from ..types import Format
from .base import BaseParser

# Heuristic keys that commonly wrap a list of records inside a single JSON object.
_LIST_KEYS = ("events", "records", "logs", "data", "items", "rows", "results", "alerts")


class JsonParser(BaseParser):
    format = Format.JSON
    streaming = False

    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)

        records: list = []
        if isinstance(doc, list):
            records = doc
        elif isinstance(doc, dict):
            for key in _LIST_KEYS:
                val = doc.get(key)
                if isinstance(val, list) and val and isinstance(val[0], (dict, list)):
                    records = val
                    break
            if not records:
                records = [doc]
        else:
            return

        for i, rec in enumerate(records):
            if isinstance(rec, dict):
                yield rec
            elif isinstance(rec, list):
                # Array-of-arrays (e.g. CSV-style); expose as positional dict.
                yield {"_row": rec}
            else:
                yield {"value": rec}
            if limit is not None and i + 1 >= limit:
                return
