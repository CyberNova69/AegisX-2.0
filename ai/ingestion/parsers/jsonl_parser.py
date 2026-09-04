"""JSONL / NDJSON parser. Streams line-by-line (memory-bounded per record)."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, Optional

from ..types import Format
from .base import BaseParser


class JsonlParser(BaseParser):
    format = Format.JSONL
    streaming = True

    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    # Preserve malformed input as an explicitly marked raw record
                    # so callers can report it; never silently discard data.
                    rec = {
                        "_raw_line": line,
                        "_parse_error": f"JSONL line {i + 1}: {exc.msg}",
                    }
                if isinstance(rec, dict):
                    yield rec
                else:
                    yield {"value": rec}
                if limit is not None and i + 1 >= limit:
                    return
