"""Text / log parser. Streams line-by-line.

Does NOT attempt full log-format detection (that belongs to the downstream
detection layer). It performs pragmatic extraction: leading timestamp, key=value
pairs, and the remaining free text as a message. Records that yield no structure
are kept verbatim with a `_raw_line` field so nothing is lost.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterator, Optional

from ..types import Format
from ..normalize import normalize_timestamp
from .base import BaseParser

_KV_RE = re.compile(r"(\w[\w.\-]*)\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\[[^\]]*\]|\S+)")
_TS_CANDIDATES = [
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?",
    r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}",
    r"\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}",
    r"\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]",
]


class TextLogParser(BaseParser):
    format = Format.TEXT_LOG
    streaming = True

    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                rec = self._parse_line(line)
                if rec is not None:
                    yield rec
                if limit is not None and i + 1 >= limit:
                    return

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        rec: Dict[str, Any] = {}

        for pat in _TS_CANDIDATES:
            m = re.search(pat, line)
            if m:
                ts = normalize_timestamp(m.group(0).strip("[]"))
                if ts:
                    rec["timestamp"] = ts
                    break

        kv_matches = _KV_RE.findall(line)
        for key, val in kv_matches:
            val = val.strip().strip('"').strip("'")
            rec[key] = val

        # Whatever is left after removing timestamp + k=v spans is the message.
        remainder = line
        for pat in _TS_CANDIDATES:
            remainder = re.sub(pat, "", remainder)
        for _, val in kv_matches:
            remainder = remainder.replace(val, "", 1)
        remainder = re.sub(r"\s{2,}", " ", remainder).strip()
        if remainder:
            rec["message"] = remainder

        if not rec:
            return {"_raw_line": line}
        rec["_raw_line"] = line
        return rec
