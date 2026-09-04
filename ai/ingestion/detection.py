"""Format detection: extension + content sniffing. Stdlib only, deterministic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Tuple

from .types import Format

_EXT_MAP = {
    ".csv": Format.CSV,
    ".tsv": Format.CSV,            # tab-separated handled by CSV parser
    ".json": Format.JSON,
    ".jsonl": Format.JSONL,
    ".ndjson": Format.JSONL,
    ".xml": Format.XML,
    ".log": Format.TEXT_LOG,
    ".txt": Format.TEXT_LOG,
    ".xlsx": Format.EXCEL,
    ".xls": Format.EXCEL,
    ".parquet": Format.PARQUET,
}

# How confident we are in an extension-based guess.
_EXTENSION_CONFIDENCE = 0.9
_CONTENT_CONFIDENCE = 0.75


def detect_format(path: str, sample_size: int = 65536) -> Tuple[Format, float]:
    """Detect the format of `path`.

    Returns (format, confidence). Uses file extension first, then validates/overrides
    with a content sniff of the first `sample_size` bytes. Confidence reflects how
    strongly the two signals agree.
    """
    p = Path(path)
    ext_fmt = _EXT_MAP.get(p.suffix.lower(), Format.UNKNOWN)

    try:
        with open(p, "rb") as fh:
            sample = fh.read(sample_size)
    except (OSError, IsADirectoryError):
        return (ext_fmt if ext_fmt != Format.UNKNOWN else Format.UNKNOWN,
                _EXTENSION_CONFIDENCE if ext_fmt != Format.UNKNOWN else 0.0)

    content_fmt = _sniff_content(sample)

    if content_fmt != Format.UNKNOWN:
        # Content is the stronger, validated signal.
        if content_fmt == ext_fmt:
            return content_fmt, 1.0
        # Trust content over a weak/conflicting extension guess.
        return content_fmt, _CONTENT_CONFIDENCE

    if ext_fmt != Format.UNKNOWN:
        return ext_fmt, _EXTENSION_CONFIDENCE
    return Format.UNKNOWN, 0.0


def _sniff_content(sample: bytes) -> Format:
    head = sample.lstrip()[:200]
    text = sample.decode("utf-8", errors="replace")

    # XML
    if head.startswith(b"<?xml") or head.startswith(b"<") and b"<" in sample[:200]:
        # Disambiguate HTML-ish from data XML lightly; treat leading tag as XML.
        return Format.XML

    # JSON array / object
    if head[:1] in (b"[", b"{"):
        try:
            json.loads(text)
            return Format.JSON
        except ValueError:
            # Could be JSONL (one object per line) — fall through to line check
            pass

    first_line = text.splitlines()[0] if text.splitlines() else ""

    # JSONL: first non-empty line is a JSON object
    if first_line.strip().startswith(("{", "[")):
        try:
            json.loads(first_line)
            return Format.JSONL
        except ValueError:
            pass

    # CSV: comma/semicolon/tab delimited with a header-ish first line
    if _looks_like_delimited(first_line):
        return Format.CSV

    # Otherwise treat as free text / log
    if first_line:
        return Format.TEXT_LOG

    return Format.UNKNOWN


def _looks_like_delimited(line: str) -> bool:
    if not line:
        return False
    for delim in (",", "\t", ";"):
        if line.count(delim) >= 2:
            return True
    return False
