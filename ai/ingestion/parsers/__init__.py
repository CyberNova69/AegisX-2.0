"""Parser registry. Maps Format -> parser class. Optional-dependency parsers are
imported lazily so the core (stdlib) ingestion layer imports cleanly without them.
"""

from __future__ import annotations

from typing import Dict, Optional, Type

from ..types import Format
from .base import BaseParser


_REGISTRY: Dict[Format, Type[BaseParser]] = {}


def _build() -> None:
    from .csv_parser import CsvParser
    from .json_parser import JsonParser
    from .jsonl_parser import JsonlParser
    from .xml_parser import XmlParser
    from .text_parser import TextLogParser
    from .excel_parser import ExcelParser
    from .parquet_parser import ParquetParser

    _REGISTRY[Format.CSV] = CsvParser
    _REGISTRY[Format.JSON] = JsonParser
    _REGISTRY[Format.JSONL] = JsonlParser
    _REGISTRY[Format.XML] = XmlParser
    _REGISTRY[Format.TEXT_LOG] = TextLogParser
    _REGISTRY[Format.EXCEL] = ExcelParser
    _REGISTRY[Format.PARQUET] = ParquetParser


def get_parser(fmt: Format) -> Optional[BaseParser]:
    """Return an instance of the parser for `fmt`, or None if unsupported."""
    if not _REGISTRY:
        _build()
    cls = _REGISTRY.get(fmt)
    return cls() if cls else None


def supported_formats() -> list:
    if not _REGISTRY:
        _build()
    return list(_REGISTRY.keys())
