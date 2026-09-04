"""Base parser interface.

Parsers yield raw records as dicts. Canonicalization happens later in the
pipeline, keeping parsers dumb and composable. Parsers that can stream (JSONL,
CSV, logs, XML) set `streaming = True`; JSON requires loading the whole document.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, Optional

from ..types import Format


class BaseParser(ABC):
    format: Format = Format.UNKNOWN
    streaming: bool = False

    @abstractmethod
    def parse(self, path: str, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Yield raw records from `path`. Honors `limit` (None = unlimited)."""
        raise NotImplementedError


class MissingDependencyError(RuntimeError):
    """Raised when a parser needs an optional third-party package."""

    def __init__(self, fmt: str, package: str):
        super().__init__(
            f"{fmt} parsing requires the '{package}' package, which is not installed. "
            f"Install it (pip install {package}) or convert the source to a supported "
            f"format (csv/json/jsonl/xml/text)."
        )
        self.format = fmt
        self.package = package
