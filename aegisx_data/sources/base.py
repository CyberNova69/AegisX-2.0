"""Abstract base class for external dataset sources.

All connectors inherit from DatasetSource and implement:
  - discover(): find available files/URLs
  - download(): fetch and cache data locally
  - parse(): yield DatasetRecord instances
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..core.types import DatasetRecord, DatasetSourceType


class DatasetSource(ABC):
    """Abstract base for external cybersecurity dataset connectors.

    Subclasses must implement parse() at minimum. download() and discover()
    are optional for sources that work from local files.
    """

    source_type: DatasetSourceType = DatasetSourceType.CUSTOM_CSV
    description: str = "Unknown dataset source"

    def __init__(self, cache_dir: Optional[Path] = None, **kwargs):
        self.cache_dir = cache_dir or Path("datasets/external/cache")
        self.extra_config = kwargs

    @abstractmethod
    def parse(self, path: Path, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        """Parse records from a local file/directory.

        Args:
            path: Local file or directory path
            limit: Maximum records to yield (None = all)

        Yields:
            DatasetRecord instances
        """
        ...

    def discover(self) -> List[Dict[str, Any]]:
        """Discover available files or URLs for this source.

        Returns a list of dicts with at least {"name", "url"} or {"name", "path"}.
        Default implementation returns an empty list (local-only sources).
        """
        return []

    def download(self, url: str, dest: Optional[Path] = None) -> Path:
        """Download a file from a URL to the cache directory.

        Args:
            url: URL to download from
            dest: Destination path (default: cache_dir/filename)

        Returns:
            Path to the downloaded file
        """
        import urllib.request

        if dest is None:
            filename = url.split("/")[-1].split("?")[0]
            dest = self.cache_dir / filename

        dest.parent.mkdir(parents=True, exist_ok=True)

        if dest.exists():
            print(f"  [CACHE HIT] {dest.name}")
            return dest

        print(f"  Downloading: {url}")
        print(f"  Destination: {dest}")
        urllib.request.urlretrieve(url, str(dest))
        print(f"  Downloaded: {dest.stat().st_size / 1024 / 1024:.1f} MB")
        return dest

    def validate_checksum(self, path: Path, expected_hash: str,
                          algorithm: str = "sha256") -> bool:
        """Validate file checksum."""
        h = hashlib.new(algorithm)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        actual = h.hexdigest()
        return actual.lower() == expected_hash.lower()

    def _make_record_id(self, source_file: str, index: int) -> str:
        """Generate a deterministic record ID."""
        stem = Path(source_file).stem
        return f"{self.source_type.value}-{stem}-{index:08d}"

    def info(self) -> Dict[str, Any]:
        """Return source metadata."""
        return {
            "source_type": self.source_type.value,
            "description": self.description,
            "cache_dir": str(self.cache_dir),
        }


class LocalFileSource(DatasetSource):
    """Base class for sources that read from local files only (no download)."""

    def discover(self) -> List[Dict[str, Any]]:
        """Discover local files in the cache directory."""
        files = []
        if self.cache_dir.exists():
            for f in sorted(self.cache_dir.iterdir()):
                if f.is_file() and f.suffix in (".csv", ".jsonl", ".json", ".txt"):
                    files.append({
                        "name": f.name,
                        "path": str(f),
                        "size_bytes": f.stat().st_size,
                    })
        return files
