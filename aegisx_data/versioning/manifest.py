"""Version manifest: metadata for a dataset version snapshot."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class VersionManifest:
    """Immutable manifest describing a dataset version snapshot.

    Stored as manifest.json in the version directory.
    """

    def __init__(
        self,
        version: str,
        created_at: Optional[str] = None,
        sources: Optional[List[str]] = None,
        record_count: int = 0,
        class_distribution: Optional[Dict[str, int]] = None,
        quality_score: Optional[float] = None,
        file_hashes: Optional[Dict[str, str]] = None,
        processing_config: Optional[Dict[str, Any]] = None,
        description: str = "",
        parent_version: Optional[str] = None,
    ):
        self.version = version
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.sources = sources or []
        self.record_count = record_count
        self.class_distribution = class_distribution or {}
        self.quality_score = quality_score
        self.file_hashes = file_hashes or {}
        self.processing_config = processing_config or {}
        self.description = description
        self.parent_version = parent_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "sources": self.sources,
            "record_count": self.record_count,
            "class_distribution": self.class_distribution,
            "quality_score": self.quality_score,
            "file_hashes": self.file_hashes,
            "processing_config": self.processing_config,
            "description": self.description,
            "parent_version": self.parent_version,
            "schema_version": "1.0",
        }

    def save(self, path: Path) -> None:
        """Save manifest to file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Path) -> "VersionManifest":
        """Load manifest from file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            version=data["version"],
            created_at=data.get("created_at"),
            sources=data.get("sources", []),
            record_count=data.get("record_count", 0),
            class_distribution=data.get("class_distribution", {}),
            quality_score=data.get("quality_score"),
            file_hashes=data.get("file_hashes", {}),
            processing_config=data.get("processing_config", {}),
            description=data.get("description", ""),
            parent_version=data.get("parent_version"),
        )
