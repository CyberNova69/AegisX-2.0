"""Filesystem-based dataset version manager.

Each version is an immutable snapshot directory:
    datasets/external/v1.0/
    ├── manifest.json
    ├── data.jsonl
    └── quality_report.json
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.types import DatasetRecord
from .manifest import VersionManifest


class VersionManager:
    """Manage dataset version snapshots on the filesystem.

    Versions are stored as: <base_dir>/v<version>/
    """

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _version_dir(self, version: str) -> Path:
        """Get the directory path for a version."""
        return self.base_dir / f"v{version}"

    def create_version(
        self,
        version: str,
        records: List[DatasetRecord],
        sources: Optional[List[str]] = None,
        processing_config: Optional[Dict[str, Any]] = None,
        quality_score: Optional[float] = None,
        description: str = "",
        parent_version: Optional[str] = None,
    ) -> VersionManifest:
        """Create a new immutable dataset version.

        Args:
            version: Version string (e.g. "1.0", "2.1")
            records: Processed records to snapshot
            sources: List of source dataset names
            processing_config: Pipeline config used
            quality_score: Quality analysis score
            description: Human-readable description
            parent_version: Previous version this was derived from

        Returns:
            VersionManifest for the created version

        Raises:
            ValueError if version already exists
        """
        version_dir = self._version_dir(version)
        if version_dir.exists():
            raise ValueError(f"Version {version} already exists at {version_dir}")

        version_dir.mkdir(parents=True)

        # Write data file
        data_path = version_dir / "data.jsonl"
        with open(data_path, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

        # Compute file hash
        data_hash = self._compute_hash(data_path)

        # Compute class distribution
        class_dist: Dict[str, int] = {}
        for r in records:
            cls = r.classification.value if r.classification else "unlabeled"
            class_dist[cls] = class_dist.get(cls, 0) + 1

        # Create manifest
        manifest = VersionManifest(
            version=version,
            sources=sources or [],
            record_count=len(records),
            class_distribution=class_dist,
            quality_score=quality_score,
            file_hashes={"data.jsonl": data_hash},
            processing_config=processing_config or {},
            description=description,
            parent_version=parent_version,
        )

        manifest.save(version_dir / "manifest.json")
        return manifest

    def load_version(self, version: str) -> tuple[List[DatasetRecord], VersionManifest]:
        """Load records and manifest from a version."""
        version_dir = self._version_dir(version)
        if not version_dir.exists():
            raise FileNotFoundError(f"Version {version} not found at {version_dir}")

        manifest = VersionManifest.load(version_dir / "manifest.json")
        records = self._load_records(version_dir / "data.jsonl")

        return records, manifest

    def list_versions(self) -> List[VersionManifest]:
        """List all available versions sorted by creation time."""
        manifests = []
        if self.base_dir.exists():
            for d in sorted(self.base_dir.iterdir()):
                if d.is_dir() and d.name.startswith("v"):
                    manifest_path = d / "manifest.json"
                    if manifest_path.exists():
                        manifests.append(VersionManifest.load(manifest_path))
        return manifests

    def get_latest_version(self) -> Optional[str]:
        """Get the latest version string."""
        versions = self.list_versions()
        if not versions:
            return None
        return versions[-1].version

    def delete_version(self, version: str) -> None:
        """Delete a version snapshot."""
        version_dir = self._version_dir(version)
        if version_dir.exists():
            shutil.rmtree(version_dir)

    def verify_integrity(self, version: str) -> Dict[str, bool]:
        """Verify file hashes for a version."""
        version_dir = self._version_dir(version)
        manifest = VersionManifest.load(version_dir / "manifest.json")

        results = {}
        for filename, expected_hash in manifest.file_hashes.items():
            filepath = version_dir / filename
            if filepath.exists():
                actual_hash = self._compute_hash(filepath)
                results[filename] = actual_hash == expected_hash
            else:
                results[filename] = False

        return results

    def diff_versions(self, version_a: str, version_b: str) -> Dict[str, Any]:
        """Compute diff between two versions."""
        records_a, manifest_a = self.load_version(version_a)
        records_b, manifest_b = self.load_version(version_b)

        ids_a = {r.record_id for r in records_a}
        ids_b = {r.record_id for r in records_b}

        return {
            "version_a": version_a,
            "version_b": version_b,
            "records_a": len(records_a),
            "records_b": len(records_b),
            "added": len(ids_b - ids_a),
            "removed": len(ids_a - ids_b),
            "common": len(ids_a & ids_b),
            "class_dist_a": manifest_a.class_distribution,
            "class_dist_b": manifest_b.class_distribution,
        }

    def _load_records(self, path: Path) -> List[DatasetRecord]:
        """Load records from a JSONL file."""
        records = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    records.append(DatasetRecord.from_dict(data))
        return records

    @staticmethod
    def _compute_hash(path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
