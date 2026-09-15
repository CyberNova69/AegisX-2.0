"""Model artifact storage management."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, Optional


class ArtifactManager:
    """Manage model artifact storage on the filesystem.

    Organized as: models/<run_id>/
        ├── adapter/           (LoRA weights + tokenizer)
        ├── training_metadata.json
        └── eval_report.json
    """

    def __init__(self, models_dir: Path):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)

    def get_artifact_dir(self, run_id: str) -> Path:
        """Get the artifact directory for a run."""
        return self.models_dir / run_id

    def save_metadata(self, run_id: str, metadata: Dict[str, Any]) -> Path:
        """Save training metadata for a run."""
        artifact_dir = self.get_artifact_dir(run_id)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / "training_metadata.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        return path

    def save_eval_report(self, run_id: str, report: Dict[str, Any]) -> Path:
        """Save evaluation report for a run."""
        artifact_dir = self.get_artifact_dir(run_id)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / "eval_report.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return path

    def load_metadata(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Load training metadata for a run."""
        path = self.get_artifact_dir(run_id) / "training_metadata.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def list_artifacts(self) -> list:
        """List all artifact directories."""
        artifacts = []
        if self.models_dir.exists():
            for d in sorted(self.models_dir.iterdir()):
                if d.is_dir():
                    has_adapter = (d / "adapter").exists()
                    has_metadata = (d / "training_metadata.json").exists()
                    artifacts.append({
                        "run_id": d.name,
                        "has_adapter": has_adapter,
                        "has_metadata": has_metadata,
                        "path": str(d),
                    })
        return artifacts

    def delete_artifact(self, run_id: str) -> None:
        """Delete all artifacts for a run."""
        artifact_dir = self.get_artifact_dir(run_id)
        if artifact_dir.exists():
            shutil.rmtree(artifact_dir)
