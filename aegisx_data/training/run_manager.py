"""Training run lifecycle management.

Manages creation, tracking, and comparison of training runs.
Each run is stored as a directory under runs/<run_id>/.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.types import RunStatus, TrainingRun


class RunManager:
    """Manage training run lifecycle and metadata."""

    def __init__(self, runs_dir: Path):
        self.runs_dir = Path(runs_dir)
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def _run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def create_run(
        self,
        dataset_version: str,
        base_model: str,
        config: Optional[Dict[str, Any]] = None,
        run_id: Optional[str] = None,
    ) -> TrainingRun:
        """Create a new training run."""
        if run_id is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            short_id = uuid.uuid4().hex[:8]
            run_id = f"run_{timestamp}_{short_id}"

        run = TrainingRun(
            run_id=run_id,
            status=RunStatus.PENDING,
            dataset_version=dataset_version,
            base_model=base_model,
            config=config or {},
        )

        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        self._save_run(run)

        return run

    def start_run(self, run_id: str) -> TrainingRun:
        """Mark a run as RUNNING."""
        run = self.get_run(run_id)
        run.status = RunStatus.RUNNING
        run.started_at = datetime.now(timezone.utc).isoformat()
        self._save_run(run)
        return run

    def complete_run(
        self,
        run_id: str,
        metrics: Optional[Dict[str, Any]] = None,
        adapter_path: Optional[str] = None,
    ) -> TrainingRun:
        """Mark a run as COMPLETED."""
        run = self.get_run(run_id)
        run.status = RunStatus.COMPLETED
        run.completed_at = datetime.now(timezone.utc).isoformat()
        if metrics:
            run.metrics.update(metrics)
        if adapter_path:
            run.adapter_path = adapter_path
        self._save_run(run)
        return run

    def fail_run(self, run_id: str, error_message: str) -> TrainingRun:
        """Mark a run as FAILED."""
        run = self.get_run(run_id)
        run.status = RunStatus.FAILED
        run.completed_at = datetime.now(timezone.utc).isoformat()
        run.error_message = error_message
        self._save_run(run)
        return run

    def log_metrics(self, run_id: str, epoch: int, metrics: Dict[str, float]) -> None:
        """Log metrics for an epoch."""
        run = self.get_run(run_id)
        run.metrics[str(epoch)] = metrics
        self._save_run(run)

    def get_run(self, run_id: str) -> TrainingRun:
        """Load a training run by ID."""
        run_file = self._run_dir(run_id) / "run.json"
        if not run_file.exists():
            raise FileNotFoundError(f"Run not found: {run_id}")
        with open(run_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return TrainingRun.from_dict(data)

    def list_runs(self, status: Optional[RunStatus] = None) -> List[TrainingRun]:
        """List all runs, optionally filtered by status."""
        runs = []
        if self.runs_dir.exists():
            for d in sorted(self.runs_dir.iterdir()):
                run_file = d / "run.json"
                if run_file.exists():
                    try:
                        with open(run_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        run = TrainingRun.from_dict(data)
                        if status is None or run.status == status:
                            runs.append(run)
                    except (json.JSONDecodeError, KeyError):
                        continue
        return runs

    def compare_runs(self, run_ids: List[str]) -> Dict[str, Any]:
        """Compare metrics across multiple runs."""
        comparison = {"runs": []}
        for run_id in run_ids:
            try:
                run = self.get_run(run_id)
                comparison["runs"].append({
                    "run_id": run.run_id,
                    "status": run.status.value,
                    "base_model": run.base_model,
                    "dataset_version": run.dataset_version,
                    "metrics": run.metrics,
                })
            except FileNotFoundError:
                comparison["runs"].append({"run_id": run_id, "error": "not found"})
        return comparison

    def delete_run(self, run_id: str) -> None:
        """Delete a training run."""
        import shutil
        run_dir = self._run_dir(run_id)
        if run_dir.exists():
            shutil.rmtree(run_dir)

    def _save_run(self, run: TrainingRun) -> None:
        """Persist run metadata to disk."""
        run_dir = self._run_dir(run.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        with open(run_dir / "run.json", "w", encoding="utf-8") as f:
            json.dump(run.to_dict(), f, indent=2)
