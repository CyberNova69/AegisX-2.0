"""Training launcher wrapping the existing finetuning/train_lora.py."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..core.types import RunStatus
from .run_manager import RunManager

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class TrainingLauncher:
    """Launch and manage training runs.

    Wraps the existing finetuning/train_lora.py for actual training
    while managing run lifecycle through RunManager.
    """

    def __init__(self, run_manager: RunManager):
        self.run_manager = run_manager

    def launch(
        self,
        dataset_version: str,
        sft_dir: Path,
        model_name: Optional[str] = None,
        config_overrides: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> str:
        """Launch a training run.

        Args:
            dataset_version: Dataset version used for training
            sft_dir: Directory containing SFT JSONL files
            model_name: Model name override
            config_overrides: Training config overrides
            dry_run: If True, validate only without training

        Returns:
            run_id of the created run
        """
        # Load base config
        config = self._load_training_config()
        if model_name:
            config.setdefault("model", {})["name"] = model_name
        if config_overrides:
            for key, value in config_overrides.items():
                if isinstance(value, dict) and key in config:
                    config[key].update(value)
                else:
                    config[key] = value

        # Override dataset paths to use our SFT output
        config.setdefault("dataset", {})["train"] = str(sft_dir / "train.jsonl")
        config["dataset"]["validation"] = str(sft_dir / "validation.jsonl")

        base_model = config.get("model", {}).get("name", "unknown")

        # Create run
        run = self.run_manager.create_run(
            dataset_version=dataset_version,
            base_model=base_model,
            config=config,
        )

        if dry_run:
            print(f"  [DRY RUN] Run created: {run.run_id}")
            print(f"  Model: {base_model}")
            print(f"  Dataset: {dataset_version}")
            print(f"  SFT dir: {sft_dir}")

            # Validate paths
            train_path = sft_dir / "train.jsonl"
            val_path = sft_dir / "validation.jsonl"

            for p in [train_path, val_path]:
                exists = p.exists()
                count = 0
                if exists:
                    with open(p, "r") as f:
                        count = sum(1 for line in f if line.strip())
                status = "OK" if exists else "MISSING"
                print(f"  {p.name}: [{status}] {count} records")

            return run.run_id

        # Launch actual training
        self.run_manager.start_run(run.run_id)

        try:
            self._run_training(run.run_id, config)
        except Exception as e:
            self.run_manager.fail_run(run.run_id, str(e))
            raise

        return run.run_id

    def _load_training_config(self) -> Dict[str, Any]:
        """Load the base training config from finetuning/config.yaml."""
        config_path = PROJECT_ROOT / "finetuning" / "config.yaml"
        try:
            sys.path.insert(0, str(PROJECT_ROOT))
            from finetuning.train_lora import load_config
            return load_config(config_path)
        except ImportError:
            # Fallback: load YAML directly
            from ..core.config import _load_yaml
            return _load_yaml(config_path)

    def _run_training(self, run_id: str, config: Dict[str, Any]) -> None:
        """Execute the training using the existing train_lora module."""
        try:
            sys.path.insert(0, str(PROJECT_ROOT))
            from finetuning.train_lora import train
            train(config, PROJECT_ROOT)

            # Extract adapter path from config
            output_dir = config.get("output", {}).get("directory", "models/aegisx-triage")
            adapter_path = str(PROJECT_ROOT / output_dir / "adapter")

            self.run_manager.complete_run(
                run_id,
                adapter_path=adapter_path,
            )
        except Exception as e:
            self.run_manager.fail_run(run_id, str(e))
            raise
