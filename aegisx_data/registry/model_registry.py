"""Local model registry.

Tracks trained model artifacts with metadata, evaluation metrics,
and lifecycle state. Stored as models/registry.json.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.types import ModelArtifact, ModelLifecycle


class ModelRegistry:
    """Local filesystem-based model registry."""

    def __init__(self, registry_path: Path):
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._registry: Dict[str, ModelArtifact] = {}
        self._load()

    def _load(self) -> None:
        """Load registry from disk."""
        if self.registry_path.exists():
            with open(self.registry_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for model_id, model_data in data.get("models", {}).items():
                self._registry[model_id] = ModelArtifact.from_dict(model_data)

    def _save(self) -> None:
        """Persist registry to disk."""
        data = {
            "schema_version": "1.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "models": {
                model_id: artifact.to_dict()
                for model_id, artifact in self._registry.items()
            },
        }
        with open(self.registry_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def register(
        self,
        run_id: str,
        base_model: str,
        adapter_path: str,
        dataset_version: str = "",
        eval_metrics: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, str]] = None,
        description: str = "",
        model_id: Optional[str] = None,
    ) -> ModelArtifact:
        """Register a trained model artifact."""
        if model_id is None:
            short_id = uuid.uuid4().hex[:8]
            model_id = f"aegisx-{short_id}"

        artifact = ModelArtifact(
            model_id=model_id,
            run_id=run_id,
            base_model=base_model,
            lifecycle=ModelLifecycle.TRAINED,
            dataset_version=dataset_version,
            adapter_path=adapter_path,
            eval_metrics=eval_metrics or {},
            tags=tags or {},
            description=description,
        )

        self._registry[model_id] = artifact
        self._save()
        return artifact

    def get(self, model_id: str) -> Optional[ModelArtifact]:
        """Get a model by ID."""
        return self._registry.get(model_id)

    def list_models(
        self,
        lifecycle: Optional[ModelLifecycle] = None,
    ) -> List[ModelArtifact]:
        """List all registered models, optionally filtered by lifecycle."""
        models = list(self._registry.values())
        if lifecycle:
            models = [m for m in models if m.lifecycle == lifecycle]
        return sorted(models, key=lambda m: m.registered_at)

    def promote(self, model_id: str) -> ModelArtifact:
        """Promote a model to PROMOTED status (current best)."""
        artifact = self._registry.get(model_id)
        if not artifact:
            raise KeyError(f"Model not found: {model_id}")

        # Demote any previously promoted models
        for other in self._registry.values():
            if other.lifecycle == ModelLifecycle.PROMOTED and other.model_id != model_id:
                other.lifecycle = ModelLifecycle.EVALUATED

        artifact.lifecycle = ModelLifecycle.PROMOTED
        self._save()
        return artifact

    def deprecate(self, model_id: str) -> ModelArtifact:
        """Deprecate a model."""
        artifact = self._registry.get(model_id)
        if not artifact:
            raise KeyError(f"Model not found: {model_id}")

        artifact.lifecycle = ModelLifecycle.DEPRECATED
        self._save()
        return artifact

    def update_metrics(
        self,
        model_id: str,
        metrics: Dict[str, Any],
    ) -> ModelArtifact:
        """Update evaluation metrics for a model."""
        artifact = self._registry.get(model_id)
        if not artifact:
            raise KeyError(f"Model not found: {model_id}")

        artifact.eval_metrics.update(metrics)
        if artifact.lifecycle == ModelLifecycle.TRAINED:
            artifact.lifecycle = ModelLifecycle.EVALUATED
        self._save()
        return artifact

    def get_promoted(self) -> Optional[ModelArtifact]:
        """Get the currently promoted (best) model."""
        for artifact in self._registry.values():
            if artifact.lifecycle == ModelLifecycle.PROMOTED:
                return artifact
        return None

    def delete(self, model_id: str) -> None:
        """Remove a model from the registry."""
        if model_id in self._registry:
            del self._registry[model_id]
            self._save()
