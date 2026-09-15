"""Tests for the model registry."""

import pytest
from pathlib import Path
from aegisx_data.registry.model_registry import ModelRegistry
from aegisx_data.core.types import ModelLifecycle


class TestModelRegistry:
    def test_register(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        artifact = registry.register(
            run_id="run-001",
            base_model="qwen2.5-7b",
            adapter_path="models/run-001/adapter",
            model_id="model-001",
        )
        assert artifact.model_id == "model-001"
        assert artifact.lifecycle == ModelLifecycle.TRAINED

    def test_list_models(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        registry.register("run1", "qwen", "path1", model_id="m1")
        registry.register("run2", "llama", "path2", model_id="m2")

        models = registry.list_models()
        assert len(models) == 2

    def test_promote(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        registry.register("run1", "qwen", "path1", model_id="m1")
        registry.register("run2", "qwen", "path2", model_id="m2")

        artifact = registry.promote("m1")
        assert artifact.lifecycle == ModelLifecycle.PROMOTED

        promoted = registry.get_promoted()
        assert promoted.model_id == "m1"

    def test_promote_demotes_previous(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        registry.register("run1", "qwen", "path1", model_id="m1")
        registry.register("run2", "qwen", "path2", model_id="m2")

        registry.promote("m1")
        registry.promote("m2")

        m1 = registry.get("m1")
        m2 = registry.get("m2")
        assert m1.lifecycle != ModelLifecycle.PROMOTED
        assert m2.lifecycle == ModelLifecycle.PROMOTED

    def test_deprecate(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        registry.register("run1", "qwen", "path1", model_id="m1")
        registry.deprecate("m1")

        m1 = registry.get("m1")
        assert m1.lifecycle == ModelLifecycle.DEPRECATED

    def test_update_metrics(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        registry.register("run1", "qwen", "path1", model_id="m1")
        registry.update_metrics("m1", {"accuracy": 0.9, "f1": 0.85})

        m1 = registry.get("m1")
        assert m1.eval_metrics["accuracy"] == 0.9
        assert m1.lifecycle == ModelLifecycle.EVALUATED

    def test_persistence(self, tmp_path):
        path = tmp_path / "registry.json"
        registry1 = ModelRegistry(path)
        registry1.register("run1", "qwen", "path1", model_id="m1")

        # Reload
        registry2 = ModelRegistry(path)
        m1 = registry2.get("m1")
        assert m1 is not None
        assert m1.model_id == "m1"

    def test_delete(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        registry.register("run1", "qwen", "path1", model_id="m1")
        registry.delete("m1")
        assert registry.get("m1") is None

    def test_nonexistent_raises(self, tmp_path):
        registry = ModelRegistry(tmp_path / "registry.json")
        with pytest.raises(KeyError):
            registry.promote("nonexistent")
