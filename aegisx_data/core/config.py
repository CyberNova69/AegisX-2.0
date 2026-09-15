"""Configuration loader for the AegisX Data Platform.

Reads configs/data_platform.yaml with environment variable overrides.
Falls back to built-in defaults when the config file is absent.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "data_platform.yaml"


# ---------------------------------------------------------------------------
# Configuration dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SourceConfig:
    """Configuration for a single dataset source."""
    name: str = ""
    url: str = ""
    cache_dir: str = ""
    enabled: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessingConfig:
    """Configuration for the processing pipeline."""
    dedup_strategy: str = "exact"  # exact | near
    validation_strict: bool = True
    mitre_mapping: bool = True
    geo_ip: bool = False
    max_dedup_window: Optional[int] = None


@dataclass
class SFTConfig:
    """Configuration for SFT dataset generation."""
    train_ratio: float = 0.8
    val_ratio: float = 0.1
    test_ratio: float = 0.1
    max_examples: Optional[int] = None
    balance_strategy: str = "oversample_minority"  # none | oversample_minority | undersample_majority
    seed: int = 42
    protected_test_path: Optional[str] = "datasets/finetuning/v1.0/test.jsonl"  # Test firewall


@dataclass
class TrainingConfig:
    """Configuration for training runs (extends finetuning/config.yaml)."""
    inherit_from: str = "finetuning/config.yaml"
    model_name: str = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
    method: str = "qlora"
    epochs: int = 3
    learning_rate: float = 2e-4
    batch_size: int = 4
    seed: int = 42


@dataclass
class OutputConfig:
    """Configuration for output paths."""
    base_dir: str = "datasets/external"
    models_dir: str = "models"
    reports_dir: str = "reports/data_platform"
    registry_file: str = "models/registry.json"
    runs_dir: str = "runs"


@dataclass
class PlatformConfig:
    """Master configuration for the AegisX Data Platform."""
    sources: Dict[str, SourceConfig] = field(default_factory=dict)
    processing: ProcessingConfig = field(default_factory=ProcessingConfig)
    sft: SFTConfig = field(default_factory=SFTConfig)
    training: TrainingConfig = field(default_factory=TrainingConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    label_maps_dir: str = "configs/label_maps"
    project_root: Path = field(default_factory=lambda: PROJECT_ROOT)

    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a relative path against the project root."""
        p = Path(relative_path)
        if p.is_absolute():
            return p
        return self.project_root / p

    def get_base_dir(self) -> Path:
        """Resolved base directory for external datasets."""
        return self.resolve_path(self.output.base_dir)

    def get_models_dir(self) -> Path:
        """Resolved models directory."""
        return self.resolve_path(self.output.models_dir)

    def get_reports_dir(self) -> Path:
        """Resolved reports directory."""
        return self.resolve_path(self.output.reports_dir)

    def get_runs_dir(self) -> Path:
        """Resolved training runs directory."""
        return self.resolve_path(self.output.runs_dir)


# ---------------------------------------------------------------------------
# YAML Loader
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file. Uses PyYAML if available, otherwise basic parsing."""
    if not path.exists():
        return {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        return _basic_yaml_parse(path)


def _basic_yaml_parse(path: Path) -> Dict[str, Any]:
    """Minimal YAML parser for simple configs without PyYAML dependency."""
    config: Dict[str, Any] = {}
    current_section: Optional[str] = None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.rstrip()
            if not stripped or stripped.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            content = stripped.lstrip()

            if ":" in content:
                key, _, value = content.partition(":")
                key = key.strip()
                value = value.strip()
                # Remove inline comments
                if " #" in value:
                    value = value[:value.index(" #")].strip()

                if indent == 0:
                    if not value:
                        current_section = key
                        config[key] = {}
                    else:
                        config[key] = _parse_yaml_value(value)
                elif current_section:
                    config[current_section][key] = _parse_yaml_value(value)

    return config


def _parse_yaml_value(value: str) -> Any:
    """Parse a YAML scalar value."""
    if not value:
        return None
    if value.lower() in ("null", "none", "~"):
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


# ---------------------------------------------------------------------------
# Config Construction
# ---------------------------------------------------------------------------

def _build_source_configs(raw: Dict[str, Any]) -> Dict[str, SourceConfig]:
    """Build SourceConfig objects from raw YAML data."""
    sources = {}
    raw_sources = raw.get("sources", {})
    if isinstance(raw_sources, dict):
        for name, cfg in raw_sources.items():
            if isinstance(cfg, dict):
                sources[name] = SourceConfig(
                    name=name,
                    url=cfg.get("url", ""),
                    cache_dir=cfg.get("cache_dir", f"datasets/external/cache/{name}"),
                    enabled=cfg.get("enabled", True),
                    extra={k: v for k, v in cfg.items()
                           if k not in ("url", "cache_dir", "enabled", "name")},
                )
    return sources


def load_config(config_path: Optional[Path] = None) -> PlatformConfig:
    """Load the platform configuration.

    Priority: environment variables > config file > defaults.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    raw = _load_yaml(config_path)

    # Build sub-configs
    sources = _build_source_configs(raw)

    proc_raw = raw.get("processing", {})
    processing = ProcessingConfig(
        dedup_strategy=proc_raw.get("dedup_strategy", "exact"),
        validation_strict=proc_raw.get("validation_strict", True),
        mitre_mapping=proc_raw.get("enrichment", {}).get("mitre_mapping", True)
            if isinstance(proc_raw.get("enrichment"), dict)
            else proc_raw.get("mitre_mapping", True),
        geo_ip=proc_raw.get("enrichment", {}).get("geo_ip", False)
            if isinstance(proc_raw.get("enrichment"), dict)
            else proc_raw.get("geo_ip", False),
    )

    sft_raw = raw.get("sft", {})
    sft = SFTConfig(
        train_ratio=float(sft_raw.get("train_ratio", 0.8)),
        val_ratio=float(sft_raw.get("val_ratio", 0.1)),
        test_ratio=float(sft_raw.get("test_ratio", 0.1)),
        max_examples=sft_raw.get("max_examples"),
        balance_strategy=sft_raw.get("balance_strategy", "oversample_minority"),
        seed=int(sft_raw.get("seed", 42)),
        protected_test_path=sft_raw.get("protected_test_path", "datasets/finetuning/v1.0/test.jsonl"),
    )

    train_raw = raw.get("training", {})
    training = TrainingConfig(
        inherit_from=train_raw.get("inherit_from", "finetuning/config.yaml"),
        model_name=train_raw.get("model_name", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"),
        method=train_raw.get("method", "qlora"),
        epochs=int(train_raw.get("epochs", 3)),
        learning_rate=float(train_raw.get("learning_rate", 2e-4)),
        batch_size=int(train_raw.get("batch_size", 4)),
        seed=int(train_raw.get("seed", 42)),
    )

    out_raw = raw.get("output", {})
    output = OutputConfig(
        base_dir=out_raw.get("base_dir", "datasets/external"),
        models_dir=out_raw.get("models_dir", "models"),
        reports_dir=out_raw.get("reports_dir", "reports/data_platform"),
        registry_file=out_raw.get("registry_file", "models/registry.json"),
        runs_dir=out_raw.get("runs_dir", "runs"),
    )

    # Apply environment variable overrides
    env_model = os.environ.get("AEGISX_MODEL_NAME")
    if env_model:
        training.model_name = env_model

    env_base_dir = os.environ.get("AEGISX_DATA_DIR")
    if env_base_dir:
        output.base_dir = env_base_dir

    return PlatformConfig(
        sources=sources,
        processing=processing,
        sft=sft,
        training=training,
        output=output,
        label_maps_dir=raw.get("label_maps_dir", "configs/label_maps"),
        project_root=PROJECT_ROOT,
    )
