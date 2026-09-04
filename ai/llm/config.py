"""
AegisX LLM Configuration Loader
================================

Loads configuration settings from configs/model.yaml and integrates
environment variables from .env / os.environ.
Strictly separates non-secret configuration from credentials.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from ai.llm.exceptions import LLMConfigurationError

@dataclass
class LLMConfig:
    """Consolidated configuration for the LLM interface."""
    provider_name: str = "mock"
    model_name: str = "mock-soc-analyst-v1"
    temperature: float = 0.2
    max_tokens: int = 1024
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    api_base_url: str = "https://api.openai.com/v1"
    api_key: Optional[str] = None

    @classmethod
    def load(cls, project_root: Optional[Path] = None) -> "LLMConfig":
        """
        Load configuration from project configs/model.yaml and .env file.
        Environment variables take precedence over yaml settings.
        """
        if project_root is None:
            project_root = Path(__file__).resolve().parent.parent.parent

        # 1. Parse .env file if present
        env_file = project_root / ".env"
        if env_file.exists():
            cls._load_env_file(env_file)

        # 2. Parse configs/model.yaml
        yaml_config = cls._load_yaml_config(project_root / "configs" / "model.yaml")

        # 3. Read settings (env vars > yaml > defaults)
        provider_name = os.environ.get("LLM_PROVIDER") or yaml_config.get("provider", {}).get("name", "mock")
        model_name = os.environ.get("LLM_MODEL") or yaml_config.get("model", {}).get("name", "mock-soc-analyst-v1")

        gen_cfg = yaml_config.get("generation", {})
        temperature = float(gen_cfg.get("temperature", 0.2))
        max_tokens = int(gen_cfg.get("max_tokens", 1024))
        timeout = float(gen_cfg.get("timeout", 30.0))
        max_retries = int(gen_cfg.get("max_retries", 3))
        retry_delay = float(gen_cfg.get("retry_delay", 1.0))

        api_cfg = yaml_config.get("api", {})
        api_base_url = os.environ.get("LLM_API_BASE") or api_cfg.get("base_url", "https://api.openai.com/v1")
        api_key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")

        # Validate settings
        cfg = cls(
            provider_name=provider_name,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            api_base_url=api_base_url,
            api_key=api_key,
        )
        cfg.validate()
        return cfg

    def validate(self):
        """Validate configuration sanity."""
        if not self.provider_name or not isinstance(self.provider_name, str):
            raise LLMConfigurationError("provider_name must be a non-empty string.")
        if not self.model_name or not isinstance(self.model_name, str):
            raise LLMConfigurationError("model_name must be a non-empty string.")
        if not (0.0 <= self.temperature <= 2.0):
            raise LLMConfigurationError(f"temperature {self.temperature} must be between 0.0 and 2.0.")
        if self.max_tokens <= 0:
            raise LLMConfigurationError(f"max_tokens {self.max_tokens} must be positive.")
        if self.timeout <= 0:
            raise LLMConfigurationError(f"timeout {self.timeout} must be positive.")
        if self.max_retries < 0:
            raise LLMConfigurationError(f"max_retries {self.max_retries} cannot be negative.")

    @staticmethod
    def _load_env_file(env_path: Path):
        """Simple stdlib .env line parser."""
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip().strip("'\"")
                        if key and key not in os.environ:
                            os.environ[key] = val
        except Exception:
            pass

    @staticmethod
    def _load_yaml_config(yaml_path: Path) -> Dict[str, Any]:
        """Simple stdlib parser for basic YAML key-value sections or PyYAML fallback."""
        if not yaml_path.exists():
            return {}
        try:
            import yaml
            with open(yaml_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            # Fallback simple line reader if PyYAML not installed
            data: Dict[str, Any] = {}
            curr_section = None
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if ":" in line and not line.startswith("-"):
                            k, v = line.split(":", 1)
                            k = k.strip()
                            v = v.split("#")[0].strip().strip("'\"")
                            if not v and not line.endswith(":"):
                                continue
                            if not v:
                                curr_section = k
                                data[curr_section] = {}
                            else:
                                if curr_section:
                                    data[curr_section][k] = v
                                else:
                                    data[k] = v
            except Exception:
                pass
            return data
