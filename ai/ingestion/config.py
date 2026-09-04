"""Ingestion configuration loader.

Reads `ai/ingestion/config.yaml`. Uses a minimal built-in parser (flat key: value
with `#` comments) so the layer stays dependency-free. If pyyaml is available it is
used instead; either way the public API is the same.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

_DEFAULTS: Dict[str, Any] = {
    "recursive": True,
    "max_records": None,
    "limit_per_file": None,
    "enabled_formats": [
        "csv", "json", "jsonl", "xml", "text_log", "excel", "parquet",
    ],
}

_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


def load_config(path: str | Path | None = None) -> Dict[str, Any]:
    cfg = dict(_DEFAULTS)
    p = Path(path) if path else _CONFIG_PATH
    if not p.exists():
        return cfg
    text = p.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text) or {}
        cfg.update(data)
        return cfg
    except ImportError:
        pass
    # Minimal fallback parser (flat key: value only).
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        cfg[key.strip()] = _coerce(val.strip())
    return cfg


def _coerce(v: str) -> Any:
    if v.lower() in ("true", "yes"):
        return True
    if v.lower() in ("false", "no", "null", "none"):
        return False if v.lower() in ("false", "no") else None
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [x.strip() for x in inner.split(",") if x.strip()] or None
    try:
        return int(v)
    except ValueError:
        return v
