"""Extended GPU preflight wrapping the existing finetuning/gpu_preflight.py.

Adds VRAM estimation for different model sizes and dataset sizes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Import from existing finetuning module
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def run_gpu_check() -> Dict[str, Any]:
    """Run GPU preflight diagnostics.

    Wraps the existing finetuning/gpu_preflight.py and extends with
    VRAM estimation.
    """
    try:
        from finetuning.gpu_preflight import run_preflight
        report = run_preflight()
    except ImportError:
        report = _basic_gpu_check()

    # Add VRAM estimation
    report["vram_estimates"] = estimate_vram_requirements()
    return report


def _basic_gpu_check() -> Dict[str, Any]:
    """Basic GPU check without finetuning module."""
    report = {
        "cuda_available": False,
        "gpu_count": 0,
        "gpus": [],
        "verdict": "NO_GPU",
    }

    try:
        import torch
        report["torch_version"] = torch.__version__
        report["cuda_available"] = torch.cuda.is_available()

        if torch.cuda.is_available():
            report["gpu_count"] = torch.cuda.device_count()
            gpus = []
            for i in range(torch.cuda.device_count()):
                name = torch.cuda.get_device_name(i)
                props = torch.cuda.get_device_properties(i)
                vram_gb = props.total_mem / (1024 ** 3)
                gpus.append({
                    "index": i,
                    "name": name,
                    "vram_gb": round(vram_gb, 1),
                })
            report["gpus"] = gpus

            max_vram = max(g["vram_gb"] for g in gpus) if gpus else 0
            if max_vram >= 24:
                report["verdict"] = "EXCELLENT"
            elif max_vram >= 12:
                report["verdict"] = "SUITABLE"
            elif max_vram >= 8:
                report["verdict"] = "POTENTIALLY_SUITABLE"
            else:
                report["verdict"] = "INSUFFICIENT"
    except ImportError:
        report["torch_version"] = None

    return report


def estimate_vram_requirements() -> Dict[str, Dict[str, Any]]:
    """Estimate VRAM requirements for common model configurations.

    Returns model configs with estimated VRAM needs for QLoRA training.
    """
    return {
        "3B_qlora": {
            "model": "Qwen2.5-3B-Instruct",
            "parameters": "3B",
            "min_vram_gb": 6,
            "recommended_vram_gb": 8,
            "method": "QLoRA (4-bit)",
            "batch_size": 4,
        },
        "7B_qlora": {
            "model": "Qwen2.5-7B-Instruct",
            "parameters": "7B",
            "min_vram_gb": 10,
            "recommended_vram_gb": 12,
            "method": "QLoRA (4-bit)",
            "batch_size": 4,
        },
        "8B_qlora": {
            "model": "Llama-3.1-8B-Instruct",
            "parameters": "8B",
            "min_vram_gb": 12,
            "recommended_vram_gb": 16,
            "method": "QLoRA (4-bit)",
            "batch_size": 4,
        },
        "14B_qlora": {
            "model": "Qwen2.5-14B-Instruct",
            "parameters": "14B",
            "min_vram_gb": 18,
            "recommended_vram_gb": 24,
            "method": "QLoRA (4-bit)",
            "batch_size": 2,
        },
    }


def recommend_model(vram_gb: float) -> Optional[str]:
    """Recommend a model based on available VRAM."""
    estimates = estimate_vram_requirements()

    best = None
    for config_name, config in estimates.items():
        if vram_gb >= config["recommended_vram_gb"]:
            best = config["model"]

    return best
