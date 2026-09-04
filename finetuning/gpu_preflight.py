#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX GPU Preflight Diagnostic (v0.1)
========================================

Reports hardware and software environment for fine-tuning readiness.
Runs safely on both the current CPU laptop and the college GPU PC.

Usage:
    python -m finetuning.gpu_preflight
"""

import platform
import sys
from pathlib import Path


def _try_import(module_name: str):
    """Try to import a module and return (module, version, error)."""
    try:
        mod = __import__(module_name)
        version = getattr(mod, "__version__", "unknown")
        return mod, version, None
    except ImportError as e:
        return None, None, str(e)


def run_preflight() -> dict:
    """Run GPU preflight diagnostics and return a report dict."""
    report = {}
    
    print("=" * 60)
    print("  AegisX GPU Preflight Diagnostic (v0.1)")
    print("=" * 60)
    
    # --- System Info ---
    print("\n--- SYSTEM ---")
    report["python_version"] = sys.version
    report["platform"] = platform.platform()
    print(f"  Python:   {sys.version.split()[0]}")
    print(f"  Platform: {platform.platform()}")
    
    # System RAM
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        # Try psutil for RAM if available
        try:
            import psutil
            ram = psutil.virtual_memory()
            ram_gb = ram.total / (1024 ** 3)
            report["system_ram_gb"] = round(ram_gb, 1)
            print(f"  RAM:      {ram_gb:.1f} GB")
        except ImportError:
            # Fallback: try to read from OS
            if platform.system() == "Windows":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                c_ulong = ctypes.c_ulonglong
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", c_ulong),
                        ("ullAvailPhys", c_ulong),
                        ("ullTotalPageFile", c_ulong),
                        ("ullAvailPageFile", c_ulong),
                        ("ullTotalVirtual", c_ulong),
                        ("ullAvailVirtual", c_ulong),
                        ("ullAvailExtendedVirtual", c_ulong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                ram_gb = stat.ullTotalPhys / (1024 ** 3)
                report["system_ram_gb"] = round(ram_gb, 1)
                print(f"  RAM:      {ram_gb:.1f} GB")
            else:
                report["system_ram_gb"] = None
                print("  RAM:      (psutil not installed)")
    except Exception:
        report["system_ram_gb"] = None
        print("  RAM:      (unable to detect)")
    
    # --- PyTorch & CUDA ---
    print("\n--- PYTORCH & CUDA ---")
    torch_mod, torch_ver, torch_err = _try_import("torch")
    if torch_mod:
        report["torch_version"] = torch_ver
        print(f"  PyTorch:       {torch_ver}")
        
        cuda_available = torch_mod.cuda.is_available()
        report["cuda_available"] = cuda_available
        print(f"  CUDA:          {'Available' if cuda_available else 'NOT Available'}")
        
        if cuda_available:
            cuda_ver = torch_mod.version.cuda
            report["cuda_version"] = cuda_ver
            print(f"  CUDA Version:  {cuda_ver}")
            
            gpu_count = torch_mod.cuda.device_count()
            report["gpu_count"] = gpu_count
            print(f"  GPU Count:     {gpu_count}")
            
            gpus = []
            for i in range(gpu_count):
                name = torch_mod.cuda.get_device_name(i)
                props = torch_mod.cuda.get_device_properties(i)
                vram_gb = props.total_mem / (1024 ** 3)
                gpu_info = {
                    "index": i,
                    "name": name,
                    "vram_gb": round(vram_gb, 1),
                    "compute_capability": f"{props.major}.{props.minor}",
                }
                gpus.append(gpu_info)
                print(f"  GPU {i}:        {name}")
                print(f"    VRAM:        {vram_gb:.1f} GB")
                print(f"    Compute:     {props.major}.{props.minor}")
            report["gpus"] = gpus
            
            bf16 = torch_mod.cuda.is_bf16_supported()
            report["bf16_supported"] = bf16
            print(f"  BF16:          {'Supported' if bf16 else 'NOT Supported'}")
        else:
            report["cuda_version"] = None
            report["gpu_count"] = 0
            report["gpus"] = []
            report["bf16_supported"] = False
    else:
        report["torch_version"] = None
        report["cuda_available"] = False
        report["cuda_version"] = None
        report["gpu_count"] = 0
        report["gpus"] = []
        report["bf16_supported"] = False
        print(f"  PyTorch:       NOT INSTALLED ({torch_err})")
    
    # --- Fine-Tuning Libraries ---
    print("\n--- FINE-TUNING LIBRARIES ---")
    libraries = [
        ("transformers", "transformers"),
        ("datasets", "datasets"),
        ("peft", "peft"),
        ("trl", "trl"),
        ("accelerate", "accelerate"),
        ("bitsandbytes", "bitsandbytes"),
    ]
    
    lib_versions = {}
    for display_name, import_name in libraries:
        _, ver, err = _try_import(import_name)
        lib_versions[display_name] = ver
        if ver:
            print(f"  {display_name:18s} {ver}")
        else:
            print(f"  {display_name:18s} NOT INSTALLED")
    report["library_versions"] = lib_versions
    
    # Unsloth (optional optimization)
    _, unsloth_ver, _ = _try_import("unsloth")
    report["unsloth_available"] = unsloth_ver is not None
    report["unsloth_version"] = unsloth_ver
    if unsloth_ver:
        print(f"  {'unsloth':18s} {unsloth_ver} (optional optimization)")
    else:
        print(f"  {'unsloth':18s} NOT INSTALLED (optional)")
    
    # --- Suitability Assessment ---
    print("\n--- SUITABILITY ASSESSMENT ---")
    
    if not report["cuda_available"]:
        verdict = "NO_GPU"
        print("  Verdict: NO compatible NVIDIA CUDA GPU detected.")
        print("")
        print("  Dataset preparation and validation are available on this machine.")
        print("  Model training requires a machine with a CUDA-capable NVIDIA GPU.")
        print("  Run this diagnostic again on the college GPU PC.")
    else:
        max_vram = max(g["vram_gb"] for g in report["gpus"]) if report["gpus"] else 0
        
        if max_vram >= 24:
            verdict = "EXCELLENT"
            print(f"  Verdict: EXCELLENT — {max_vram:.0f} GB VRAM detected.")
            print("  This GPU can fine-tune models up to ~14B parameters with QLoRA.")
        elif max_vram >= 12:
            verdict = "SUITABLE"
            print(f"  Verdict: SUITABLE — {max_vram:.0f} GB VRAM detected.")
            print("  This GPU can fine-tune 7B–8B models with QLoRA (4-bit quantization).")
        elif max_vram >= 8:
            verdict = "POTENTIALLY_SUITABLE"
            print(f"  Verdict: POTENTIALLY SUITABLE — {max_vram:.0f} GB VRAM detected.")
            print("  This GPU can fine-tune 3B models with QLoRA. Larger models may OOM.")
        else:
            verdict = "INSUFFICIENT"
            print(f"  Verdict: INSUFFICIENT — {max_vram:.0f} GB VRAM detected.")
            print("  This GPU may not have enough VRAM for QLoRA fine-tuning.")
    
    report["verdict"] = verdict
    
    # --- Missing Dependencies ---
    missing = [k for k, v in lib_versions.items() if v is None]
    if missing or not report.get("torch_version"):
        print("\n--- MISSING DEPENDENCIES ---")
        if not report.get("torch_version"):
            missing.insert(0, "torch")
        print(f"  Install with: pip install {' '.join(missing)}")
        print(f"  Or use:       pip install -r requirements-finetuning.txt")
    
    print(f"\n{'=' * 60}\n")
    return report


def main():
    run_preflight()


if __name__ == "__main__":
    main()
