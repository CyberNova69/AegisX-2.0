#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX QLoRA Training Script (v0.1)
=====================================

Supervised fine-tuning of a causal language model using QLoRA for SOC alert
triage. Designed to run on the college GPU PC.

Key features:
  - Loads config from finetuning/config.yaml (or CLI overrides).
  - GPU safety check: aborts cleanly on CPU-only machines.
  - --dry-run mode: validates config and paths without loading a model.
  - Checkpoint resumption via --resume-from.
  - Saves adapter weights + tokenizer + training_metadata.json.

Usage:
    python -m finetuning.train_lora --dry-run       # Validate config on CPU laptop
    python -m finetuning.train_lora                  # Full training on college GPU
    python -m finetuning.train_lora --model "..."    # Override model name
    python -m finetuning.train_lora --resume-from checkpoints/checkpoint-500

This is a research-ready fine-tuning script for a student SOC project.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


# ---------------------------------------------------------------------------
# Config loading (YAML or fallback)
# ---------------------------------------------------------------------------

def load_config(config_path: Path = CONFIG_PATH) -> Dict[str, Any]:
    """Load training configuration from YAML file."""
    if not config_path.exists():
        print(f"  [ERROR] Config file not found: {config_path}")
        sys.exit(1)
    
    try:
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        return config
    except ImportError:
        # Fallback: basic YAML parsing for simple configs
        return _basic_yaml_parse(config_path)


def _basic_yaml_parse(config_path: Path) -> Dict[str, Any]:
    """Minimal YAML parser for flat/nested configs without PyYAML."""
    config = {}
    current_section = None
    current_subsection = None
    
    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.rstrip()
            
            # Skip comments and empty lines
            if not stripped or stripped.lstrip().startswith("#"):
                continue
            
            # Determine indentation level
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
                        current_subsection = None
                        config[key] = {}
                    else:
                        config[key] = _parse_value(value)
                elif indent <= 4 and current_section:
                    if not value:
                        current_subsection = key
                        config[current_section][key] = {}
                    elif value.startswith("-"):
                        # List under section
                        config[current_section][key] = []
                    else:
                        config[current_section][key] = _parse_value(value)
                elif current_section and current_subsection:
                    config[current_section][current_subsection][key] = _parse_value(value)
            elif content.startswith("- ") and current_section:
                # List item
                item = content[2:].strip().strip('"').strip("'")
                # Find the last key that should be a list
                for k, v in config[current_section].items():
                    if isinstance(v, list):
                        v.append(item)
                        break
    
    return config


def _parse_value(value: str):
    """Parse a YAML value into the appropriate Python type."""
    if not value:
        return None
    if value.lower() == "null" or value.lower() == "none":
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    # Remove quotes
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
# Config validation
# ---------------------------------------------------------------------------

def validate_config(config: Dict[str, Any], project_root: Path) -> list:
    """Validate training config and return list of issues."""
    issues = []
    
    # Model config
    model_cfg = config.get("model", {})
    if not model_cfg.get("name"):
        issues.append("model.name is required")
    
    max_seq = model_cfg.get("max_seq_length", 2048)
    if not isinstance(max_seq, int) or max_seq < 128:
        issues.append(f"model.max_seq_length must be >= 128, got {max_seq}")
    
    # Training config
    train_cfg = config.get("training", {})
    lr = train_cfg.get("learning_rate", 2e-4)
    if not isinstance(lr, (int, float)) or lr <= 0:
        issues.append(f"training.learning_rate must be > 0, got {lr}")
    
    epochs = train_cfg.get("epochs", 3)
    if not isinstance(epochs, int) or epochs < 1:
        issues.append(f"training.epochs must be >= 1, got {epochs}")
    
    batch_size = train_cfg.get("batch_size", 4)
    if not isinstance(batch_size, int) or batch_size < 1:
        issues.append(f"training.batch_size must be >= 1, got {batch_size}")
    
    seed = train_cfg.get("seed", 42)
    if not isinstance(seed, int):
        issues.append(f"training.seed must be an integer, got {seed}")
    
    # LoRA config
    lora_cfg = config.get("lora", {})
    r = lora_cfg.get("r", 16)
    if not isinstance(r, int) or r < 1:
        issues.append(f"lora.r must be >= 1, got {r}")
    
    alpha = lora_cfg.get("alpha", 32)
    if not isinstance(alpha, (int, float)) or alpha <= 0:
        issues.append(f"lora.alpha must be > 0, got {alpha}")
    
    dropout = lora_cfg.get("dropout", 0.05)
    if not isinstance(dropout, (int, float)) or not (0.0 <= dropout < 1.0):
        issues.append(f"lora.dropout must be in [0.0, 1.0), got {dropout}")
    
    # Dataset paths
    ds_cfg = config.get("dataset", {})
    for split_name in ["train", "validation"]:
        path_str = ds_cfg.get(split_name)
        if path_str:
            p = project_root / path_str
            if not p.exists():
                issues.append(f"dataset.{split_name} not found: {p}")
    
    return issues


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------

def dry_run(config: Dict[str, Any], project_root: Path):
    """Validate config and paths without loading any model."""
    print("=" * 60)
    print("  AegisX QLoRA Training — DRY RUN")
    print("=" * 60)
    
    # Validate config
    print("\n  Validating configuration...")
    issues = validate_config(config, project_root)
    
    if issues:
        print("\n  [ERRORS FOUND]")
        for issue in issues:
            print(f"    - {issue}")
        sys.exit(1)
    else:
        print("    All configuration values valid.")
    
    # Print config summary
    model_cfg = config.get("model", {})
    train_cfg = config.get("training", {})
    lora_cfg = config.get("lora", {})
    ds_cfg = config.get("dataset", {})
    output_cfg = config.get("output", {})
    
    print("\n  --- Configuration Summary ---")
    print(f"    Model:           {model_cfg.get('name')}")
    print(f"    Max Seq Length:   {model_cfg.get('max_seq_length', 2048)}")
    print(f"    Method:          {train_cfg.get('method', 'qlora')}")
    print(f"    Epochs:          {train_cfg.get('epochs', 3)}")
    print(f"    LR:              {train_cfg.get('learning_rate', 2e-4)}")
    print(f"    Batch Size:      {train_cfg.get('batch_size', 4)}")
    print(f"    Grad Accum:      {train_cfg.get('gradient_accumulation_steps', 4)}")
    effective_batch = train_cfg.get('batch_size', 4) * train_cfg.get('gradient_accumulation_steps', 4)
    print(f"    Effective Batch: {effective_batch}")
    print(f"    LoRA r:          {lora_cfg.get('r', 16)}")
    print(f"    LoRA alpha:      {lora_cfg.get('alpha', 32)}")
    print(f"    LoRA dropout:    {lora_cfg.get('dropout', 0.05)}")
    print(f"    BF16:            {train_cfg.get('bf16', True)}")
    print(f"    Seed:            {train_cfg.get('seed', 42)}")
    
    # Check dataset files
    print("\n  --- Dataset Paths ---")
    for split_name in ["train", "validation", "test"]:
        path_str = ds_cfg.get(split_name)
        if path_str:
            p = project_root / path_str
            exists = p.exists()
            marker = "OK" if exists else "MISSING"
            readonly = " (read-only, for eval)" if split_name == "test" else ""
            print(f"    {split_name:12s} [{marker}] {path_str}{readonly}")
            
            if exists:
                # Count records
                count = 0
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            count += 1
                print(f"    {'':12s}        {count} records")
    
    # Check output directory
    output_dir = project_root / output_cfg.get("directory", "models/aegisx-triage")
    print(f"\n  --- Output ---")
    print(f"    Directory:       {output_dir}")
    print(f"    Exists:          {output_dir.exists()}")
    
    # GPU check
    print("\n  --- GPU Status ---")
    try:
        import torch
        if torch.cuda.is_available():
            name = torch.cuda.get_device_name(0)
            props = torch.cuda.get_device_properties(0)
            vram_gb = props.total_mem / (1024 ** 3)
            print(f"    GPU:             {name} ({vram_gb:.1f} GB)")
            print(f"    Status:          READY for training")
        else:
            print(f"    GPU:             None detected")
            print(f"    Status:          Training requires CUDA GPU (use college PC)")
    except ImportError:
        print(f"    GPU:             PyTorch not installed")
        print(f"    Status:          Install requirements-finetuning.txt on college PC")
    
    print(f"\n  DRY RUN COMPLETE — Configuration is valid.")
    print(f"{'=' * 60}\n")


# ---------------------------------------------------------------------------
# Full training
# ---------------------------------------------------------------------------

def train(config: Dict[str, Any], project_root: Path, resume_from: Optional[str] = None):
    """
    Full QLoRA training pipeline.
    
    This function requires CUDA GPU and the full fine-tuning dependency stack.
    It will abort cleanly if requirements are not met.
    """
    print("=" * 60)
    print("  AegisX QLoRA Training (v0.1)")
    print("=" * 60)
    
    # ---- GPU Safety Check ----
    try:
        import torch
    except ImportError:
        print("\n  [FATAL] PyTorch is not installed.")
        print("  Install: pip install -r requirements-finetuning.txt")
        sys.exit(1)
    
    if not torch.cuda.is_available():
        print("\n  [FATAL] No CUDA GPU detected. QLoRA training requires an NVIDIA GPU.")
        print("  Run 'python -m finetuning.gpu_preflight' for diagnostics.")
        print("  Transfer this project to the college GPU PC for training.")
        sys.exit(1)
    
    gpu_name = torch.cuda.get_device_name(0)
    props = torch.cuda.get_device_properties(0)
    vram_gb = props.total_mem / (1024 ** 3)
    print(f"\n  GPU:     {gpu_name} ({vram_gb:.1f} GB VRAM)")
    
    # ---- Validate Config ----
    issues = validate_config(config, project_root)
    if issues:
        print("\n  [CONFIG ERRORS]")
        for issue in issues:
            print(f"    - {issue}")
        sys.exit(1)
    
    # ---- Import Training Libraries ----
    try:
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            TrainingArguments,
            BitsAndBytesConfig,
        )
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer
        from datasets import load_dataset
    except ImportError as e:
        print(f"\n  [FATAL] Missing training dependency: {e}")
        print("  Install: pip install -r requirements-finetuning.txt")
        sys.exit(1)
    
    # ---- Extract Config ----
    model_cfg = config.get("model", {})
    train_cfg = config.get("training", {})
    lora_cfg = config.get("lora", {})
    ds_cfg = config.get("dataset", {})
    output_cfg = config.get("output", {})
    
    model_name = model_cfg["name"]
    max_seq_length = model_cfg.get("max_seq_length", 2048)
    output_dir = project_root / output_cfg.get("directory", "models/aegisx-triage")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    seed = train_cfg.get("seed", 42)
    torch.manual_seed(seed)
    
    print(f"  Model:   {model_name}")
    print(f"  Output:  {output_dir}")
    
    # ---- Set Up Quantization ----
    print("\n  Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=model_cfg.get("trust_remote_code", False),
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    print("  Loading model with 4-bit quantization...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16 if train_cfg.get("bf16", True) else torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=model_cfg.get("trust_remote_code", False),
    )
    
    model = prepare_model_for_kbit_training(model)
    
    # ---- Apply LoRA ----
    print("  Applying LoRA adapters...")
    target_modules = lora_cfg.get("target_modules", ["q_proj", "k_proj", "v_proj", "o_proj"])
    if isinstance(target_modules, str):
        target_modules = [target_modules]
    
    peft_config = LoraConfig(
        r=lora_cfg.get("r", 16),
        lora_alpha=lora_cfg.get("alpha", 32),
        lora_dropout=lora_cfg.get("dropout", 0.05),
        target_modules=target_modules,
        bias=lora_cfg.get("bias", "none"),
        task_type=lora_cfg.get("task_type", "CAUSAL_LM"),
    )
    
    model = get_peft_model(model, peft_config)
    trainable, total = model.get_nb_trainable_parameters()
    print(f"  Trainable params: {trainable:,} / {total:,} ({100 * trainable / total:.2f}%)")
    
    # ---- Load Datasets ----
    print("\n  Loading SFT datasets...")
    train_path = str(project_root / ds_cfg["train"])
    val_path = str(project_root / ds_cfg["validation"])
    
    train_dataset = load_dataset("json", data_files=train_path, split="train")
    val_dataset = load_dataset("json", data_files=val_path, split="train")
    
    print(f"    Train:      {len(train_dataset)} examples")
    print(f"    Validation: {len(val_dataset)} examples")
    
    # ---- Formatting Function ----
    def formatting_func(example):
        """Apply chat template to messages."""
        return tokenizer.apply_chat_template(
            example["messages"],
            tokenize=False,
            add_generation_prompt=False,
        )
    
    # ---- Training Arguments ----
    run_name = f"aegisx-triage-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    
    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        run_name=run_name,
        num_train_epochs=train_cfg.get("epochs", 3),
        per_device_train_batch_size=train_cfg.get("batch_size", 4),
        per_device_eval_batch_size=train_cfg.get("batch_size", 4),
        gradient_accumulation_steps=train_cfg.get("gradient_accumulation_steps", 4),
        learning_rate=train_cfg.get("learning_rate", 2e-4),
        warmup_ratio=train_cfg.get("warmup_ratio", 0.05),
        weight_decay=train_cfg.get("weight_decay", 0.01),
        max_grad_norm=train_cfg.get("max_grad_norm", 1.0),
        optim=train_cfg.get("optim", "paged_adamw_8bit"),
        logging_steps=train_cfg.get("logging_steps", 10),
        eval_strategy=train_cfg.get("evaluation_strategy", "epoch"),
        save_strategy=train_cfg.get("save_strategy", "epoch"),
        seed=seed,
        fp16=train_cfg.get("fp16", False),
        bf16=train_cfg.get("bf16", True),
        report_to="none",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
    )
    
    # ---- Trainer ----
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        formatting_func=formatting_func,
        tokenizer=tokenizer,
        max_seq_length=max_seq_length,
    )
    
    # ---- Train ----
    print(f"\n  Starting training...")
    start_time = time.time()
    
    if resume_from:
        print(f"  Resuming from checkpoint: {resume_from}")
        trainer.train(resume_from_checkpoint=resume_from)
    else:
        trainer.train()
    
    elapsed = time.time() - start_time
    
    # ---- Save ----
    print(f"\n  Training complete in {elapsed:.1f}s ({elapsed / 60:.1f} min)")
    
    adapter_dir = output_dir / "adapter"
    adapter_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"  Saving adapter to: {adapter_dir}")
    model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    
    # ---- Training Metadata ----
    metadata = {
        "pipeline_version": "0.1.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "run_name": run_name,
        "base_model": model_name,
        "training_time_seconds": round(elapsed, 1),
        "gpu": gpu_name,
        "gpu_vram_gb": round(vram_gb, 1),
        "trainable_parameters": trainable,
        "total_parameters": total,
        "trainable_pct": round(100 * trainable / total, 2),
        "config": config,
        "train_examples": len(train_dataset),
        "val_examples": len(val_dataset),
        "library_versions": {
            "torch": torch.__version__,
        },
        "disclaimer": "Research-ready synthetic SOC triage model. NOT production-grade.",
    }
    
    # Add library versions
    try:
        import transformers
        metadata["library_versions"]["transformers"] = transformers.__version__
    except Exception:
        pass
    try:
        import peft
        metadata["library_versions"]["peft"] = peft.__version__
    except Exception:
        pass
    try:
        import trl
        metadata["library_versions"]["trl"] = trl.__version__
    except Exception:
        pass
    
    metadata_path = output_dir / "training_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"  Metadata saved: {metadata_path}")
    print(f"\n{'=' * 60}")
    print(f"  TRAINING COMPLETE")
    print(f"  Adapter: {adapter_dir}")
    print(f"  Next: python -m finetuning.evaluate_model")
    print(f"{'=' * 60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AegisX QLoRA Training — Fine-tune a model for SOC alert triage"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config and paths without loading any model",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config YAML (default: finetuning/config.yaml)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override model name from config",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=None,
        help="Override number of training epochs",
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=None,
        help="Override learning rate",
    )
    parser.add_argument(
        "--resume-from",
        type=str,
        default=None,
        help="Resume from a checkpoint directory",
    )
    args = parser.parse_args()
    
    # Load config
    config_path = Path(args.config) if args.config else CONFIG_PATH
    config = load_config(config_path)
    
    # Apply CLI overrides
    if args.model:
        config.setdefault("model", {})["name"] = args.model
    if args.epochs:
        config.setdefault("training", {})["epochs"] = args.epochs
    if args.lr:
        config.setdefault("training", {})["learning_rate"] = args.lr
    
    if args.dry_run:
        dry_run(config, PROJECT_ROOT)
    else:
        train(config, PROJECT_ROOT, resume_from=args.resume_from)


if __name__ == "__main__":
    main()
