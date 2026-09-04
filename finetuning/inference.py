#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX Fine-Tuned Model Inference (v0.1)
==========================================

Single-alert inference using the fine-tuned LoRA adapter.
Compatible with the existing TriageAgent schema.

Usage:
    python -m finetuning.inference --alert alert.json
    python -m finetuning.inference --alert alert.json --adapter-path models/aegisx-triage/adapter

This is a research-ready inference tool for a student SOC project.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.prompts.triage import get_triage_system_prompt, format_triage_user_prompt
from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    VALID_ACTION_PRIORITIES,
)

CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


# ---------------------------------------------------------------------------
# Output validation
# ---------------------------------------------------------------------------

def validate_triage_output(output: Dict[str, Any]) -> tuple:
    """
    Validate model output against TriageResult schema.
    Returns (is_valid, cleaned_output_or_none, error_or_none).
    """
    required_fields = ["classification", "severity", "confidence", "investigation_required", "summary"]
    for field in required_fields:
        if field not in output:
            return False, None, f"Missing required field: {field}"
    
    if output["classification"] not in VALID_CLASSIFICATIONS:
        return False, None, f"Invalid classification: {output['classification']}"
    
    if output["severity"] not in VALID_SEVERITIES:
        return False, None, f"Invalid severity: {output['severity']}"
    
    conf = output.get("confidence")
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        return False, None, f"Invalid confidence: {conf}"
    
    if not isinstance(output.get("investigation_required"), bool):
        return False, None, f"investigation_required must be boolean"
    
    # Validate findings structure
    findings = output.get("findings", [])
    if not isinstance(findings, list):
        return False, None, "findings must be a list"
    
    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict):
            return False, None, f"Finding[{idx}] must be a dict"
        if "finding" not in finding:
            return False, None, f"Finding[{idx}] missing 'finding' field"
    
    # Validate recommended_actions structure
    actions = output.get("recommended_actions", [])
    if not isinstance(actions, list):
        return False, None, "recommended_actions must be a list"
    
    for idx, action in enumerate(actions):
        if not isinstance(action, dict):
            return False, None, f"Action[{idx}] must be a dict"
        if "action" not in action:
            return False, None, f"Action[{idx}] missing 'action' field"
        priority = action.get("priority", "medium")
        if priority not in VALID_ACTION_PRIORITIES:
            # Auto-fix to medium rather than reject
            action["priority"] = "medium"
    
    return True, output, None


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def run_inference(
    alert_data: Dict[str, Any],
    model,
    tokenizer,
    system_prompt: str,
    max_new_tokens: int = 1024,
) -> Dict[str, Any]:
    """
    Run inference on a single alert using the loaded model.
    Returns the parsed TriageResult-compatible output.
    """
    import torch
    
    user_prompt = format_triage_user_prompt(alert_data)
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    
    prompt_text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )
    
    inputs = tokenizer(prompt_text, return_tensors="pt").to(model.device)
    
    start_time = time.time()
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=1.0,
            pad_token_id=tokenizer.eos_token_id,
        )
    latency_ms = round((time.time() - start_time) * 1000, 1)
    
    # Decode only the generated portion
    generated = output_ids[0][inputs["input_ids"].shape[-1]:]
    response_text = tokenizer.decode(generated, skip_special_tokens=True).strip()
    
    # Parse JSON
    try:
        result = json.loads(response_text)
    except json.JSONDecodeError:
        # Try to extract JSON from code block or surrounding text
        try:
            start = response_text.index("{")
            end = response_text.rindex("}") + 1
            result = json.loads(response_text[start:end])
        except (ValueError, json.JSONDecodeError):
            return {
                "_error": "Failed to parse model output as JSON",
                "_raw_output": response_text,
                "_latency_ms": latency_ms,
            }
    
    # Validate
    is_valid, cleaned, error = validate_triage_output(result)
    if not is_valid:
        result["_validation_warning"] = error
    
    result["_latency_ms"] = latency_ms
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AegisX Fine-Tuned Model Inference — Single alert triage"
    )
    parser.add_argument(
        "--alert",
        type=str,
        required=True,
        help="Path to alert JSON file (must contain 'alert', 'context', 'evidence' keys)",
    )
    parser.add_argument(
        "--adapter-path",
        type=str,
        default=None,
        help="Path to LoRA adapter directory (default: models/aegisx-triage/adapter)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override base model name from config",
    )
    parser.add_argument(
        "--max-new-tokens",
        type=int,
        default=1024,
        help="Maximum tokens to generate",
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("  AegisX Fine-Tuned Inference (v0.1)")
    print("=" * 60)
    
    # ---- Load Alert ----
    alert_path = Path(args.alert)
    if not alert_path.exists():
        print(f"\n  [ERROR] Alert file not found: {alert_path}")
        sys.exit(1)
    
    with open(alert_path, "r", encoding="utf-8") as f:
        alert_raw = json.load(f)
    
    # The alert file may be a full v0.4 record or just the input block
    if "input" in alert_raw:
        alert_data = alert_raw["input"]
    elif "alert" in alert_raw and "context" in alert_raw and "evidence" in alert_raw:
        alert_data = alert_raw
    else:
        print("\n  [ERROR] Alert JSON must contain 'alert', 'context', 'evidence' keys.")
        sys.exit(1)
    
    print(f"\n  Alert: {alert_data.get('alert', {}).get('title', 'N/A')}")
    print(f"  Host:  {alert_data.get('context', {}).get('hostname', 'N/A')}")
    
    # ---- GPU Check ----
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel
    except ImportError as e:
        print(f"\n  [FATAL] Missing dependency: {e}")
        print("  Install: pip install -r requirements-finetuning.txt")
        sys.exit(1)
    
    if not torch.cuda.is_available():
        print("\n  [FATAL] No CUDA GPU for inference.")
        sys.exit(1)
    
    # ---- Load Config ----
    from finetuning.train_lora import load_config
    config = load_config()
    model_name = args.model or config.get("model", {}).get("name")
    
    adapter_path = args.adapter_path or str(
        PROJECT_ROOT / config.get("output", {}).get("directory", "models/aegisx-triage") / "adapter"
    )
    adapter_path = Path(adapter_path)
    if not adapter_path.is_absolute():
        adapter_path = PROJECT_ROOT / adapter_path
    
    print(f"  Model:   {model_name}")
    print(f"  Adapter: {adapter_path}")
    
    # ---- Load Model ----
    print("\n  Loading model...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=bnb_config,
        device_map="auto",
    )
    
    if adapter_path.exists():
        print(f"  Loading adapter from: {adapter_path}")
        model = PeftModel.from_pretrained(model, str(adapter_path))
    else:
        print(f"  [WARN] Adapter not found at {adapter_path}. Using base model.")
    
    # ---- Run Inference ----
    system_prompt = get_triage_system_prompt()
    print("\n  Running inference...")
    
    result = run_inference(
        alert_data, model, tokenizer, system_prompt,
        max_new_tokens=args.max_new_tokens,
    )
    
    # ---- Print Result ----
    print(f"\n{'=' * 60}")
    print("  TRIAGE RESULT")
    print(f"{'=' * 60}")
    print(json.dumps(result, indent=2))
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
