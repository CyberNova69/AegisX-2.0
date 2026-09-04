#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisX Model Evaluation Script (v0.1)
=======================================

Post-training evaluation comparing baseline vs. fine-tuned model performance
on the held-out v0.4 test.jsonl set.

Metrics:
  - Classification accuracy, per-class precision/recall/F1
  - Severity accuracy
  - investigation_required accuracy
  - Structured output validity rate
  - Evidence reference validity rate

Usage:
    python -m finetuning.evaluate_model --adapter-path models/aegisx-triage/adapter
    python -m finetuning.evaluate_model --baseline    # Baseline-only evaluation

Results are labeled as "held-out synthetic test performance", NOT "real-world SOC accuracy".
This is a research-ready evaluation script for a student SOC project.
"""

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.agents.schemas import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    VALID_ACTION_PRIORITIES,
)
from ai.prompts.triage import get_triage_system_prompt, format_triage_user_prompt

CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


# ---------------------------------------------------------------------------
# Metrics computation (CPU-safe, no model dependency)
# ---------------------------------------------------------------------------

def compute_accuracy(predictions: List[str], labels: List[str]) -> float:
    """Compute simple accuracy."""
    if not labels:
        return 0.0
    correct = sum(1 for p, l in zip(predictions, labels) if p == l)
    return correct / len(labels)


def compute_per_class_metrics(
    predictions: List[str],
    labels: List[str],
    classes: Optional[set] = None,
) -> Dict[str, Dict[str, float]]:
    """Compute precision, recall, F1 for each class."""
    if classes is None:
        classes = set(labels) | set(predictions)
    
    metrics = {}
    for cls in sorted(classes):
        tp = sum(1 for p, l in zip(predictions, labels) if p == cls and l == cls)
        fp = sum(1 for p, l in zip(predictions, labels) if p == cls and l != cls)
        fn = sum(1 for p, l in zip(predictions, labels) if p != cls and l == cls)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        metrics[cls] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": tp + fn,
        }
    
    return metrics


def validate_structured_output(output: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate that a model output conforms to the TriageResult schema.
    Returns (is_valid, error_reason).
    """
    required = ["classification", "severity", "confidence", "investigation_required", "summary"]
    for field in required:
        if field not in output:
            return False, f"Missing field: {field}"
    
    if output["classification"] not in VALID_CLASSIFICATIONS:
        return False, f"Invalid classification: {output['classification']}"
    
    if output["severity"] not in VALID_SEVERITIES:
        return False, f"Invalid severity: {output['severity']}"
    
    conf = output.get("confidence")
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        return False, f"Invalid confidence: {conf}"
    
    if not isinstance(output.get("investigation_required"), bool):
        return False, f"investigation_required not boolean"
    
    return True, None


def validate_evidence_refs(output: Dict[str, Any], valid_ids: set) -> Tuple[bool, Optional[str]]:
    """Validate that all evidence references in output point to valid input IDs."""
    for idx, finding in enumerate(output.get("findings", [])):
        if isinstance(finding, dict):
            for ref in finding.get("evidence_ids", []):
                if ref not in valid_ids:
                    return False, f"Finding[{idx}] invalid ref: {ref}"
    
    for ref in output.get("evidence_ids", []):
        if ref not in valid_ids:
            return False, f"Top-level invalid ref: {ref}"
    
    return True, None


# ---------------------------------------------------------------------------
# Test set loading
# ---------------------------------------------------------------------------

def load_test_set(test_path: Path) -> List[Dict[str, Any]]:
    """Load the held-out test set."""
    records = []
    with open(test_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"  [WARN] Skipping malformed JSON in test set line {line_num}: {e}")
    return records


# ---------------------------------------------------------------------------
# Model inference (requires GPU + model)
# ---------------------------------------------------------------------------

def run_inference_batch(
    records: List[Dict[str, Any]],
    model,
    tokenizer,
    system_prompt: str,
    max_new_tokens: int = 1024,
) -> List[Dict[str, Any]]:
    """
    Run inference on test records using a loaded model + tokenizer.
    Returns list of parsed model outputs (or error markers).
    """
    import torch
    
    results = []
    for i, record in enumerate(records):
        input_data = record["input"]
        user_prompt = format_triage_user_prompt(input_data)
        
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
        
        with torch.no_grad():
            output_ids = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                temperature=1.0,
                pad_token_id=tokenizer.eos_token_id,
            )
        
        # Decode only the generated portion
        generated = output_ids[0][inputs["input_ids"].shape[-1]:]
        response_text = tokenizer.decode(generated, skip_special_tokens=True).strip()
        
        # Parse JSON from response
        try:
            # Try direct parse
            parsed = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            try:
                start = response_text.index("{")
                end = response_text.rindex("}") + 1
                parsed = json.loads(response_text[start:end])
            except (ValueError, json.JSONDecodeError):
                parsed = {"_parse_error": True, "_raw": response_text}
        
        results.append(parsed)
        
        if (i + 1) % 10 == 0:
            print(f"    Inference progress: {i + 1}/{len(records)}")
    
    return results


# ---------------------------------------------------------------------------
# Evaluation pipeline
# ---------------------------------------------------------------------------

def evaluate(
    predictions: List[Dict[str, Any]],
    records: List[Dict[str, Any]],
    label: str = "model",
) -> Dict[str, Any]:
    """
    Evaluate model predictions against ground-truth labels.
    Returns a structured evaluation report.
    """
    pred_classifications = []
    true_classifications = []
    pred_severities = []
    true_severities = []
    pred_investigation = []
    true_investigation = []
    
    valid_structure_count = 0
    valid_evidence_count = 0
    parse_error_count = 0
    total = len(records)
    
    for pred, record in zip(predictions, records):
        gt = record["output"]
        
        # Check for parse errors
        if pred.get("_parse_error"):
            parse_error_count += 1
            continue
        
        # Structural validity
        is_valid, _ = validate_structured_output(pred)
        if is_valid:
            valid_structure_count += 1
        
        # Evidence reference validity
        valid_ids = {
            evt["id"]
            for evt in record["input"].get("evidence", [])
            if isinstance(evt, dict) and "id" in evt
        }
        ev_valid, _ = validate_evidence_refs(pred, valid_ids)
        if ev_valid:
            valid_evidence_count += 1
        
        # Collect labels
        pred_cls = pred.get("classification", "UNKNOWN")
        true_cls = gt.get("classification", "UNKNOWN")
        pred_classifications.append(pred_cls)
        true_classifications.append(true_cls)
        
        if pred.get("severity") and gt.get("severity"):
            pred_severities.append(pred["severity"])
            # Ground truth severity may come from findings
            true_sev = gt.get("severity")
            if true_sev is None:
                true_sev = record["input"]["alert"].get("severity", "medium")
            true_severities.append(true_sev)
        
        if isinstance(pred.get("investigation_required"), bool):
            pred_investigation.append(pred["investigation_required"])
            # Compute expected investigation_required
            conf = gt.get("confidence", 0.5)
            if true_cls == "benign" and conf >= 0.75:
                true_investigation.append(False)
            else:
                true_investigation.append(True)
    
    # Compute metrics
    report = {
        "label": label,
        "disclaimer": "Held-out synthetic test performance. NOT real-world SOC accuracy.",
        "total_records": total,
        "parse_errors": parse_error_count,
        "parse_success_rate": round((total - parse_error_count) / total, 4) if total > 0 else 0,
        "structured_output_validity_rate": round(valid_structure_count / total, 4) if total > 0 else 0,
        "evidence_reference_validity_rate": round(valid_evidence_count / total, 4) if total > 0 else 0,
        "classification_accuracy": round(compute_accuracy(pred_classifications, true_classifications), 4),
        "classification_per_class": compute_per_class_metrics(
            pred_classifications, true_classifications, VALID_CLASSIFICATIONS
        ),
        "severity_accuracy": round(compute_accuracy(pred_severities, true_severities), 4) if true_severities else None,
        "investigation_required_accuracy": round(
            compute_accuracy(
                [str(p) for p in pred_investigation],
                [str(t) for t in true_investigation],
            ), 4
        ) if true_investigation else None,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    return report


def generate_comparison_markdown(
    baseline_report: Optional[Dict],
    finetuned_report: Optional[Dict],
) -> str:
    """Generate a human-readable comparison markdown report."""
    lines = [
        "# AegisX Fine-Tuning Evaluation Report",
        "",
        "> **Disclaimer**: These results reflect held-out synthetic test performance.",
        "> They do NOT represent real-world SOC accuracy.",
        "",
    ]
    
    reports = []
    if baseline_report:
        reports.append(("Baseline", baseline_report))
    if finetuned_report:
        reports.append(("Fine-Tuned", finetuned_report))
    
    if len(reports) == 2:
        lines.append("## Summary Comparison")
        lines.append("")
        lines.append("| Metric | Baseline | Fine-Tuned | Delta |")
        lines.append("|--------|----------|------------|-------|")
        
        metrics_to_compare = [
            ("Classification Accuracy", "classification_accuracy"),
            ("Severity Accuracy", "severity_accuracy"),
            ("Investigation Required Accuracy", "investigation_required_accuracy"),
            ("Structured Output Validity", "structured_output_validity_rate"),
            ("Evidence Reference Validity", "evidence_reference_validity_rate"),
            ("Parse Success Rate", "parse_success_rate"),
        ]
        
        for display_name, key in metrics_to_compare:
            b_val = baseline_report.get(key)
            f_val = finetuned_report.get(key)
            if b_val is not None and f_val is not None:
                delta = f_val - b_val
                sign = "+" if delta > 0 else ""
                lines.append(
                    f"| {display_name} | {b_val:.4f} | {f_val:.4f} | {sign}{delta:.4f} |"
                )
        lines.append("")
    
    for label, report in reports:
        lines.append(f"## {label} Results")
        lines.append("")
        lines.append(f"- **Total Records**: {report['total_records']}")
        lines.append(f"- **Parse Errors**: {report['parse_errors']}")
        lines.append(f"- **Classification Accuracy**: {report.get('classification_accuracy', 'N/A')}")
        lines.append(f"- **Severity Accuracy**: {report.get('severity_accuracy', 'N/A')}")
        lines.append(f"- **Investigation Required Accuracy**: {report.get('investigation_required_accuracy', 'N/A')}")
        lines.append(f"- **Structured Output Validity**: {report.get('structured_output_validity_rate', 'N/A')}")
        lines.append(f"- **Evidence Reference Validity**: {report.get('evidence_reference_validity_rate', 'N/A')}")
        lines.append("")
        
        per_class = report.get("classification_per_class", {})
        if per_class:
            lines.append(f"### {label} — Per-Class Metrics")
            lines.append("")
            lines.append("| Class | Precision | Recall | F1 | Support |")
            lines.append("|-------|-----------|--------|-----|---------|")
            for cls in sorted(per_class.keys()):
                m = per_class[cls]
                lines.append(
                    f"| {cls} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['support']} |"
                )
            lines.append("")
    
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AegisX Model Evaluation — Compare baseline vs. fine-tuned"
    )
    parser.add_argument(
        "--adapter-path",
        type=str,
        default=None,
        help="Path to fine-tuned LoRA adapter directory",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Run baseline-only evaluation (no adapter)",
    )
    parser.add_argument(
        "--test-file",
        type=str,
        default="datasets/finetuning/v0.4/test.jsonl",
        help="Path to held-out test set",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports/finetuning",
        help="Directory for evaluation reports",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override base model name",
    )
    parser.add_argument(
        "--metrics-only",
        action="store_true",
        help="Compute metrics from existing prediction files (no inference needed)",
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("  AegisX Model Evaluation (v0.1)")
    print("=" * 60)
    
    test_path = Path(args.test_file)
    if not test_path.is_absolute():
        test_path = PROJECT_ROOT / test_path
    
    if not test_path.exists():
        print(f"\n  [ERROR] Test file not found: {test_path}")
        sys.exit(1)
    
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    records = load_test_set(test_path)
    print(f"\n  Test records loaded: {len(records)}")
    
    # Determine what to evaluate
    baseline_report = None
    finetuned_report = None
    
    if args.metrics_only:
        # Load pre-computed predictions
        baseline_pred_path = output_dir / "baseline_predictions.json"
        finetuned_pred_path = output_dir / "finetuned_predictions.json"
        
        if baseline_pred_path.exists():
            with open(baseline_pred_path) as f:
                baseline_preds = json.load(f)
            baseline_report = evaluate(baseline_preds, records, "baseline")
        
        if finetuned_pred_path.exists():
            with open(finetuned_pred_path) as f:
                finetuned_preds = json.load(f)
            finetuned_report = evaluate(finetuned_preds, records, "finetuned")
    else:
        # Full inference mode — requires GPU
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
            from peft import PeftModel
        except ImportError as e:
            print(f"\n  [FATAL] Missing dependency: {e}")
            print("  Install: pip install -r requirements-finetuning.txt")
            print("  Or use --metrics-only with pre-computed predictions.")
            sys.exit(1)
        
        if not torch.cuda.is_available():
            print("\n  [FATAL] No CUDA GPU for inference.")
            print("  Use --metrics-only for CPU-based metric computation.")
            sys.exit(1)
        
        system_prompt = get_triage_system_prompt()
        
        # Load config to get model name
        from finetuning.train_lora import load_config
        config = load_config()
        model_name = args.model or config.get("model", {}).get("name")
        
        if not model_name:
            print("\n  [ERROR] No model name specified.")
            sys.exit(1)
        
        print(f"\n  Base model: {model_name}")
        
        # Load base model
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        
        if args.baseline or not args.adapter_path:
            # Baseline evaluation
            print("\n  --- Baseline Evaluation ---")
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                quantization_config=bnb_config,
                device_map="auto",
            )
            
            baseline_preds = run_inference_batch(records, model, tokenizer, system_prompt)
            baseline_report = evaluate(baseline_preds, records, "baseline")
            
            # Save predictions
            with open(output_dir / "baseline_predictions.json", "w") as f:
                json.dump(baseline_preds, f, indent=2)
            with open(output_dir / "baseline_results.json", "w") as f:
                json.dump(baseline_report, f, indent=2)
            
            print(f"    Classification accuracy: {baseline_report['classification_accuracy']:.4f}")
            
            del model
            torch.cuda.empty_cache()
        
        if args.adapter_path:
            # Fine-tuned evaluation
            print("\n  --- Fine-Tuned Evaluation ---")
            adapter_path = Path(args.adapter_path)
            if not adapter_path.is_absolute():
                adapter_path = PROJECT_ROOT / adapter_path
            
            if not adapter_path.exists():
                print(f"  [ERROR] Adapter not found: {adapter_path}")
                sys.exit(1)
            
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                quantization_config=bnb_config,
                device_map="auto",
            )
            model = PeftModel.from_pretrained(model, str(adapter_path))
            
            finetuned_preds = run_inference_batch(records, model, tokenizer, system_prompt)
            finetuned_report = evaluate(finetuned_preds, records, "finetuned")
            
            # Save predictions
            with open(output_dir / "finetuned_predictions.json", "w") as f:
                json.dump(finetuned_preds, f, indent=2)
            with open(output_dir / "finetuned_results.json", "w") as f:
                json.dump(finetuned_report, f, indent=2)
            
            print(f"    Classification accuracy: {finetuned_report['classification_accuracy']:.4f}")
            
            del model
            torch.cuda.empty_cache()
    
    # Generate comparison report
    if baseline_report or finetuned_report:
        comparison_md = generate_comparison_markdown(baseline_report, finetuned_report)
        comparison_path = output_dir / "comparison.md"
        with open(comparison_path, "w", encoding="utf-8") as f:
            f.write(comparison_md)
        print(f"\n  Report saved: {comparison_path}")
        
        # Save combined comparison JSON
        comparison_data = {
            "baseline": baseline_report,
            "finetuned": finetuned_report,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(output_dir / "comparison.json", "w") as f:
            json.dump(comparison_data, f, indent=2)
    
    print(f"\n{'=' * 60}")
    print(f"  EVALUATION COMPLETE")
    print(f"  Reports: {output_dir}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
