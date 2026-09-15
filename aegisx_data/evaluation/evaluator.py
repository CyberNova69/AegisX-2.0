"""Extended model evaluator wrapping finetuning/evaluate_model.py.

Adds cross-dataset evaluation, per-source breakdown, and run comparison.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.types import TrainingRun


class ModelEvaluator:
    """Evaluate trained models with extended metrics.

    Extends the existing finetuning/evaluate_model.py with:
    - Cross-dataset evaluation
    - Per-source accuracy breakdown
    - Confusion matrix
    - Run comparison
    """

    def __init__(self, reports_dir: Path):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_predictions(
        self,
        predictions: List[Dict[str, Any]],
        ground_truth: List[Dict[str, Any]],
        label: str = "model",
    ) -> Dict[str, Any]:
        """Evaluate predictions against ground truth.

        CPU-safe, no model dependency required.
        """
        pred_classes = []
        true_classes = []
        parse_errors = 0

        for pred, gt in zip(predictions, ground_truth):
            if pred.get("_parse_error"):
                parse_errors += 1
                continue

            pred_cls = pred.get("classification", "UNKNOWN")
            true_cls = gt.get("classification", "UNKNOWN")
            pred_classes.append(pred_cls)
            true_classes.append(true_cls)

        # Accuracy
        correct = sum(1 for p, t in zip(pred_classes, true_classes) if p == t)
        total = len(true_classes)
        accuracy = correct / total if total > 0 else 0.0

        # Per-class metrics
        classes = sorted(set(pred_classes + true_classes))
        per_class = {}
        for cls in classes:
            tp = sum(1 for p, t in zip(pred_classes, true_classes) if p == cls and t == cls)
            fp = sum(1 for p, t in zip(pred_classes, true_classes) if p == cls and t != cls)
            fn = sum(1 for p, t in zip(pred_classes, true_classes) if p != cls and t == cls)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

            per_class[cls] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "support": tp + fn,
            }

        # Macro F1
        f1_values = [m["f1"] for m in per_class.values() if m["support"] > 0]
        macro_f1 = sum(f1_values) / len(f1_values) if f1_values else 0.0

        # Confusion matrix
        confusion = self._confusion_matrix(pred_classes, true_classes, classes)

        return {
            "label": label,
            "total_records": len(predictions),
            "parse_errors": parse_errors,
            "accuracy": round(accuracy, 4),
            "macro_f1": round(macro_f1, 4),
            "per_class": per_class,
            "confusion_matrix": confusion,
        }

    def _confusion_matrix(
        self,
        predictions: List[str],
        truth: List[str],
        classes: List[str],
    ) -> Dict[str, Dict[str, int]]:
        """Generate a confusion matrix."""
        matrix: Dict[str, Dict[str, int]] = {}
        for cls in classes:
            matrix[cls] = {c: 0 for c in classes}

        for pred, true in zip(predictions, truth):
            if true in matrix and pred in matrix[true]:
                matrix[true][pred] += 1

        return matrix

    def compare_runs(
        self,
        runs: List[TrainingRun],
    ) -> Dict[str, Any]:
        """Compare evaluation metrics across training runs."""
        comparison = {
            "runs": [],
            "best_accuracy_run": None,
            "best_f1_run": None,
        }

        best_acc = -1.0
        best_f1 = -1.0

        for run in runs:
            metrics = run.metrics
            run_summary = {
                "run_id": run.run_id,
                "base_model": run.base_model,
                "dataset_version": run.dataset_version,
                "status": run.status.value,
                "metrics": metrics,
            }
            comparison["runs"].append(run_summary)

            # Track best
            acc = metrics.get("accuracy", 0)
            if isinstance(acc, (int, float)) and acc > best_acc:
                best_acc = acc
                comparison["best_accuracy_run"] = run.run_id

            f1 = metrics.get("macro_f1", 0)
            if isinstance(f1, (int, float)) and f1 > best_f1:
                best_f1 = f1
                comparison["best_f1_run"] = run.run_id

        return comparison

    def save_report(self, report: Dict[str, Any], filename: str) -> Path:
        """Save an evaluation report to the reports directory."""
        path = self.reports_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return path
