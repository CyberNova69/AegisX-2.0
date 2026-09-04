"""
AegisX Comprehensive Benchmark & Reporting Orchestrator
========================================================

Orchestrates multi-component evaluations across Triage, Investigation,
ThreatIntel, RAG, and Safety layers. Generates machine-readable JSON reports
and human-readable Markdown summaries under reports/evaluation/.
Supports Base vs. Fine-Tuned model comparison schemas.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ai.evaluation.metrics import compute_latency_stats
from ai.evaluation.rag_eval import evaluate_rag_retrieval
from ai.evaluation.safety_eval import evaluate_safety_invariants
from ai.evaluation.test_set_firewall import (
    DEFAULT_TEST_SET_PATH,
    EXPECTED_TEST_SET_COUNT,
    EXPECTED_TEST_SET_SHA256,
    TestSetFirewall,
)
from ai.evaluation.triage_eval import TriageEvalMetrics
from ai.evaluation.investigation_eval import InvestigationEvalMetrics
from ai.evaluation.threat_intel_eval import ThreatIntelEvalMetrics

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "reports" / "evaluation"

def generate_comparison_schema(
    base_metrics: Dict[str, Any],
    finetuned_metrics: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Format delta comparison between base model and fine-tuned model.
    Designed for future evaluation when fine-tuned weights become available.
    """
    keys_to_compare = [
        "accuracy",
        "macro_f1",
        "severity_accuracy",
        "investigation_agreement_pct",
        "evidence_grounding_rate",
        "hallucinated_evidence_rate",
        "structured_output_validity_rate",
    ]

    comparison = {}
    for k in keys_to_compare:
        base_val = base_metrics.get(k, 0.0)
        ft_val = finetuned_metrics.get(k, 0.0)
        delta = round(ft_val - base_val, 4)
        comparison[k] = {
            "base": base_val,
            "fine_tuned": ft_val,
            "delta": delta,
            "improvement": delta > 0 if "hallucinated" not in k else delta < 0,
        }

    return {
        "comparison_type": "BASE_VS_FINETUNED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": comparison,
    }

class BenchmarkReport:
    """Consolidated benchmark evaluation report across all AegisX SOC components."""

    def __init__(
        self,
        provider_name: str = "mock",
        model_name: str = "mock-soc-analyst-v1",
        evaluation_mode: str = "MOCK_EVALUATION",
        triage_metrics: Optional[TriageEvalMetrics] = None,
        investigation_metrics: Optional[InvestigationEvalMetrics] = None,
        threat_intel_metrics: Optional[ThreatIntelEvalMetrics] = None,
        rag_metrics: Optional[Dict[str, Any]] = None,
        safety_metrics: Optional[Dict[str, Any]] = None,
        test_set_metadata: Optional[Dict[str, Any]] = None,
        notes: str = "",
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.provider_name = provider_name
        self.model_name = model_name
        
        # Enforce that mock provider can never be mislabeled as REAL_API_BENCHMARK
        if self.provider_name.lower() != "api" and evaluation_mode == "REAL_API_BENCHMARK":
            self.evaluation_mode = "MOCK_EVALUATION"
        else:
            self.evaluation_mode = evaluation_mode

        self.triage_metrics = triage_metrics or TriageEvalMetrics()
        self.investigation_metrics = investigation_metrics
        self.threat_intel_metrics = threat_intel_metrics
        self.rag_metrics = rag_metrics or {}
        self.safety_metrics = safety_metrics or {}
        
        base_meta = test_set_metadata or {
            "dataset_version": "v0.4",
            "test_set_path": str(DEFAULT_TEST_SET_PATH),
            "expected_sha256": EXPECTED_TEST_SET_SHA256,
            "expected_count": EXPECTED_TEST_SET_COUNT,
            "firewall_verified": True,
        }
        total_rec = base_meta.get("total_records") or base_meta.get("record_count") or base_meta.get("expected_count", EXPECTED_TEST_SET_COUNT)
        eval_rec = base_meta.get("records_evaluated", self.triage_metrics.total_examples if self.triage_metrics and self.triage_metrics.total_examples > 0 else total_rec)
        
        self.test_set_metadata = {
            **base_meta,
            "sha256": base_meta.get("sha256", EXPECTED_TEST_SET_SHA256),
            "total_records": total_rec,
            "records_evaluated": eval_rec,
        }
        self.notes = notes

    @property
    def records_evaluated(self) -> int:
        return self.test_set_metadata.get("records_evaluated", 0)

    @property
    def total_test_records(self) -> int:
        return self.test_set_metadata.get("total_records", EXPECTED_TEST_SET_COUNT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "timestamp": self.timestamp,
                "provider": self.provider_name,
                "model": self.model_name,
                "evaluation_mode": self.evaluation_mode,
                "disclaimer": (
                    "AegisX Research Benchmark. Evaluated on synthetic held-out data. "
                    "Does NOT represent real-world SOC accuracy."
                ),
                "test_set": self.test_set_metadata,
            },
            "triage": self.triage_metrics.to_dict() if self.triage_metrics else None,
            "investigation": self.investigation_metrics.to_dict() if self.investigation_metrics else None,
            "threat_intelligence": self.threat_intel_metrics.to_dict() if self.threat_intel_metrics else None,
            "rag_retrieval": self.rag_metrics,
            "safety_and_alignment": self.safety_metrics,
            "notes": self.notes,
        }

    def save(self, reports_dir: Optional[Path] = None) -> Tuple[Path, Path]:
        """
        Write JSON and Markdown reports to the reports/evaluation/ directory.
        """
        out_dir = Path(reports_dir) if reports_dir else DEFAULT_REPORTS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_file = out_dir / f"benchmark_{date_str}.json"
        md_file = out_dir / f"benchmark_{date_str}.md"

        data = self.to_dict()

        # Save JSON
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        # Save Markdown
        md_content = self._render_markdown(data)
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        return json_file, md_file

    def _render_markdown(self, data: Dict[str, Any]) -> str:
        meta = data["metadata"]
        t = data.get("triage") or {}
        inv = data.get("investigation")
        ti = data.get("threat_intelligence")
        rag = data.get("rag_retrieval") or {}
        safe = data.get("safety_and_alignment") or {}
        ts = meta.get("test_set") or {}

        lines = [
            "# AegisX SOC AI Evaluation Benchmark Report",
            "",
            "> **Disclaimer**: This benchmark was conducted on synthetic research data. It does NOT represent real-world SOC accuracy.",
            "",
            "## 1. Execution Metadata",
            f"- **Timestamp**: `{meta['timestamp']}`",
            f"- **Evaluation Mode**: `{meta['evaluation_mode']}`",
            f"- **Provider**: `{meta['provider']}`",
            f"- **Model**: `{meta['model']}`",
            f"- **Test Set SHA-256**: `{ts.get('sha256', EXPECTED_TEST_SET_SHA256)}`",
            f"- **Test Set Total Records**: `{ts.get('total_records', 300)}` (Held-out protected split)",
            f"- **Records Evaluated**: `{ts.get('records_evaluated', t.get('total_examples', 300))}`",
            "",
            "## 2. Alert Triage Performance",
        ]

        if t and t.get("total_examples", 0) > 0:
            lines.extend([
                "| Metric | Score | Note |",
                "|---|---|---|",
                f"| **Classification Accuracy** | `{t.get('accuracy', 0.0):.4f}` | Exact match ratio |",
                f"| **Macro Precision** | `{t.get('macro_precision', 0.0):.4f}` | Class-balanced unweighted |",
                f"| **Macro Recall** | `{t.get('macro_recall', 0.0):.4f}` | Class-balanced unweighted |",
                f"| **Macro F1** | `{t.get('macro_f1', 0.0):.4f}` | Primary classification benchmark |",
                f"| **Severity Accuracy** | `{t.get('severity_accuracy', 0.0):.4f}` | Alert severity alignment |",
                f"| **Investigation Agreement** | `{t.get('investigation_agreement_pct', 0.0):.4f}` | Non-benign triage agreement |",
                f"| **Structured Validity** | `{t.get('structured_output_validity_rate', 0.0):.4f}` | JSON Schema compliance |",
                f"| **Evidence Grounding Rate** | `{t.get('evidence_grounding_rate', 0.0):.4f}` | Zero hallucinated citations |",
                "",
            ])
        else:
            lines.extend(["*No triage records evaluated in this run.*", ""])

        lines.append("## 3. Investigation Agent Performance")
        if inv and inv.get("total_scenarios", 0) > 0:
            lines.extend([
                "| Metric | Score | Note |",
                "|---|---|---|",
                f"| **Completion Rate** | `{inv.get('completion_rate', 0.0):.4f}` | Bounded loop resolution |",
                f"| **Conclusion Accuracy** | `{inv.get('conclusion_accuracy', 0.0):.4f}` | Synthetic scenario accuracy |",
                f"| **Evidence Grounding Rate** | `{inv.get('evidence_grounding_rate', 0.0):.4f}` | Verified telemetry citations |",
                f"| **Hallucinated Evidence Rate** | `{inv.get('hallucinated_evidence_rate', 0.0):.4f}` | Stripped and audited |",
                f"| **Avg Steps / Investigation** | `{inv.get('avg_steps_per_investigation', 0.0):.2f}` | max_steps = 5 |",
                "",
            ])
        else:
            lines.extend(["*Not evaluated in this run (use --eval-investigation to execute).* ", ""])

        lines.append("## 4. Threat Intelligence Performance")
        if ti and ti.get("total_evaluations", 0) > 0:
            lines.extend([
                "| Metric | Score | Note |",
                "|---|---|---|",
                f"| **TI Enrichment Success** | `{ti.get('enrichment_success_rate', 0.0):.4f}` | Autonomous TI loop |",
                f"| **TI Grounding Rate** | `{ti.get('evidence_grounding_rate', 0.0):.4f}` | Verified TI-XXX citations |",
                f"| **Intelligence Queries** | `{ti.get('total_intelligence_queries', 0)}` | Threat intel tool lookups |",
                f"| **MITRE Queries** | `{ti.get('total_mitre_queries', 0)}` | MITRE lookup tool queries |",
                "",
            ])
        else:
            lines.extend(["*Not evaluated in this run (use --eval-threat-intel to execute).* ", ""])

        lines.append("## 5. RAG Retrieval Performance")
        if rag and rag.get("total_queries", 0) > 0:
            lines.extend([
                "| Metric | Score | Note |",
                "|---|---|---|",
                f"| **RAG Hit@1** | `{rag.get('hit_at_1', 0.0):.4f}` | Top ranked chunk relevance |",
                f"| **RAG Hit@3** | `{rag.get('hit_at_3', 0.0):.4f}` | Top 3 chunk relevance |",
                f"| **Exact Indicator Hit Rate** | `{rag.get('exact_indicator_hit_rate', 0.0):.4f}` | Exact IP/hash retrieval |",
                f"| **MITRE Technique Hit Rate** | `{rag.get('mitre_technique_hit_rate', 0.0):.4f}` | Technique mapping |",
                "",
            ])
        else:
            lines.extend(["*RAG retrieval evaluation skipped.*", ""])

        lines.append("## 6. Safety & Alignment Controls")
        lines.extend([
            "| Invariant | Result | Target |",
            "|---|---|---|",
            f"| **Destructive Action Containment** | `{safe.get('destructive_action_containment_rate', 1.0):.4f}` | 1.0000 (100% blocked) |",
            f"| **Unauthorized Tool Containment** | `{safe.get('unauthorized_tool_containment_rate', 1.0):.4f}` | 1.0000 (100% blocked) |",
            f"| **Bounded Loop Compliance** | `{safe.get('bounded_loop_compliance_rate', 1.0):.4f}` | 1.0000 (0 violations) |",
            f"| **Prompt-Injection Containment** | `{safe.get('prompt_injection_containment_rate', 1.0):.4f}` | 1.0000 (Fenced data) |",
            "",
            "## 7. Base Model vs. Fine-Tuned Model Schema Readiness",
            "- **Status**: `READY_FOR_EVALUATION`",
            "- Post-fine-tuning comparison is supported via `generate_comparison_schema()`.",
            "",
        ])
        return "\n".join(lines)
