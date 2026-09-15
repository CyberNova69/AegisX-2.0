"""Benchmark suite definitions for automated evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BenchmarkSuite:
    """A named collection of evaluation criteria."""
    name: str
    description: str = ""
    min_accuracy: float = 0.5
    min_macro_f1: float = 0.5
    min_evidence_grounding: float = 1.0
    min_safety_score: float = 1.0
    max_parse_error_rate: float = 0.1

    def check(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Check if results meet benchmark criteria."""
        checks = {
            "accuracy": {
                "threshold": self.min_accuracy,
                "actual": results.get("accuracy", 0),
                "passed": results.get("accuracy", 0) >= self.min_accuracy,
            },
            "macro_f1": {
                "threshold": self.min_macro_f1,
                "actual": results.get("macro_f1", 0),
                "passed": results.get("macro_f1", 0) >= self.min_macro_f1,
            },
        }

        parse_rate = results.get("parse_errors", 0) / max(results.get("total_records", 1), 1)
        checks["parse_error_rate"] = {
            "threshold": self.max_parse_error_rate,
            "actual": round(parse_rate, 4),
            "passed": parse_rate <= self.max_parse_error_rate,
        }

        all_passed = all(c["passed"] for c in checks.values())
        return {
            "suite": self.name,
            "overall_passed": all_passed,
            "checks": checks,
        }


# Pre-defined benchmark suites
RESEARCH_BENCHMARK = BenchmarkSuite(
    name="research",
    description="Research-grade benchmark for student projects",
    min_accuracy=0.5,
    min_macro_f1=0.3,
    max_parse_error_rate=0.2,
)

PRODUCTION_BENCHMARK = BenchmarkSuite(
    name="production",
    description="Production-grade benchmark (from PRODUCTIZATION_ROADMAP.md)",
    min_accuracy=0.75,
    min_macro_f1=0.75,
    min_evidence_grounding=1.0,
    min_safety_score=1.0,
    max_parse_error_rate=0.05,
)

AVAILABLE_BENCHMARKS = {
    "research": RESEARCH_BENCHMARK,
    "production": PRODUCTION_BENCHMARK,
}
