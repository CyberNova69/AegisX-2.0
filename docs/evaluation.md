# AegisX — AI Evaluation & Benchmarking Framework (Phase 5 Part 5)

> **Critical Notice**: The v0.4 test set (`datasets/finetuning/v0.4/test.jsonl`) is held out and must remain untouched until final evaluation.  
> This evaluation framework is strictly evaluation-only. It establishes reproducible baselines before model fine-tuning without modifying test data.

---

## 1. Overview and Purpose

The AegisX Evaluation Framework provides standardized, multi-component benchmarking across the entire SOC AI pipeline:
1. **Alert Triage Evaluation**: Accuracy, Macro Precision/Recall/F1, Severity alignment, and investigation decision agreement.
2. **Investigation Evaluation**: Bounded loop completion, scenario conclusion accuracy, and evidence grounding.
3. **Threat Intelligence Evaluation**: Autonomous indicator discovery, intelligence correlation, and technique mapping.
4. **RAG Retrieval Evaluation**: Independent sparse BM25 retrieval precision (Hit@1, Hit@3, Hit@5), indicator recall, and latency statistics.
5. **Safety & Contract Invariants**: Enforces 100% containment of destructive actions, unauthorized tool calls, max-step violations, hallucinated evidence IDs, and prompt-injection containment.
6. **Reproducible Reporting**: Generates machine-readable JSON and human-readable Markdown reports under `reports/evaluation/`.
7. **Base vs. Fine-Tuned Model Comparison**: Standardized delta schema ready to evaluate fine-tuned LoRA checkpoints against the baseline model.

---

## 2. Evaluation Architecture

```text
datasets/finetuning/v0.4/test.jsonl (Protected 300 records)
                   │
                   ▼  [Strict Test-Set Firewall: Read-Only]
          [Test Set Loader]
                   │
                   ├────────────────────────┬────────────────────────┐
                   ▼                        ▼                        ▼
           [Triage Evaluator]     [Investigation Evaluator]  [Threat Intel Evaluator]
           (Accuracy, Macro F1,    (Completion, Grounding,    (Queries, Indicators,
            Confusion Matrix)      Steps, Conclusions)        Attribution, Grounding)
                   │                        │                        │
                   └────────────────────────┼────────────────────────┘
                                            │
                                            ▼
                                   [RAG Retrieval Evaluator]
                                   (Hit@1, Hit@3, Hit@5, Latency)
                                            │
                                            ▼
                                   [Safety & Alignment Audit]
                                   (Zero destructive, Zero injections,
                                    Zero hallucinations allowed)
                                            │
                                            ▼
                                 [Benchmark Orchestrator]
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
       reports/evaluation/benchmark_*.json           reports/evaluation/benchmark_*.md
```

---

## 3. Test-Set Firewall

The test-set firewall (`ai/evaluation/test_set_firewall.py`) enforces strict isolation:
- **Read-Only Verification**: The evaluation loader strictly opens `test.jsonl` in read-only mode (`"r"`). Any modifying mode (`"w"`, `"a"`, `"+"`, `"x"`) raises `FirewallViolationError`.
- **Training Pipeline Isolation**: Verifies that fine-tuning preparation scripts (`finetuning/prepare_sft_dataset.py`) and dataset outputs exclude `test.jsonl`.
- **Integrity Validation**: Computes SHA-256 and verifies the golden checksum:
  - `BFF898861F75A0982D6C2F6EFDBA99F0C5E8549A4B0EA72A687E91A8D80A4333`
  - Exactly 300 records.

---

## 4. Evaluated Metrics Summary

### A. Alert Triage Metrics
- **Accuracy**: Exact match ratio across the 5 classification classes (`benign`, `suspicious`, `likely_malicious`, `confirmed_malicious`, `insufficient_evidence`).
- **Macro Precision, Recall, and F1**: Unweighted macro-average across classes, providing balanced assessment for class-balanced test sets.
- **Confusion Matrix**: Full 5x5 prediction matrix.
- **Severity Accuracy**: Exact match on alert severity.
- **Investigation Agreement**: Agreement on whether the alert warrants investigation.
- **Structured Output Validity**: Rate of schema-compliant JSON outputs.

### B. Investigation Metrics
- **Completion Rate**: Fraction of investigations reaching a terminal conclusion within bounds.
- **Conclusion Accuracy**: Accuracy against expected scenario outcomes.
- **Evidence Grounding Rate**: Percentage of findings backed strictly by verified telemetry IDs.
- **Hallucinated Evidence Rate**: Stripped and logged ungrounded citations.
- **Average Steps**: Steps consumed per investigation (must be $\le 5$).

### C. Threat Intelligence & RAG Retrieval Metrics
- **Hit@1, Hit@3, Hit@5**: Proportion of queries where relevant intelligence chunks rank within top-K.
- **Exact Indicator Hit Rate**: Success rate retrieving exact IP/hash profiles.
- **Unknown Indicator Rejection Rate**: Correct rejection / below-threshold scoring for unrecorded indicators.
- **Retrieval Latency**: Millisecond distribution (average, median, p95).

### D. Safety & Alignment Controls
- **Destructive Action Containment**: Expected 1.0000 (100% blocked).
- **Unauthorized Tool Containment**: Expected 1.0000 (100% blocked).
- **Bounded Loop Compliance**: Zero runaway loops.
- **Prompt-Injection Containment**: Fenced untrusted data isolation.

---

## 5. Report Locations & Artifacts

All benchmark outputs are persisted in:
```text
reports/evaluation/
├── benchmark_YYYYMMDD_HHMMSS.json   # Full machine-readable metrics & confusion matrices
└── benchmark_YYYYMMDD_HHMMSS.md     # Markdown executive summary
```

---

## 6. Offline Testing vs. Real API Evaluation

- **Offline Unit Testing (Default)**: Uses `MockProvider` and deterministic synthetic scenarios. Zero API cost, zero network dependence, executes in milliseconds.
- **Real API Evaluation**: Enabled via `--provider api --model <model-name>`.
- **Diagnostic Transparency**: If the API provider is unavailable, the evaluator reports the failure cleanly rather than substituting mock results and mislabeling them.

---

## 7. Base vs. Fine-Tuned Model Comparison Methodology

The framework includes `generate_comparison_schema(base_metrics, finetuned_metrics)`:
- Computes exact deltas for Accuracy, Macro F1, Severity Accuracy, Grounding Rate, and Latency.
- Flags whether the delta represents an improvement (e.g. higher accuracy or lower hallucination rate).
- Facilitates side-by-side benchmarking when fine-tuned weights are trained on the college GPU.

---

## 8. Running the Evaluation Suite

```bash
# Run all evaluation framework unit tests (15 tests)
python -m unittest tests/test_evaluation_framework.py -v

# Run full project regression suite (213 tests)
python -m unittest discover -s tests -p "test_*.py"

# Run the benchmark runner on a sample of the held-out test set
python -m ai.evaluation.evaluate --sample-size 10 --output-dir reports/evaluation
```
