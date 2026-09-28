# AegisX 2.0 — Document Cleanup Decision Table

**Date:** 2026-09-23
**Method:** Content-level audit of every markdown/text/report document in the repo.
**Duplicate detection:** SHA-256 hash comparison + heading/content similarity analysis.

---

## Legend

| Category | Meaning |
|----------|---------|
| **KEEP** | Important final project documentation or unique evidence |
| **ARCHIVE** | Historically useful but not needed in main structure → `archive/` |
| **MERGE** | Contains useful info duplicated across files → consolidate |
| **DELETE** | Clearly duplicate, temporary, generated, obsolete, or irrelevant |
| **REVIEW_REQUIRED** | Cannot safely determine purpose — needs your decision |

---

## 1. Root-Level Files

| File | Size | Category | Reason | Replacement/Source of Truth |
|------|------|----------|--------|-----------------------------|
| `README.md` | 4.4 KB | **KEEP** | Project root README | — |
| `.env` | 617 B | **KEEP** | Active config (review secrets before transfer) | `.env.example` |
| `.env.example` | 559 B | **KEEP** | Template for env vars | — |
| `.gitignore` | 998 B | **KEEP** | Git config | — |
| `requirements.txt` | 461 B | **KEEP** | Production dependencies | — |
| `requirements-finetuning.txt` | 430 B | **KEEP** | GPU training dependencies | — |
| `PHASE_1_5_COMPREHENSIVE_AUDIT_REPORT.txt` | 11 KB | **ARCHIVE** | Historical Phase 1-5 audit by Claude Code (2026-09-05). Superseded by later reports. | `archive/other/` |
| `analyze_boundaries.py` | 9.8 KB | **DELETE** | Scratch Phase 3 analysis script — not imported by anything | — |
| `run_controlled_experiment.py` | 9.5 KB | **DELETE** | Scratch Phase 3 experiment runner — not imported by anything | — |
| `check_results.py` | 437 B | **DELETE** | Trivial scratch script | — |
| `output.txt` | 29 B | **DELETE** | Temporary output file | — |
| `output_100k.txt` | 30 B | **DELETE** | Temporary output file | — |
| `output_300k.txt` | 80 B | **DELETE** | Temporary output file | — |
| `output_400k.txt` | 81 B | **DELETE** | Temporary output file | — |
| `timing.txt` | 112 B | **DELETE** | Temporary timing output | — |

---

## 2. `docs/` Directory (15 files)

### Overlap Analysis

The `docs/` folder contains **5 dataset-related documents** that form a historical chain:
- `fine_tuning_dataset_audit.md` (v0.2 audit)
- `fine_tuning_dataset_v0.3.md` (v0.3 report)
- `fine_tuning_dataset_v0.4.md` (v0.4 report)
- `fine_tuning_dataset_v0.5_design.md` (v0.5 design spec)
- `phase1_dataset_audit.md` (comprehensive v0.2-v0.4 audit)
- `phase1_v0.5_improvement_report.md` (v0.5 implementation report)

These 6 documents describe the **same dataset evolution** with significant overlap. The `phase1_dataset_audit.md` (25 KB) supersedes `fine_tuning_dataset_audit.md` (34 KB), and `phase1_v0.5_improvement_report.md` supersedes the v0.5 design doc.

| File | Size | Category | Reason | Replacement/Source of Truth |
|------|------|----------|--------|-----------------------------|
| `RERANKER_INTEGRATION.md` | 8.5 KB | **KEEP** | Authoritative RAG/reranker architecture doc. Unique content. | becomes `docs/RAG.md` |
| `PRODUCTIZATION_ROADMAP.md` | 12.3 KB | **KEEP** | Comprehensive gap analysis and roadmap (2026-09-04). Unique strategic content. | — |
| `investigation_agent.md` | 11 KB | **KEEP** | Phase 4 investigation agent architecture. Unique, references active code. | contributes to `docs/ARCHITECTURE.md` |
| `threat_intel_and_rag.md` | 7.4 KB | **ARCHIVE** | Phase 5 RAG/TI documentation. Largely superseded by `RERANKER_INTEGRATION.md`. | `archive/rag/` |
| `evaluation.md` | 7.6 KB | **KEEP** | Evaluation framework documentation. References active code. | becomes `docs/EVALUATION.md` |
| `dataset_pipeline.md` | 4.7 KB | **ARCHIVE** | v0.2 dataset pipeline documentation. Superseded by v0.5 and v1.0 dataset reality. | `archive/training/` |
| `llm_interface.md` | 3.9 KB | **KEEP** | LLM abstraction layer documentation. Concise, references active code. | contributes to `docs/ARCHITECTURE.md` |
| `triage_agent.md` | 5 KB | **KEEP** | Triage agent architecture. References active code. | contributes to `docs/ARCHITECTURE.md` |
| `college_gpu_finetuning_runbook.md` | 6.5 KB | **KEEP** | Actionable GPU training runbook. Directly useful for RTX laptop. | becomes `docs/TRAINING.md` |
| `fine_tuning_dataset_audit.md` | 34 KB | **ARCHIVE** | v0.2 dataset audit. Superseded by `phase1_dataset_audit.md`. | `archive/training/` |
| `fine_tuning_dataset_v0.3.md` | 19.5 KB | **ARCHIVE** | v0.3 dataset report. Historical; v0.5/v1.0 are current. | `archive/training/` |
| `fine_tuning_dataset_v0.4.md` | 16.2 KB | **ARCHIVE** | v0.4 dataset report. Historical; v0.5/v1.0 are current. | `archive/training/` |
| `fine_tuning_dataset_v0.5_design.md` | 10.1 KB | **ARCHIVE** | v0.5 design spec. Implemented; result report supersedes. | `archive/training/` |
| `phase1_dataset_audit.md` | 25.3 KB | **KEEP** | Comprehensive dataset foundation audit (v0.2-v0.4). Unique findings. | becomes `docs/DATASET.md` |
| `phase1_v0.5_improvement_report.md` | 18.7 KB | **KEEP** | v0.5 implementation report with unique validation evidence. | merged into `docs/DATASET.md` |
| `PRE_TRANSFER_AUDIT.md` | ~15 KB | **DELETE** | Created during this audit; superseded by this decision table + final manifest. | This document replaces it. |

---

## 3. `reports/backend/` (14 files)

### Overlap Analysis

3 PostgreSQL reports with heavily overlapping content (audit-implement-verify chain). Also 3 P0 backend reports that form a similar chain.

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `FINAL_P0_BACKEND_VERIFICATION.md` | 33.9 KB | **KEEP** | Final comprehensive backend audit (588 tests). Supersedes all prior. | Authoritative backend doc |
| `P0_BACKEND_E2E_VERIFICATION.md` | 24 KB | **ARCHIVE** | Intermediate audit, superseded by FINAL | `archive/other/` |
| `P0_BACKEND_INTEGRATION_CLOSURE_REPORT.md` | 11.1 KB | **ARCHIVE** | Intermediate closure, superseded by FINAL | `archive/other/` |
| `POSTGRESQL_RUNTIME_PERSISTENCE_VERIFICATION.md` | 24.3 KB | **KEEP** | Most complete PostgreSQL verification. Unique DDL audit. | Authoritative DB doc |
| `POSTGRESQL_RUNTIME_INVESTIGATION_AUDIT.md` | 24.9 KB | **ARCHIVE** | Planning audit, superseded by implementation + verification | `archive/other/` |
| `POSTGRESQL_RUNTIME_IMPLEMENTATION_REPORT.md` | 9.3 KB | **ARCHIVE** | Implementation report, superseded by persistence verification | `archive/other/` |
| `RAG_LLM_GROUNDING_VERIFICATION.md` | 15.1 KB | **KEEP** | Verifies RAG-LLM grounding chain. Unique verification evidence. | — |
| `RAG_RUNTIME_GROUNDING_REPORT.md` | 12.7 KB | **ARCHIVE** | Fix implementation report, superseded by verification | `archive/rag/` |
| `AGENT_TRACE_AUDIT_LOG_VERIFICATION.md` | 13.1 KB | **KEEP** | Unique agent trace verification. Not duplicated. | — |
| `D01_DASHBOARD_ALERT_STORE_FIX_REPORT.md` | 4.6 KB | **ARCHIVE** | One-time bug fix report. | `archive/other/` |
| `LIVE_DB_INVESTIGATION_WORKFLOW_VERIFICATION.md` | 10.9 KB | **KEEP** | Live DB workflow verification. Unique runtime evidence. | — |
| `PHASE2_PRODUCTIZATION_JWT_AUDIT_REPORT.md` | 7 KB | **KEEP** | JWT/RBAC security audit. Unique auth evidence. | — |
| `REAL_POSTGRESQL_E2E_RUNTIME_VERIFICATION.md` | 5.9 KB | **ARCHIVE** | Content covered by POSTGRESQL_RUNTIME_PERSISTENCE | `archive/other/` |
| `RESPONSE_SAFETY_HUMAN_APPROVAL_VERIFICATION.md` | 15.1 KB | **KEEP** | Safety invariant verification. Critical security evidence. | — |

---

## 4. `reports/evaluation/` (15 files)

7 timestamped benchmark runs (JSON + MD pairs). The **last two runs** (2026-09-04) used `REAL_API_BENCHMARK` mode and are the only valuable ones.

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `benchmark_20260903_122251.json` | 8.3 KB | **DELETE** | Mock benchmark. Superseded. | — |
| `benchmark_20260903_122305.json` | 8.3 KB | **DELETE** | Mock benchmark. Superseded. | — |
| `benchmark_20260903_122305.md` | 2.5 KB | **DELETE** | Mock benchmark report. Superseded. | — |
| `benchmark_20260903_123552.json` | 8.3 KB | **DELETE** | Mock benchmark. Superseded. | — |
| `benchmark_20260903_123552.md` | 2.5 KB | **DELETE** | Mock benchmark report. Superseded. | — |
| `benchmark_20260903_123757.json` | 8.3 KB | **DELETE** | Mock benchmark. Superseded. | — |
| `benchmark_20260903_123757.md` | 2.5 KB | **DELETE** | Mock benchmark report. Superseded. | — |
| `benchmark_20260903_123908.json` | 8.3 KB | **DELETE** | Mock benchmark. Superseded. | — |
| `benchmark_20260903_123908.md` | 2.5 KB | **DELETE** | Mock benchmark report. Superseded. | — |
| `benchmark_20260903_124820.json` | 6.8 KB | **DELETE** | Mock benchmark. Superseded. | — |
| `benchmark_20260903_124820.md` | 2.2 KB | **DELETE** | Mock benchmark report. Superseded. | — |
| `benchmark_20260904_050251.json` | 6.8 KB | **KEEP** | Real API benchmark (first). Unique baseline. | — |
| `benchmark_20260904_050251.md` | 2.2 KB | **KEEP** | Real API benchmark report. | — |
| `benchmark_20260904_051013.json` | 6.9 KB | **KEEP** | Real API benchmark (final). Current baseline. | — |
| `benchmark_20260904_051013.md` | 2.2 KB | **KEEP** | Real API benchmark report (final). | — |

---

## 5. `reports/phase3/` (25 items)

Most redundancy-heavy directory. Phase 3 prompt accuracy improvement cycle with many intermediate AI-generated reports.

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `SUMMARY_OF_IMPROVEMENTS.md` | 4 KB | **KEEP** | Concise final summary of Phase 3. | — |
| `PHASE_3_ACCURACY_ROOT_CAUSE_AUDIT.md` | 24.9 KB | **KEEP** | Unique root cause analysis. Definitive diagnostic doc. | — |
| `PHASE_3_PROMPT_V2_ERROR_ANALYSIS.md` | 49.1 KB | **ARCHIVE** | Massive auto-generated error analysis. Raw data. | `archive/evaluation/` |
| `PHASE_3_PROMPT_DESIGN_REVIEW.md` | 17.2 KB | **ARCHIVE** | Intermediate design review. Superseded. | `archive/evaluation/` |
| `PHASE_3_ACCURACY_DEEP_AUDIT.md` | 10.2 KB | **ARCHIVE** | Intermediate audit, superseded by ROOT_CAUSE | `archive/evaluation/` |
| `PHASE_3_ACCURACY_IMPROVEMENT_REPORT.md` | 8.5 KB | **ARCHIVE** | Intermediate, superseded by SUMMARY | `archive/evaluation/` |
| `PHASE_3_LABEL_BOUNDARY_AUDIT.md` | 15.1 KB | **ARCHIVE** | Intermediate boundary analysis. | `archive/evaluation/` |
| `PHASE_3_CONTROLLED_EXPERIMENT_READINESS.md` | 4.7 KB | **DELETE** | Pre-experiment readiness. Obsolete. | — |
| `PHASE_3_CONTROLLED_PROMPT_EXPERIMENT.md` | 6.3 KB | **DELETE** | Experiment plan. Executed. Obsolete. | — |
| `PHASE_3_PROMPT_EXPERIMENT_V2_PREPARATION.md` | 9.1 KB | **DELETE** | Preparation notes. Superseded by execution. | — |
| `PHASE_3_PROMPT_EXPERIMENT_V2_HARNESS_REPAIR.md` | 11.4 KB | **DELETE** | Harness repair notes. Bug was fixed. | — |
| `PHASE_3_PROMPT_EXPERIMENT_V2_PATH_FIX.md` | 8.3 KB | **DELETE** | Path fix notes. Bug was fixed. | — |
| `PHASE_3_PROMPT_INTEGRITY_REPAIR.md` | 3.6 KB | **DELETE** | Integrity repair notes. Bug was fixed. | — |
| `NEXT_ACCURACY_STEP_RECOMMENDATION.md` | 14.6 KB | **ARCHIVE** | Forward-looking recommendation. | `archive/evaluation/` |
| `baseline_prompt.txt` | 2 KB | **DELETE** | **EXACT DUPLICATE** of `ai/prompts/triage/system.txt` (SHA-256 match) | Production file |
| `experimental_prompt.txt` | 3.4 KB | **ARCHIVE** | Experimental prompt variant. Historical. | `archive/evaluation/` |
| `PHASE_3_EXPERIMENTAL_PROMPT_V2.txt` | 6 KB | **ARCHIVE** | Experimental prompt V2. Historical. | `archive/evaluation/` |
| `PHASE_3_EXPERIMENTAL_PROMPT_V3.txt` | 7 KB | **ARCHIVE** | Experimental prompt V3. Historical. | `archive/evaluation/` |
| `controlled_baseline_results.json` | 6.6 KB | **DELETE** | Raw JSON experiment output. | — |
| `controlled_prompt_experiment_manifest.json` | 2.4 KB | **DELETE** | Raw JSON manifest. | — |
| `PHASE_3_PROMPT_EXPERIMENT_V2_MANIFEST.json` | 2.6 KB | **DELETE** | Raw JSON manifest. | — |
| `experiment_v2/` | dir | **DELETE** | Raw experiment output directory. | — |
| `experiment_v2_mock/` | dir | **DELETE** | Mock experiment output. | — |
| `experiment_v3/` | dir | **DELETE** | Raw experiment output. | — |
| `experiment_v3_clean/` | dir | **DELETE** | Cleaned experiment output. | — |

---

## 6. `reports/fine_tuning/` (9 files + 1 backup)

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `CLASSIFICATION_TAXONOMY_ALIGNMENT_AUDIT.md` | 23 KB | **KEEP** | Unique taxonomy alignment analysis. | — |
| `DATA_PIPELINE_AUDIT.md` | 21.5 KB | **KEEP** | Comprehensive data pipeline audit. | — |
| `END_TO_END_COMPATIBILITY_AUDIT.md` | 12.9 KB | **ARCHIVE** | Content covered by later verifications. | `archive/training/` |
| `LABEL_TAXONOMY_VERIFICATION.md` | 10.7 KB | **ARCHIVE** | Content in TAXONOMY_ALIGNMENT. | `archive/training/` |
| `P0_P1_REPAIR_VERIFICATION.md` | 13.2 KB | **ARCHIVE** | Intermediate repair verification. | `archive/training/` |
| `REAL_EXTERNAL_CORPUS_INTEGRATION_REPORT.md` | 4.5 KB | **KEEP** | External corpus integration. Unique. | — |
| `SCALE_300K_400K_VERIFICATION.md` | 14.4 KB | **DELETE** | For sft_benchmark data being deleted. | — |
| `SCALE_300K_400K_VERIFICATION.md.backup` | 13.8 KB | **DELETE** | Backup of above. Duplicate. | — |
| `TAXONOMY_ALIGNMENT_VERIFICATION.md` | 8.5 KB | **ARCHIVE** | Content in CLASSIFICATION_TAXONOMY_ALIGNMENT_AUDIT. | `archive/training/` |

---

## 7. `reports/demo/` (5 files)

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `pipeline_dashboard.html` | 33.3 KB | **ARCHIVE** | HTML demo. Not production code. | `archive/other/` |
| `pipeline_results.json` | 111 KB | **ARCHIVE** | Demo results. Not documentation. | `archive/other/` |
| `check_report.json` | 1.6 KB | **DELETE** | Trivial check output. | — |
| `ingestion_smoke_report.json` | 1.4 KB | **DELETE** | Smoke test output. | — |
| `processing_smoke_report.json` | 7 KB | **DELETE** | Processing smoke test output. | — |

---

## 8. `reports/git/` (3 files)

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `GIT_SYNC_AUDIT.md` | 15.6 KB | **DELETE** | One-time git sync operation. Completed. | — |
| `GIT_SYNC_PREPARATION.md` | 5.5 KB | **DELETE** | Completed. | — |
| `GIT_SYNC_RESULT.md` | 3.1 KB | **DELETE** | Completed. | — |

---

## 9. `reports/` (standalone)

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `phase1_dataset_audit.json` | 80.8 KB | **DELETE** | Raw JSON audit data. MD version in docs/ has this content. | `docs/phase1_dataset_audit.md` |

---

## 10. `experiments/toolkit_rag/` Documents (14 files)

### Overlap: RAG_COMPARISON.md vs TOOLKIT_RAG_COMPARISON.md vs AEGISX_TOOLKIT_COMPARISON.md

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `README.md` | 1.6 KB | **KEEP** | Experiment directory index | — |
| `ADOPTION_PLAN.md` | 10.1 KB | **KEEP** | Final adoption recommendation. Unique. | — |
| `ARCHITECTURE_AFTER_AUDIT.md` | 12.3 KB | **KEEP** | Post-audit architecture proposal. Unique. | — |
| `TOOLKIT_RAG_COMPARISON.md` | 6.6 KB | **KEEP** | Auto-generated benchmark results. Unique data. | — |
| `ERROR_ANALYSIS.md` | 25 KB | **KEEP** | Query-by-query error analysis. Unique evidence. | — |
| `DATASET_PROFILE.md` | 4.8 KB | **KEEP** | RAG corpus profile. Unique characterization. | — |
| `PHASE1_RESULTS.md` | 6.5 KB | **KEEP** | Hybrid RAG experiment results. Unique. | — |
| `PERFORMANCE_REPORT.md` | 1.3 KB | **KEEP** | Latency/performance data. Unique metrics. | — |
| `EXISTING_RAG_INTERFACE.md` | 4.4 KB | **ARCHIVE** | Interface docs for comparison. Now in active code. | `archive/rag/` |
| `ENVIRONMENT.md` | 1.9 KB | **DELETE** | Environment snapshot. Duplicated in toolkit_setup/ENVIRONMENT.md. | — |
| `RAG_COMPARISON.md` | 9.3 KB | **ARCHIVE** | Overlaps with TOOLKIT_RAG_COMPARISON and AEGISX_TOOLKIT_COMPARISON. | `archive/rag/` |
| `AEGISX_TOOLKIT_COMPARISON.md` | 7.7 KB | **ARCHIVE** | Overlaps with RAG_COMPARISON. | `archive/rag/` |
| `TOOLKIT_AUDIT.md` | 10.5 KB | **ARCHIVE** | Overlaps with TOOLKIT_RAG_CANDIDATES. | `archive/rag/` |
| `TOOLKIT_RAG_CANDIDATES.md` | 10.7 KB | **ARCHIVE** | Overlaps with TOOLKIT_AUDIT. | `archive/rag/` |

---

## 11. `experiments/toolkit_setup/` Documents (5 files)

| File | Size | Category | Reason | Replacement |
|------|------|----------|--------|-------------|
| `README.md` | 2.6 KB | **KEEP** | Phase 9 completion record | — |
| `ENVIRONMENT.md` | 4.2 KB | **KEEP** | Environment documentation | — |
| `LIBRARY_MATRIX.md` | 5.7 KB | **KEEP** | Library compatibility matrix. Unique. | — |
| `TOOLKIT_LIBRARY_AUDIT.md` | 12.9 KB | **KEEP** | Library-by-library audit results. Unique. | — |
| `requirements.txt` | 650 B | **KEEP** | Toolkit-specific requirements | — |

---

## 12. Exact Duplicates Found

| File A | File B | Hash Match | Decision |
|--------|--------|------------|----------|
| `ai/prompts/triage/system.txt` | `reports/phase3/baseline_prompt.txt` | `8C9C6E6E68BE` | **DELETE** baseline_prompt.txt |
| `ai/prompts/attack_story/system.txt` | `ai/prompts/common/security_instructions.txt` | `E3B0C44298FC` | Both **empty (0 B)**. KEEP as stubs. |
| `SCALE_300K_400K_VERIFICATION.md` | `SCALE_300K_400K_VERIFICATION.md.backup` | Near-identical | **DELETE** .backup |

---

## 13. Large Non-Document Items

| Item | Size | Category | Reason |
|------|------|----------|--------|
| `sft_benchmark/` | 5,787 MB | **DELETE** | Regenerable benchmark data. Preserve scripts first. |
| `temp_sft_benchmark/` | ~0 MB | **DELETE** | Temporary directory |
| `scratch/` (root) | ~0 MB | **DELETE** | 3 scratch files |
| `.workbuddy-ai/` | ~0 MB | **DELETE** | External AI agent artifacts |
| `.pytest_cache/` | ~0.1 MB | **DELETE** | Test cache |
| `__pycache__/` (50 dirs) | ~3.8 MB | **DELETE** | Python bytecode cache |
| `.venv/` | 11.4 MB | **EXCLUDE** | Do not copy to pendrive; recreate on target |

---

## 14. Summary Statistics

| Category | Count | Action |
|----------|-------|--------|
| **KEEP** | ~40 files | Remain in project tree |
| **ARCHIVE** | ~25 files | Move to `archive/` subdirectories |
| **DELETE** | ~35 files + 5,790 MB dirs | Remove permanently |
| **REVIEW_REQUIRED** | 0 | All items classified |

---

## 15. Proposed Final `docs/` Structure

```
docs/
  ARCHITECTURE.md          (from investigation_agent.md + llm_interface.md + triage_agent.md)
  RAG.md                   (from RERANKER_INTEGRATION.md)
  DATASET.md               (from phase1_dataset_audit.md + phase1_v0.5_improvement_report.md)
  TRAINING.md              (from college_gpu_finetuning_runbook.md)
  EVALUATION.md            (from evaluation.md)
  PRODUCTIZATION_ROADMAP.md (keep as-is)
  PROJECT_STATUS.md         (NEW: single current-state document)
  DOCUMENT_CLEANUP_DECISIONS.md (this file)
```

> [!IMPORTANT]
> Existing authoritative docs (RERANKER_INTEGRATION.md, evaluation.md, etc.) will be **renamed** to standardized names, not rewritten. Content is already the source of truth.

---

## 16. Proposed `archive/` Structure

```
archive/
  rag/
    threat_intel_and_rag.md
    EXISTING_RAG_INTERFACE.md
    RAG_COMPARISON.md
    AEGISX_TOOLKIT_COMPARISON.md
    TOOLKIT_AUDIT.md
    TOOLKIT_RAG_CANDIDATES.md
    RAG_RUNTIME_GROUNDING_REPORT.md
  training/
    dataset_pipeline.md
    fine_tuning_dataset_audit.md
    fine_tuning_dataset_v0.3.md
    fine_tuning_dataset_v0.4.md
    fine_tuning_dataset_v0.5_design.md
    END_TO_END_COMPATIBILITY_AUDIT.md
    LABEL_TAXONOMY_VERIFICATION.md
    P0_P1_REPAIR_VERIFICATION.md
    TAXONOMY_ALIGNMENT_VERIFICATION.md
  evaluation/
    PHASE_3_PROMPT_V2_ERROR_ANALYSIS.md
    PHASE_3_PROMPT_DESIGN_REVIEW.md
    PHASE_3_ACCURACY_DEEP_AUDIT.md
    PHASE_3_ACCURACY_IMPROVEMENT_REPORT.md
    PHASE_3_LABEL_BOUNDARY_AUDIT.md
    NEXT_ACCURACY_STEP_RECOMMENDATION.md
    experimental_prompt.txt
    PHASE_3_EXPERIMENTAL_PROMPT_V2.txt
    PHASE_3_EXPERIMENTAL_PROMPT_V3.txt
  other/
    PHASE_1_5_COMPREHENSIVE_AUDIT_REPORT.txt
    P0_BACKEND_E2E_VERIFICATION.md
    P0_BACKEND_INTEGRATION_CLOSURE_REPORT.md
    POSTGRESQL_RUNTIME_INVESTIGATION_AUDIT.md
    POSTGRESQL_RUNTIME_IMPLEMENTATION_REPORT.md
    REAL_POSTGRESQL_E2E_RUNTIME_VERIFICATION.md
    D01_DASHBOARD_ALERT_STORE_FIX_REPORT.md
    pipeline_dashboard.html
    pipeline_results.json
```
