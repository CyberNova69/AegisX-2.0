# AegisX — Prototype to Product Roadmap

> **Status of this document**: Gap analysis + execution plan. Written against the codebase as of 2026-09-04.
> **Audience**: The AegisX team. Read the "Reality Check" section first.

---

## 1. Reality check

AegisX is a solid research prototype. It is **not** close to a product. Being precise about the gap is more useful than being encouraging.

### What genuinely works

| Area | State | Evidence |
|---|---|---|
| Synthetic dataset pipeline | Mature, 4 iterations (v0.2 → v0.5) | `scripts/generate_dataset*.py`, JSON-Schema validated |
| LLM abstraction | Clean, provider-agnostic, stdlib-only | `ai/llm/` — mock / api / local |
| Triage agent | Implemented + tested | `ai/agents/triage_agent.py`, `tests/test_triage_agent.py` |
| Investigation agent | Implemented + tested, bounded multi-turn loop | `ai/agents/investigation_agent.py` (325 LOC) |
| Read-only tool layer | 6 tools behind a registry | `ai/tools/` |
| Evaluation harness | Real, with held-out split + SHA-256 test-set firewall | `ai/evaluation/` |
| **Safety invariants** | **All 4 at 1.0000** | Destructive containment, unauthorized tool containment, bounded loop compliance, prompt-injection containment |
| Fine-tuning pipeline | Complete QLoRA pipeline, GPU preflight | `finetuning/` (613 LOC trainer) |

The safety engineering is genuinely good. Prompt-injection containment at 100% with fenced data is a real achievement, not a checkbox.

### What is broken or missing

| Gap | Severity | Detail |
|---|---|---|
| **Model accuracy is unusable** | 🔴 Blocker | Classification accuracy `0.30`, macro F1 `0.17`. The product would be wrong ~5 times out of 6. |
| **No backend service** | 🔴 Blocker | Zero API, zero DB, zero persistence. It is a library with CLI scripts. |
| **Orchestrator is an empty file** | 🔴 Blocker | `ai/orchestration/workflow.py` is 0 bytes. Triage never hands off to investigation. |
| **No real data ingestion** | 🔴 Blocker | All telemetry comes from `ai/tools/synthetic_data.py` (953 LOC). Phase 10 is unstarted. |
| **No version control** | 🔴 Blocker | **There is no git repository.** ~20.5k LOC, 14 test files, no history, no backup. |
| **13 empty stub files** | 🟠 High | `ai/orchestration/workflow.py`, `attack_story_agent.py`, `verification_agent.py`, `ai/training/*`, `ai/llm/{model,inference,prompts}.py` |
| **README phase table is stale** | 🟠 High | Lists Orchestration/RAG/Threat-Intel/Evaluation as "⏳ Planned" — all four exist in code |
| **No UI / dashboard** | 🟠 High | Member 3 scope, nothing built |
| **No auth, RBAC, multi-tenancy, audit log** | 🟠 High | Mandatory for security software |
| **No Docker, no CI, no deployment story** | 🟠 High | `requirements.txt` contains only comments |
| **RAG is lexical only** | 🟡 Medium | BM25/TF-IDF in `ai/rag/embeddings.py`. Fast and dependency-free, but no semantic matching. |
| **HTTP via raw `urllib`** | 🟡 Medium | `ai/llm/providers/api.py`. Works, but no connection pooling, no streaming. |

### Where the 20.5k LOC actually is

```
scripts/     ~6,400 LOC   dataset generation (v0.2–v0.5) + validators   ← throwaway work
tests/       ~4,000 LOC   14 test files
finetuning/  ~1,950 LOC   QLoRA pipeline
ai/          ~8,200 LOC   ← THE ACTUAL PRODUCT
```

Roughly **40% of the codebase is data-generation scaffolding** that gets deleted or frozen once training data is final. The product surface is smaller than the line count suggests.

---

## 2. The one thing that matters most

**Fix accuracy before building anything else.**

A dashboard on top of an F1-0.17 model is a liability, not a feature. An analyst who gets burned twice by a wrong AI verdict will never open the tool again — and in a SOC, a false *benign* verdict means a missed breach.

Every other workstream is worthless until the model clears a usability bar. **Set a go/no-go gate: macro F1 ≥ 0.75 on the held-out 300-record test set before writing any backend code.**

### Root-causing the 0.17 F1

Do not assume this is a model-size problem. Diagnose in this order:

1. **Label distribution.** Read the confusion matrix from `ai/evaluation/benchmark.py`. With 100 generated training examples and 300 test records, a skewed class balance alone can produce F1 ≈ 0.17.
2. **Schema/prompt mismatch.** Structured validity is `0.93` and evidence grounding is `1.00` — the model is *compliant*, it is just *wrong*. That signature usually means the label space in the prompt does not match the label space in the eval key, or the model defaults to one class.
3. **Synthetic data artifacts.** Self-generated data has label leakage and limited diversity. The v0.3 → v0.4 → v0.5 churn is a symptom. Validate against a real public dataset (see Phase 6).
4. **Only then** fine-tune. QLoRA on a 7B model will not fix a broken label space.

### Add an abstention path (cheap, high value)

Route to a human whenever confidence < threshold. A SOC tool that says *"insufficient evidence, needs analyst review"* is genuinely useful. One that always guesses and is wrong 83% of the time is worse than no tool. `insufficient_evidence` already exists as a triage class — wire it to a confidence threshold and measure how much accuracy improves when the model is allowed to abstain.

---

## 3. Roadmap

### Phase 0 — Stop the bleeding (2–3 days)

Nothing else should be started until this is done.

- [ ] **`git init` + initial commit.** This is the single highest-priority item. There is currently no way to recover from a bad edit.
- [ ] Add branch protection on `main`; require CI green.
- [ ] Write a real `requirements.txt`. Decide explicitly: stay stdlib-only, or adopt `pydantic` v2 + `httpx` + `structlog`. **Recommendation: adopt them.** The hand-rolled YAML parser in `ai/llm/config.py` and the raw `urllib` provider will not survive contact with production.
- [ ] `Dockerfile` + `docker-compose.yml` (app + Postgres + Redis).
- [ ] GitHub Actions: run all 14 test files on push.
- [ ] **Delete or implement the 13 empty stubs.** Empty files in a phase marked "🟢 Complete" will be noticed in any demo or code review.

### Phase 1 — Make the model useful (3–5 weeks) ← critical path

- [ ] Root-cause the F1 using the steps in §2.
- [ ] Expand training data: 100 examples is far too few. Target ≥ 2,000 with balanced classes and hard negatives.
- [ ] Run `finetuning/gpu_preflight.py` on the college GPU, train QLoRA on the v0.5 SFT set.
- [ ] Evaluate base vs. fine-tuned with `finetuning/evaluate_model.py` / `ai/evaluation/benchmark.py`.
- [ ] Wire the abstention/confidence-threshold path.
- [ ] **Gate: macro F1 ≥ 0.75, evidence grounding = 1.00, safety invariants = 1.00.**

### Phase 2 — Chain the agents (2–3 weeks)

- [ ] Implement `ai/orchestration/workflow.py`: alert → triage → (branch on `needs_investigation`) → investigation → threat-intel enrichment → report.
- [ ] Wire the existing agents into the workflow. They are built but not connected.
- [ ] Implement `verification_agent.py` as a critic pass before the report is shown. Cheapest available reduction in hallucination.
- [ ] Implement `attack_story_agent.py` (narrative timeline) or delete it.

### Phase 3 — Make it a service (4–6 weeks)

- [ ] FastAPI: `POST /alerts`, `GET /cases/{id}`, `POST /cases/{id}/investigate`, `GET /reports/{id}`.
- [ ] Postgres schema: `cases`, `alerts`, `investigations`, `tool_calls`, `reports`, `analyst_feedback`.
- [ ] Async execution. The investigation loop is multi-turn and slow — it cannot block a request. Use Arq/Celery + Redis with retries and per-investigation timeouts.
- [ ] SSE streaming so the analyst watches the investigation progress live. Large UX win, moderate cost.
- [ ] Persist every LLM call and tool call for replay and audit.

### Phase 4 — Real data in (3–4 weeks) ← Phase 10

- [ ] Define a normalized alert schema. **Target OCSF** rather than inventing one.
- [ ] Build ingestion adapters, in this order:
  1. Webhook receiver (Wazuh / Elastic / Splunk) — highest value, lowest effort
  2. Sysmon / Windows Event Log via WEL
  3. EDR API connectors
- [ ] **Key architectural move**: replace `synthetic_data.py` behind the *existing* `ai/tools/base.py` interface. The agents must not change — only the data source behind the tool registry. If this boundary holds, the prototype's agent logic transfers to production intact.
- [ ] Keep the synthetic backend as a demo/safety mode.

### Phase 5 — Product hardening (4–6 weeks)

- [ ] Auth: SSO/SAML. RBAC: analyst / senior analyst / admin.
- [ ] Multi-tenancy with strict data isolation.
- [ ] **Immutable audit log** — every tool call, LLM call, recommendation, and human action. Non-negotiable for security software; it is also your compliance story.
- [ ] **Human-in-the-loop approval for write actions** (host isolation, account disable). Currently explicitly out of scope. Any product version needs this gated behind explicit approval with a full audit trail.
- [ ] **PII and secret redaction before telemetry leaves the network.** If you use a hosted LLM, this is a hard blocker for real customers. Send redacted telemetry, re-hydrate locally.
- [ ] Cost controls: token budget per investigation, response caching, per-tenant rate limits.
- [ ] Prompt-injection defence beyond fenced data — test adversarial payloads embedded in real telemetry (process command lines, filenames). Current 100% score is against synthetic, well-behaved input.

### Phase 6 — Prove it (ongoing)

- [ ] Evaluate against real public data, not only self-generated: **Splunk Boss of the SOC**, **Atomic Red Team** traces, or **DARPA TC**. Self-generated data has leakage and diversity ceilings.
- [ ] Analyst feedback loop: thumbs up/down on every report → feeds the next SFT dataset version. **This is the actual moat.** Every deployment makes the model better in a way competitors cannot copy.
- [ ] Continuous eval in CI: regressions in accuracy block merges.
- [ ] Independent red-team of the full agent chain before any external deployment.

---

## 4. What not to do

- **Don't build the dashboard first.** It is the most visible work and the least valuable while F1 is 0.17.
- **Don't add more agents.** Breadth (Phases 5–7) is seductive and actively harmful while the core is inaccurate. Five agents at 17% F1 is worse than two agents at 80%.
- **Don't fine-tune before diagnosing.** QLoRA cannot fix a mismatched label space.
- **Don't rewrite the RAG layer yet.** BM25/TF-IDF is a defensible v1 choice — fast, zero-dependency, no GPU. Only move to real embeddings if `ai/evaluation/rag_eval.py` shows retrieval quality is the actual bottleneck.
- **Don't delete the dataset scripts yet.** Freeze them. You will need them for the feedback loop in Phase 6.

---

## 5. Definition of "shippable product"

AegisX is a product when all of these are true:

| # | Criterion | Bar |
|---|---|---|
| 1 | Model accuracy | Macro F1 ≥ 0.75 on held-out real-world data |
| 2 | Safety invariants | 1.00 across all four, re-verified on real inputs |
| 3 | Agent orchestration | Alert → triage → investigation → report, fully automated |
| 4 | Service | FastAPI + Postgres, multi-tenant, authenticated |
| 5 | Real ingestion | At least one production adapter (Wazuh or Sysmon) |
| 6 | Actions | Read-only by default; writes require explicit human approval |
| 7 | Audit | Immutable, complete, replayable |
| 8 | Data protection | Redaction before any external LLM call |
| 9 | UI | Alert queue + live investigation view + report with evidence |
| 10 | Ops | Docker, CI/CD, monitoring, cost controls |

**Estimated effort** for a focused team of 3 working sequentially through the critical path:

- **Demo-grade** (criteria 1–3 + minimal UI): **6–8 weeks**
- **Shippable v1** (all 10 criteria): **4–6 months**

---

## 6. Suggested immediate next actions

In order, starting today:

1. `git init` and commit. **Do this before anything else.**
2. Add `requirements.txt` with real dependencies; set up Docker + CI.
3. Pull the confusion matrix from the latest benchmark and diagnose the 0.17 F1.
4. Delete or implement the 13 empty stub files.
5. Fix the stale phase table in `README.md`.
6. Start implementing `ai/orchestration/workflow.py` — it is the missing spine.
