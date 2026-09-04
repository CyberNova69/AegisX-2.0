#!/usr/bin/env python3
"""
AegisX — Build self-contained demo dashboard
=============================================

Reads the pipeline results JSON and emits a single self-contained HTML file
(data embedded, no server, no external assets) suitable for showing reviewers.

Usage:
    python scripts/demo_pipeline.py --all --json > reports/demo/pipeline_results.json
    python scripts/build_demo_report.py

Output:
    reports/demo/pipeline_dashboard.html
"""

import json
from html import escape
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS = PROJECT_ROOT / "reports" / "demo" / "pipeline_results.json"
OUTPUT = PROJECT_ROOT / "reports" / "demo" / "pipeline_dashboard.html"

SEVERITY_COLORS = {
    "critical": ("#FCEBEB", "#A32D2D", "#501313"),
    "high": ("#FAECE7", "#993C1D", "#4A1B0C"),
    "medium": ("#FAEEDA", "#854F0B", "#412402"),
    "low": ("#E6F1FB", "#185FA5", "#042C53"),
    "informational": ("#F1EFE8", "#5F5E5A", "#2C2C2A"),
}

CONCLUSION_COLORS = {
    "confirmed_malicious": ("#FCEBEB", "#A32D2D", "#501313"),
    "likely_malicious": ("#FAECE7", "#993C1D", "#4A1B0C"),
    "suspicious": ("#FAEEDA", "#854F0B", "#412402"),
    "insufficient_evidence": ("#F1EFE8", "#5F5E5A", "#2C2C2A"),
    "benign": ("#EAF3DE", "#3B6D11", "#173404"),
}


def badge(value, color_map):
    bg, border, fg = color_map.get(value, ("#F1EFE8", "#5F5E5A", "#2C2C2A"))
    label = escape(str(value).replace("_", " ").upper())
    return (f'<span class="badge" style="background:{bg};border-color:{border};color:{fg}">'
            f"{label}</span>")


def render_scenario(r):
    triage = r["triage"]
    inv = r["investigation"]
    alert = r["alert"]
    ctx = r["context"]

    verdict = inv["conclusion"] if inv else triage["classification"]
    confidence = inv["confidence"] if inv else triage["confidence"]
    severity = (inv or triage).get("severity", "medium")

    steps_html = ""
    if inv and inv.get("investigation_steps"):
        for s in inv["investigation_steps"]:
            count = s.get("result", {}).get("data", {}).get("count", 0)
            eids = ", ".join(s.get("evidence_ids", [])) or "—"
            steps_html += (
                f'<div class="step">'
                f'<div class="step-num">{s.get("step_number")}</div>'
                f'<div class="step-body">'
                f'<div class="step-tool">{escape(str(s.get("tool_name")))}</div>'
                f'<div class="step-meta">{escape(str(s.get("purpose")))}</div>'
                f'<div class="step-meta muted">{count} item(s) · evidence: {escape(eids)}</div>'
                f"</div></div>"
            )
    else:
        steps_html = ('<div class="step"><div class="step-num">—</div>'
                      '<div class="step-body"><div class="step-tool">Investigation skipped</div>'
                      '<div class="step-meta muted">Triage classified this alert benign '
                      'with confidence ≥ 0.75, so no tool calls were made.</div>'
                      "</div></div>")

    findings_html = ""
    if inv and inv.get("findings"):
        for f in inv["findings"]:
            eids = ", ".join(f.get("evidence_ids", [])) or "none"
            findings_html += (
                f'<li><strong>{escape(str(f.get("title")))}</strong><br>'
                f'<span class="muted">{escape(str(f.get("description")))}</span><br>'
                f'<span class="mono small">evidence: {escape(eids)}</span></li>'
            )
    else:
        findings_html = '<li><span class="muted">No investigation findings.</span></li>'

    actions_html = ""
    src_actions = (inv or triage).get("recommended_actions", []) or []
    for a in src_actions:
        actions_html += (
            f'<li><span class="prio">{escape(str(a.get("priority", "medium")).upper())}</span> '
            f"{escape(str(a.get('action')))}</li>"
        )
    if not actions_html:
        actions_html = '<li><span class="muted">None.</span></li>'

    return f"""
    <section class="card">
      <div class="card-head">
        <div>
          <div class="alert-title">{escape(str(alert.get("title")))}</div>
          <div class="muted small">
            {escape(str(r["scenario"]))} · {escape(str(ctx.get("hostname")))} ·
            user {escape(str(ctx.get("username")))} · {escape(str(alert.get("source")))}
          </div>
        </div>
        <div class="card-badges">
          {badge(verdict, CONCLUSION_COLORS)}
          {badge(severity, SEVERITY_COLORS)}
        </div>
      </div>

      <div class="grid">
        <div class="col">
          <div class="label">Triage</div>
          <div class="kv"><span>Classification</span><b>{escape(str(triage["classification"]).replace("_", " "))}</b></div>
          <div class="kv"><span>Confidence</span><b>{triage["confidence"]:.2f}</b></div>
          <div class="kv"><span>Investigation</span><b>{"required" if triage["investigation_required"] else "not required"}</b></div>
          <div class="label" style="margin-top:12px">Investigation steps</div>
          <div class="steps">{steps_html}</div>
        </div>
        <div class="col">
          <div class="label">Final report</div>
          <div class="kv"><span>Verdict</span><b>{escape(str(verdict).replace("_", " "))}</b></div>
          <div class="kv"><span>Confidence</span><b>{confidence:.2f}</b></div>
          <div class="kv"><span>Evidence</span><b>{len(inv.get("evidence", [])) if inv else len(triage.get("evidence_ids", []))} item(s)</b></div>
          <div class="label" style="margin-top:12px">Findings</div>
          <ul class="tight">{findings_html}</ul>
          <div class="label" style="margin-top:12px">Recommended actions</div>
          <ul class="tight">{actions_html}</ul>
        </div>
      </div>
    </section>
    """


def main():
    if not RESULTS.exists():
        raise SystemExit(f"Missing {RESULTS}. Run demo_pipeline.py --all --json first.")

    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    total = len(data)
    investigated = sum(1 for r in data if r["investigation"])
    step_count = sum(len(r["investigation"]["investigation_steps"])
                     for r in data if r["investigation"])
    matches = 0
    for r in data:
        got = r["investigation"]["conclusion"] if r["investigation"] else r["triage"]["classification"]
        if got == r["expected_conclusion"]:
            matches += 1

    cards = "\n".join(render_scenario(r) for r in data)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisX — SOC Pipeline Demo</title>
<style>
  :root {{ --bg:#FAFAF8; --card:#FFFFFF; --line:#E3E1DA; --fg:#2C2C2A; --muted:#5F5E5A; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:32px 24px; background:var(--bg); color:var(--fg);
    font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1080px; margin:0 auto; }}
  h1 {{ font-size:22px; font-weight:500; margin:0 0 4px; }}
  .sub {{ color:var(--muted); margin:0 0 24px; font-size:13px; }}
  .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }}
  .stat .n {{ font-size:22px; font-weight:500; }}
  .stat .l {{ color:var(--muted); font-size:12px; }}
  .flow {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:14px 16px; margin-bottom:24px; font-size:13px; color:var(--muted); }}
  .flow b {{ color:var(--fg); font-weight:500; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:18px 20px; margin-bottom:16px; }}
  .card-head {{ display:flex; justify-content:space-between; gap:16px; align-items:flex-start;
    padding-bottom:12px; border-bottom:1px solid var(--line); margin-bottom:14px; }}
  .alert-title {{ font-size:15px; font-weight:500; }}
  .card-badges {{ display:flex; gap:6px; flex-shrink:0; }}
  .badge {{ font-size:11px; font-weight:500; padding:3px 9px; border-radius:999px;
    border:1px solid; white-space:nowrap; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:24px; }}
  .label {{ font-size:12px; color:var(--muted); text-transform:lowercase;
    letter-spacing:.02em; margin-bottom:6px; }}
  .kv {{ display:flex; justify-content:space-between; font-size:13px; padding:2px 0; }}
  .kv span {{ color:var(--muted); }}
  .steps {{ display:flex; flex-direction:column; gap:8px; }}
  .step {{ display:flex; gap:10px; }}
  .step-num {{ width:20px; height:20px; flex-shrink:0; border-radius:6px; background:#EEEDFE;
    color:#26215C; font-size:11px; display:flex; align-items:center; justify-content:center; }}
  .step-tool {{ font-size:13px; font-weight:500; }}
  .step-meta {{ font-size:12px; color:var(--muted); }}
  ul.tight {{ margin:0; padding-left:18px; font-size:13px; }}
  ul.tight li {{ margin-bottom:6px; }}
  .prio {{ font-size:10px; font-weight:500; border:1px solid var(--line);
    border-radius:4px; padding:1px 5px; color:var(--muted); }}
  .muted {{ color:var(--muted); }}
  .small {{ font-size:12px; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:24px; padding-top:16px;
    border-top:1px solid var(--line); }}
  @media (max-width:760px) {{ .grid,.stats {{ grid-template-columns:1fr; }} }}
</style></head>
<body><div class="wrap">
  <h1>AegisX — Automated SOC Pipeline</h1>
  <p class="sub">End-to-end run: alert → AI triage → decision → agentic investigation → grounded report.
     Deterministic mock provider, offline, {total} synthetic scenarios.</p>

  <div class="stats">
    <div class="stat"><div class="n">{total}</div><div class="l">scenarios run</div></div>
    <div class="stat"><div class="n">{matches}/{total}</div><div class="l">verdicts matched</div></div>
    <div class="stat"><div class="n">{investigated}</div><div class="l">investigated</div></div>
    <div class="stat"><div class="n">{step_count}</div><div class="l">tool invocations</div></div>
  </div>

  <div class="flow">
    <b>Security alert</b> → <b>TriageAgent</b> (classification · severity · confidence) →
    <b>decision branch</b> (investigate only if not confidently benign) →
    <b>InvestigationAgent</b> (multi-turn read-only tool loop) →
    <b>grounded report</b> (findings · evidence · recommended actions) →
    <b>human analyst</b> (reviews and approves)
  </div>

  {cards}

  <footer>
    Demonstrates pipeline architecture and agent orchestration on synthetic data.
    It is not a measure of real-world SOC accuracy — classification quality is a
    separate, ongoing workstream. All investigation tools are read-only;
    no endpoint remediation is performed.
  </footer>
</div></body></html>
"""
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(html, encoding="utf-8")
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")
    print(f"  scenarios={total} matched={matches} investigated={investigated} steps={step_count}")


if __name__ == "__main__":
    main()
