#!/usr/bin/env python3
"""
AegisX RAG Verification Suite — Member 2 / RAG & Pipeline Verification Engineer
"""
import json, sys, time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.rag import DocumentIngester, BM25Scorer, RAGRetriever, RAGPipeline, create_default_rag_pipeline
from ai.rag.retriever import RetrievalResult
from ai.tools.synthetic_threat_intel import list_all_threat_intel, get_threat_intel

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; C = "\033[96m"; B = "\033[1m"; RST = "\033[0m"

def hdr(m):
    print(f"\n{B}{C}{'='*70}{RST}\n{B}{C}  {m}{RST}\n{B}{C}{'='*70}{RST}")

def ok(m):  print(f"  {G}OK  {m}{RST}")
def warn(m): print(f"  {Y}WARN{m}{RST}")
def err(m):  print(f"  {R}FAIL{m}{RST}")
def info(m): print(f"  {C}>>  {m}{RST}")

# --- KB PROFILE ---
hdr("PHASE 2-3  Knowledge Base Profile")
ing = DocumentIngester(chunk_size=400, chunk_overlap=50)
mitre_docs = ing.load_mitre_reference()
mitre_chunks = sum([ing.chunk_document(d) for d in mitre_docs], [])
ti_docs = ing.load_synthetic_threat_intel()
ti_chunks = sum([ing.chunk_document(d) for d in ti_docs], [])
total_chunks = len(mitre_chunks) + len(ti_chunks)
ok(f"MITRE docs={len(mitre_docs)}, chunks={len(mitre_chunks)}")
ok(f"ThreatIntel docs={len(ti_docs)}, chunks={len(ti_chunks)}")
ok(f"Total indexable chunks={total_chunks}")
tids = [d.metadata.get('technique_id','') for d in mitre_docs]
info(f"Technique IDs: {tids}")
ti_inds = [d.metadata.get('indicator','') for d in ti_docs]
info(f"TI Indicators: {ti_inds}")

# --- STARTUP ---
hdr("PHASE 5  RAG Startup")
t0 = time.perf_counter()
pipeline = create_default_rag_pipeline(auto_init=True)
ms = (time.perf_counter()-t0)*1000
ok(f"Initialized in {ms:.1f} ms")
ok(f"Indexed chunks: {pipeline.retriever.count()}")
ok(f"Config: top_k={pipeline.top_k}, threshold={pipeline.similarity_threshold}, reranker={pipeline.reranker_config.enabled}")

# --- 5 QUERY TESTS ---
TESTS = [
  ("TEST-1","SSH Brute Force",
   "Multiple failed SSH login attempts are occurring against an administrator account from the same source IP.",
   ["brute","ssh","credential","T1110","password"],["T1110"]),
  ("TEST-2","PowerShell Execution",
   "A suspicious PowerShell process downloads and executes a remote script.",
   ["powershell","T1059","execution","script"],["T1059.001"]),
  ("TEST-3","Credential Dumping LSASS",
   "An attacker accesses LSASS memory to obtain Windows credentials.",
   ["lsass","credential","T1003","memory","dump"],["T1003","T1003.001"]),
  ("TEST-4","Phishing",
   "A user receives a malicious email attachment and opens it.",
   ["phishing","T1566","malicious","attachment","email"],["T1566"]),
  ("TEST-5","Suspicious Network",
   "A workstation makes repeated outbound connections to a suspicious external IP address.",
   ["command","control","c2","T1071","outbound","network"],["T1071"]),
]

hdr("PHASE 6-7  Verification Test Suite (top_k=3)")
test_results = []
table_rows = []
for (tid, name, query, kws, mitre_ids) in TESTS:
    t0 = time.perf_counter()
    results = pipeline.query(query, top_k=3)
    ms = (time.perf_counter()-t0)*1000
    all_text = " ".join((r.chunk.content+" "+r.chunk.title).lower() for r in results)
    kw_hits = [k for k in kws if k.lower() in all_text]
    mitre_hits = [m for m in mitre_ids if m.lower() in all_text]
    if mitre_hits and len(kw_hits)>=2: status="PASS"
    elif kw_hits or mitre_hits: status="PARTIAL"
    else: status="FAIL"
    col = G if status=="PASS" else (Y if status=="PARTIAL" else R)
    print(f"\n  [{col}{status}{RST}] {tid}: {name}  ({ms:.1f} ms)")
    for r in results:
        prev = r.chunk.content[:100].replace("\n"," ")
        rel = "YES" if any(k.lower() in (r.chunk.content+r.chunk.title).lower() for k in kws) else "no"
        print(f"       Rank {r.rank} | Score {r.score:.4f} | {r.chunk.document_id} | Relevant:{rel}")
        print(f"       \"{prev}...\"")
    table_rows.append({"test":tid,"name":name,"status":status,"top_score":results[0].score if results else 0,"top_src":results[0].chunk.document_id if results else "NONE"})
    test_results.append({"tid":tid,"name":name,"query":query,"status":status,"kw_hits":kw_hits,"mitre_hits":mitre_hits,"results":[r.to_dict() for r in results]})

# --- TOP-K ---
hdr("PHASE 9  Top-K Behaviour")
q = "brute force SSH login failed administrator"
for k in [1,3,5]:
    r = pipeline.query(q, top_k=k)
    ok(f"top_k={k} -> {len(r)} results  scores={[round(x.score,3) for x in r]}")

# --- MITRE EXPLICIT ---
hdr("PHASE 10  MITRE ATT&CK Explicit Retrieval")
MITRE_EXPLICIT=[
    ("T1110","Brute Force",["brute","password","guessing"]),
    ("T1059.001","PowerShell",["powershell","script","execution"]),
    ("T1003","OS Credential Dumping",["credential","lsass","dump"]),
    ("T1566","Phishing",["phishing","email","attachment"]),
]
mitre_rows = []
for (m_id, m_name, kws) in MITRE_EXPLICIT:
    r_id = pipeline.query(m_id, top_k=3)
    r_sem = pipeline.query(m_name, top_k=3)
    t_id  = " ".join((r.chunk.content+r.chunk.title).lower() for r in r_id)
    t_sem = " ".join((r.chunk.content+r.chunk.title).lower() for r in r_sem)
    id_hit  = m_id.lower() in t_id or any(k in t_id for k in kws)
    sem_hit = any(k in t_sem for k in kws)
    status = "PASS" if (id_hit and sem_hit) else ("PARTIAL" if (id_hit or sem_hit) else "FAIL")
    col = G if status=="PASS" else (Y if status=="PARTIAL" else R)
    top = r_id[0] if r_id else None
    print(f"  [{col}{status}{RST}] {m_id}: {m_name}  ID-q:{'Y' if id_hit else 'N'} SEM-q:{'Y' if sem_hit else 'N'}  top={top.chunk.title[:40] if top else 'NONE'} score={top.score if top else 0}")
    mitre_rows.append({"tid":m_id,"name":m_name,"status":status,"id_hit":id_hit,"sem_hit":sem_hit})

# --- THREAT INTEL ---
hdr("PHASE 11  Threat Intelligence Retrieval")
TI_TESTS=[
    ("198.51.100.200","FIN7/Cobalt Strike C2"),
    ("198.51.100.77","SSH Brute Force node"),
    ("198.51.100.250","LockBit Ransomware endpoint"),
    ("7a35e729a67442ec9a58bb0e43d93963470ff4fa31557bf8f6b0f49fa8a221f7","FIN7 Macro Dropper hash"),
]
ti_rows = []
for (ind, label) in TI_TESTS:
    direct = get_threat_intel(ind)
    r = pipeline.query(ind, top_k=3)
    all_t = " ".join((x.chunk.content+x.chunk.title).lower() for x in r)
    rag_hit = ind.lower() in all_t
    status = "PASS" if (direct and rag_hit) else ("PARTIAL" if direct else "FAIL")
    col = G if status=="PASS" else (Y if status=="PARTIAL" else R)
    rep = direct.get("reputation","N/A") if direct else "NOT FOUND"
    actor = direct.get("threat_actor","N/A") if direct else "N/A"
    top = r[0] if r else None
    print(f"  [{col}{status}{RST}] {label}")
    print(f"       Direct TI: rep={rep}, actor={actor}  | RAG hit:{rag_hit}  top_score={top.score if top else 0}")
    ti_rows.append({"ind":ind,"label":label,"status":status,"direct":direct is not None,"rag_hit":rag_hit,"rep":rep})

# --- OUTPUT CONTRACT ---
hdr("PHASE 12  Output Contract")
r = pipeline.query("PowerShell execution remote script", top_k=3)
d = r[0].to_dict() if r else {}
required = {"rank","score","chunk_id","document_id","title","content","metadata"}
missing = required - set(d.keys())
ok(f"Required keys present: {sorted(required-missing)}")
if missing: warn(f"Missing keys: {missing}")
else: ok("Schema COMPLETE — all fields present")
ctx = pipeline.format_context_for_prompt(r)
ok(f"format_context_for_prompt header present: {'RETRIEVED THREAT' in ctx}")
ok(f"Sample output first result:")
for k,v in d.items():
    print(f"       {k}: {str(v)[:80]}")

# --- LLM INTERFACE ---
hdr("PHASE 13  RAG -> LLM Interface Inspection")
from ai.llm.client import LLMClient
from ai.prompts.triage import get_triage_system_prompt, format_triage_user_prompt
sys_p = get_triage_system_prompt()
ok(f"Triage system prompt: {len(sys_p)} chars")
mock_alert = {
    "alert":{"title":"SSH Brute Force","severity":"high","source":"Wazuh","rule_id":"5710","rule_name":"SSH Auth Fail","timestamp":"2026-09-27T04:00:00Z"},
    "context":{"hostname":"linux-01","username":"admin","department":"IT","os":"Ubuntu","environment":"prod","asset_criticality":"high","ip_address":"198.51.100.77"},
    "evidence":[{"id":"EVT-001","type":"auth","description":"47 SSH failures from 198.51.100.77","timestamp":"2026-09-27T04:00:00Z","raw_data":{}}]
}
rag_ctx = pipeline.format_context_for_prompt(pipeline.query("SSH brute force admin 198.51.100.77", top_k=3))
user_p = format_triage_user_prompt(mock_alert)
full_p = rag_ctx + "\n\n" + user_p
ok(f"Full assembled prompt: {len(full_p)} chars")
ok(f"RAG context in prompt: {'RETRIEVED THREAT' in full_p}")
client = LLMClient.from_mock()
ok(f"LLMClient.from_mock() provider={client.provider.name}")
ok("RAG->LLM interface COMPLETE (query->context->prompt builder->LLM client all connected)")
ok("Qwen3 8B NOT called — BLOCKED BY GPU (other machine)")

# --- MOCK E2E ---
hdr("PHASE 14  Mock End-to-End [MOCK - NOT REAL MODEL]")
t0 = time.perf_counter()
resp = client.generate(user_prompt=full_p, system_prompt=sys_p)
ms = (time.perf_counter()-t0)*1000
out = resp.structured_data or {}
ok(f"Mock LLM responded in {ms:.1f} ms  [MOCK]")
ok(f"Structured output keys: {list(out.keys())}")
print(f"  MOCK classification={out.get('classification')} severity={out.get('severity')} confidence={out.get('confidence')}")
print(f"  [NOTE: Above is MOCK output — NOT from Qwen3 8B]")

# --- FINAL SUMMARY ---
hdr("SUMMARY TABLE")
print(f"  {'Test':<35} {'Status':<10} {'Top Score':<12} {'Top Source'}")
print(f"  {'-'*70}")
for row in table_rows:
    col = G if row['status']=="PASS" else (Y if row['status']=="PARTIAL" else R)
    print(f"  {row['name']:<35} {col}{row['status']:<10}{RST} {row['top_score']:<12.4f} {row['top_src']}")
print()

# Save JSON
report = {
    "knowledge_base":{"mitre_docs":len(mitre_docs),"mitre_chunks":len(mitre_chunks),"ti_docs":len(ti_docs),"ti_chunks":len(ti_chunks),"total":total_chunks,"technique_ids":tids},
    "startup":{"ok":True,"chunks":pipeline.retriever.count()},
    "tests":test_results,
    "topk":{"1":len(pipeline.query(q,top_k=1)),"3":len(pipeline.query(q,top_k=3)),"5":len(pipeline.query(q,top_k=5))},
    "mitre":mitre_rows,
    "threat_intel":ti_rows,
    "output_schema_complete":not missing,
    "llm_interface_connected":True,
    "mock_e2e_success":resp.structured_data is not None,
}
out_path = PROJECT_ROOT / "reports" / "rag_verification_raw.json"
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path,"w",encoding="utf-8") as f:
    json.dump(report, f, indent=2, default=str)
ok(f"JSON report saved -> {out_path}")
print(f"\n{B}Verification complete.{RST}\n")

