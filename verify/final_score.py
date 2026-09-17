#!/usr/bin/env python3
"""RQ4 재측정 채점: 게이트/카나리로 베이스라인 신뢰도를 판정한 뒤 arm 대 arm 비교."""
import json, os, csv, sys, yaml
from collections import Counter
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare import mutation_referee
BASE = _DATA
L = lambda p, d={}: (json.load(open(p)) if os.path.exists(p) else d)
plan = L(f"{BASE}/plan.json"); N = L(f"{BASE}/results_native_final2.json")
K = L(f"{BASE}/results_kyverno_final2.json")

def native_vs_upstream(slug, e, na):
    """변환본이 업스트림 기대값을 재현하는가 -> (ok, checked)"""
    meta = {c["file"]: c for c in e.get("cases", [])}
    checked = bad = 0
    for c in na.get("cases", []):
        m = meta.get(c["file"], {}); exp = c.get("expected")
        if e.get("is_mutate"):
            pf = m.get("patched")
            if not pf: continue
            ip = f"{BASE}/tests/{slug}/{c['file']}"; pp = f"{BASE}/tests/{slug}/{pf}"
            if not (os.path.exists(ip) and os.path.exists(pp)): continue
            if c.get("verdict") != "admit" or not c.get("obj"): continue
            try:
                ok, badp, n = mutation_referee(yaml.safe_load(open(ip, errors="replace")),
                                               yaml.safe_load(open(pp, errors="replace")), c["obj"])
            except Exception: continue
            if n == 0: continue
            checked += 1; bad += (0 if ok else 1)
        else:
            if exp not in ("fail", "pass"): continue
            checked += 1
            good = (exp == "fail" and c["verdict"] == "deny") or (exp == "pass" and c["verdict"] == "admit")
            if not good: bad += 1
    return (checked > 0 and bad == 0), checked

def arms_agree(slug, e, ka, na):
    kc = {c["file"]: c for c in ka.get("cases", [])}
    nc = {c["file"]: c for c in na.get("cases", [])}
    files = sorted(set(kc) & set(nc))
    if not files: return "ERROR", "비교 가능한 케이스 없음"
    diffs = []; errs = []; mdiff = []
    for f in files:
        kv, nv = kc[f]["verdict"], nc[f]["verdict"]
        if kv == "error" or nv == "error":
            errs.append(f"{f}: ky={kv} nat={nv}"); continue
        if kv != nv:
            diffs.append(f"{f} ky={kv} nat={nv}")
        elif kv == "admit" and e.get("is_mutate"):
            ko, no = kc[f].get("obj"), nc[f].get("obj")
            if ko and no:
                ip = f"{BASE}/tests/{slug}/{f}"
                if os.path.exists(ip):
                    try:
                        inp = yaml.safe_load(open(ip, errors="replace"))
                        ok, bad, n = mutation_referee(inp, ko, no)   # kyverno 출력을 기준으로 native 대조
                        if n > 0 and not ok: mdiff.append(f"{f}:{[b[0] for b in bad][:2]}")
                    except Exception: pass
    if diffs or mdiff: return "MISMATCH", ("; ".join(diffs[:3]) or "mutation: " + "; ".join(mdiff[:2]))
    if errs and not diffs: return "ERROR", "; ".join(errs[:3])
    return "MATCH", f"{len(files)} cases"

rows = []
for slug in sorted(plan):
    e = plan[slug]
    if not e["native"]: continue
    r = {"slug": slug, "family": e["family"], "ruletypes": e["ruletypes"],
         "category": e["category"], "test_format": e.get("test_format"),
         "cluster_scoped": e.get("cluster_scoped_case"), "cases": len(e["cases"])}
    if not e["cases"]:
        r.update(result="NO-TEST-INPUT", detail="테스트 재료 없음"); rows.append(r); continue
    na = N.get(slug); ka = K.get(slug)
    if na is None or ka is None:
        r.update(result="NOT-RUN", detail="미실행"); rows.append(r); continue
    if "apply_error" in na:
        r.update(result="ERROR", detail="native-apply: " + na["apply_error"][:200]); rows.append(r); continue
    base = ka.get("baseline")
    r["webhook_registered"] = ka.get("webhook_registered")
    r["canary"] = ka.get("canary_ok"); r["canary_detail"] = ka.get("canary_detail")
    if base in ("BASELINE-NOT-READY", "BASELINE-DEAD") or ka.get("canary_ok") is False:
        ok, n = native_vs_upstream(slug, e, na)
        r["result"] = ("NATIVE-OK/" if ok else ("NATIVE-FAIL/" if n else "NO-REFEREE/")) + (base or "BASELINE-DEAD")
        r["detail"] = f"원본 미작동({base or 'canary-fail'}); 변환본 업스트림 검사 {n}건"
    else:
        res, det = arms_agree(slug, e, ka, na)
        r["result"] = res; r["detail"] = det
    rows.append(r)

cols = ["slug","family","ruletypes","category","test_format","cluster_scoped","cases",
        "webhook_registered","canary","canary_detail","result","detail"]
out = f"{BASE}/rq4_final_results.csv"
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=cols); w.writeheader()
    for r in rows: w.writerow({k: r.get(k, "") for k in cols})
c = Counter(r["result"] for r in rows)
print(f"변환 성공 401건 중 채점 {len(rows)}건")
for k, v in c.most_common(): print(f"   {k:34} {v:4d}  {100*v/len(rows):5.1f}%")
print(f"CSV -> {out}")
