#!/usr/bin/env python3
import json, sys, os, copy
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

BASE=_DATA
VOLATILE_META={"creationTimestamp","uid","resourceVersion","generation","managedFields",
               "namespace","selfLink","annotations_kubectl"}
def canon_sa_token(d):
    """API server injects kube-api-access-<random> volume/mount per request; canonicalize."""
    import re as _re
    def fix(x):
        if isinstance(x,dict):
            for k,v in list(x.items()):
                if k=="name" and isinstance(v,str) and _re.match(r"^kube-api-access-[a-z0-9]{5}$",v):
                    x[k]="kube-api-access-CANON"
                elif k.endswith("controller-uid") and isinstance(v,str):
                    x[k]="CONTROLLER-UID-CANON"
                elif k in ("labels","matchLabels","selector") and isinstance(v,dict):
                    for lk in list(v):
                        if lk.endswith("controller-uid"): v[lk]="CONTROLLER-UID-CANON"
                    fix(v)
                else: fix(v)
        elif isinstance(x,list):
            for i in x: fix(i)
    fix(d); return d

def norm(o):
    if not isinstance(o,dict): return o
    d=copy.deepcopy(o)
    d=canon_sa_token(d)
    d.pop("status",None)
    m=d.get("metadata",{}) or {}
    for k in list(m):
        if k in VOLATILE_META: m.pop(k,None)
    ann=m.get("annotations") or {}
    ann.pop("kubectl.kubernetes.io/last-applied-configuration",None)
    # kyverno adds its own bookkeeping annotation
    for k in list(ann):
        if k.startswith("policies.kyverno.io/"): ann.pop(k)
    if not ann: m.pop("annotations",None)
    d["metadata"]=m
    return d

def diff_paths(a,b,p="",out=None):
    if out is None: out=[]
    if type(a)!=type(b): out.append(p or "/"); return out
    if isinstance(a,dict):
        for k in sorted(set(a)|set(b)):
            if k not in a or k not in b: out.append(f"{p}/{k}")
            else: diff_paths(a[k],b[k],f"{p}/{k}",out)
    elif isinstance(a,list):
        if len(a)!=len(b): out.append(f"{p}[len]")
        else:
            for i,(x,y) in enumerate(zip(a,b)): diff_paths(x,y,f"{p}[{i}]",out)
    elif a!=b: out.append(p or "/")
    return out

def compare(tag):
    plan=json.load(open(f"{BASE}/plan.json"))
    K=json.load(open(f"{BASE}/results_kyverno_{tag}.json"))
    N=json.load(open(f"{BASE}/results_native_{tag}.json"))
    rows={}
    for s in sorted(set(K)&set(N)):
        e=plan[s]; kk=K[s]; nn=N[s]
        if "apply_error" in kk or "apply_error" in nn:
            rows[s]={"result":"ERROR","reason":("kyverno-apply: "+kk["apply_error"][:200]) if "apply_error" in kk
                     else ("native-apply: "+nn["apply_error"][:200])}
            continue
        kc={c["file"]:c for c in kk.get("cases",[])}
        nc={c["file"]:c for c in nn.get("cases",[])}
        files=sorted(set(kc)&set(nc))
        if not files:
            rows[s]={"result":"ERROR","reason":"no comparable cases"}; continue
        diffs=[]; errs=[]; mutdiffs=[]
        for f in files:
            kv,nv=kc[f]["verdict"],nc[f]["verdict"]
            if kv=="error" or nv=="error":
                errs.append(f"{f}: ky={kv} nat={nv} :: {(kc[f].get('err') or nc[f].get('err') or '')[:160]}")
                continue
            if kv!=nv: diffs.append({"file":f,"expected":kc[f].get("expected"),"kyverno":kv,"native":nv,
                                     "kyverno_err":(kc[f].get("err") or "")[:200],"native_err":(nc[f].get("err") or "")[:200]})
            elif kv=="admit" and e["is_mutate"]:
                a,b=norm(kc[f].get("obj")),norm(nc[f].get("obj"))
                if a and b:
                    dp=diff_paths(a,b)
                    if dp: mutdiffs.append({"file":f,"paths":dp[:8]})
        if errs and not diffs and not mutdiffs:
            rows[s]={"result":"ERROR","reason":"; ".join(errs[:3]),"n_cases":len(files)}
        elif diffs or mutdiffs:
            rows[s]={"result":"MISMATCH","verdict_diffs":diffs,"mutation_diffs":mutdiffs,
                     "n_cases":len(files),"errors":errs[:2]}
        else:
            rows[s]={"result":"MATCH","n_cases":len(files),
                     "n_deny":sum(1 for f in files if kc[f]["verdict"]=="deny"),
                     "n_admit":sum(1 for f in files if kc[f]["verdict"]=="admit"),
                     "is_mutate":e["is_mutate"]}
    json.dump(rows,open(f"{BASE}/compare_{tag}.json","w"),indent=0)
    from collections import Counter
    c=Counter(v["result"] for v in rows.values())
    print(f"[{tag}] compared={len(rows)} ", dict(c))
    # sanity: does kyverno arm reproduce upstream expectations?
    okexp=badexp=0
    for s,v in rows.items():
        for f,cc in {c["file"]:c for c in K[s].get("cases",[])}.items():
            exp=cc.get("expected")
            if exp=="fail" and cc["verdict"]=="deny": okexp+=1
            elif exp=="pass" and cc["verdict"]=="admit": okexp+=1
            elif exp in ("fail","pass"): badexp+=1
    print(f"  kyverno-arm vs upstream expectation: agree={okexp} disagree={badexp}")
    return rows
if __name__=="__main__": compare(sys.argv[1] if len(sys.argv)>1 else "main")

# ---------- [F] mutate 심판: 서버 주입 기본값 정규화 + 잎 경로 비교 ----------
SERVER_DEFAULT_KEYS = {
    "imagePullPolicy","terminationMessagePath","terminationMessagePolicy","dnsPolicy",
    "restartPolicy","schedulerName","securityContext","serviceAccount","serviceAccountName",
    "terminationGracePeriodSeconds","revisionHistoryLimit","progressDeadlineSeconds","strategy",
    "concurrencyPolicy","failedJobsHistoryLimit","successfulJobsHistoryLimit","suspend",
    "backoffLimit","completionMode","parallelism","completions","manualSelector",
    "creationTimestamp","generation","uid","resourceVersion","selfLink","status",
    "clusterIP","clusterIPs","ipFamilies","ipFamilyPolicy","internalTrafficPolicy",
    "sessionAffinity","type","protocol","targetPort","volumeMode","storageClassName",
    "deprecatedServiceAccount","hostNetwork","preemptionPolicy","priority","enableServiceLinks",
    "tolerations","nodeName","podReplacementPolicy","automountServiceAccountToken",
}
def strip_server_defaults(o):
    """서버가 자동으로 채우는 필드를 제거해 CLI 기준 patched 픽스처와 비교 가능하게 만든다."""
    if isinstance(o, dict):
        return {k: strip_server_defaults(v) for k, v in o.items()
                if k not in SERVER_DEFAULT_KEYS}
    if isinstance(o, list):
        return [strip_server_defaults(x) for x in o]
    return o

def leaf_paths(o, p=()):
    """스칼라 잎에 도달하는 경로를 '튜플'로 산출.
       주의: 쿠버네티스 라벨/어노테이션 키에는 '/'가 들어가므로 문자열 경로를 쓰면 안 된다."""
    out = []
    if isinstance(o, dict):
        for k in sorted(o, key=str): out += leaf_paths(o[k], p + (("k", str(k)),))
    elif isinstance(o, list):
        for i, x in enumerate(o): out += leaf_paths(x, p + (("i", i),))
    else:
        out.append(p)
    return out

MISSING = "__MISSING__"
def dig_path(o, path):
    for typ, seg in path:
        if typ == "i":
            if not isinstance(o, list) or len(o) <= seg: return MISSING
            o = o[seg]
        else:
            if not isinstance(o, dict) or seg not in o: return MISSING
            o = o[seg]
    return o

def path_str(path):
    return "/" + "/".join(str(seg) if typ == "k" else f"[{seg}]" for typ, seg in path)

def mutation_referee(input_doc, patched_doc, actual_obj):
    """[F] 패치가 실제로 건드리는 '잎 경로'만 비교한다.
       returns (ok, mismatches[list of (path, expected, got)], n_checked)"""
    a = strip_server_defaults(norm(input_doc))
    b = strip_server_defaults(norm(patched_doc))
    got = strip_server_defaults(norm(actual_obj)) if actual_obj else {}
    touched = []
    for lp in leaf_paths(b):
        av = dig_path(a, lp); bv = dig_path(b, lp)
        if av != bv: touched.append(lp)          # 패치가 바꾼 잎만
    bad = []
    for lp in touched:
        exp = dig_path(b, lp); act = dig_path(got, lp)
        if act != exp: bad.append((path_str(lp), exp, act))
    return (len(bad) == 0 and len(touched) > 0), bad, len(touched)
