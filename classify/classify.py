#!/usr/bin/env python3
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

# Structural VAP/MAP-migratability classifier for the Kyverno policy corpus.
import os, sys, csv, json, re, yaml

REPO = os.path.abspath(sys.argv[1])
OUT_CSV = sys.argv[2]

POLICY_KINDS = {"ClusterPolicy","Policy","ValidatingPolicy","MutatingPolicy",
                "GeneratingPolicy","ImageValidatingPolicy","DeletingPolicy",
                "ClusterCleanupPolicy","CleanupPolicy"}
K_KINDS = {"GeneratingPolicy","ImageValidatingPolicy","DeletingPolicy",
           "ClusterCleanupPolicy","CleanupPolicy"}
RANK = {"N-DIRECT":0,"N-PARAM":1,"W-DYNAMIC":2,"W-AGGREGATE":3,"W-EXTERNAL":4}
ORDER = {"N-DIRECT":0,"N-PARAM":1,"W-DYNAMIC":2,"W-AGGREGATE":3,"W-EXTERNAL":4,"K-ONLY":5,"REVIEW":6}
def worse(a,b): return a if RANK[a]>=RANK[b] else b

def canonical_files():
    out=[]
    for root,dirs,files in os.walk(REPO):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fn in files:
            if not (fn.endswith(".yaml") or fn.endswith(".yml")): continue
            if fn.rsplit(".",1)[0] != os.path.basename(root): continue
            out.append(os.path.join(root,fn))
    return sorted(out)

def has_validate_cel(d):
    for r in (d.get("spec",{}) or {}).get("rules",[]) or []:
        if isinstance(r.get("validate"),dict) and "cel" in r["validate"]: return True
    if d.get("apiVersion","").startswith("policies.kyverno.io") and d.get("kind")=="ValidatingPolicy": return True
    return False

def is_single_named(segs):
    s=list(segs)
    if not s: return None
    if s[0]=="api": s=s[2:]
    elif s[0]=="apis": s=s[3:]
    else: return None
    if not s: return None
    if s[0]=="namespaces":
        if len(s)==2: return True
        return len(s[2:])>=2
    return len(s)>=2

def classify_apicall(ac):
    if ac.get("service"): return ("W-EXTERNAL","apiCall->external service")
    url=str(ac.get("urlPath","") or "")
    if url.startswith("http"): return ("W-EXTERNAL",f"apiCall external URL {url}")
    method=(ac.get("method") or "GET").upper()
    if method=="POST" or ("data" in ac and ac.get("data")):
        return ("W-AGGREGATE",f"apiCall POST/live-call {url}")
    path=url.split("?")[0]; query=url.split("?",1)[1] if "?" in url else ""
    if path in ("","/version","/healthz","/readyz","/livez"):
        return ("W-AGGREGATE",f"non-resource live apiCall urlPath={url} (not paramRef-expressible)")
    tmpl=("{{" in url)
    if "labelSelector" in query: return ("W-AGGREGATE",f"apiCall LIST labelSelector {url}")
    if "fieldSelector" in query and "metadata.name=" in query:
        return (("W-DYNAMIC" if tmpl else "N-PARAM"),f"apiCall single-by-fieldSelector {url}")
    segs=[x for x in path.split("/") if x]
    single=is_single_named(segs)
    if single is None: return ("REVIEW",f"apiCall unparsed urlPath={url}")
    if single: return (("W-DYNAMIC" if tmpl else "N-PARAM"),f"apiCall single GET {url}")
    return ("W-AGGREGATE",f"apiCall LIST {url}")

def classify_context_entry(c):
    if "configMap" in c:
        cm=c.get("configMap") or {}
        if "{{" in json.dumps(cm): return ("W-DYNAMIC",f"configMap templated {cm}")
        return ("N-PARAM",f"static configMap {cm.get('namespace')}/{cm.get('name')}")
    if "apiCall" in c: return classify_apicall(c.get("apiCall") or {})
    if "globalReference" in c: return ("W-EXTERNAL","globalReference")
    if "imageRegistry" in c: return ("W-EXTERNAL","imageRegistry")
    if "variable" in c: return ("N-DIRECT","variable(self)")
    return ("REVIEW","unknown-context:"+",".join(k for k in c if k!="name"))

CALL_RE = re.compile(r'(resource\.(?:Get|List|Post)|globalContext\.\w+|http\.\w+|image\.GetMetadata)\s*\(([^)]*)\)')
def split_args(s):
    out=[]; cur=""; depth=0; q=None
    for ch in s:
        if q:
            cur+=ch
            if ch==q: q=None
            continue
        if ch in "'\"": q=ch; cur+=ch; continue
        if ch in "([{": depth+=1; cur+=ch; continue
        if ch in ")]}": depth-=1; cur+=ch; continue
        if ch=="," and depth==0: out.append(cur.strip()); cur=""; continue
        cur+=ch
    if cur.strip(): out.append(cur.strip())
    return out
def is_literal(a):
    a=a.strip(); return (a.startswith("'") and a.endswith("'")) or (a.startswith('"') and a.endswith('"'))
def arg_dynamic(a, static_vars):
    a=a.strip()
    if is_literal(a): return False
    if "object" in a or "request" in a: return True
    m=re.match(r'variables\.(\w+)', a)
    if m: return m.group(1) not in static_vars
    return True

def rule_context_entries(r):
    """rule-level context plus validate/mutate foreach[].context"""
    out=list(r.get("context",[]) or [])
    for sec in ("validate","mutate"):
        blk=r.get(sec) or {}
        fe=blk.get("foreach")
        if isinstance(fe,list):
            for it in fe:
                if isinstance(it,dict):
                    out.extend(it.get("context",[]) or [])
    return out

def rule_has_paramkind(r):
    v=r.get("validate") or {}
    cel=v.get("cel") or {}
    return "paramKind" in cel

def classify_celcrd(doc):
    spec=doc.get("spec",{}) or {}
    exprs=[]
    for v in spec.get("variables",[]) or []:
        if isinstance(v,dict) and "expression" in v: exprs.append(str(v["expression"]))
    for key in ("validations","matchConditions"):
        for v in spec.get(key,[]) or []:
            if isinstance(v,dict):
                for kk in ("expression","message","messageExpression"):
                    if kk in v: exprs.append(str(v[kk]))
    for m in spec.get("mutations",[]) or []: exprs.append(json.dumps(m))
    blob="\n".join(exprs)
    static_vars=set()
    for v in spec.get("variables",[]) or []:
        if isinstance(v,dict) and is_literal(str(v.get("expression",""))): static_vars.add(v.get("name"))
    cat="N-DIRECT"; reasons=[]
    for m in CALL_RE.finditer(blob):
        fn=m.group(1); args=split_args(m.group(2))
        if fn=="resource.Get":
            dyn = any(arg_dynamic(a,static_vars) for a in args[2:4]) if len(args)>=4 else True
            c=("W-DYNAMIC" if dyn else "N-PARAM"); reasons.append(f"{fn}({','.join(args)})->{c}"); cat=worse(cat,c)
        elif fn in ("resource.List","resource.Post"):
            cat=worse(cat,"W-AGGREGATE"); reasons.append(f"{fn}->W-AGGREGATE")
        else:
            cat=worse(cat,"W-EXTERNAL"); reasons.append(f"{fn}->W-EXTERNAL")
    if "paramKind" in spec:
        cat=worse(cat,"N-PARAM"); reasons.append("spec.paramKind (native paramRef)")
    return cat, ("; ".join(reasons) if reasons else "self-fields only (CEL)")

def match_kinds_of(doc):
    spec=doc.get("spec",{}) or {}; ks=set()
    for r in spec.get("rules",[]) or []:
        mt=r.get("match",{}) or {}
        for grp in ("any","all"):
            for m in mt.get(grp,[]) or []:
                for k in ((m.get("resources",{}) or {}).get("kinds",[]) or []): ks.add(k)
        for k in ((mt.get("resources",{}) or {}).get("kinds",[]) or []): ks.add(k)
    for rr in (spec.get("matchConstraints",{}) or {}).get("resourceRules",[]) or []:
        for k in rr.get("resources",[]) or []: ks.add(k)
    return ",".join(sorted(ks))

def classify_doc(doc):
    kind=doc.get("kind"); apiv=doc.get("apiVersion",""); spec=doc.get("spec",{}) or {}
    if kind in K_KINDS:
        rk={"GeneratingPolicy":"generate","ImageValidatingPolicy":"verifyImages",
            "DeletingPolicy":"cleanup","ClusterCleanupPolicy":"cleanup","CleanupPolicy":"cleanup"}[kind]
        return ("K-ONLY","none",rk,f"{kind}: {rk} has no native VAP/MAP concept")
    if apiv.startswith("policies.kyverno.io"):
        if kind=="ValidatingPolicy":
            cat,reason=classify_celcrd(doc); return (cat,("VAP" if cat in("N-DIRECT","N-PARAM") else "none"),"validate",reason)
        if kind=="MutatingPolicy":
            cat,reason=classify_celcrd(doc); return (cat,("MAP" if cat in("N-DIRECT","N-PARAM") else "none"),"mutate",reason)
        return ("REVIEW","none","?",f"unhandled CEL-CRD kind {kind}")
    rules=spec.get("rules",[]) or []
    ruletypes=set(); has_mutate_existing=False
    for r in rules:
        for t in ("validate","mutate","generate","verifyImages"):
            if t in r: ruletypes.add(t)
        if "targets" in (r.get("mutate") or {}): has_mutate_existing=True
    if "generate" in ruletypes: return ("K-ONLY","none","generate","generate rule: no native equivalent")
    if "verifyImages" in ruletypes: return ("K-ONLY","none","verifyImages","image signature/attestation verify: no native equivalent")
    if has_mutate_existing: return ("K-ONLY","none","mutateExisting","mutate.targets (mutateExisting): no native MAP equivalent")
    cat="N-DIRECT"; reasons=[]
    # match/exclude by roles/clusterRoles needs RBAC-binding resolution -> not native
    def uses_rbac(r):
        for sec in ("match","exclude"):
            blk=r.get(sec) or {}
            for sb in [blk]+ (blk.get("any",[]) or []) + (blk.get("all",[]) or []):
                if isinstance(sb,dict) and (sb.get("roles") or sb.get("clusterRoles")): return True
        return False
    if any(uses_rbac(r) for r in rules):
        cat=worse(cat,"W-AGGREGATE"); reasons.append("match/exclude by roles/clusterRoles needs RBAC lookup")
    for r in rules:
        if rule_has_paramkind(r):
            cat=worse(cat,"N-PARAM"); reasons.append("validate.cel.paramKind (native paramRef)")
        for c in rule_context_entries(r):
            cc,rr=classify_context_entry(c)
            if cc=="REVIEW": return ("REVIEW","none","/".join(sorted(ruletypes)) or "?",rr)
            cat=worse(cat,cc)
            if cc!="N-DIRECT": reasons.append(rr)
    if not ruletypes: return ("REVIEW","none","none","no recognized rule type")
    tgt="none"
    if cat in ("N-DIRECT","N-PARAM"):
        if {"validate","mutate"}<=ruletypes: tgt="VAP+MAP"
        elif "validate" in ruletypes: tgt="VAP"
        elif "mutate" in ruletypes: tgt="MAP"
    return (cat,tgt,"/".join(sorted(ruletypes)),("; ".join(reasons) if reasons else "self-fields only"))

def representation(kind, path):
    if kind=="ValidatingPolicy": return "vpol"
    if kind=="MutatingPolicy": return "mpol"
    if kind=="GeneratingPolicy": return "gpol"
    if kind=="ImageValidatingPolicy": return "ivpol"
    if kind in ("DeletingPolicy","ClusterCleanupPolicy","CleanupPolicy"): return "cleanup"
    rel=os.path.relpath(path,REPO); top=rel.split(os.sep)[0]
    return "clusterpolicy-cel" if top.endswith("-cel") else "clusterpolicy"

rows=[]; counts={}; excluded=[]
for f in canonical_files():
    try:
        docs=[d for d in yaml.safe_load_all(open(f,encoding="utf-8",errors="replace")) if isinstance(d,dict)]
    except Exception as e:
        excluded.append((os.path.relpath(f,REPO),f"parse-error:{e}")); continue
    poldocs=[d for d in docs if d.get("kind") in POLICY_KINDS]
    if not poldocs:
        excluded.append((os.path.relpath(f,REPO),"no-policy-kind:"+",".join(sorted({d.get('kind','?') for d in docs})))); continue
    best=None
    for d in poldocs:
        cat,tgt,rt,reason=classify_doc(d)
        rec=dict(path=os.path.relpath(f,REPO), name=(d.get("metadata",{}) or {}).get("name",""),
                 kind=d.get("kind"), apiVersion=d.get("apiVersion",""),
                 representation=representation(d.get("kind"),f), ruletypes=rt,
                 category=cat, native_target=tgt, cross_ref=reason,
                 match_kinds=match_kinds_of(d), has_validate_cel=str(has_validate_cel(d)))
        if best is None or ORDER[rec["category"]]>ORDER[best["category"]]: best=rec
    rows.append(best); counts[best["category"]]=counts.get(best["category"],0)+1

cols=["path","name","kind","apiVersion","representation","ruletypes","category","native_target","cross_ref","match_kinds","has_validate_cel"]
with open(OUT_CSV,"w",newline="") as fh:
    w=csv.DictWriter(fh,fieldnames=cols); w.writeheader()
    for r in sorted(rows,key=lambda x:(x["category"],x["path"])): w.writerow(r)

total=len(rows)
print(f"CANONICAL policy files analysed: {total}")
print(f"EXCLUDED (no policy kind / parse error): {len(excluded)}")
print("\n=== category counts ===")
for c in ["N-DIRECT","N-PARAM","W-DYNAMIC","W-AGGREGATE","W-EXTERNAL","K-ONLY","REVIEW"]:
    n=counts.get(c,0); print(f"  {c:12} {n:5d}  {100*n/total:5.1f}%")
native=counts.get("N-DIRECT",0)+counts.get("N-PARAM",0)
web=sum(counts.get(c,0) for c in ("W-DYNAMIC","W-AGGREGATE","W-EXTERNAL"))
print("\n=== headline ===")
print(f"  fundamentally native-able (N-DIRECT+N-PARAM): {native} ({100*native/total:.1f}%)")
print(f"  webhook-required (W-*):                       {web} ({100*web/total:.1f}%)")
print(f"  K-ONLY:                                       {counts.get('K-ONLY',0)} ({100*counts.get('K-ONLY',0)/total:.1f}%)")
print(f"  N-PARAM (often mislabeled 'webhook'):         {counts.get('N-PARAM',0)} ({100*counts.get('N-PARAM',0)/total:.1f}%)")
print(f"  REVIEW:                                       {counts.get('REVIEW',0)}")
print("\n=== representation x category ===")
byrep={}
for r in rows: byrep.setdefault(r["representation"],{}).setdefault(r["category"],0); byrep[r["representation"]][r["category"]]+=1
for rep in sorted(byrep): print(f"  {rep:20} "+" ".join(f"{k}:{v}" for k,v in sorted(byrep[rep].items())))
print("\n=== REVIEW list ===")
for r in rows:
    if r["category"]=="REVIEW": print(f"  {r['path']}  [{r['ruletypes']}]  {r['cross_ref']}")
# dump summary json
json.dump({"total":total,"counts":counts,"excluded":excluded}, open(OUT_CSV+".summary.json","w"), indent=1)
print(f"\nCSV -> {OUT_CSV}")
print(f"excluded sample: {excluded[:3]}")
