#!/usr/bin/env python3
"""RQ4 equivalence harness: per-policy namespace isolation makes batching safe."""
import os, sys, json, yaml, subprocess, time, copy, argparse
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

BASE=_DATA
SCR=_SCRATCH
ENV={**os.environ,"KUBECONFIG":f"{SCR}/kubeconfig"}
NSLOTS=140

def kc(args, inp=None, timeout=90):
    try:
        p=subprocess.run(["kubectl"]+args, input=inp, capture_output=True, text=True, env=ENV, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124,"","TIMEOUT"

def load_plan(): return json.load(open(f"{BASE}/plan.json"))

# ---------- scoping ----------
def scope_kyverno(doc, ns, cluster_scoped=False, extra_ns=()):
    """정책을 '그 정책의 케이스가 실제로 사용하는 네임스페이스'로 한정한다.
       [C]  클러스터 스코프 대상에는 namespaces 제약을 주입하지 않는다(매치 0이 되어버림).
       [B+] 픽스처가 선언한 네임스페이스를 포함하지 않으면 정책이 리소스와 만나지 못한다."""
    if cluster_scoped: return doc
    nslist=sorted({ns} | {x for x in (extra_ns or ()) if x})
    spec=doc.setdefault("spec",{})
    if doc.get("kind") in ("ClusterPolicy","Policy"):
        for r in spec.get("rules",[]) or []:
            m=r.get("match",{}) or {}
            blocks=[]
            if "any" in m: blocks=m["any"]
            elif "all" in m: blocks=m["all"]
            elif "resources" in m: blocks=[m]
            for b in blocks:
                res=b.get("resources")
                if isinstance(res,dict): res["namespaces"]=nslist
    else:  # vpol / mpol
        mc=spec.setdefault("matchConstraints",{})
        mc["namespaceSelector"]={"matchExpressions":[
            {"key":"kubernetes.io/metadata.name","operator":"In","values":nslist}]}
    return doc

def scope_native(docs, ns, cluster_scoped=False, extra_ns=()):
    """[C] 클러스터 스코프 대상이면 namespaceSelector를 걸지 않는다.
       [B+] 그 외에는 슬롯 네임스페이스와 픽스처 선언 네임스페이스의 합집합으로 한정."""
    out=[]
    nslist=sorted({ns} | {x for x in (extra_ns or ()) if x})
    for d in docs:
        d=copy.deepcopy(d)
        if d.get("kind","").endswith("Binding") and not cluster_scoped:
            mr=d["spec"].setdefault("matchResources",{})
            mr["namespaceSelector"]={"matchExpressions":[
                {"key":"kubernetes.io/metadata.name","operator":"In","values":nslist}]}
        out.append(d)
    return out

def read_docs(p):
    return [d for d in yaml.safe_load_all(open(p,errors="replace")) if isinstance(d,dict)]

# ---------- submission ----------
def submit(case_doc, ns, namespaced, declared_ns=None):
    """[B] 픽스처가 metadata.namespace를 선언했으면 그 값을 보존한다.
       정책이 네임스페이스 이름/라벨을 조건으로 쓰는 경우 강제 이동은 전제를 파괴한다."""
    d=copy.deepcopy(case_doc)
    meta=d.setdefault("metadata",{})
    if namespaced:
        target_ns = declared_ns or (case_doc.get("metadata",{}) or {}).get("namespace") or ns
        meta["namespace"]=target_ns
    else:
        meta.pop("namespace",None); target_ns=None
    args=["create","--dry-run=server","-o","json","-f","-"]
    if namespaced: args+=["-n",target_ns]
    rc,out,err=kc(args, inp=yaml.safe_dump(d))
    if rc==0:
        try: obj=json.loads(out)
        except Exception: obj=None
        return {"verdict":"admit","obj":obj}
    e=err.strip()
    low=e.lower()
    if ("denied the request" in low or "denied request" in low
        or "admission webhook" in low and "denied" in low
        or "validatingadmissionpolicy" in low and "denied" in low):
        return {"verdict":"deny","err":e[:900]}
    return {"verdict":"error","err":e[:900]}

def wait_kyverno_ready(names, timeout=180):
    """poll policy Ready conditions"""
    t0=time.time()
    while time.time()-t0<timeout:
        rc,out,_=kc(["get","clusterpolicy,vpol,mpol","-o","json"])
        if rc==0:
            try: items=json.loads(out).get("items",[])
            except Exception: items=[]
            got={}
            for it in items:
                n=it["metadata"]["name"]
                st=it.get("status",{}) or {}
                conds=st.get("conditions",[]) or []
                cs=st.get("conditionStatus")
                if isinstance(cs,dict) and "ready" in cs:
                    got[n]=bool(cs.get("ready"))      # vpol/mpol: needs webhook configured (~40s)
                else:
                    ready=any(c.get("type")=="Ready" and c.get("status")=="True" for c in conds)
                    got[n]=ready or not conds
            if names and all(got.get(n,False) for n in names): return True, time.time()-t0
            if not names: return True,0
        time.sleep(3)
    return False, time.time()-t0


# ---------- 절차2: 원본 웹훅 등록 게이트 ----------
import sys as _sys
_sys.path.insert(0,BASE)
try:
    from convert_cel_crds import GVR as _GVR, norm_kind as _nk
except Exception:
    _GVR={}; _nk=lambda x:str(x).lower()

def target_plurals(e):
    """정책 케이스의 kind들을 API plural로 변환"""
    out=set()
    for c in e.get("cases",[]):
        k=c.get("kind")
        if not k: continue
        if k in _GVR: out.add(_GVR[k][2])
        else:
            kk=_nk(k)
            out.add(kk+"es" if kk.endswith(("s","x","z","ch","sh")) else kk+"s")
    return out

def kyverno_webhook_has(plurals):
    rc,out,_=kc(["get","validatingwebhookconfiguration","kyverno-resource-validating-webhook-cfg",
                 "-o","json"])
    if rc!=0: return set()
    try: d=json.loads(out)
    except Exception: return set()
    have=set()
    for wh in d.get("webhooks",[]) or []:
        for r in wh.get("rules",[]) or []:
            for res in (r.get("resources") or []):
                have.add(res.split("/")[0])
                if res=="*": have|=set(plurals)
    return have

def celcrd_ready(names):
    rc,out,_=kc(["get","vpol,mpol","-o","json"])
    if rc!=0: return {}
    try: items=json.loads(out).get("items",[])
    except Exception: return {}
    st={}
    for it in items:
        n=it["metadata"]["name"]
        cs=(it.get("status",{}) or {}).get("conditionStatus",{}) or {}
        conds={c.get("type"):c.get("status") for c in (cs.get("conditions") or [])}
        st[n]= bool(cs.get("ready")) and conds.get("WebhookConfigured")=="True"
    return st

def wait_webhook_registered(entries, timeout=300):
    """entries: [(slug, polname, family, plurals)] -> dict slug->bool"""
    t0=time.time(); ready={s:False for s,_,_,_ in entries}
    cp=[(s,n,pl) for s,n,f,pl in entries if f not in ("vpol","mpol")]
    cc=[(s,n) for s,n,f,pl in entries if f in ("vpol","mpol")]
    while time.time()-t0<timeout:
        if cp:
            allpl=set().union(*[pl for _,_,pl in cp]) if cp else set()
            have=kyverno_webhook_has(allpl)
            for s,n,pl in cp:
                if pl and pl.issubset(have): ready[s]=True
        if cc:
            st=celcrd_ready([n for _,n in cc])
            for s,n in cc:
                if st.get(n): ready[s]=True
        if all(ready.values()): return ready, time.time()-t0
        time.sleep(4)
    return ready, time.time()-t0

# ---------- 절차3: 카나리 ----------
def canary_case(e):
    """검증에 쓸 대표 케이스: validate는 fail 기대 1개, mutate는 patched 있는 케이스 1개"""
    if e.get("is_mutate"):
        for c in e.get("cases",[]):
            if c.get("patched"): return c
        return None
    for c in e.get("cases",[]):
        if c.get("expected")=="fail": return c
    return None

def run_canary(slug, e, ns):
    """원본이 실제로 작동하는지 확인. -> (ok, detail)"""
    c=canary_case(e)
    if not c: return None,"no-canary-case"
    fp=f"{BASE}/tests/{slug}/{c['file']}"
    if not os.path.exists(fp): return None,"canary-file-missing"
    try: cd=yaml.safe_load(open(fp,errors="replace"))
    except Exception as ex: return None,f"canary-parse:{ex}"
    r=submit(cd, ns, c.get("namespaced",True), declared_ns=c.get("declared_ns"))
    if e.get("is_mutate"):
        pf=c.get("patched")
        if not pf or not os.path.exists(f"{BASE}/tests/{slug}/{pf}"): return None,"no-patched"
        if r["verdict"]!="admit" or not r.get("obj"): return False,f"canary-verdict={r['verdict']}"
        try:
            from compare import mutation_referee
            inp=yaml.safe_load(open(fp,errors="replace"))
            ref=yaml.safe_load(open(f"{BASE}/tests/{slug}/{pf}",errors="replace"))
            ok,bad,n=mutation_referee(inp,ref,r["obj"])
            return (ok if n>0 else None), (f"mutation-checked={n} bad={len(bad)}" if n>0 else "no-leaf")
        except Exception as ex: return None,f"canary-mut-err:{ex}"
    return (r["verdict"]=="deny"), f"canary-verdict={r['verdict']}"

# ---------- arms ----------
def ensure_namespaces(plan, slugs):
    """[B] 픽스처가 선언한 네임스페이스를 라벨까지 포함해 미리 만들어 둔다."""
    want={}
    for s in slugs:
        e=plan.get(s) or {}
        for c in e.get("cases",[]):
            dn=c.get("declared_ns")
            if dn: want.setdefault(dn,{}).update(e.get("ns_labels") or {})
        for k,v in (e.get("ns_labels") or {}).items():
            pass
    SYSTEM_NS={"default","kube-system","kube-public","kube-node-lease","kyverno"}
    docs=[]; skipped=[]
    for ns,labels in sorted(want.items()):
        if ns in SYSTEM_NS:
            # 시스템 네임스페이스는 이미 존재하며 라벨을 덧씌우지 않는다(부작용 방지).
            skipped.append(ns); continue
        lb={"rq4-fixture":"true"}; lb.update({k:str(v) for k,v in (labels or {}).items()})
        docs.append({"apiVersion":"v1","kind":"Namespace",
                     "metadata":{"name":ns,"labels":lb}})
    if docs:
        kc(["apply","-f","-"],inp=yaml.safe_dump_all(docs),timeout=180)
    return {"created":sorted(d["metadata"]["name"] for d in docs),"system_skipped":sorted(skipped)}

GATE_TIMEOUT=300
def run_arm(arm, slugs, plan, batch_size, outpath, settle):
    results={}
    if os.path.exists(outpath):
        results=json.load(open(outpath))
    todo=[s for s in slugs if s not in results]
    print(f"[{arm}] todo={len(todo)} (done={len(results)})", flush=True)
    ensure_namespaces(plan, todo)                                  # [B]
    # [E] 클러스터 스코프 대상 정책은 격리(배치 1)로 분리 실행
    iso=[s for s in todo if (plan.get(s) or {}).get("cluster_scoped_case")
         or (plan.get(s) or {}).get("declared_namespaces")]                           # [E] batch=1
                                                                                       # 선언 ns를 공유하면
                                                                                       # 배치 간섭이 생기므로 격리
    rest=[s for s in todo if s not in set(iso)]
    cel=[s for s in rest if (plan.get(s) or {}).get("family") in ("vpol","mpol")]      # 절차4 <=10
    reg=[s for s in rest if s not in set(cel)]
    CEL_B=min(10,batch_size)
    batches =[reg[i:i+batch_size] for i in range(0,len(reg),batch_size)]
    batches+=[cel[i:i+CEL_B] for i in range(0,len(cel),CEL_B)]
    batches+=[[s] for s in iso]
    print(f"[{arm}] batches: 일반 {len(reg)}건/{batch_size}  vpol·mpol {len(cel)}건/{CEL_B}  격리 {len(iso)}건/1",flush=True)
    for bi,batch in enumerate(batches):
        d=f"{SCR}/arm_{arm}"; subprocess.run(["rm","-rf",d]); os.makedirs(d,exist_ok=True)
        applied=[]; polnames=[]
        for si,slug in enumerate(batch):
            ns=f"rq4-{si:03d}"
            e=plan[slug]
            cscope=bool(e.get("cluster_scoped_case"))               # [C]
            try:
                if arm=="kyverno":
                    doc=yaml.safe_load(open(f"{BASE}/originals-normalized/{slug}.yaml",errors="replace"))
                    doc=scope_kyverno(doc,ns,cluster_scoped=cscope)
                    yaml.safe_dump(doc,open(f"{d}/{si:03d}.yaml","w"),sort_keys=False)
                    polnames.append(doc["metadata"]["name"])
                else:
                    docs=read_docs(f"{BASE}/native/{slug}.yaml")
                    docs=scope_native(docs,ns,cluster_scoped=cscope)
                    yaml.safe_dump_all(docs,open(f"{d}/{si:03d}.yaml","w"),sort_keys=False)
                applied.append((slug,ns,si))
            except Exception as ex:
                results[slug]={"apply_error":f"prep: {ex}"}
        rc,out,err=kc(["apply","-f",d],timeout=300)
        apply_err=err
        # per-file fallback for partial failures
        if rc!=0:
            for slug,ns,si in applied:
                r2,o2,e2=kc(["apply","-f",f"{d}/{si:03d}.yaml"],timeout=90)
                if r2!=0: results[slug]={"apply_error":e2.strip()[:600]}
        gate={}; canary={}
        if arm=="kyverno":
            wait_kyverno_ready([p for p in polnames], timeout=180)
            ents=[]
            for slug,ns,si in applied:
                e=plan[slug]
                ents.append((slug, e["name"], e.get("family"), target_plurals(e)))
            gate,gt=wait_webhook_registered(ents, timeout=GATE_TIMEOUT)          # 절차2
            nready=[s for s,v in gate.items() if not v]
            print(f"[{arm}] batch {bi}: webhook-gate ok={sum(gate.values())}/{len(gate)} ({gt:.0f}s)"
                  + (f" NOT-READY={len(nready)}" if nready else ""),flush=True)
            time.sleep(settle)
            for slug,ns,si in applied:                                   # 절차3 카나리
                if not gate.get(slug,False):
                    results[slug]={"baseline":"BASELINE-NOT-READY","ns":ns,"cases":[]}
                    continue
                ok,detail=run_canary(slug, plan[slug], ns)
                canary[slug]=(ok,detail)
        else:
            time.sleep(settle)
        for slug,ns,si in applied:
            if slug in results and ("apply_error" in results[slug] or
                                    results[slug].get("baseline")=="BASELINE-NOT-READY"): continue
            e=plan[slug]; cases=[]
            for c in e["cases"]:
                fp=f"{BASE}/tests/{slug}/{c['file']}"
                if not os.path.exists(fp): continue
                try: cd=yaml.safe_load(open(fp,errors="replace"))
                except Exception as ex:
                    cases.append({"file":c["file"],"verdict":"error","err":f"parse {ex}"}); continue
                if not isinstance(cd,dict): continue
                r=submit(cd, ns, c.get("namespaced",True), declared_ns=c.get("declared_ns"))
                r["file"]=c["file"]; r["expected"]=c.get("expected"); r["source"]=c.get("source")
                cases.append(r)
            rec={"ns":ns,"cases":cases}
            if arm=="kyverno":
                cok,cdet=canary.get(slug,(None,"not-run"))
                rec["canary_ok"]=cok; rec["canary_detail"]=cdet
                rec["webhook_registered"]=bool(gate.get(slug,False))
                if cok is False: rec["baseline"]="BASELINE-DEAD"
            results[slug]=rec
        kc(["delete","-f",d,"--ignore-not-found","--wait=true"],timeout=600)
        # ensure a clean slate before reusing namespace slots (prevents cross-batch interference)
        for _ in range(60):
            rc,out,_=kc(["get","clusterpolicy,vpol,mpol,validatingadmissionpolicy,mutatingadmissionpolicy",
                         "-o","jsonpath={.items[*].metadata.name}"])
            if rc==0 and not out.strip(): break
            time.sleep(3)
        json.dump(results,open(outpath,"w"))
        print(f"[{arm}] batch {bi+1}/{len(batches)} done ({len(results)}/{len(slugs)})",flush=True)
        if arm=="kyverno": time.sleep(6)
    return results

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("cmd"); ap.add_argument("--slugs",default=None)
    ap.add_argument("--batch",type=int,default=40); ap.add_argument("--settle",type=int,default=12)
    ap.add_argument("--tag",default="main")
    ap.add_argument("--gate",type=int,default=300)
    a=ap.parse_args()
    plan=load_plan()
    global GATE_TIMEOUT
    GATE_TIMEOUT=a.gate
    if a.slugs: slugs=[l.strip() for l in open(a.slugs) if l.strip()]
    else: slugs=sorted(plan)
    if a.cmd=="ns":
        docs=[{"apiVersion":"v1","kind":"Namespace","metadata":{"name":f"rq4-{i:03d}","labels":{"rq4":"true"}}} for i in range(NSLOTS)]
        rc,out,err=kc(["apply","-f","-"],inp=yaml.safe_dump_all(docs))
        print(out[-300:] if rc==0 else err)
    elif a.cmd in ("kyverno","native"):
        run_arm(a.cmd,slugs,plan,a.batch,f"{BASE}/results_{a.cmd}_{a.tag}.json",a.settle)
    else: print("?")

if __name__=="__main__": main()
