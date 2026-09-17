#!/usr/bin/env python3
"""Emulate Kyverno pod-controller autogen inside native VAP/MAP conversions."""
import os, re, sys, json, yaml, copy
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

BASE=_DATA
TEMPLATE_KINDS=[("apps","v1",["deployments","statefulsets","daemonsets","replicasets"]),
                ("batch","v1",["jobs"]),
                ("","v1",["replicationcontrollers"])]
CRON=[("batch","v1",["cronjobs"])]

def rw(expr, mode):
    if not isinstance(expr,str): return expr
    if mode=="template": sp,me="object.spec.template.spec","object.spec.template.metadata"
    else: sp,me="object.spec.jobTemplate.spec.template.spec","object.spec.jobTemplate.spec.template.metadata"
    e=expr
    for var in ("object","oldObject"):
        p_sp=sp.replace("object",var); p_me=me.replace("object",var)
        e=re.sub(rf"\b{var}\.spec\.", p_sp+".", e)
        e=re.sub(rf"\b{var}\.spec\b(?!\.)", p_sp, e)
        e=re.sub(rf"\b{var}\.metadata\.", p_me+".", e)
        e=re.sub(rf"\b{var}\.metadata\b(?!\.)", p_me, e)
    return e

def rw_deep(x, mode):
    if isinstance(x,str): return rw(x,mode)
    if isinstance(x,list): return [rw_deep(i,mode) for i in x]
    if isinstance(x,dict): return {k:rw_deep(v,mode) for k,v in x.items()}
    return x

def matches_pods(spec):
    for rr in (spec.get("matchConstraints",{}) or {}).get("resourceRules",[]) or []:
        if "pods" in (rr.get("resources") or []) and ("" in (rr.get("apiGroups") or [""])):
            return rr
    return None

def expand_file(path):
    docs=[d for d in yaml.safe_load_all(open(path,errors="replace")) if isinstance(d,dict)]
    if any(str((d.get("metadata",{}) or {}).get("name","")).endswith(("-ag1","-ag2","-ag1-b","-ag2-b")) for d in docs):
        return 0
    out=list(docs); added=0
    for d in docs:
        kind=d.get("kind")
        if kind not in ("ValidatingAdmissionPolicy","MutatingAdmissionPolicy"): continue
        spec=d.get("spec",{}) or {}
        podrule=matches_pods(spec)
        if not podrule: continue
        # skip if the policy ALSO already targets controllers (author handled it)
        allres=set()
        for rr in spec["matchConstraints"]["resourceRules"]:
            allres |= set(rr.get("resources") or [])
        if allres & {"deployments","cronjobs","statefulsets","daemonsets","jobs"}: continue
        ops=podrule.get("operations") or ["CREATE","UPDATE"]
        for mode,groups in (("template",TEMPLATE_KINDS),("cronjob",CRON)):
            nd=copy.deepcopy(d)
            nspec=nd["spec"]
            nd["metadata"]={"name":d["metadata"]["name"][:57]+("-ag1" if mode=="template" else "-ag2")}
            rules=[]
            for g,v,plurals in groups:
                rules.append({"apiGroups":[g],"apiVersions":[v],"operations":ops,"resources":plurals})
            mc=copy.deepcopy(spec.get("matchConstraints",{}) or {})
            mc["resourceRules"]=rules
            nspec["matchConstraints"]=mc
            for key in ("validations","variables","matchConditions","auditAnnotations","mutations"):
                if key in nspec: nspec[key]=rw_deep(nspec[key],mode)
            out.append(nd)
            bkind=("ValidatingAdmissionPolicyBinding" if kind=="ValidatingAdmissionPolicy"
                   else "MutatingAdmissionPolicyBinding")
            b={"apiVersion":"admissionregistration.k8s.io/v1","kind":bkind,
               "metadata":{"name":nd["metadata"]["name"]+"-b"},
               "spec":{"policyName":nd["metadata"]["name"]}}
            if kind=="ValidatingAdmissionPolicy": b["spec"]["validationActions"]=["Deny"]
            out.append(b); added+=1
    if added:
        yaml.safe_dump_all(out,open(path,"w"),sort_keys=False)
    return added

def main():
    plan=json.load(open(f"{BASE}/plan.json"))
    CTRL={"Deployment","StatefulSet","DaemonSet","ReplicaSet","Job","CronJob","ReplicationController"}
    n=0; tot=0
    for slug,v in sorted(plan.items()):
        p=f"{BASE}/native/{slug}.yaml"
        if not os.path.exists(p): continue
        # only expand when the policy's own kyverno original would autogen (i.e. matches Pod)
        try: a=expand_file(p)
        except Exception as e:
            print("EXPAND-ERR",slug,e); continue
        if a: n+=1; tot+=a
    print(f"expanded {n} native files (+{tot} autogen policy pairs)")

if __name__=="__main__": main()
