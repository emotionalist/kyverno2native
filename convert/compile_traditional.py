#!/usr/bin/env python3
"""Deterministic compiler: traditional Kyverno (pattern/deny/preconditions/PSM) -> native VAP/MAP."""
import os, re, sys, json, yaml, copy
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

sys.path.insert(0,_HERE)
import convert_cel_crds as T
from convert_cel_crds import build_match_constraints, native_name, ConvertError
BASE=_DATA

def q(s): return json.dumps(str(s))

def wildcard_to_regex(v):
    out="^"
    for ch in v:
        if ch=="*": out+=".*"
        elif ch=="?": out+="."
        else: out+=re.escape(ch)
    return out+"$"

def leaf(pathexpr, v):
    """CEL for 'field at pathexpr matches kyverno pattern value v'"""
    if v is None: return None
    if isinstance(v,bool): return f"{pathexpr} == {'true' if v else 'false'}"
    if isinstance(v,(int,float)): return f"{pathexpr} == {v}"
    s=str(v).strip()
    if s in ("*",): return "true"
    if s in ("?*",): return f"{pathexpr} != \"\""
    if s.lower()=="null": return None
    if "|" in s and not any(c in s for c in "<>"):
        parts=[p.strip() for p in s.split("|")]
        return "(" + " || ".join(leaf(pathexpr,p) for p in parts) + ")"
    m=re.match(r"^(>=|<=|>|<)\s*(-?\d+(?:\.\d+)?)$", s)
    if m:
        op,num=m.group(1),m.group(2)
        return f"{pathexpr} {op} {num}"
    if s in ("true","false"):
        return f"(type({pathexpr}) == bool ? {pathexpr} == {s} : {pathexpr} == {q(s)})"
    if s in ("!true","!false"):
        b=s[1:]
        return f"(type({pathexpr}) == bool ? {pathexpr} != {b} : {pathexpr} != {q(b)})"
    if s.startswith("!"):
        rest=s[1:]
        if "*" in rest or "?" in rest:
            return f"!{pathexpr}.matches({q(wildcard_to_regex(rest))})"
        return f"{pathexpr} != {q(rest)}"
    if "*" in s or "?" in s:
        return f"{pathexpr}.matches({q(wildcard_to_regex(s))})"
    return f"{pathexpr} == {q(s)}"

ANCHOR=re.compile(r"^(=|X|\^|\+|<|>)?\((.+)\)$")
def parse_key(k):
    m=ANCHOR.match(str(k))
    if m: return (m.group(1) or "COND"), m.group(2)
    return "PLAIN", str(k)

def compile_node(node, path, depth=0):
    """returns CEL bool expr requiring 'node pattern' holds at 'path'"""
    if depth>8: raise ConvertError("pattern too deep")
    if isinstance(node,dict):
        conds=[]; asserts=[]
        for k,v in node.items():
            kind,name=parse_key(k)
            if ("*" in name or "?" in name) and kind in ("PLAIN","=","X"):
                rx=q(wildcard_to_regex(name)); kv=f"__k{depth}"
                velem=f"{path}[{kv}]"
                inner=(leaf(velem,v) if not isinstance(v,(dict,list)) else compile_node(v,velem,depth+1)) or "true"
                if kind=="X":
                    # 부정 앵커: 글롭에 매치하면서 값까지 맞는 키가 하나도 없어야 함
                    asserts.append(f"!has({path}) || !{path}.exists({kv}, {kv}.matches({rx}) && ({inner}))")
                elif kind=="=":
                    # 등가 앵커: 매치하는 키가 있으면 전부 값이 맞아야 함(없으면 통과)
                    asserts.append(f"!has({path}) || {path}.all({kv}, !{kv}.matches({rx}) || ({inner}))")
                else:
                    # 평문 와일드카드 키: 매치하는 키가 '적어도 하나' 존재하고 값이 맞아야 함
                    # (.all()은 매치가 없을 때 공허참이 되어 통과시켜 버린다)
                    asserts.append(f"has({path}) && {path}.exists({kv}, {kv}.matches({rx}) && ({inner}))")
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$",name):
                child=f"{path}.{name}"; exists=f"has({child})"
            else:
                child=f"{path}[{q(name)}]"; exists=f"{q(name)} in {path}"
            if kind=="COND":
                c=compile_present(v,child,depth+1,exists)
                if c is not None: conds.append(c)
            elif kind=="X":
                if v is None or str(v).strip().lower()=="null":
                    asserts.append(f"!({exists})")
                else:
                    inner=leaf(child,v) if not isinstance(v,(dict,list)) else compile_node(v,child,depth+1)
                    asserts.append(f"(!({exists}) || !({inner}))")
            elif kind=="=":
                inner=compile_present(v,child,depth+1,exists)
                asserts.append(f"!({exists}) || ({inner})")
            elif kind=="^":
                if isinstance(v,list) and len(v)==1:
                    ie=compile_node(v[0],"__y",depth+1)
                    asserts.append(f"{exists} && {child}.exists(__y, {ie})")
                else:
                    asserts.append(compile_present(v,child,depth+1,exists))
            elif kind=="PLAIN":
                asserts.append(compile_present(v,child,depth+1,exists))
            else:
                raise ConvertError(f"anchor {kind} unsupported")
        asserts=[a for a in asserts if a]
        body=" && ".join(f"({a})" for a in asserts) if asserts else "true"
        if conds:
            cexpr=" && ".join(f"({c})" for c in conds)
            return f"!({cexpr}) || ({body})"
        return body
    if isinstance(node,list):
        if len(node)!=1: raise ConvertError("multi-element pattern list")
        inner=compile_node(node[0],"__x",depth+1)
        return f"{path}.all(__x, {inner})"
    r=leaf(path,node)
    return r if r is not None else "true"

def compile_present(v, child, depth, exists=None):
    """require the field exists AND matches"""
    if exists is None: exists=f"has({child})"
    if isinstance(v,(dict,list)):
        return f"{exists} && ({compile_node(v,child,depth)})"
    l=leaf(child,v)
    if l is None: return f"!({exists})"
    if l=="true": return exists
    return f"{exists} && ({l})"

# ---------- JMESPath-ish conditions ----------
JM=re.compile(r"^\{\{\s*(.+?)\s*\}\}$")
def jmes_to_cel(x):
    if not isinstance(x,str): return json.dumps(x)
    m=JM.match(x.strip())
    if not m:
        if "{{" in x: raise ConvertError(f"embedded template {x[:60]}")
        return q(x)
    e=m.group(1).strip()
    # Kyverno idiom: "{{request.operation || 'BACKGROUND'}}" -> admission always has operation
    md=re.match(r"^(.+?)\s*\|\|\s*['\"]?[A-Za-z_][A-Za-z0-9_]*['\"]?$", e)
    if md: e=md.group(1).strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.\[\]\"'@\- ]*$", e) or "(" in e:
        raise ConvertError(f"complex JMESPath {e[:60]}")
    e=e.replace("request.object.","object.").replace("request.oldObject.","oldObject.")
    if e.startswith("request.") and not e.startswith("request.operation") and not e.startswith("request.userInfo") \
       and not e.startswith("request.namespace") and not e.startswith("request.name"):
        raise ConvertError(f"unsupported request path {e}")
    if "[]" in e or "[*]" in e: raise ConvertError("jmespath projection")
    return e

OPMAP={"Equals":"==","NotEquals":"!=","GreaterThan":">","LessThan":"<",
       "GreaterThanOrEquals":">=","LessThanOrEquals":"<="}
def cond_to_cel(c):
    k=c.get("key"); op=c.get("operator"); v=c.get("value")
    left=jmes_to_cel(k)
    if op in OPMAP:
        if isinstance(v,str) and JM.match(v.strip()): right=jmes_to_cel(v)
        elif isinstance(v,bool): right="true" if v else "false"
        elif isinstance(v,(int,float)): right=str(v)
        else:
            if isinstance(v,str) and ("*" in v or "?" in v):
                rx=q(wildcard_to_regex(v))
                return f"{left}.matches({rx})" if op=="Equals" else f"!{left}.matches({rx})"
            right=q(v)
        return f"{left} {OPMAP[op]} {right}"
    if op in ("In","AnyIn","AllIn"):
        if not isinstance(v,list): raise ConvertError("In with non-list")
        return "(" + " || ".join(f"{left} == {q(x)}" for x in v) + ")"
    if op in ("NotIn","AnyNotIn","AllNotIn"):
        if not isinstance(v,list): raise ConvertError("NotIn with non-list")
        return "(" + " && ".join(f"{left} != {q(x)}" for x in v) + ")"
    raise ConvertError(f"operator {op}")

def conds_block(b):
    if isinstance(b,list): return " && ".join(f"({cond_to_cel(c)})" for c in b)
    if isinstance(b,dict):
        parts=[]
        if b.get("all"): parts.append(" && ".join(f"({cond_to_cel(c)})" for c in b["all"]))
        if b.get("any"): parts.append("(" + " || ".join(f"({cond_to_cel(c)})" for c in b["any"]) + ")")
        return " && ".join(parts) if parts else None
    raise ConvertError("bad conditions block")

# ---------- mutate: patchStrategicMerge ----------
MAPFIELDS={"labels","annotations","nodeSelector","matchLabels","selector"}
def psm_to_apply(psm):
    """Kyverno patchStrategicMerge -> MAP ApplyConfiguration expression + add-if-absent matchConditions"""
    conds=[]
    def maplit(d):
        return "{" + ", ".join(f"{q(k)}: {q(v)}" for k,v in d.items()) + "}"
    def build(node, dotted, objpath):
        fields=[]
        for k,v in node.items():
            kind,name=parse_key(k)
            if kind not in ("PLAIN","+"): raise ConvertError(f"PSM anchor {kind}")
            child_dot=f"{dotted}.{name}" if dotted else name
            child_obj=f"{objpath}.{name}"
            if kind=="+": conds.append(f"!has({child_obj})")
            if isinstance(v,dict):
                if name in MAPFIELDS:
                    if not all(isinstance(x,(str,int,float,bool)) for x in v.values()):
                        raise ConvertError("PSM nested map values")
                    for mk in list(v):
                        kk,nm=parse_key(mk)
                        if kk=="+":
                            conds.append(f"!({q(nm)} in {child_obj})")
                            v={(nm if x==mk else x):y for x,y in v.items()}
                        elif kk!="PLAIN": raise ConvertError("PSM map anchor")
                    fields.append(f"{name}: {maplit(v)}")
                else:
                    fields.append(f"{name}: Object.{child_dot}{build(v, child_dot, child_obj)}")
            elif isinstance(v,list):
                raise ConvertError("PSM list merge")
            else:
                if isinstance(v,str) and "{{" in v: raise ConvertError("PSM template value")
                lit=q(v) if isinstance(v,str) else json.dumps(v)
                fields.append(f"{name}: {lit}")
        return "{" + ", ".join(fields) + "}"
    body=build(psm, "", "object")
    return "Object"+body, conds

# ---------- rule compilation ----------
def compile_rule(r, slug, idx, unknown, total_rules):
    v=r.get("validate") or {}; m=r.get("mutate") or {}
    if r.get("context"): raise ConvertError("rule context (needs paramRef mapping)")
    if "foreach" in v or "foreach" in m: raise ConvertError("foreach")
    if "patchesJson6902" in m: raise ConvertError("patchesJson6902")
    if "cel" in v: raise ConvertError("cel rule (handled elsewhere)")
    mc,_=build_match_constraints(r, unknown)
    matchconds=[]
    if r.get("preconditions"):
        c=conds_block(r["preconditions"])
        if c: matchconds.append({"name":"preconditions","expression":c})
    name=native_name(slug, f"-r{idx}" if total_rules>1 else "")
    if v:
        exprs=[]
        if "pattern" in v:
            exprs.append({"expression":compile_node(v["pattern"],"object"),
                          "message":(v.get("message") or "policy violation")[:180]})
        elif "anyPattern" in v:
            parts=[f"({compile_node(p,'object')})" for p in v["anyPattern"]]
            exprs.append({"expression":" || ".join(parts),
                          "message":(v.get("message") or "policy violation")[:180]})
        elif "deny" in v:
            c=conds_block((v["deny"] or {}).get("conditions"))
            if not c: raise ConvertError("empty deny conditions")
            exprs.append({"expression":f"!({c})","message":(v.get("message") or "denied")[:180]})
        else: raise ConvertError("validate without pattern/anyPattern/deny")
        pol={"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicy",
             "metadata":{"name":name},
             "spec":{"failurePolicy":"Fail","matchConstraints":mc,"validations":exprs}}
        if matchconds: pol["spec"]["matchConditions"]=matchconds
        b={"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicyBinding",
           "metadata":{"name":name+"-b"},"spec":{"policyName":name,"validationActions":["Deny"]}}
        return [pol,b]
    if m:
        if "patchStrategicMerge" not in m: raise ConvertError("mutate without PSM")
        expr,addconds=psm_to_apply(m["patchStrategicMerge"])
        for i,c in enumerate(addconds): matchconds.append({"name":f"addifabsent{i}","expression":c})
        matchconds=[{"name":re.sub(r"[^a-z0-9.-]","-",str(mc["name"]).lower())[:63].strip("-.") or f"mc{j}",
                     "expression":mc["expression"]} for j,mc in enumerate(matchconds)]
        pol={"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy",
             "metadata":{"name":name},
             "spec":{"failurePolicy":"Fail","reinvocationPolicy":"Never","matchConstraints":mc,
                     "mutations":[{"patchType":"ApplyConfiguration","applyConfiguration":{"expression":expr}}]}}
        if matchconds: pol["spec"]["matchConditions"]=matchconds
        b={"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicyBinding",
           "metadata":{"name":name+"-b"},"spec":{"policyName":name}}
        return [pol,b]
    raise ConvertError("rule has neither validate nor mutate")

def main():
    targets=[t for t in json.load(open(f"{BASE}/targets.json")) if t["family"]=="clusterpolicy"]
    ok=0; failed=[]; unknown=set(); meta={}
    for t in targets:
        slug=t["slug"]
        d=yaml.safe_load(open(f"{BASE}/originals-normalized/{slug}.yaml",errors="replace"))
        rules=(d.get("spec",{}) or {}).get("rules",[]) or []
        docs=[]; errs=[]
        for i,r in enumerate(rules):
            try: docs+=compile_rule(r,slug,i,unknown,len(rules))
            except ConvertError as e: errs.append(f"rule[{r.get('name')}]: {e}")
            except Exception as e: errs.append(f"rule[{r.get('name')}]: EXC {type(e).__name__}: {e}")
        if docs and not errs:
            yaml.safe_dump_all(docs,open(f"{BASE}/native/{slug}.yaml","w"),sort_keys=False)
            meta[slug]={"method":"compiler","rules":len(rules)}
            ok+=1
        elif docs and errs:
            failed.append((slug,"PARTIAL: "+"; ".join(errs)))
        else:
            failed.append((slug,"; ".join(errs) or "no rules"))
    json.dump(meta,open(f"{BASE}/convert_meta_compiler.json","w"),indent=0)
    json.dump(sorted(failed),open(f"{BASE}/convert_failures_compiler.json","w"),indent=1)
    print(f"compiled OK: {ok} / {len(targets)}   failed: {len(failed)}")
    from collections import Counter
    reasons=Counter()
    for s,r in failed:
        key=re.sub(r"rule\[[^\]]*\]: ","",r).split(":")[0][:44]
        reasons[key]+=1
    for k,v in reasons.most_common(14): print(f"   {v:4d}  {k}")

if __name__=="__main__": main()
