#!/usr/bin/env python3
"""RQ4 toolkit: deterministic Kyverno->native conversion, original normalization, fixture harvest."""
import os, sys, re, json, yaml, hashlib, copy
from collections import Counter

import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

SCR = os.environ.get("RQ4_SCR", _SCRATCH)
REPO = os.environ.get("RQ4_REPO", os.path.join(SCR, "policies"))

# ---------- [G] fixture kind <-> policy match-kind normalisation ----------
def norm_kind(x):
    """'namespaces' / 'Namespace' / 'v1/Namespace' / 'Pod/exec' -> 'namespace'"""
    x = str(x).strip().split("/")[-1].lower()
    if not x: return x
    x = re.sub(r"ies$", "y", x)
    x = re.sub(r"([sxz]|ch|sh)es$", r"\1", x)
    x = re.sub(r"s$", "", x)
    return x

def kind_matches(fixture_kind, match_kinds):
    """match_kinds: iterable of policy match kinds (any notation). empty/'*' => match all"""
    ms = {norm_kind(m) for m in (match_kinds or []) if str(m).strip()}
    if not ms or "*" in {str(m).strip() for m in (match_kinds or [])}: return True
    return norm_kind(fixture_kind) in ms
BASE = _DATA
_tf = os.path.join(BASE, "targets.json")
TARGETS = json.load(open(_tf)) if os.path.exists(_tf) else []

# ---------- kind -> GVR ----------
GVR = {}
def _gvr_path():
    for c in (os.path.join(BASE, "gvr_raw.txt"), os.path.join(SCR, "gvr_raw.txt")):
        if os.path.exists(c): return c
    return None
_gp = _gvr_path()
if _gp:
    for line in open(_gp):
        parts = line.strip().split("|")
        if len(parts) != 4: continue
        plural, apiv, namespaced, kind = parts
        if "/" in apiv: group, version = apiv.rsplit("/", 1)
        else: group, version = "", apiv
        GVR.setdefault(kind, (group, version, plural, namespaced == "true"))
NAMESPACED = {k: v[3] for k, v in GVR.items()}
def is_cluster_scoped(kind):
    """True if kind is known cluster-scoped; falls back to a static list when GVR is unavailable."""
    k = str(kind).split("/")[-1]
    if k in NAMESPACED: return not NAMESPACED[k]
    return k in CLUSTER_SCOPED_STATIC

CLUSTER_SCOPED_STATIC = {
    "Namespace","Node","PersistentVolume","ClusterRole","ClusterRoleBinding","StorageClass",
    "PriorityClass","IngressClass","RuntimeClass","CustomResourceDefinition","APIService",
    "ValidatingWebhookConfiguration","MutatingWebhookConfiguration","ClusterPolicy",
    "ValidatingAdmissionPolicy","MutatingAdmissionPolicy","CSIDriver","CSINode",
    "VolumeAttachment","ClusterIssuer","APIServer","Infrastructure","Mesh","TLSOption","Cluster",
}

# fixture-derived GVK fallback for kinds not served by the cluster
FIX_GVK = {}
_fp = os.path.join(BASE, "fixture_gvk.json")
if os.path.exists(_fp):
    for k, v in json.load(open(_fp)).items():
        av = v["apiVersions"][0]
        if "/" in av: g, ver = av.rsplit("/", 1)
        else: g, ver = "", av
        FIX_GVK[k] = (g, ver)

VOWELS = set("aeiou")
def pluralize(kind):
    k = kind.lower()
    if k.endswith("y") and k[-2] not in VOWELS: return k[:-1] + "ies"
    if k.endswith(("s", "x", "z", "ch", "sh")): return k + "es"
    return k + "s"

def native_name(slug, suffix=""):
    s = slug.lower().replace("__", "-").replace("_", "-")
    s = re.sub(r"[^a-z0-9-]", "-", s)
    h = hashlib.md5(slug.encode()).hexdigest()[:6]
    core = s[:44].strip("-")
    return f"{core}-{h}{suffix}"

def load_policy_doc(t):
    p = os.path.join(REPO, t["path"])
    docs = [d for d in yaml.safe_load_all(open(p, errors="replace")) if isinstance(d, dict)]
    for d in docs:
        if d.get("kind") == t["kind"] and (d.get("metadata", {}) or {}).get("name") == t["name"]:
            return d
    for d in docs:
        if d.get("kind") == t["kind"]: return d
    return None

# ---------- match(any/all) -> matchConstraints ----------
class ConvertError(Exception): pass

def kinds_to_rules(kinds, operations, unknown_kinds):
    """map Kyverno kind strings to VAP resourceRules; returns (rules, kindset)"""
    byGV = {}
    kindset = set()
    for ks in kinds:
        parts = str(ks).split("/")
        sub = None
        if len(parts) >= 2 and re.match(r"^[a-z]", parts[-1]):
            sub = parts[-1]; parts = parts[:-1]
        if len(parts) == 1:
            kind = parts[0]; group = version = None
        elif len(parts) == 2:
            # 'v1/Pod' or 'group/Kind' — resolve via GVR by kind (last part)
            kind = parts[1]; group = None; version = None
        elif len(parts) == 3:
            group, version, kind = parts
            if group == "core": group = ""
        else:
            raise ConvertError(f"unparsable kind '{ks}'")
        if kind in ("*",): raise ConvertError("wildcard kind")
        if re.match(r"^[a-z]", kind): raise ConvertError(f"unparsable kind '{ks}'")
        kindset.add(kind)
        if kind in GVR:
            g, v, plural, _ = GVR[kind]
            if group is None: group, version = g, v
        elif kind in FIX_GVK and group is None:
            group, version = FIX_GVK[kind]
            plural = pluralize(kind)
            unknown_kinds.add((group, version, kind))
        else:
            unknown_kinds.add((group or "", version or "", kind))
            g = group if group is not None else ""
            v = version if version is not None else "v1"
            plural = pluralize(kind)
            group, version = g, v
        if sub: plural = f"{plural}/{sub}"
        byGV.setdefault((group, version), set()).add(plural)
    rules = []
    for (g, v), plurals in sorted(byGV.items()):
        rules.append({"apiGroups": [g], "apiVersions": [v],
                      "operations": operations, "resources": sorted(plurals)})
    return rules, kindset

def build_match_constraints(rule, unknown_kinds):
    m = rule.get("match", {}) or {}
    blocks = []
    if "any" in m: blocks = [b.get("resources", {}) or {} for b in m["any"]]
    elif "all" in m:
        if len(m["all"]) > 1: raise ConvertError("match.all with multiple blocks")
        blocks = [b.get("resources", {}) or {} for b in m["all"]]
    elif "resources" in m: blocks = [m["resources"] or {}]
    else: raise ConvertError("no match resources")

    kinds, namespaces, ops = [], [], []
    objsel = nssel = None
    for b in blocks:
        for bad in ("roles", "clusterRoles", "subjects"):
            if b.get(bad): raise ConvertError(f"match by {bad}")
        kinds += b.get("kinds", []) or []
        namespaces += b.get("namespaces", []) or []
        ops += b.get("operations", []) or []
        if b.get("selector"): objsel = b["selector"]
        if b.get("namespaceSelector"): nssel = b["namespaceSelector"]
        if b.get("names"): raise ConvertError("match by resource names (needs CEL name matchCondition)")
        if b.get("annotations"): raise ConvertError("match by annotations")
    if not kinds: raise ConvertError("no kinds in match")
    operations = sorted(set(ops)) if ops else ["CREATE", "UPDATE"]
    operations = [o for o in operations if o in ("CREATE", "UPDATE", "DELETE", "CONNECT")]
    rules_, kindset = kinds_to_rules(kinds, operations, unknown_kinds)
    mc = {"resourceRules": rules_}
    if namespaces:
        if any("*" in n or "{{" in n for n in namespaces): raise ConvertError("wildcard/templated namespaces")
        mc["namespaceSelector"] = {"matchExpressions": [
            {"key": "kubernetes.io/metadata.name", "operator": "In", "values": sorted(set(namespaces))}]}
    if nssel: mc["namespaceSelector"] = nssel
    if objsel: mc["objectSelector"] = objsel

    ex = rule.get("exclude", {}) or {}
    if ex:
        exblocks = []
        if "any" in ex: exblocks = [b.get("resources", {}) or {} for b in ex["any"]]
        elif "resources" in ex: exblocks = [ex["resources"] or {}]
        elif "all" in ex: raise ConvertError("exclude.all")
        exns = []
        for b in exblocks:
            for bad in ("roles", "clusterRoles", "subjects"):
                if b.get(bad): raise ConvertError(f"exclude by {bad}")
            if b.get("kinds") and not b.get("namespaces"):
                raise ConvertError("exclude by kinds")
            exns += b.get("namespaces", []) or []
            if set(b.keys()) - {"namespaces", "kinds"}: raise ConvertError(f"exclude fields {sorted(b.keys())}")
        if exns:
            if "namespaceSelector" in mc: raise ConvertError("both include-ns and exclude-ns")
            mc["namespaceSelector"] = {"matchExpressions": [
                {"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": sorted(set(exns))}]}
    return mc, kindset

# ---------- converters ----------
def convert_cel(t, doc, unknown_kinds):
    """clusterpolicy-cel -> one VAP(+binding) per validate.cel rule"""
    spec = doc.get("spec", {}) or {}
    rules = spec.get("rules", []) or []
    docs_out, notes, kindset_all = [], [], set()
    vi = 0
    for r in rules:
        v = r.get("validate") or {}
        cel = v.get("cel")
        if not isinstance(cel, dict):
            raise ConvertError(f"rule '{r.get('name')}' has no validate.cel (mixed policy)")
        if r.get("preconditions"): raise ConvertError("JMESPath preconditions in cel rule")
        mc, kindset = build_match_constraints(r, unknown_kinds)
        kindset_all |= kindset
        name = native_name(t["slug"], f"-r{vi}" if len(rules) > 1 else "")
        vap = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
               "metadata": {"name": name},
               "spec": {"failurePolicy": "Fail", "matchConstraints": mc,
                        "validations": []}}
        for e in cel.get("expressions", []) or []:
            ent = {"expression": e["expression"]}
            for k in ("message", "messageExpression"):
                if e.get(k): ent[k] = e[k]
            vap["spec"]["validations"].append(ent)
        if cel.get("variables"): vap["spec"]["variables"] = cel["variables"]
        if cel.get("auditAnnotations"): vap["spec"]["auditAnnotations"] = cel["auditAnnotations"]
        mcond = []
        for pc in r.get("celPreconditions", []) or []:
            mcond.append({"name": pc.get("name", f"pc{len(mcond)}"), "expression": pc["expression"]})
        if mcond: vap["spec"]["matchConditions"] = mcond
        binding = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                   "metadata": {"name": name + "-b"},
                   "spec": {"policyName": name, "validationActions": ["Deny"]}}
        if cel.get("paramKind"):
            vap["spec"]["paramKind"] = cel["paramKind"]
            pr = copy.deepcopy(cel.get("paramRef") or {})
            if pr: binding["spec"]["paramRef"] = pr
            notes.append(f"paramKind {cel['paramKind']} paramRef {pr}")
        docs_out += [vap, binding]
        vi += 1
    if not docs_out: raise ConvertError("no cel validate rules found")
    return docs_out, notes, kindset_all

DROP_VPOL = {"validationActions", "evaluation", "webhookConfiguration", "autogen", "generate"}
def convert_vpol(t, doc, unknown_kinds):
    spec = doc.get("spec", {}) or {}
    name = native_name(t["slug"])
    vspec = {k: copy.deepcopy(v) for k, v in spec.items() if k not in DROP_VPOL}
    vspec.setdefault("failurePolicy", "Fail")
    if "matchConstraints" not in vspec: raise ConvertError("vpol without matchConstraints")
    kindset = set()
    for rr in vspec["matchConstraints"].get("resourceRules", []) or []:
        for res in rr.get("resources", []) or []: kindset.add(res)
    vap = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
           "metadata": {"name": name}, "spec": vspec}
    binding = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
               "metadata": {"name": name + "-b"},
               "spec": {"policyName": name, "validationActions": ["Deny"]}}
    notes = []
    for k in sorted(set(spec) & DROP_VPOL): notes.append(f"dropped spec.{k}")
    return [vap, binding], notes, kindset

DROP_MPOL = {"evaluation", "autogen", "targetMatchConstraints"}
def convert_mpol(t, doc, unknown_kinds):
    spec = doc.get("spec", {}) or {}
    if "targetMatchConstraints" in spec: raise ConvertError("mutateExisting mpol")
    name = native_name(t["slug"])
    mspec = {k: copy.deepcopy(v) for k, v in spec.items() if k not in DROP_MPOL}
    mspec.setdefault("failurePolicy", "Fail")
    mspec.setdefault("reinvocationPolicy", "Never")
    if "matchConstraints" not in mspec: raise ConvertError("mpol without matchConstraints")
    if "mutations" not in mspec: raise ConvertError("mpol without mutations")
    mapd = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingAdmissionPolicy",
            "metadata": {"name": name}, "spec": mspec}
    binding = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingAdmissionPolicyBinding",
               "metadata": {"name": name + "-b"}, "spec": {"policyName": name}}
    notes = [f"dropped spec.{k}" for k in sorted(set(spec) & DROP_MPOL)]
    return [mapd, binding], notes, set()

# ---------- original normalization ----------
def normalize_original(t, doc):
    d = copy.deepcopy(doc)
    spec = d.setdefault("spec", {})
    if t["kind"] in ("ClusterPolicy", "Policy"):
        per_rule = any(isinstance(r.get("validate"), dict) and "failureAction" in r["validate"]
                       for r in spec.get("rules", []) or [])
        if per_rule:
            for r in spec.get("rules", []) or []:
                if isinstance(r.get("validate"), dict): r["validate"]["failureAction"] = "Enforce"
            spec.pop("validationFailureAction", None)
        else:
            has_validate = any("validate" in r for r in spec.get("rules", []) or [])
            if has_validate: spec["validationFailureAction"] = "Enforce"
        for r in spec.get("rules", []) or []:
            if isinstance(r.get("validate"), dict) and isinstance(r["validate"].get("cel"), dict):
                r["validate"]["cel"].pop("generate", None)  # do not autogen VAPs during kyverno arm
        spec["background"] = False
    elif t["kind"] == "ValidatingPolicy":
        d["apiVersion"] = "policies.kyverno.io/v1"
        spec["validationActions"] = ["Deny"]
        ev = spec.setdefault("evaluation", {}); ev["admission"] = {"enabled": True}
        ev.pop("background", None)
    elif t["kind"] == "MutatingPolicy":
        d["apiVersion"] = "policies.kyverno.io/v1"
        ev = spec.setdefault("evaluation", {}); ev["admission"] = {"enabled": True}
        ev.pop("background", None)
    return d

# ---------- fixture harvest ----------
CLUSTER_SCOPED_HINT = {"Namespace","Node","PersistentVolume","ClusterRole","ClusterRoleBinding",
    "StorageClass","PriorityClass","IngressClass","RuntimeClass","CustomResourceDefinition",
    "APIServer","Infrastructure","FlowSchema","Mesh","Cluster","TLSOption"}

SETUP_FILES = {"policy-ready.yaml","ns.yaml","cm.yaml","crd-assert.yaml","policy-update.yaml",
               "crb.yaml","priorityClass.yaml","pc.yaml"}
POLICY_KINDS_FIXTURE = {"ClusterPolicy","Policy","ValidatingPolicy","MutatingPolicy",
                        "GeneratingPolicy","ImageValidatingPolicy","DeletingPolicy",
                        "ClusterCleanupPolicy","CleanupPolicy","Test","CustomResourceDefinition"}

def _yaml_docs(p):
    try: return [d for d in yaml.safe_load_all(open(p, errors="replace")) if isinstance(d, dict)]
    except Exception: return []

def _expects_error(apply_obj):
    """[A] chainsaw: apply.expect[].check contains ($error != null): true  -> expected deny"""
    for ex in (apply_obj.get("expect") or []):
        chk = ex.get("check") or {}
        if not isinstance(chk, dict): continue
        for k, v in chk.items():
            if "error" in str(k) and v is True: return True
    return False

def harvest_chainsaw(t, pdir):
    """[A] parse .chainsaw-test/chainsaw-test.yaml into the same case shape as kyverno-test."""
    cdir = os.path.join(pdir, ".chainsaw-test")
    ct = os.path.join(cdir, "chainsaw-test.yaml")
    if not os.path.exists(ct): return None
    td = yaml.safe_load(open(ct, errors="replace"))
    if not isinstance(td, dict): return {"error": "chainsaw-not-dict"}
    mk = [x for x in (t.get("match_kinds") or "").split(",") if x.strip()]
    cases = []; referees = []
    for st in ((td.get("spec") or {}).get("steps") or []):
        for entry in (st.get("try") or []):
            ap = entry.get("apply")
            if isinstance(ap, dict) and ap.get("file"):
                f = ap["file"]
                if f.startswith("../"): continue                      # [A]3 정책 자체 적용 제외
                if os.path.basename(f) in SETUP_FILES: continue       # [A]3 설정용 제외
                rp = os.path.join(cdir, f)
                docs = [d for d in _yaml_docs(rp)
                        if d.get("kind") not in POLICY_KINDS_FIXTURE
                        and kind_matches(d.get("kind"), mk)]          # [G]
                exp = "fail" if _expects_error(ap) else "pass"
                for d in docs:
                    cases.append({"kind": d.get("kind"),
                                  "name": (d.get("metadata", {}) or {}).get("name"),
                                  "expected": exp, "doc": d, "patched": None,
                                  "rule": None, "source": "chainsaw", "src_file": f})
            asr = entry.get("assert")
            if isinstance(asr, dict) and asr.get("file"):
                rp = os.path.join(cdir, asr["file"])
                for d in _yaml_docs(rp):
                    if d.get("kind") in POLICY_KINDS_FIXTURE: continue
                    if not kind_matches(d.get("kind"), mk): continue
                    referees.append(d)
    for f in sorted(os.listdir(cdir)) if os.path.isdir(cdir) else []:
        if f.startswith(("patched", "not-patched")) and f.endswith((".yaml", ".yml")):
            for d in _yaml_docs(os.path.join(cdir, f)):
                if d.get("kind") in POLICY_KINDS_FIXTURE: continue
                if not kind_matches(d.get("kind"), mk): continue
                referees.append(d)
    # attach referees to mutate cases by resource name
    byname = {}
    for r in referees:
        n = (r.get("metadata", {}) or {}).get("name")
        if n: byname.setdefault(n, r)
    for c in cases:
        if c["name"] in byname: c["patched"] = byname[c["name"]]
    if not cases and not referees: return {"error": "chainsaw-no-cases"}
    return {"cases": cases, "variables_needed": False, "format": "chainsaw",
            "n_referees": len(referees)}

def harvest(t):
    pdir = os.path.join(REPO, t["dir"])
    ktest = None
    for cand in (".kyverno-test/kyverno-test.yaml", "kyverno-test.yaml", ".kyverno-test/kyverno-test.yml"):
        p = os.path.join(pdir, cand)
        if os.path.exists(p): ktest = p; break
    if ktest:
        r = harvest_kyverno_test(t, ktest)
        # [A] kyverno-test에 이 정책용 결과가 없거나 mutate 심판이 없으면 chainsaw로 보강
        if r is not None and "error" not in r:
            has_ref = any(c.get("patched") for c in r["cases"])
            is_mut = "mutate" in (t.get("ruletypes") or "")
            if is_mut and not has_ref:
                cs = harvest_chainsaw(t, pdir)
                if cs and "error" not in cs:
                    byname = {(c["name"]): c.get("patched") for c in cs["cases"] if c.get("patched")}
                    filled = 0
                    for c in r["cases"]:
                        if not c.get("patched") and c["name"] in byname:
                            c["patched"] = byname[c["name"]]; filled += 1
                    r["referee_from_chainsaw"] = filled
            return r
        cs = harvest_chainsaw(t, pdir)
        if cs and "error" not in cs: return cs
        return r
    # [A]1 kyverno-test가 없으면 chainsaw로
    return harvest_chainsaw(t, pdir)

def harvest_kyverno_test(t, ktest):
    try:
        tdoc = yaml.safe_load(open(ktest, errors="replace"))
    except Exception as e:
        return {"error": f"test-parse: {e}"}
    if not isinstance(tdoc, dict): return {"error": "test-not-dict"}
    tdir = os.path.dirname(ktest)
    resources = {}
    for rf in (tdoc.get("resources", []) or []):
        rp = os.path.normpath(os.path.join(tdir, rf))
        for d in _yaml_docs(rp):
            k = d.get("kind"); n = (d.get("metadata", {}) or {}).get("name")
            if k and n: resources[(k, n)] = d
    cases = []
    variables_needed = bool(tdoc.get("variables") or tdoc.get("values"))
    for res in tdoc.get("results", []) or []:
        if res.get("policy") != t["name"]: continue
        expected = res.get("result"); kind = res.get("kind")
        patched = res.get("patchedResources") or res.get("patchedResource")
        pdoc = None
        if patched:
            pp = os.path.normpath(os.path.join(tdir, patched))
            if os.path.exists(pp): pdoc = _yaml_docs(pp)
        rnames = res.get("resources", []) or ([res["resource"]] if res.get("resource") else [])
        for rn in rnames:
            rn2 = rn.split("/")[-1]
            doc = resources.get((kind, rn2))
            if doc is None:
                for (k, n), dd in resources.items():
                    if n == rn2: doc = dd; kind = k; break
            if doc is None: continue
            pd = None
            if pdoc:
                for cand in pdoc:
                    if (cand.get("metadata", {}) or {}).get("name") == rn2: pd = cand; break
                if pd is None and len(pdoc) == 1: pd = pdoc[0]
            cases.append({"kind": doc.get("kind"), "name": rn2, "expected": expected,
                          "doc": doc, "patched": pd, "rule": res.get("rule"),
                          "source": "kyverno-test", "src_file": os.path.basename(ktest)})
    if not cases: return {"error": "no-cases-for-policy"}
    cases = aggregate_by_resource(cases)                      # [D]
    return {"cases": cases, "variables_needed": variables_needed, "format": "kyverno-test"}

def aggregate_by_resource(cases):
    """[D] 업스트림 기대값은 (규칙,리소스) 쌍 단위지만 실제 클러스터에서는 모든 규칙이
       동시에 적용된다. 같은 리소스에 대한 여러 규칙 기대값을 하나로 합치되
       'fail이 하나라도 있으면 deny'로 집계한다."""
    order = {"skip": 0, "pass": 1, "fail": 2}
    by = {}
    for c in cases:
        key = (c.get("kind"), c.get("name"))
        prev = by.get(key)
        if prev is None:
            c = dict(c); c["rules"] = [c.get("rule")] if c.get("rule") else []
            by[key] = c; continue
        prev["rules"] = (prev.get("rules") or []) + ([c.get("rule")] if c.get("rule") else [])
        if order.get(c.get("expected"), 0) > order.get(prev.get("expected"), 0):
            prev["expected"] = c.get("expected")
        if c.get("patched") and not prev.get("patched"):
            prev["patched"] = c["patched"]
    out = list(by.values())
    for c in out:
        c["n_rules"] = len(c.get("rules") or [])
        c.pop("rule", None)
    return out

# ---------- main driving ----------
def main():
    cmd = sys.argv[1]
    unknown_kinds = set()
    if cmd == "convert":
        stats = Counter(); fails = []
        conv_meta = {}
        for t in TARGETS:
            fam = t["family"]
            if fam not in ("clusterpolicy-cel", "vpol", "mpol"): continue
            doc = load_policy_doc(t)
            if doc is None: fails.append((t["slug"], "load-failed")); stats["load-failed"] += 1; continue
            try:
                if fam == "clusterpolicy-cel": docs, notes, kinds = convert_cel(t, doc, unknown_kinds)
                elif fam == "vpol": docs, notes, kinds = convert_vpol(t, doc, unknown_kinds)
                else: docs, notes, kinds = convert_mpol(t, doc, unknown_kinds)
                with open(os.path.join(BASE, "native", t["slug"] + ".yaml"), "w") as f:
                    yaml.safe_dump_all(docs, f, sort_keys=False)
                conv_meta[t["slug"]] = {"native_names": [d["metadata"]["name"] for d in docs if "Binding" not in d["kind"]],
                                        "notes": notes, "method": "deterministic"}
                stats["ok"] += 1
            except ConvertError as e:
                fails.append((t["slug"], str(e))); stats["convert-error"] += 1
            except Exception as e:
                fails.append((t["slug"], f"EXC {e}")); stats["exception"] += 1
        json.dump(conv_meta, open(os.path.join(BASE, "convert_meta_det.json"), "w"), indent=0)
        json.dump(sorted(fails), open(os.path.join(BASE, "convert_failures_det.json"), "w"), indent=1)
        json.dump(sorted(list(unknown_kinds)), open(os.path.join(BASE, "unknown_kinds.json"), "w"))
        print("deterministic conversion:", dict(stats))
        print("unknown kinds:", len(unknown_kinds))
        for s, r in fails[:15]: print("  FAIL", s, "::", r)
    elif cmd == "normalize":
        stats = Counter()
        for t in TARGETS:
            doc = load_policy_doc(t)
            if doc is None: stats["load-failed"] += 1; continue
            nd = normalize_original(t, doc)
            with open(os.path.join(BASE, "originals-normalized", t["slug"] + ".yaml"), "w") as f:
                yaml.safe_dump(nd, f, sort_keys=False)
            stats["ok"] += 1
        print("normalize:", dict(stats))
    elif cmd == "harvest":
        stats = Counter(); meta = {}
        for t in TARGETS:
            h = harvest(t)
            if h is None: stats["no-test-material"] += 1; meta[t["slug"]] = {"status": "none"}; continue
            if "error" in h: stats[h["error"].split(":")[0]] += 1; meta[t["slug"]] = {"status": h["error"]}; continue
            tdir = os.path.join(BASE, "tests", t["slug"]); os.makedirs(tdir, exist_ok=True)
            cm = []
            for i, c in enumerate(h["cases"]):
                fn = f"case-{i:03d}.yaml"
                yaml.safe_dump(c["doc"], open(os.path.join(tdir, fn), "w"), sort_keys=False)
                cs_kind = is_cluster_scoped(c["kind"])                       # [C]/[G]
                ent = {"file": fn, "kind": c["kind"], "name": c["name"], "expected": c["expected"],
                       "rules": c.get("rules") or ([c["rule"]] if c.get("rule") else []),
                       "n_rules": c.get("n_rules", 1),                          # [D]
                       "source": c.get("source", "kyverno-test"),
                       "src_file": c.get("src_file"),
                       "namespaced": not cs_kind,
                       "cluster_scoped": cs_kind,
                       "declared_ns": (c["doc"].get("metadata", {}) or {}).get("namespace")}  # [B]
                if c["patched"]:
                    pfn = f"case-{i:03d}.patched.yaml"
                    yaml.safe_dump(c["patched"], open(os.path.join(tdir, pfn), "w"), sort_keys=False)
                    ent["patched"] = pfn
                cm.append(ent)
            meta[t["slug"]] = {"status": "ok", "cases": cm,
                               "variables_needed": h.get("variables_needed", False),
                               "format": h.get("format"),
                               "cluster_scoped_case": any(x["cluster_scoped"] for x in cm),   # [C]/[E]
                               "declared_namespaces": sorted({x["declared_ns"] for x in cm if x.get("declared_ns")})}
            stats["ok"] += 1
            exp = {c["expected"] for c in h["cases"]}
            if "fail" in exp and ("pass" in exp or "skip" in exp): stats["has-both"] += 1
        json.dump(meta, open(os.path.join(BASE, "harvest_meta.json"), "w"), indent=0)
        print("harvest:", dict(stats))
    else:
        print("unknown cmd")

if __name__ == "__main__":
    main()
