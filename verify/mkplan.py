#!/usr/bin/env python3
"""Build plan.json for the RQ4 harness (post-fix: carries [B] declared_ns, [C]/[E] scope, [D] rules)."""
import os, json, sys
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_ROOT = _os.path.dirname(_HERE)
_SCRATCH = _os.environ.get("KNA_SCRATCH", _os.path.join(_ROOT, ".scratch"))
_DATA = _os.environ.get("KNA_ROOT", _ROOT)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import convert_cel_crds as T
BASE = _DATA

targets = {t["slug"]: t for t in json.load(open(f"{BASE}/targets.json"))}
H = json.load(open(f"{BASE}/harvest_meta.json"))
ns_info = json.load(open(f"{BASE}/ns_info.json"))

plan = {}
for slug, t in targets.items():
    h = H.get(slug, {})
    e = {"slug": slug, "family": t.get("family") or t.get("representation"), "ruletypes": t["ruletypes"],
         "category": t["category"], "name": t["name"], "cases": []}
    e["native"] = os.path.exists(f"{BASE}/native/{slug}.yaml")
    if h.get("status") == "ok":
        for c in h["cases"]:
            e["cases"].append({k: c.get(k) for k in
                ("file","kind","name","expected","patched","namespaced","cluster_scoped",
                 "declared_ns","source","src_file","n_rules","rules")})
    ni = ns_info.get(slug, {"ns_names": [], "ns_labels": {}})
    e["fixed_ns"] = ni["ns_names"][0] if ni["ns_names"] else None
    e["ns_labels"] = ni["ns_labels"]
    e["cluster_scoped_case"] = bool(h.get("cluster_scoped_case")) or any(
        c.get("cluster_scoped") for c in e["cases"])                       # [C]/[E]
    e["declared_namespaces"] = h.get("declared_namespaces") or []          # [B]
    e["test_format"] = h.get("format")
    e["is_mutate"] = "mutate" in t["ruletypes"]
    e["lane"] = "seq" if (e["cluster_scoped_case"] or e["fixed_ns"] or e["ns_labels"]) else "batch"
    plan[slug] = e

json.dump(plan, open(f"{BASE}/plan.json", "w"), indent=0)
from collections import Counter
print("policies:", len(plan))
print("  native+cases (검증 가능):", sum(1 for v in plan.values() if v["native"] and v["cases"]))
print("  cases total:", sum(len(v["cases"]) for v in plan.values()))
print("  cluster_scoped_case:", sum(1 for v in plan.values() if v["cluster_scoped_case"]), "-> [E] 격리 실행")
print("  declared_namespaces 보유:", sum(1 for v in plan.values() if v["declared_namespaces"]), "-> [B] 사전 생성")
print("  test_format:", dict(Counter(v["test_format"] for v in plan.values() if v["test_format"])))
print("  lane:", dict(Counter(v["lane"] for v in plan.values())))
