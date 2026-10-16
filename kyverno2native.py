#!/usr/bin/env python3
"""
kyverno2native — convert Kyverno policies to Kubernetes native admission policies.

Usage:
    kyverno2native.py POLICY.yaml [POLICY.yaml ...] [-o OUTDIR] [--report report.csv]
    kyverno2native.py -r /path/to/kyverno/policies -o out/

Emits ValidatingAdmissionPolicy / MutatingAdmissionPolicy (+ bindings) to stdout,
or one file per input policy when -o is given.
"""
import os, sys, re, json, argparse, hashlib, pathlib

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "convert"))

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required:  pip install pyyaml")

import convert_cel_crds as cel
import compile_traditional as trad
from convert_cel_crds import ConvertError

POLICY_KINDS = {"ClusterPolicy", "Policy", "ValidatingPolicy", "MutatingPolicy"}
SKIP_KINDS = {"GeneratingPolicy", "ImageValidatingPolicy", "DeletingPolicy",
              "ClusterCleanupPolicy", "CleanupPolicy"}


def family_of(doc):
    """Which converter handles this document."""
    kind = doc.get("kind")
    if kind == "ValidatingPolicy":
        return "vpol"
    if kind == "MutatingPolicy":
        return "mpol"
    if kind in ("ClusterPolicy", "Policy"):
        for r in (doc.get("spec") or {}).get("rules") or []:
            if isinstance((r.get("validate") or {}).get("cel"), dict):
                return "clusterpolicy-cel"
        return "clusterpolicy"
    return None


def slug_for(path, doc):
    """Stable, collision-free identifier: policy name, prefixed by its parent
    directory when that disambiguates (the Kyverno library reuses names across
    the clusterpolicy / -cel / -vpol variants of the same policy)."""
    name = (doc.get("metadata") or {}).get("name") or pathlib.Path(path).stem
    stem = pathlib.Path(path).stem
    parent = pathlib.Path(path).parent.name
    parts = [name] if stem == name else [stem]
    if parent and parent not in (name, stem):
        parts.insert(0, parent)
    return re.sub(r"[^A-Za-z0-9_.-]", "-", "__".join(parts))


def convert_doc(doc, slug):
    """Returns (docs, family). Raises ConvertError."""
    fam = family_of(doc)
    if fam is None:
        raise ConvertError(f"not a convertible policy kind: {doc.get('kind')}")
    t = {"slug": slug, "family": fam, "name": (doc.get("metadata") or {}).get("name", slug),
         "kind": doc.get("kind")}
    unknown = set()
    if fam == "clusterpolicy-cel":
        docs, _, _ = cel.convert_cel(t, doc, unknown)
    elif fam == "vpol":
        docs, _, _ = cel.convert_vpol(t, doc, unknown)
    elif fam == "mpol":
        docs, _, _ = cel.convert_mpol(t, doc, unknown)
    else:
        rules = (doc.get("spec") or {}).get("rules") or []
        docs, errs = [], []
        for i, r in enumerate(rules):
            try:
                docs += trad.compile_rule(r, slug, i, unknown, len(rules))
            except ConvertError as e:
                errs.append(f"rule[{r.get('name')}]: {e}")
            except Exception as e:
                errs.append(f"rule[{r.get('name')}]: {type(e).__name__}: {e}")
        if errs:
            raise ConvertError("; ".join(errs))
        if not docs:
            raise ConvertError("no convertible rules")
    return docs, fam


def main():
    ap = argparse.ArgumentParser(
        prog="kyverno2native",
        description="Convert Kyverno policies to Kubernetes ValidatingAdmissionPolicy / "
                    "MutatingAdmissionPolicy.")
    ap.add_argument("inputs", nargs="*", help="Kyverno policy YAML file(s)")
    ap.add_argument("-r", "--recursive", metavar="DIR",
                    help="convert every *.yaml policy found under DIR")
    ap.add_argument("-o", "--outdir", help="write one file per policy here (default: stdout)")
    ap.add_argument("--report", metavar="CSV", help="write a per-policy result CSV")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress the summary")
    a = ap.parse_args()

    paths = list(a.inputs)
    if a.recursive:
        for root, dirs, files in os.walk(a.recursive):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            paths += [os.path.join(root, f) for f in files
                      if f.endswith((".yaml", ".yml"))]
    if not paths:
        ap.error("give at least one policy file, or -r DIR")

    if a.outdir:
        os.makedirs(a.outdir, exist_ok=True)

    rows, ok, skipped, failed = [], 0, 0, 0
    for p in sorted(set(paths)):
        try:
            docs_in = [d for d in yaml.safe_load_all(open(p, errors="replace"))
                       if isinstance(d, dict)]
        except Exception as e:
            rows.append((p, "", "", "error", f"unreadable: {e}")); failed += 1; continue

        pol = [d for d in docs_in if d.get("kind") in POLICY_KINDS]
        if not pol:
            if any(d.get("kind") in SKIP_KINDS for d in docs_in):
                rows.append((p, "", "", "skipped", "Kyverno-only policy kind"))
                skipped += 1
            continue

        for doc in pol:
            slug = slug_for(p, doc)
            try:
                out, fam = convert_doc(doc, slug)
            except ConvertError as e:
                rows.append((p, slug, family_of(doc) or "", "unsupported", str(e)))
                failed += 1
                continue
            except Exception as e:
                rows.append((p, slug, family_of(doc) or "", "error",
                             f"{type(e).__name__}: {e}"))
                failed += 1
                continue
            text = yaml.safe_dump_all(out, sort_keys=False)
            if a.outdir:
                with open(os.path.join(a.outdir, slug + ".yaml"), "w") as f:
                    f.write(text)
            else:
                print("---")
                print(text, end="")
            n_obj = len([d for d in out if not d["kind"].endswith("Binding")])
            rows.append((p, slug, fam, "converted", f"{n_obj} policy object(s)"))
            ok += 1

    if a.report:
        import csv
        with open(a.report, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["file", "policy", "family", "result", "detail"])
            w.writerows(rows)

    if not a.quiet:
        print(f"\nconverted {ok}   unsupported/error {failed}   skipped {skipped}",
              file=sys.stderr)
        if failed:
            from collections import Counter
            reasons = Counter(re.sub(r"rule\[[^\]]*\]: ", "", r[4]).split(":")[0][:52]
                              for r in rows if r[3] in ("unsupported", "error"))
            for k, v in reasons.most_common(10):
                print(f"   {v:4d}  {k}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
