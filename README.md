# Kyverno → Kubernetes native admission policy

How much of the [Kyverno policy library](https://github.com/kyverno/policies) can be expressed
with Kubernetes' built-in admission policies — `ValidatingAdmissionPolicy` (VAP) and
`MutatingAdmissionPolicy` (MAP) — instead of an admission webhook?

This repository contains the classification, the converters, and the converted policies.

- **Corpus**: `kyverno/policies` @ `ef9843f`, 646 canonical policy files
- **Target**: Kubernetes v1.36.1 (VAP and MAP are both GA at `admissionregistration.k8s.io/v1`)
- **Kyverno**: v1.18.2

---

## 1. Classification — what can and cannot be native

Every policy was classified by what it needs to read in order to decide.

| Category | Count | Meaning |
|---|---:|---|
| `N-DIRECT` | 514 | Decidable from the admitted object itself (plus `namespaceObject`, `request`, `oldObject`, `authorizer`) |
| `N-PARAM` | 26 | Needs exactly one static external object → `paramKind` + `paramRef` |
| `W-DYNAMIC` | 4 | Needs an object whose identity is computed at request time |
| `W-AGGREGATE` | 26 | Needs a collection, an aggregation, or RBAC binding resolution |
| `W-EXTERNAL` | 21 | Needs an external service, an image registry, or a non-resource endpoint |
| `K-ONLY` | 52 | Kyverno-only rule types: `generate`, `verifyImages`, `mutate.targets`, cleanup, `validate.manifests` |
| `N-PARTIAL-TIME` | 3 | Needs the wall clock; reproducible on CREATE only |

**Natively expressible: 540 / 646 (83.6 %). Webhook required: 51 (7.9 %). Kyverno-only: 52 (8.0 %).**

Full table: [`results/classification.csv`](results/classification.csv) — the authoritative
column is `category_final_v4`, and `final_note` records why a row is what it is.

### Why the webhook-required 51 cannot be native

Native admission has exactly one cross-object read: `paramKind` + `paramRef`, selecting either a
static name or a static label selector. The API server then evaluates the policy once per matching
param and denies if any evaluation denies.

That inverts *"deny if there exists a bad object"* — which covers uniqueness and
reference checks — but it cannot express:

- **"require that an object exists"** — zero params means zero evaluations means *admit*, the
  opposite of the intent. This is what keeps `require-pdb`, `check-hpa-exists`,
  `require-netpol`, `require-authorizationpolicy` on a webhook.
- **counting, summing, or comparing across objects** — each evaluation sees exactly one param.
- **two distinct external kinds in one rule** — `paramKind` names one kind.
- **a lookup whose kind, not just name, comes from the request.**

Plus the hard limits: no network (image registries, external services), no crypto
(signature verification), no non-resource endpoints (`/version`), and no RBAC
binding-membership resolution — `authorizer` answers *"may this user do X"*, never
*"is this user bound to ClusterRole Y"*.

### Things that look webhook-only but are not

Four native facilities cover cases that a syntactic reading would send to a webhook:

| Facility | Covers |
|---|---|
| `namespaceObject` | Reading labels/annotations of the request's **own** namespace — no lookup, no param |
| `authorizer` | *"May this user do X?"*, including an explicit SubjectAccessReview on the requesting user |
| `paramRef` label-selector fan-out | *"Deny if the request references a bad object"*, including uniqueness rules |
| `timestamp(object.metadata.creationTimestamp)` | The wall clock on CREATE — CEL has no `now()`, but the API server stamps this before validating admission |

---

## 2. Kyverno's own autogen does not cover this

Kyverno can generate a VAP from a ClusterPolicy. Measured over all 540 natively-classified
policies, with the opt-in enabled everywhere it can be set:

| Result | Count | |
|---|---:|---|
| **A** — autogen produced a VAP | **113** | 20.9 % |
| **B** — opted in, autogen still failed | 20 | |
| **C** — opt-in cannot be set at all | 407 | 75.4 % |

Per-policy detail with Kyverno's own status/log message as the reason:
[`results/autogen_measurement.csv`](results/autogen_measurement.csv).

**The opt-in is `spec.rules[].validate.cel.generate: true`** (boolean, default `false`). Without
it Kyverno reports `skip generating ValidatingAdmissionPolicy: validate.cel.generate is not set to
true`; with it, a VAP named `cpol-<policy>` appears, owned by the ClusterPolicy.

The 407 in **C** are not a configuration oversight — there is nowhere to put the flag:

- **245 traditional ClusterPolicies** use `pattern` / `anyPattern` / `deny` / `foreach`. The opt-in
  lives inside the `validate.cel` block, and Kyverno's own validating webhook rejects a rule that
  has both:
  `path: spec.rules[0].validate..: only one of pattern, anyPattern, deny, foreach, cel can be specified`.
  Opting in would mean rewriting the rule in CEL first — which is the conversion.
- **162 CEL CRDs** (`ValidatingPolicy` 112, `MutatingPolicy` 50) have no autogen opt-in field in
  their spec at all. Applied as-is they report `status.generated: false` and emit nothing.

So autogen handles only single-rule ClusterPolicies already written in `validate.cel`.

The 20 in **B**, by Kyverno's own reported reason: 15 × `multiple rules are not applicable`
(autogen is single-rule only), 1 × `Roles / ClusterRoles / Subjects in any/all is not applicable`,
1 × the generated VAP was itself rejected by the API server (a multi-line Kyverno
`validate.message` copied verbatim; VAP messages may not contain line breaks), 3 × the target CRD
was not installed.

**MAP generation is unavailable on this stack.** Setting
`--generateMutatingAdmissionPolicy=true` — changing only that flag — puts the Kyverno admission
controller into `CrashLoopBackOff`:

```
cmd/kyverno/main.go:462 > MutatingAdmissionPolicies isn't supported in the API server
error="mutating admission policy API is not registered"
```

The API is in fact present: `kubectl api-resources --api-group=admissionregistration.k8s.io`
lists `mutatingadmissionpolicies` at `admissionregistration.k8s.io/v1`, while
`/apis/admissionregistration.k8s.io/v1alpha1` and `/v1beta1` both return 404. Kyverno v1.18.2
probes only the removed alpha/beta versions.

---

## 3. The converters

Two deterministic converters, no LLM in the pipeline.

| Script | Handles | Output |
|---|---|---:|
| [`convert/convert_cel_crds.py`](convert/convert_cel_crds.py) | `ValidatingPolicy`, `MutatingPolicy`, and ClusterPolicies using `validate.cel` | 288 |
| [`convert/compile_traditional.py`](convert/compile_traditional.py) | Traditional Kyverno: `pattern`, `anyPattern`, `deny.conditions`, `preconditions`, `patchStrategicMerge` → CEL | 112 |
| [`convert/expand_pod_controllers.py`](convert/expand_pod_controllers.py) | Emulates Kyverno's pod-controller autogen for both | — |

**401 of 523 policies converted.** Provenance per policy:
[`results/conversion_provenance.csv`](results/conversion_provenance.csv).
Output: [`converted/`](converted/) — 401 multi-document YAML files, 1798 policy objects.

Pod-controller expansion rewrites `object.spec.X` to `object.spec.template.spec.X` for
Deployment / StatefulSet / DaemonSet / ReplicaSet / ReplicationController / Job, and to
`object.spec.jobTemplate.spec.template.spec.X` for CronJob, emitting those as separate policy
objects (`-ag1`, `-ag2`).

### Kyverno pattern semantics the compiler implements

| Kyverno | CEL |
|---|---|
| plain key | path must exist **and** match |
| `=(key)` | if present, must match; absent passes |
| `X(key)` | must be absent |
| `(key)` | conditional anchor → `.filter()` predicate or an implication |
| `+(key)` | add-if-absent, **per key** — `has(x) ? existing : new` inside the ApplyConfiguration |
| `^(key)` | at least one list element must satisfy |
| `<(key)` | global anchor → hoisted into `matchConditions` |
| wildcard map key | existence (`.exists()`), not `.all()` |
| `foreach` + `deny` | quantifier inversion: `deny if C(e)` ≡ `all(e, !C(e))` |
| `patchStrategicMerge` on a keyed list | `ApplyConfiguration` |
| `patchStrategicMerge` on an atomic list | `JSONPatch` (ApplyConfiguration cannot touch atomic lists) |

### 122 not converted

Front-end gaps, typed in `results/conversion_provenance.csv`: `foreach` 30, complex JMESPath 50,
`patchStrategicMerge` list merge 9, match-scope (names, exclude kinds, wildcard kind) 10,
`patchesJson6902` 5, `rule.context` → `paramRef` 11, anchors 2, `validate.podSecurity` /
`validate.manifests` 5.

---

## 4. Verification

Each converted policy and its Kyverno original were applied to the same cluster and given the same
upstream test fixtures (`.kyverno-test` / `.chainsaw-test` from the policy library), then compared:
deny/admit verdicts for validate rules, and the produced object against the upstream
`patchedResource` for mutate rules.

**Of the policies where both could be compared directly: 167 agreed, 0 disagreed.**

Per-policy results: [`results/verification_results.csv`](results/verification_results.csv).

```
verify/mkplan.py        build the test plan and harvest upstream fixtures
verify/harness.py       apply policies, submit fixtures, collect verdicts
verify/compare.py       mutation referee — compares only the leaf paths a patch touches
verify/final_score.py   score the two arms
```

---

## Layout

```
classify/classify.py              structural classifier over the corpus
convert/                          the two converters + pod-controller expansion
verify/                           test-plan builder, harness, referee, scorer
converted/                        401 generated VAP/MAP YAML files
results/classification.csv        646 rows — the classification
results/autogen_measurement.csv   540 rows — Kyverno autogen, measured
results/conversion_provenance.csv 523 rows — which converter produced which file
results/verification_results.csv  per-policy comparison against the Kyverno original
```

## Running

The scripts resolve paths relative to the repository. Point `KNA_CORPUS` at a clone of
`kyverno/policies` if you want to re-run the classification or the converters:

```bash
git clone https://github.com/kyverno/policies /tmp/kyverno-policies
KNA_CORPUS=/tmp/kyverno-policies python3 classify/classify.py /tmp/kyverno-policies out.csv
```

Requires Python 3 with `PyYAML`. The verification scripts additionally need `kubectl` against a
cluster with Kyverno installed.
