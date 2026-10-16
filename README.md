# kyverno2native

Convert [Kyverno](https://kyverno.io) policies into Kubernetes' built-in admission
policies — `ValidatingAdmissionPolicy` (VAP) and `MutatingAdmissionPolicy` (MAP).

```bash
python3 kyverno2native.py my-policy.yaml
```

*[한국어 README](README.ko.md)*

---

## Why this exists

Kubernetes admission policy has traditionally been enforced by **admission webhooks**: the API
server makes a synchronous HTTP call to an external policy engine on every request. That costs a
network round trip per request, requires the engine to stay up, and couples cluster availability
to it — if the webhook fails, you either bypass the policy or block legitimate traffic.

Since VAP (GA in 1.30) and MAP (GA in 1.36), the API server can evaluate CEL expressions
in-process instead. No webhook, no network hop, no extra component to keep alive.

So: **how much of what you enforce with a webhook today could just be a native policy?**

Kyverno ships `autogen`, which generates a VAP from a ClusterPolicy. We measured it against the
540 policies in the Kyverno library that are natively expressible, with its opt-in enabled
everywhere it can be set. **It converted 113.** The other 427 were not a configuration oversight:

- **245 traditional policies** (`pattern` / `anyPattern` / `deny` / `foreach`) have nowhere to put
  the opt-in. It lives inside the `validate.cel` block, and Kyverno's own webhook rejects a rule
  that has both:
  `only one of pattern, anyPattern, deny, foreach, cel can be specified`.
  Opting in would mean rewriting the rule in CEL first — which *is* the conversion.
- **162 CEL CRDs** (`ValidatingPolicy`, `MutatingPolicy`) have no autogen opt-in field at all.
- autogen handles **single-rule policies only**, and refuses policies that match on the
  requester's roles.
- **MAP generation is unusable** on Kubernetes 1.36: setting
  `--generateMutatingAdmissionPolicy=true` puts the Kyverno admission controller into
  CrashLoopBackOff — it probes the removed alpha/beta MAP API while MAP is GA at `v1`.

This tool covers what autogen cannot.

## What it does

| Input | Handled by | Output |
|---|---|---|
| `ClusterPolicy` using `validate.cel` | structural converter | VAP + binding |
| `ValidatingPolicy`, `MutatingPolicy` (CEL CRDs) | structural converter | VAP / MAP + binding |
| `ClusterPolicy` in traditional syntax | **compiler** | VAP / MAP + binding |

The two paths are genuinely different jobs. CEL-based policies are already CEL — the work is
rebuilding the envelope (`matchConstraints`, GVR mapping, naming, bindings). Traditional policies
have no CEL equivalent: their pattern tree, anchors and JMESPath conditions must be *compiled*
into boolean CEL expressions.

Both emulate Kyverno's **pod-controller autogen**, emitting extra policy objects so a Pod rule
also applies to Deployment / StatefulSet / DaemonSet / ReplicaSet / ReplicationController / Job
(`-ag1`) and CronJob (`-ag2`).

### Pattern semantics the compiler implements

| Kyverno | CEL |
|---|---|
| plain key | path must exist **and** match |
| `=(key)` | if present, must match; absent passes |
| `X(key)` | must be absent |
| `(key)` | conditional anchor → `.filter()` predicate or an implication |
| `+(key)` | add-if-absent, **per key** |
| `^(key)` | at least one list element must satisfy |
| `<(key)` | global anchor → hoisted into `matchConditions` |
| wildcard map key | existence (`.exists()`), not `.all()` — `.all()` is vacuously true on no match |
| list under a pattern | `.all()` over the list |
| `deny.conditions` | negated into a `validations` expression (deny is existential, validations is universal) |
| `patchStrategicMerge`, keyed list | `ApplyConfiguration` |
| `patchStrategicMerge`, atomic list | `JSONPatch` — ApplyConfiguration cannot touch atomic lists |

## Install

Python 3.8+ and PyYAML. No other dependencies.

```bash
git clone https://github.com/<you>/kyverno2native
cd kyverno2native
pip install -r requirements.txt
```

## Usage

```bash
# one policy, to stdout
python3 kyverno2native.py policy.yaml

# a whole directory, one output file per policy
python3 kyverno2native.py -r ./policies -o ./out

# with a per-policy result report
python3 kyverno2native.py -r ./policies -o ./out --report report.csv
```

```
positional arguments:
  inputs                Kyverno policy YAML file(s)

options:
  -r, --recursive DIR   convert every *.yaml policy found under DIR
  -o, --outdir DIR      write one file per policy here (default: stdout)
  --report CSV          write a per-policy result CSV
  -q, --quiet           suppress the summary
```

Policies it cannot convert are reported with the reason and skipped; the rest still convert.

### Example

```yaml
# in
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-ro-rootfs
spec:
  rules:
  - name: validate-readOnlyRootFilesystem
    match:
      any:
      - resources: {kinds: [Pod]}
    validate:
      message: "Root filesystem must be read-only."
      pattern:
        spec:
          containers:
          - securityContext:
              readOnlyRootFilesystem: true
```

```yaml
# out
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-ro-rootfs-cedde0
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ['']
      apiVersions: [v1]
      operations: [CREATE, UPDATE]
      resources: [pods]
  validations:
  - expression: (has(object.spec) && ((has(object.spec.containers) &&
      (object.spec.containers.all(__x, (has(__x.securityContext) &&
      ((has(__x.securityContext.readOnlyRootFilesystem) &&
      (__x.securityContext.readOnlyRootFilesystem == true)))))))))
    message: Root filesystem must be read-only.
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-ro-rootfs-cedde0-b
spec:
  policyName: require-ro-rootfs-cedde0
  validationActions: [Deny]
```

More in [`examples/`](examples/).

## Results on the Kyverno policy library

Run against [kyverno/policies](https://github.com/kyverno/policies) @ `ef9843f`, 523 policies
classified as natively expressible:

```
converted      400
unsupported    123
```

Converted output for the full corpus is in [`converted/`](converted/) (401 files — 400 from the
converters plus one hand-written policy retained from an earlier experiment).

Each converted policy was applied to a live cluster alongside its Kyverno original and given the
same upstream test fixtures. **Where both could be compared directly: 167 agreed, 0 disagreed.**

### What it does not convert yet

| Reason | Count |
|---|---:|
| `foreach` (iteration) | 30 |
| Complex JMESPath / `deny.conditions` beyond the supported subset | 50 |
| `patchStrategicMerge` list merge | 9 |
| Match scope: resource names, `exclude` by kind/field, wildcard kind | 10 |
| `patchesJson6902` | 5 |
| `rule.context` → `paramRef` mapping | 11 |
| Anchors: PSM map anchor, global `<(key)` | 2 |
| `validate.podSecurity`, `validate.manifests` | 5 |

These are front-end gaps in the compiler, not limits of CEL. A follow-up study hand-converted a
representative of each class and verified them on a cluster: of 14 representatives, 7 converted
with no semantic loss, 6 with a specific documented loss, and 1 is genuinely impossible —
`validate.manifests`, which verifies a cosign signature, because CEL has no crypto primitives.

## Known limitations

- **No `foreach` yet** — the single largest gap.
- Kyverno engine extras have no CEL equivalent and are approximated or lost: the OCI image
  reference parser (`images` variable), JSON encode/decode, JSON6902 `/-` append (vs SSA keyed
  merge), and the built-in Pod Security Standards engine tracking `version: latest`.
- `background: true` (Kyverno's scan over pre-existing resources) has no native counterpart —
  VAP/MAP are admission-time only. `validationFailureAction: Audit` *is* expressible, as
  `validationActions: ["Audit", "Warn"]`.
- CEL has no clock. A time-window policy is reproducible on CREATE via
  `timestamp(object.metadata.creationTimestamp)`, but not on UPDATE.
- Generated policy names are `<name>-<6 hex>`; they are stable for a given input but will not
  match any names you already have.
- **Review the output before applying it.** This is a translator, not a verifier.

## Repository layout

```
kyverno2native.py       CLI
convert/                the two converters + pod-controller expansion
classify/               structural classifier used to decide what is natively expressible
verify/                 harness used to compare converted policies against the originals
converted/              converted output for the whole Kyverno library
results/                classification, autogen measurement, provenance, verification CSVs
examples/               before/after pairs
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for attribution to the Kyverno
policy library.
