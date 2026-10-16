# Contributing

Issues and pull requests are welcome.

## Reporting a conversion failure

Please include the Kyverno policy that failed and the line the tool printed, e.g.
`foreach` or `complex JMESPath ...`. A minimal policy that reproduces it is ideal.

## Adding support for a Kyverno construct

Conversion is split in two:

- `convert/convert_cel_crds.py` — policies already written in CEL. Work here is about the
  envelope: `matchConstraints`, Kind→resource mapping, naming, bindings.
- `convert/compile_traditional.py` — the compiler for traditional syntax. `compile_node()`
  walks the pattern tree; `parse_key()` strips anchors; `jmes_to_cel()` and `cond_to_cel()`
  handle `deny.conditions`; `psm_to_apply()` handles `patchStrategicMerge`.

A construct that cannot be compiled raises `ConvertError` with a short reason — that string is
what the CLI reports and groups by.

When adding a construct, please also add a before/after pair under `examples/` and check the
generated policy is accepted by an API server:

```bash
kubectl apply --dry-run=server -f out/your-policy.yaml
```

## Semantics to be careful with

Kyverno anchors do not map one-to-one onto CEL. A plain pattern key requires the path to
**exist**; `=(key)` does not. A wildcard map key means **existence**, so `.all()` is wrong —
it is vacuously true when nothing matches. `deny` is existential while `validations` is
universal, so one must be the negation of the other. The table in the README records the full
mapping.
