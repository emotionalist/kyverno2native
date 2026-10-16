# Examples

Each `.txt` file holds a before/after pair: the original Kyverno policy followed by the
native VAP/MAP the converter produced.

| File | Shows |
|---|---|
| `argo__application-prevent-default-project.txt` | A simple negated pattern (`!default`) and a precondition folded into `operations` |
| `best-practices__require-labels.txt` | Pod-controller expansion — one policy becomes three VAP pairs (`-ag1`, `-ag2`) |
| `best-practices__require-ro-rootfs.txt` | A pattern under a list compiled to `.all()` |
| `karpenter__add-karpenter-donot-evict.txt` | `patchStrategicMerge` + `+()` add-if-absent anchor → MAP `ApplyConfiguration` |

`require-ro-rootfs.yaml` is a minimal input you can run directly:

```bash
python3 ../kyverno2native.py require-ro-rootfs.yaml
```
