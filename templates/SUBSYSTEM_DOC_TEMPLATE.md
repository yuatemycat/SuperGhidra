# `superghidra.<domain>` — <Short Domain Title>

> **Progressive Discovery Index (< 300 Tokens):** Read this index before inspecting raw `.py` files in `superghidra/<domain>/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`<module_a>.py`](<module_a>.py) | `<ClassA>`, `<func_a>` | <One-sentence description of module responsibility and performance profile.> |
| [`<module_b>.py`](<module_b>.py) | `<ClassB>`, `<DataclassB>` | <One-sentence description of module responsibility and integration boundary.> |

## 2. Key Data Structures & Architectural Invariants
- **`<PrimaryDataclass>` Layout / Schema:** <Specify byte layout, field types, or serialization contract (e.g., `.to_dict()`, `.from_dict()`).>
- **Safety / Soundness Invariant:** <Specify hard invariants that must never be violated (e.g., read-only `.rep` access, `EvidenceLedger` proof gating, `UNKNOWN` vs `UNSAT` soundness, or `EmulatorFleetGuard` allow-listing).>
- **Backward-Compatibility Invariant:** Every canonical module `superghidra/<domain>/<mod>.py` must have a corresponding root-level `<mod>.py` `sys.modules` alias shim and lazy export entry in `superghidra/<domain>/__init__.py` and `superghidra/__init__.py`.

## 3. Quick-Test Command
```powershell
python -m pytest tests/<domain> -q
```
