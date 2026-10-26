# SuperGhidra API & Schema Deprecation Policy

This document defines the formal stability guarantees, deprecation lifecycle, and versioning rules for the SuperGhidra public API and versioned JSON schemas.

---

## 1. Semantic Versioning Contract

SuperGhidra adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html):

- **Patch Releases (`0.x.Y` / `1.x.Y`)**:
  - Confined strictly to bug fixes, security hardening, internal optimizations, and documentation corrections.
  - Zero modifications to public function signatures, parameter names, or schema formats.
- **Minor Releases (`0.X.0` / `1.X.0`)**:
  - Introduction of new additive features, non-breaking API exports, and backward-compatible schema enhancements.
  - Deprecation notices for existing public interfaces scheduled for future removal.
- **Major Releases (`X.0.0`)**:
  - Removal of previously deprecated interfaces, modules, or legacy schemas.
  - Breaking architectural changes and major schema upgrades.

---

## 2. API Stability Tiers

SuperGhidra classifies all codebase interfaces into three distinct stability tiers:

```
┌─────────────────────────────────────────────────────────────┐
│                 Tier 1: Frozen Core API                     │
│       Defined by superghidra.__all__ (33 Public Symbols)     │
├──────────────────────────────┬──────────────────────────────┤
│  Tier 2: Experimental Core   │ Tier 3: Legacy Compatibility │
│ (superghidra.experimental.*) │    (superghidra.compat.*)    │
└──────────────────────────────┴──────────────────────────────┘
```

### Tier 1: Frozen Core API (Stable)
The frozen public API is strictly declared in [`src/superghidra/__init__.py`](src/superghidra/__init__.py) under `__all__`:

| Subsystem | Canonical Symbols |
| :--- | :--- |
| **Binary Loader** | `load_binary`, `BinaryImage`, `Section`, `Symbol`, `Import`, `Relocation` |
| **MSVC RTTI & MFC Recovery** | `recover_classes`, `ClassRecoveryReport`, `RTTIClass`, `RTTIBaseClass`, `MemberVariable`, `CRuntimeClassInfo`, `MFCClassSchema`, `MFCArchiveDecoder` |
| **Write Overlay** | `WriteOverlay` |
| **Oracle Daemon Client** | `query_oracle`, `is_daemon_online`, `start_daemon`, `stop_daemon`, `client_send_request` |
| **Compilable C Filter** | `CompilableDecompilerFilter`, `filter_c_code` |
| **Synthetic Symbol Exporters** | `DWARF5Exporter`, `PDBExporter`, `SymFileExporter`, `MapFileExporter`, `export_from_ledger` |

**Stability Guarantee:**
- Any breaking modification to a Tier 1 function or class signature requires a minimum transition window of **one full minor release** (e.g. deprecated in `0.5.0`, removed no earlier than `0.6.0` or `1.0.0`).
- Runtime deprecation notices must be raised using Python's standard `warnings.warn(..., category=DeprecationWarning, stacklevel=2)`.
- Following the `1.0.0` release, all Tier 1 symbols are guaranteed backward-compatible across all `1.x` versions.

### Tier 2: Experimental Domain (`superghidra.experimental.*`)
Subsystems undergoing active algorithmic research reside under the `superghidra.experimental` namespace:
- GPU ADRP Scanner & Function Seeder (`superghidra.acceleration.*`)
- Batched CFG Binary Differ & Struct Shift Migrator (`superghidra.diff.*`)
- Zero-JVM P-Code Lifter & SMT Verifier (`superghidra.lifters.*`)
- Android Emulator Sidecar & APK Cross-Referencer (`superghidra.integrations.*`)
- Compressed Slot Buffer Storage (`superghidra.storage.*`)
- Resource Governor & SHM IPC Bridge (`superghidra.core.*`)

**Stability Guarantee:**
- Tier 2 modules may evolve or undergo refactoring between minor releases.
- Breaking changes within `superghidra.experimental` are documented in `CHANGELOG.md` under `### Changed` or `### Removed`.
- Mature Tier 2 subsystems are systematically promoted to Tier 1 through RFC review.

### Tier 3: Legacy Compatibility Shims (`superghidra.compat.*`)
Maintained to ensure backward compatibility for external callers previously importing top-level root modules (`import binary_loader`, `import ghidra_oracle`).
- Emits a `DeprecationWarning` upon first import guiding callers to canonical package paths.
- Slated for permanent retirement in version `1.0.0`.

---

## 3. Versioned JSON Schema Evolution

SuperGhidra maintains draft 2020-12 JSON schemas in [`src/superghidra/schemas/`](src/superghidra/schemas/):

- `overlay.schema.v1.json` (`WriteOverlay` / `ghidra_overlay.json`)
- `delta_log.schema.v1.json` (`SemanticDeltaLog` / `.ghidra-delta.jsonl`)
- `evidence_ledger.schema.v1.json` (`ReconstructionObligationLedger`)
- `struct_shift.schema.v1.json` (`StructShiftMigrator`)

### Schema Modification Rules:
1. **Additive Changes (Minor Bump, e.g. `v1.0` -> `v1.1`)**:
   - Adding optional fields or metadata properties.
   - Validators configured with `additionalProperties: true` remain forward-compatible.
   - Downstream consumers reading older payloads must not encounter validation failures.
2. **Breaking Changes (Major Bump, e.g. `v1.x` -> `v2.0`)**:
   - Renaming or removing existing properties.
   - Changing property types or narrowing existing validation constraints.
   - Adding new required fields.
   - Whenever a major schema version is introduced, SuperGhidra must provide automated bi-directional migration adapters (`SchemaMigrator`) preserving legacy file ingestion.

---

## 4. Deprecation Notice Protocol

When an API symbol or schema attribute is marked for deprecation:

1. **Code Instrumentation**:
   ```python
   import warnings

   def legacy_function(*args, **kwargs):
       warnings.warn(
           "legacy_function is deprecated and will be removed in version 1.0.0. "
           "Use superghidra.core.canonical_function instead.",
           category=DeprecationWarning,
           stacklevel=2,
       )
       return canonical_function(*args, **kwargs)
   ```
2. **Documentation Update**:
   - The docstring must indicate the deprecation version and recommended alternative.
   - The symbol must be documented in `CHANGELOG.md` under the `### Deprecated` section of the corresponding release.
3. **Grace Period**:
   - Deprecated items must remain functional and test-covered for at least **one minor version cycle** prior to physical removal.
