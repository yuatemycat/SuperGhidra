# `superghidra.core` — Daemon, Oracle, Resource Governor, SHM IPC & Headless Engine

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/core/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`ghidra_oracle.py`](ghidra_oracle.py) | `GhidraOracleSession`, `GhidraDaemonServer`, `L2SQLiteCache`, `WriteOverlay`, `client_send_request` | Persistent lock-free TCP daemon (`127.0.0.1:5073`), sub-ms L2 SQLite WAL cache, and JSON write-overlay. |
| [`resource_governor.py`](resource_governor.py) | `ResourceMode`, `FunctionComplexityTier`, `ModePolicy`, `get_default_mode_policy`, `DecompilerComplexityGovernor`, `JVMResourceConfigurator`, `DecompileProcessPoolReaper`, `PersistentDecompilerDBCache`, `TelemetryResourceGovernor` | Closed-loop CPU/RAM governor (`eco`, `balanced`, `turbo`, `auto`) and complexity-aware decompiler style downshifting. |
| [`shm_decompiler_bridge.py`](shm_decompiler_bridge.py) | `ShmBinaryView`, `ShmRingBuffer`, `ShmChannel`, `ShmMessage`, `SectionInfo`, `benchmark_shm_bridge` | Zero-copy OS shared-memory binary views and ~5 µs SPSC/MPMC ring buffer IPC. |
| [`dependency_cache_dag.py`](dependency_cache_dag.py) | `DependencyCacheDAG`, `DecompilationLRUCache`, `InvalidationImpactReport` | Directed call & type dependency DAG for selective 1-hop cache invalidation (99.73% retention). |
| [`headless_analyzer_tuner.py`](headless_analyzer_tuner.py) | `AnalyzerConfiguration`, `AnalyzerProfileName`, `HeadlessCommandBuilder`, `ScriptGenerator`, `get_profile_config` | Cascade shield disabling pathological analyzers (`Non-Returning Functions - Discovered`, `Repair Flow Damage`). |
| [`cross_platform_headless_harness.py`](cross_platform_headless_harness.py) | `HeadlessProfile`, `HeadlessEnvironmentConfigurator` | Multi-OS (`PeLoader`/`ElfLoader`), RAM disk (`/dev/shm`), JADX, and Colab hardware tier flags. |
| [`native_decompiler_pgo_builder.py`](native_decompiler_pgo_builder.py) | `DecompilerBuildConfig`, `NativeDecompilerPGOBuilder` | CMake/Ninja LTO + 2-phase PGO builder for native `decompile` and `RuleFoldJniBridgeThunk` C++ patches. |
| [`evidence_ledger.py`](evidence_ledger.py) | `ReconstructionObligationLedger`, `ProofObligation`, `VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier` | Re-export of [`superghidra.diff.evidence_ledger`](../diff/evidence_ledger.py) for core consumers. |

## 2. Key Data Structures & Invariants
- **Read-Only Project Invariant:** `GhidraOracleSession` opens `.rep` databases exclusively with `readOnly=True`. Mutations are persisted to `WriteOverlay` (`ghidra_overlay.json`) and `SemanticDeltaLog` (`.ghidra-delta.jsonl`).
- **Stale Lock Safety:** `clean_locks()` never deletes `.lock` files by default; it only deletes locks older than `stale_seconds` when `delete_stale=True` (`--clean-stale-locks`).
- **Per-Program L2 Cache Isolation:** `L2SQLiteCache` keys rows by `(program_id, query_type, normalized_key)` so multi-binary sessions never collide.
- **Headless Command Invariant:** `HeadlessCommandBuilder` never combines `-readOnly` with `-import` mode.
- **Launch Properties Format:** `JVMResourceConfigurator` emits one `VMARGS=` entry per line and never emits invalid `MAXMEM` keys.

## 3. Quick-Test Command
```powershell
python -m pytest tests/core -q
```
