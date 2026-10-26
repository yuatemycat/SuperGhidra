# `superghidra.core` — Daemon, Oracle, Resource Governor, SHM IPC & Headless Engine

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/core/`.

## 1. Core Production Modules

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`ghidra_oracle.py`](ghidra_oracle.py) | `GhidraOracleSession`, `GhidraDaemonServer`, `L2SQLiteCache`, `WriteOverlay`, `client_send_request` | Persistent TCP daemon (`127.0.0.1:5073`), L2 SQLite WAL cache, and JSON write-overlay (`ghidra_overlay.json`). |
| [`compilable_filter.py`](compilable_filter.py) | `CompilableDecompilerFilter`, `GHIDRA_TYPE_MAP` | Rewrites Ghidra pseudo-types (`undefined8`, `ulonglong`) and intrinsics (`CONCAT44`, `SUB84`), collapses pointer-stride expressions, and injects standard C headers. |
| [`live_binary_tools.py`](live_binary_tools.py) | `staged_decompile_function`, `query_binary_dataflow`, `solve_global_type_lattice`, `deflatten_control_flow`, `compile_usercall_prototype`, `match_flirt_signatures`, `import_type_library` | Operates directly on binary files on disk without opening a Ghidra `.rep` project. |
| [`native_compiler.py`](native_compiler.py) | `compile_and_run`, `msvc_env` | Compiles and runs C/C++ test drivers with `gcc`/`clang` or portable MSVC `cl.exe` (`SUPERGHIDRA_MSVC_ROOT`). |
| [`resource_governor.py`](resource_governor.py) | `ResourceMode`, `FunctionComplexityTier`, `ModePolicy`, `get_default_mode_policy`, `DecompilerComplexityGovernor`, `JVMResourceConfigurator`, `DecompileProcessPoolReaper`, `PersistentDecompilerDBCache`, `TelemetryResourceGovernor` | CPU/RAM budget selector (`eco`, `balanced`, `turbo`, `auto`) and decompiler timeout/simplification-style controller. |
| [`shm_decompiler_bridge.py`](shm_decompiler_bridge.py) | `ShmBinaryView`, `ShmRingBuffer`, `ShmChannel`, `ShmMessage`, `SectionInfo`, `benchmark_shm_bridge` | OS shared-memory binary section views and SPSC/MPMC ring buffer IPC (~5 µs local roundtrip). |
| [`dependency_cache_dag.py`](dependency_cache_dag.py) | `DependencyCacheDAG`, `DecompilationLRUCache`, `InvalidationImpactReport` | Directed call and struct-field dependency graph for selective 1-hop decompilation cache eviction (99.73% retention on synthetic 1,000-node graphs). |
| [`headless_analyzer_tuner.py`](headless_analyzer_tuner.py) | `AnalyzerConfiguration`, `AnalyzerProfileName`, `HeadlessCommandBuilder`, `ScriptGenerator`, `get_profile_config` | Disables slow or destructive Ghidra analyzers (`Non-Returning Functions - Discovered`, `Repair Flow Damage`) during headless imports. |
| [`cross_platform_headless_harness.py`](cross_platform_headless_harness.py) | `HeadlessProfile`, `HeadlessEnvironmentConfigurator` | Configures OS loader flags (`PeLoader`/`ElfLoader`), RAM disk paths (`/dev/shm`), and JVM heap limits. |
| [`native_decompiler_pgo_builder.py`](native_decompiler_pgo_builder.py) | `DecompilerBuildConfig`, `NativeDecompilerPGOBuilder` | CMake/Ninja LTO and 2-phase PGO build driver for the native C++ `decompile` binary. |
| [`cluster_daemon.py`](cluster_daemon.py) | `ClusterCoordinator`, `ClusterWorkerNode`, `TaskEnvelope`, `ClusterTaskType`, `WorkerStatus` | gRPC (and in-memory fallback) worker registration, heartbeat tracking, and task dispatch. |
| [`evidence_ledger.py`](evidence_ledger.py) | `ReconstructionObligationLedger`, `ProofObligation`, `VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier` | Re-export of [`superghidra.diff.evidence_ledger`](../diff/evidence_ledger.py) for core consumers. |

## 2. Experimental / Research Modules

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`parity_engine.py`](parity_engine.py) | `StagedPCodePassManager`, `SymbolicCFGDeflattener`, `UsercallPrototypeCompiler`, `AppcallMarshaller`, `CFGSignatureIndex`, `ClangHeaderImporter`, `SGDBBlockStore`, `SparseMatrixDatalogEngine` | Standalone reference implementations for Section 3 IDA Pro gap closures (Gaps 1–7) and boolean-matrix Datalog reachability. |
| [`mitigation_roadmap_engine.py`](mitigation_roadmap_engine.py) | `GNNPCodeTensorEncoder`, `LeafXRefInversionEngine`, `ABIShimAndStructShiftAdapter`, `EmulatorMemorySidecar`, `OffHeapDWARF5SQLiteIndexer`, `MSVCAndMFCRecoveryEngine`, `ResourceGovernorAndCacheDAG` | Experimental research prototype simulating Section 5 gap-mitigation workflows M1–M7 on synthetic inputs. |

## 3. Key Data Structures & Invariants
- **Read-Only Project Invariant:** `GhidraOracleSession` opens `.rep` databases exclusively with `readOnly=True`. Mutations are persisted to `WriteOverlay` (`ghidra_overlay.json`) and `SemanticDeltaLog` (`.ghidra-delta.jsonl`).
- **Stale Lock Safety:** `clean_locks()` never deletes `.lock` files by default; it only deletes locks older than `stale_seconds` when `delete_stale=True` (`--clean-stale-locks`).
- **Per-Program L2 Cache Isolation:** `L2SQLiteCache` keys rows by `(program_id, query_type, normalized_key)` so multi-binary sessions never collide.
- **Headless Command Invariant:** `HeadlessCommandBuilder` never combines `-readOnly` with `-import` mode.
- **Launch Properties Format:** `JVMResourceConfigurator` emits one `VMARGS=` entry per line and never emits invalid `MAXMEM` keys.

## 4. Quick-Test Command
```powershell
python -m pytest tests/core -q
```
