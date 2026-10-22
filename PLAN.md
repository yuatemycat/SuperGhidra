# SuperGhidra Master Plan & Architectural Roadmap

**Target Environment:** OpenJDK 21+ / Ghidra 12.1.x / Windows & Linux Headless / PyGhidra  
**Workload Target:** 64-bit ARM (`AArch64`) Production Binaries (`libg.so`, `libscid_sdk.so`)  
**Core Reference:** `GHIDRA_REFORMATION_ARCHITECTURAL_SPEC.md(1).docx` (repo root) & [`README.md`](README.md)  
**Status Tracker:** 35 baseline items and 6 frontiers implemented. Several are partial or experimental; see [Known Limitations](#-known-limitations) and the 2026-10-17 audit notes below.

---

## 📋 Table of Contents
1. [Section 1: Storage Layer Reformation](#1-storage-layer-reformation)
2. [Section 2: CPU Decompiler & Auto-Analysis Reformation](#2-cpu-decompiler--auto-analysis-reformation)
3. [Section 3: GPU Side-Task Acceleration](#3-gpu-side-task-acceleration)
4. [Section 4: Persistent Lock-Free Ghidra Oracle Daemon](#4-persistent-lock-free-ghidra-oracle-daemon)
5. [Section 5: Cross-Platform Headless & Cloud Optimization](#5-cross-platform-headless--cloud-optimization)
6. [Section 6: Ghidra Internal Engine & C++ Decompiler PGO](#6-ghidra-internal-engine--c-decompiler-pgo)
7. [Section 7: Next-Generation Zero-JVM & Neural Decompilation](#7-next-generation-zero-jvm--neural-decompilation)
8. [Section 8: Dynamic Speed-vs-Resource Governor & L2 Cache](#8-dynamic-speed-vs-resource-governor--l2-cache)
9. [Section 9: Multi-Agent MCP Integration (SuperghidraMCP)](#9-multi-agent-mcp-integration-superghidramcp)
10. [🚀 Future Architectural Frontiers & Next Phase](#-future-architectural-frontiers--next-phase)

---

## 1. Storage Layer Reformation
*Goal: Shrink `.rep` storage footprint by ~80% and eliminate `.lock` collision crashes.*

- [x] ~~**Block-Level Frame Compression (LZ4 / Zstandard L3)**~~
  - *Implemented in:* [`storage_compression_prototype.py`](superghidra/storage/storage_compression_prototype.py)
  - *Accomplished:* 16 KB block codec with 64-bit slot directory (`[block_id, offset, comp_len, orig_len]`). The Python-internal container uses its own magic, distinct from the Java-compatible `SGDB` format.
  - *Benchmark:* **54.16% reduction** (LZ4) and **69.27% - 85.39% reduction** (Zstd L3), lossless. Measured on synthetic Ghidra-like pages from `GhidraPageSimulator`, not on real `.gbf` buffers.
- [x] ~~**Elimination of Stale `.lock` and `.lock~` Collisions**~~
  - *Implemented in:* [`ghidra_oracle.py`](ghidra_oracle.py) (`clean_locks()`)
  - *Accomplished:* Programs open read-only (`openProgram(..., readOnly=True)`). Lock files are reported, not deleted, unless `--clean-stale-locks` is passed and the lock is older than the stale threshold.
- [x] ~~**Project Directory Hygiene & Deduplication**~~
  - *Implemented in:* the shared `pyghidra_mcp_projects` folder
  - *Accomplished:* Purged orphaned locks (`my_project.lock`, `my_project.lock~`); multi-agent sessions now share single read-only project daemon.

---

## 2. CPU Decompiler & Auto-Analysis Reformation
*Goal: Eliminate JVM cold-start latency and pathological analysis hangs.*

- [x] ~~**Per-Query JVM & Project Cold-Start Elimination**~~
  - *Implemented in:* [`ghidra_oracle.py`](superghidra/core/ghidra_oracle.py)
  - *Accomplished:* Persistent daemon on `127.0.0.1:5073` keeps JVM and `DecompInterface` hot; drops query latency from 15s to <5 ms.
- [x] ~~**Cascade Shield for Pathological Analyzers**~~
  - *Implemented in:* [`headless_analyzer_tuner.py`](superghidra/core/headless_analyzer_tuner.py)
  - *Accomplished:* Enforces invariant disabling `"Non-Returning Functions - Discovered"` and `"Repair Flow Damage"`, preventing 300+ second quadratic stalling loops on obfuscated game binaries.
- [x] ~~**PreScript and PostScript Generator**~~
  - *Implemented in:* [`headless_analyzer_tuner.py`](superghidra/core/headless_analyzer_tuner.py)
  - *Accomplished:* Emits ready-to-run Java PreScripts (`SuperGhidraPreScript.java`) with custom analyzer configurations.
- [x] ~~**Fine-Grained 1-Hop Cache Invalidation DAG**~~
  - *Implemented in:* [`dependency_cache_dag.py`](superghidra/core/dependency_cache_dag.py)
  - *Accomplished:* Dependency DAG retaining **99.73% of cached functions** on struct/signature edits instead of global cache flushes.

---

## 3. GPU Side-Task Acceleration
*Goal: Offload embarrassingly parallel scanning, diffing, and indexing to GPU compute shaders.*

- [x] ~~**WGPU / CUDA ARM64 `ADRP + ADD/LDR` Reference Scanner**~~
  - *Implemented in:* [`gpu_adrp_scanner.py`](superghidra/acceleration/gpu_adrp_scanner.py)
  - *Accomplished:* Sweeps 5.76M ARM64 instructions in parallel using DirectX 12 / Vulkan compute shaders in **959.55 ms** on real 23 MB `libg.so`, isolating 6,295 candidate pairs.
- [x] ~~**Batched Cosine-Similarity Binary Diff Engine**~~
  - *Implemented in:* [`binary_diff_engine.py`](superghidra/diff/binary_diff_engine.py)
  - *Accomplished:* Mutual Top-1 bipartite matching and greedy max-weight pairing for 45,000+ stripped functions across binary versions.
- [x] ~~**Reconstruction Obligation Ledger (Evidence Gate)**~~
  - *Implemented in:* [`evidence_ledger.py`](superghidra/core/evidence_ledger.py)
  - *Accomplished:* Formal invariant gate enforcing VTable slot index, allocation size, and struct displacement proofs before renaming symbols.
- [x] ~~**Git-Mergeable Semantic Delta Log**~~
  - *Implemented in:* [`semantic_delta_log.py`](superghidra/diff/semantic_delta_log.py)
  - *Accomplished:* Append-only `.ghidra-delta.jsonl` with SHA-256 cryptographic proofs (23,840 events/sec).
- [x] ~~**Off-Heap DWARF / PDB Structural Deduplicator**~~
  - *Implemented in:* [`dwarf_pdb_preindexer.py`](superghidra/formats/dwarf_pdb_preindexer.py)
  - *Accomplished:* Off-heap SQLite indexer parsing 85,026 types/sec with 2.70 µs lookup.

---

## 4. Persistent Lock-Free Ghidra Oracle Daemon
*Goal: Provide instant, zero-lock CLI and TCP interface for agents and analysts.*

- [x] ~~**Dual-Mode Read-Only TCP/JSON Server & CLI Client**~~
  - *Implemented in:* [`ghidra_oracle.py`](superghidra/core/ghidra_oracle.py)
  - *Commands:* `serve`, `decompile`, `vtable`, `disassemble`, `refs`, `adrp_add`, `opcodes`, `rva`, `rename`, `comment`, `overlay`, `status`, `stop`.
- [x] ~~**Microsecond Address Translation (Zero JVM)**~~
  - *Implemented in:* [`ghidra_oracle.py`](ghidra_oracle.py)
  - *Benchmark:* Resolves `0x00CF2D84` -> `0x00BF2D84` in **0.0030 ms** without touching the JVM.
- [x] ~~**In-Memory + JSON Symbol Write-Overlay**~~
  - *Implemented in:* `WriteOverlay` in [`ghidra_oracle.py`](ghidra_oracle.py)
  - *Accomplished:* Allows renaming and commenting without dirtying read-only `.rep` databases.

---

## 5. Cross-Platform Headless & Cloud Optimization
*Goal: Automate multi-OS (Windows, Linux, Colab) batch decompilation and APK JNI linkage.*

- [x] ~~**Unified APK Java + JNI (`lib/*.so`) Cross-Referencer**~~
  - *Implemented in:* [`apk_jni_cross_referencer.py`](superghidra/integrations/apk_jni_cross_referencer.py)
  - *Accomplished:* Maps JADX DEX `native` declarations to ARM64 `.so` export symbols and `RegisterNatives` dynamic function pointer tables.
- [x] ~~**Multi-OS Headless Execution Harness (`PeLoader` & `ElfLoader`)**~~
  - *Implemented in:* [`cross_platform_headless_harness.py`](superghidra/core/cross_platform_headless_harness.py)
  - *Accomplished:* Generates tuned execution flags, RAM disk `/dev/shm` bindings, and JADX memory caps.
- [x] ~~**Google Colab Hardware Tier Matrix**~~
  - *Implemented in:* [`cross_platform_headless_harness.py`](cross_platform_headless_harness.py)
  - *Accomplished:* Configuration recipes for Free CPU (RAM disk), NVIDIA T4 (EGL + FP16), and Cloud TPU v5e (JAX XLA flags).

---

## 6. Ghidra Internal Engine & C++ Decompiler PGO
*Goal: Recompile native C++ decompiler with maximum optimizations and custom P-code rules.*

- [x] ~~**Native C++ Decompiler LTO & PGO Automated Builder**~~
  - *Implemented in:* [`native_decompiler_pgo_builder.py`](superghidra/core/native_decompiler_pgo_builder.py)
  - *Accomplished:* CMake/Ninja script generator compiling `decompile.exe` / `decompile` with `-O3 -march=native -flto` and 2-phase PGO profiling.
- [x] ~~**Custom C++ P-Code `Rule` and `Action` Patch Generator**~~
  - *Implemented in:* [`native_decompiler_pgo_builder.py`](native_decompiler_pgo_builder.py)
  - *Accomplished:* Emits C++ source patches for `blockaction.cc` and `coreaction.cc` folding ARM64 vector idioms.
- [x] ~~**In-Process PyGhidra (JPype) Environment Bootstrapper**~~
  - *Implemented in:* `setup_environment()` in [`ghidra_oracle.py`](ghidra_oracle.py)
  - *Accomplished:* Configures `JAVA_HOME`, `GHIDRA_INSTALL_DIR`, and PATH precedence automatically.

---

## 7. Next-Generation Zero-JVM & Neural Decompilation
*Goal: Decouple lifter from Java platform and accelerate via neural architectures.*

- [x] ~~**Direct Python ARM64/x86 P-Code IR Lifter (Zero-JVM)**~~
  - *Implemented in:* [`pcode_lifter_bridge.py`](superghidra/lifters/pcode_lifter_bridge.py)
  - *Accomplished:* Pure CPython IR lifter executing at **1,050,641 insns/sec** on real `libg.so` without booting Java.
- [x] ~~**GNN / TPU Systolic Array Adjacency Matrix Generator**~~
  - *Implemented in:* `PcodeGraphBuilder` in [`pcode_lifter_bridge.py`](pcode_lifter_bridge.py)
  - *Accomplished:* Converts P-code blocks into fixed-shape padded tensors for TPU systolic arrays.
- [x] ~~**Two-Phase Skeleton-to-Skin Neural Decompiler Pipeline**~~
  - *Implemented in:* [`neural_decompiler_pipeline.py`](superghidra/integrations/neural_decompiler_pipeline.py)
  - *Accomplished:* Phase 1 structural/VTable recovery ("skeleton") coupled with Phase 2 LLM semantic naming ("skin") gated by `EvidenceLedger`.
- [x] ~~**Zero-Copy Shared-Memory IPC Bridge**~~
  - *Implemented in:* [`shm_decompiler_bridge.py`](superghidra/core/shm_decompiler_bridge.py)
  - *Accomplished:* POSIX/Win32 shared memory view (zero-copy `ShmBinaryView`) and SPSC ring buffer (pops copy the payload; MPMC mode uses a named OS mutex). **~5 µs IPC roundtrip** on the dev machine.
- [x] ~~**GPU Parallel Function Seeder**~~
  - *Implemented in:* [`gpu_function_seeder.py`](superghidra/acceleration/gpu_function_seeder.py)
  - *Accomplished:* Discovered **8,617 functions in 39.81 ms** (**144.77 Million insns/sec**) on real `libg.so`.

---

## 8. Dynamic Speed-vs-Resource Governor & L2 Cache
*Goal: Closed-loop CPU and RAM reduction with sub-millisecond offline query bypass.*

- [x] ~~**Persistent L2 SQLite WAL Cache**~~
  - *Implemented in:* `L2SQLiteCache` in [`ghidra_oracle.py`](ghidra_oracle.py) (keyed per program) & `l2_cache.py`
  - *Accomplished:* Intercepts repeat queries (`decompile`, `vtable`, `disassemble`, `refs`, `adrp_add`, `opcodes`) in **< 0.05 ms** with **0% JVM CPU**.
- [x] ~~**Native Decompiler Idle Watchdog & Hibernation**~~
  - *Implemented in:* [`ghidra_oracle.py`](ghidra_oracle.py) & `decompiler_pool.py`
  - *Accomplished:* Watchdog kills idle `decompile.exe` subprocesses after 15s/120s and triggers `System.gc()`.
- [x] ~~**Multi-Tier Resource Mode Profiles**~~
  - *Profiles:*
    - `eco`: Pinned to 1 core, 50ms duty-cycle throttle, 15s idle reaper, default `normalize`.
    - `balanced`: 2 cores, 10ms duty-cycle throttle, 120s idle reaper, default `decompile`.
    - `turbo`: All cores, unthrottled (0ms), permanently warm (never sleeps).
    - `auto`: Telemetry closed-loop monitoring CPU thresholds (throttles at >70% CPU, boosts at <25%).
- [x] ~~**Decompiler Simplification Style Downshifting**~~
  - *Options:* `--style [firstpass|register|jumptable|paramid|normalize|decompile]`
  - *Accomplished:* Automatically downshifts massive 10,000+ line dispatchers to `firstpass` or `normalize` (15%-55% CPU) to prevent decompiler timeout crashes.

---

## 9. Multi-Agent MCP Integration ([SuperghidraMCP](https://github.com/yuatemycat/SuperghidraMCP))
*Goal: Native exposure of SuperGhidra across all LLM agent platforms.*

- [x] ~~**SuperghidraMCP Server Core**~~
  - *Location:* [`yuatemycat/SuperghidraMCP`](https://github.com/yuatemycat/SuperghidraMCP) (separate repository)
  - *Accomplished:* L2 cache, Resource Governor, 38 registered tools; 235 unit tests passing.
- [x] ~~**6 New Native SuperGhidra MCP Tools**~~
  - `rva_translate`: Instant zero-JVM address translation (<0.003 ms).
  - `gpu_adrp_scan`: Parallel ARM64 reference pair scanning.
  - `gpu_seed_functions`: Parallel function entry point discovery (144M insns/s).
  - `set_governor_mode`: Runtime profile hot-swapping (`eco`, `balanced`, `turbo`, `auto`).
  - `hibernate`: Immediate decompiler process termination and JVM heap uncommit.
  - `clear_cache`: Full L2 cache and decompiler pool invalidation.
- [x] ~~**Tri-Platform Registration**~~
  - [x] ~~Registered as an MCP server in Hermes Agent, the AGY CLI and Claude Code / Claude Desktop.~~

---

## 🚀 Future Architectural Frontiers & Next Phase

The baseline specification (Sections 1 through 8) and MCP unification are implemented; see Known Limitations for what is partial. Frontier status:

### Frontier 1: Standalone Synthetic DWARF / PDB Symbol Exporter
- [x] ~~**Goal:** Export recovered class layouts, VTables, struct member alignments, and method names from `EvidenceLedger` / `_ghidra_names.json` directly into standalone `.debug_info` (DWARF 5) and `.pdb` (Microsoft PDB) symbol containers.~~
- [x] ~~**Impact:** Allows external debuggers (IDA Pro, Binary Ninja, LLDB, x64dbg, Cheat Engine) to natively load recovered symbol types without opening or converting a `.rep` project database.~~
- [x] ~~**Target Modules:** [`synthetic_symbol_exporter.py`](superghidra/formats/synthetic_symbol_exporter.py)~~
- [x] ~~**Accomplished:**~~
  - DWARF 5 ELF64 container (`DWARF5Exporter`, `EM_AARCH64` by default) emitting CU headers, `.debug_info`, `.debug_abbrev`, `.debug_line`, `.debug_str`, and `.symtab`; every `DW_AT_type` references a real DIE.
  - **Experimental** MSF 7.0 / PDB container (`PDBExporter`): correct 64-byte DBI header, FPM blocks reserved, valid named-stream map, `S_PUB32` records. No GSI hash stream, so MSVC/LLVM tools may not load it.
  - Breakpad `.sym` format (`SymFileExporter`) and linker `.map` format (`MapFileExporter`).
  - Batch export API: `export_from_ledger(ledger, output_base, formats=['dwarf', 'pdb', 'sym', 'map'])` and CLI.

### Frontier 2: SMT-Backed Decompilation Equivalence Verifier
- [x] ~~**Goal:** Pair `pcode_lifter_bridge.py` with the Z3 SMT solver and angr symbolic execution to prove that neural-refined or reconstructed C code produces bit-exact identical register/memory state transitions to original ARM64 P-code.~~
- [x] ~~**Impact:** Mathematical verification of game hook logic and struct offsets before compiling native `guest_hook.cpp` payloads.~~
- [x] ~~**Target Modules:** [`smt_pcode_verifier.py`](superghidra/lifters/smt_pcode_verifier.py)~~
- [x] ~~**Accomplished:**~~
  - Symbolic state simulator (`SymbolicState`, `PcodeSymbolicSimulator`) mapping registers to 64/32-bit Z3 bitvectors and memory to symbolic byte arrays.
  - Full P-code opcode translation: `COPY`, `INT_ADD`, `INT_SUB`, `INT_AND`, `INT_OR`, `INT_XOR`, `INT_LEFT`, `INT_RIGHT`, `INT_MULT`, `LOAD`, `STORE`, and comparisons.
  - C AST evaluator (`CCodeParser`, `CSymbolicEvaluator`) parsing decompiled/hook C statements and resolving struct field dereferences.
  - Z3 formal equivalence query solver (`SMTPcodeVerifier`) returning mathematical proofs (UNSAT) or concrete bug counterexamples (SAT).
  - Integration with `EvidenceLedger` formal gate enforcing provable equivalence for `FUNCTION_HOOK` and `STRUCT_FIELD_RENAME` obligations.

### Frontier 3: In-Engine Java Extension (`Ghidra/Skeleton`)
- [x] ~~**Goal:** Package the transparent LZ4/Zstandard `LocalManagedBufferFile` codec directly into a compiled Ghidra extension `.zip` using Gradle and OpenJDK 21.~~
- [x] ~~**Impact:** Installs as an official module in `<ghidra_install_dir>\Ghidra\Extensions`, enabling GUI users to get transparent block compression without running external scripts.~~
- [x] ~~**Implemented in:** [`ghidra_extension_skeleton/`](ghidra_extension_skeleton/) & [`ghidra_extension_packager.py`](superghidra/storage/ghidra_extension_packager.py)~~
  - *Accomplished:* Official layout with `extension.properties`, `Module.manifest`, `build.gradle`, `SuperGhidraBufferFileAdapter.java`, `SuperGhidraExtensionPlugin.java`, `CompressionAlgorithm.java`, and packager producing `dist/SuperGhidraCodec-1.0.0.zip`.

### Frontier 4: Cloud Colab Headless TPU v5e / T4 Pipeline Orchestrator
- [x] ~~**Goal:** Build an automated Google Colab deployment script that sets up `/dev/shm` RAM disks, pulls `libg.so`, runs JADX DEX analysis, and executes batched JAX/XLA TPU v5e systolic array inference for megafunction recovery.~~
- [x] ~~**Impact:** Offloads massive multi-hour decompilation tasks to free cloud TPU/GPU runtimes with zero workstation CPU consumption.~~
- [x] ~~**Implemented in:** [`colab_cloud_orchestrator.py`](superghidra/integrations/colab_cloud_orchestrator.py) & [`colab_cloud_orchestrator.ipynb`](colab_cloud_orchestrator.ipynb)~~
  - *Accomplished:* Multi-tier cloud profile (Free CPU, T4 GPU, TPU v5e JAX/XLA systolic arrays), ambient HF_TOKEN authentication, /content storage invariant, /dev/shm RAM disk staging, JADX G1GC bounds, Zero-JVM P-Code bfloat16 tensor packing, and EvidenceLedger gated symbol reconstruction.

### Frontier 5: Live Android Emulator Memory Introspection Sidecar
- [x] ~~**Goal:** Connect `shm_decompiler_bridge.py` to an active emulator runtime (MuMu / MEmu / QEMU via Frida or memory mapping) to cross-reference static Ghidra RVAs with live dynamic game memory pointers.~~
- [x] ~~**Impact:** Auto-verifies VTable pointers, dynamic encryption keys, and heap struct instances in real-time.~~
- [x] ~~**Target Modules:** [`emulator_memory_sidecar.py`](superghidra/integrations/emulator_memory_sidecar.py)~~
- [x] ~~**Accomplished:**~~
  - ~~Strict adherence to `android-emulator-fleet-safety`: protects live game instance (`emulator-5564`) from mutations, safeguards system default (`127.0.0.1:21503`), targets authorized sandbox (`emulator-5580`) and MEmu_1 (`127.0.0.1:21513`).~~
  - ~~Dynamic memory reader abstractions: `Win32ProcessMemoryReader`, `FridaMemoryReader`, and `MockMemoryReader`.~~
  - ~~Module base resolver (static Ghidra RVA <-> live dynamic pointer translation: `dynamic_addr = module_base + rva`).~~
  - ~~Live verifiers: `verify_vtable_pointer` (confidence-scored pointer verification), `verify_struct_field` (typed field validation & range checks), `extract_dynamic_encryption_keys` (Shannon entropy estimation).~~
  - ~~Microsecond IPC streaming via `ShmChannel` (`EmulatorSidecarShmServer` & `EmulatorSidecarShmClient`).~~

### Frontier 6: Cross-Version Automated Struct Shift Migrator Tool & MCP Integration
- [x] ~~**Goal:** Expose an automated MCP tool in SuperghidraMCP that takes two binary versions (e.g., `libg v1` and `libg v2`), detects all shifted struct offsets (e.g. `m_turnTick` shifting from `+0x20` to `+0x24`), and outputs a ready-to-compile header diff.~~
- [x] ~~**Impact:** Reduces client update hook migration time from days to seconds.~~
- [x] ~~**Target Modules:**~~
  - ~~SuperGhidra: [`struct_shift_migrator.py`](superghidra/diff/struct_shift_migrator.py)~~
  - ~~pyghidra-mcp: `tools.py`, `mcp_tools.py`, `server.py`, `models.py`~~
  - ~~MCP Schema: `migrate_struct_shifts.json`~~
- [x] ~~**Accomplished:**~~
  - ~~ARM64 bitwise decoder (`LDR`, `STR`, `LDP`, `STP`, unsigned/unscaled immediate) and x86-64 disassembly parser.~~
  - ~~Cross-version displacement matching, insertion point detection, and shift classification (`identical`, `insertion_shift`, `expansion_shift`, `alignment_adjustment`).~~
  - ~~Automatic C++ header patch generator (unified diff and annotated C++ struct definitions).~~
  - ~~Full MCP tool exposure with `migrate_struct_shifts` registered and schema distributed.~~

### Frontier 7: Multi-Architecture Binaries & Windows Class Recovery
- [x] ~~**Unified loader** ([`binary_loader.py`](superghidra/formats/binary_loader.py)): ELF 32/64 LE/BE, PE32/PE32+ EXE/DLL, Mach-O thin/universal; exports, imports, function starts, PDB path; stripped-section-table fallback.~~
- [x] ~~**x86 decoder** ([`x86_decode.py`](superghidra/lifters/x86_decode.py)): 16/32/64-bit, VEX/EVEX; Capstone-verified lengths. Diff engine and struct migrator routed through loader + decoder (32-bit x86, SSE/AVX accesses, DLL export-name matching).~~
- [x] ~~**MSVC RTTI + MFC CRuntimeClass recovery** ([`msvc_class_recovery.py`](superghidra/formats/msvc_class_recovery.py)) with `Serialize()` resolution; MCP tools `inspect_binary`, `recover_cpp_classes`.~~
- [x] ~~**ARM32/Thumb-2 decoder** ([`arm_thumb_decode.py`](superghidra/lifters/arm_thumb_decode.py)): 16-bit Thumb, 32-bit Thumb-2, 32-bit ARM state; memory displacement extraction (`LDR`/`STR`/`LDRB`/`STRB`/`LDRH`/`STRH`/`LDRD`/`STRD`), branch and call target resolution, prologue/epilogue detection. Integrated into [`struct_shift_migrator.py`](superghidra/diff/struct_shift_migrator.py) and [`binary_diff_engine.py`](superghidra/diff/binary_diff_engine.py) (`extract_cfgs_from_arm32_bytes`).~~
- [x] ~~**CArchive stream decoder driven by recovered `Serialize()` layouts (LiquidWork integration)** (`src/mfc_decoder.rs`): pure Rust deserializer, schema-driven layout engine, SolidWorks `Contents/Config-0-ResolvedFeatures` bidirectional extractor and in-place dimension mutator.~~

---

## 📊 Verification (2026-10-20)

| Suite | Command | Result |
| :--- | :--- | :--- |
| SuperGhidra | `python -m pytest` (repo root) | **535 passed**, 3 integration tests passed |
| pyghidra-mcp | `.venv\Scripts\python -m pytest tests\unit` | **246 passed** |

Regression tests for the 2026-10-17 audit live in `test_g1_regressions.py`, `test_g2_regressions.py`, `test_g2b_regressions.py`, `test_g3a_regressions.py`, `test_g3b_regressions.py` and `pyghidra-mcp/tests/unit/test_g4a_regressions.py`. Test runs no longer write into the repository (ledger → `SUPERGHIDRA_DATA_DIR` or `~/.superghidra`; benchmark report → temp dir).

---

## ⚠️ Known Limitations

- **Java codec is standalone.** Ghidra builds its own `LocalManagedBufferFile` and has no hook to replace it, so installing the extension does not compress Ghidra projects.
- **PDB export is experimental.** It has no GSI hash stream, so MSVC/LLVM tools may not load it. DWARF export is the supported path.
- **SMT verifier is sound but incomplete.** It returns `UNKNOWN`, never "equivalent", for floats, calls, unhandled P-code and loops beyond the unroll limit.
- **ARM64 lifter covers an integer subset.** Atomics and unsupported encodings lift as `UNIMPLEMENTED`.
- **Neural and Colab output needs a real LLM endpoint.** Without one, the neural stage returns neutral heuristic names labelled `heuristic-fallback`, and the Colab pipeline reports `not_implemented` stages.
- **Emulator `pid` access is trust-based.** The caller must declare the device serial for a `pid`; the binding can't be auto-verified.
- **Benchmarks depend on the machine.** Numbers vary with hardware; storage numbers use synthetic pages.
- **The MCP server must be restarted (and agy's schema cache refreshed) after code changes.** A stale server process re-caches old schemas.
