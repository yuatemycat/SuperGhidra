# SuperGhidra Agent Progressive Discovery Router (`AGENTS.md`)

> **Token Budget Protocol (< 1,500 Tokens):** Do **NOT** read the entire repository. Follow the 3-step progressive discovery workflow below to bound context usage.

## 1. Mandatory Graph-First Discovery Protocol (`code-review-graph`)
Before reading raw `.py` files, query the structural AST graph via `code-review-graph` MCP tools:
1. **`get_minimal_context_tool(task="<your goal>")`** — Entry point; returns compact task-scoped context.
2. **`semantic_search_nodes_tool(query="<symbol or concept>")`** — Locate exact classes, functions, or types across domains.
3. **`get_impact_radius_tool(target="<file_or_symbol>")`** — Inspect blast radius before modifying shared interfaces.
4. Read **only** the target domain's `superghidra/<domain>/README.md`, then view specific line ranges of the target file.

---

## 2. Bounded 7-Domain System Map

```
SuperGhidra/
├── superghidra/                  # Canonical Python package
│   ├── core/                     # Daemon, Oracle, Resource Governor, SHM IPC, Cache DAG, Headless, Parity Engine (Gaps 1-7 & Sparse Datalog VSA)
│   ├── storage/                  # LZ4/Zstd 16 KB Codec, 64-bit Slot Directory, Java BufferFile Extension Packager
│   ├── acceleration/             # WGPU/CUDA/SIMD ARM64 ADRP Scanner, Parallel Function Seeder
│   ├── diff/                     # Batched Cosine CFG Diff Engine, Struct Shift Migrator, CRDT Swarms, Next-Gen Leapfrog Engine
│   ├── lifters/                  # Zero-JVM ARM64/x86_64 P-Code Lifter, Z3 SMT Verifier, E-Graph MBA Simplifier, MLIR Goto-Free Restructurer
│   ├── formats/                  # Multi-Arch Binary Loader, DWARF/PDB Pre-indexer, Symbol Exporters, MSVC/MFC CArchive
│   └── integrations/             # APK JNI Cross-Referencer, Emulator Memory Sidecar, Colab Orchestrator, Neural Pipeline
├── tests/<domain>/               # Domain-isolated Pytest suites (527 tests, 45 subtests across 34 test files)
├── templates/                    # Standard scaffolds for modules, MCP tools, tests, docs, and agent briefs
├── docs/{benchmarks,specs}/      # Empirical benchmark reports, gap analysis, and architectural specifications
└── *.py                          # Zero-overhead root backward-compatibility shims (for pyghidra-mcp & external callers)
```

---

## 3. Agent Decision Matrix

| If your task is... | Only read Subsystem Index | And inspect Canonical Files | Domain Verification Command |
| :--- | :--- | :--- | :--- |
| **Daemon, TCP Oracle, L2 Cache, Resource Governor, SHM IPC, Cache DAG, or Parity Engine (Gaps 1-7, __usercall, Appcall, Sparse Datalog VSA, Section 5 Mitigations M1-M7)** | [`superghidra/core/README.md`](superghidra/core/README.md) | `superghidra/core/ghidra_oracle.py`<br>`superghidra/core/resource_governor.py`<br>`superghidra/core/shm_decompiler_bridge.py`<br>`superghidra/core/parity_engine.py`<br>`superghidra/core/mitigation_roadmap_engine.py` | `python -m pytest tests/core -q` |
| **Headless Tuning, Cascade Shield, or Native C++ Decompiler PGO** | [`superghidra/core/README.md`](superghidra/core/README.md) | `superghidra/core/headless_analyzer_tuner.py`<br>`superghidra/core/cross_platform_headless_harness.py`<br>`superghidra/core/native_decompiler_pgo_builder.py` | `python -m pytest tests/core tests/storage -q` |
| **LZ4/Zstd Buffer Compression, 64-bit Slot Directory, or `SuperGhidraCodec.jar`** | [`superghidra/storage/README.md`](superghidra/storage/README.md) | `superghidra/storage/storage_compression_prototype.py`<br>`superghidra/storage/ghidra_extension_packager.py`<br>`ghidra_extension_skeleton/` | `python -m pytest tests/storage -q` |
| **GPU ARM64 `ADRP+ADD/LDR` Sweeps or Function Prologue Seeding** | [`superghidra/acceleration/README.md`](superghidra/acceleration/README.md) | `superghidra/acceleration/gpu_adrp_scanner.py`<br>`superghidra/acceleration/gpu_function_seeder.py` | `python -m pytest tests/acceleration -q` |
| **Cross-Version Binary Diffing, Struct Shift Migration, CRDT Swarms, Whole-Binary Type Lattice, Next-Gen Benchmark Scorecard, or Phase 1 & 2 Kill-Shots 1-5 (Patchestry MLIR, Rellic Goto-Free, D-LiFT GRPO, CSR VSA, Template Collapser, Concolic Trace)** | [`superghidra/diff/README.md`](superghidra/diff/README.md) | `superghidra/diff/binary_diff_engine.py`<br>`superghidra/diff/struct_shift_migrator.py`<br>`superghidra/diff/benchmark_and_nextgen_engine.py`<br>`superghidra/diff/phase1_phase2_roadmap_engine.py` | `python -m pytest tests/diff -q` |
| **Zero-JVM P-Code Lifting, Z3 SMT Verification, ARM/Thumb/x86 Decoding, or E-Graph MBA & MLIR Goto-Free Restructuring** | [`superghidra/lifters/README.md`](superghidra/lifters/README.md) | `superghidra/lifters/pcode_lifter_bridge.py`<br>`superghidra/lifters/smt_pcode_verifier.py`<br>`superghidra/lifters/egraph_mlir_pipeline.py` | `python -m pytest tests/lifters -q` |
| **ELF/PE/Mach-O Loading, DWARF5/PDB Indexing/Export, or MSVC RTTI & MFC `CArchive`** | [`superghidra/formats/README.md`](superghidra/formats/README.md) | `superghidra/formats/binary_loader.py`<br>`superghidra/formats/dwarf_pdb_preindexer.py`<br>`superghidra/formats/synthetic_symbol_exporter.py`<br>`superghidra/formats/msvc_class_recovery.py`<br>`superghidra/formats/serialize_trace.py`<br>`superghidra/formats/mfc_archive.py` | `python -m pytest tests/formats -q` |
| **APK JNI Cross-Ref, Android Emulator Sidecar, Colab TPU/T4, Neural Skinning, or D-LiFT Z3 Neural Verification Backend & GRPO Engine** | [`superghidra/integrations/README.md`](superghidra/integrations/README.md) | `superghidra/integrations/apk_jni_cross_referencer.py`<br>`superghidra/integrations/emulator_memory_sidecar.py`<br>`superghidra/integrations/colab_cloud_orchestrator.py`<br>`superghidra/integrations/neural_decompiler_pipeline.py`<br>`superghidra/integrations/d_lift_verifier.py` | `python -m pytest tests/integrations -q` |
| **Adding a New Module, MCP Tool, Test Suite, or Agent Sub-Task** | [`templates/`](templates/) | `templates/NEW_MODULE_TEMPLATE.py`<br>`templates/NEW_MCP_TOOL_TEMPLATE.py`<br>`templates/TEST_CASE_TEMPLATE.py`<br>`templates/AGENT_TASK_BRIEF_TEMPLATE.md` | `python -m pytest tests/integrations/test_mcp_38_tools.py -q` |

---

## 4. Critical Architectural Invariants (Never Violate)
1. **Non-Breaking Root Shims:** External consumers (the sibling checkout `../pyghidra-mcp/src/pyghidra_mcp/mcp_tools.py`) import top-level module names (`import gpu_adrp_scanner`, `import binary_loader`, `import msvc_class_recovery`, etc.). Every module in `superghidra/<domain>/<mod>.py` **must** retain its root `<mod>.py` `sys.modules` alias shim.
2. **Read-Only Ghidra Database Safety:** `ghidra_oracle.py` opens `.rep` projects with `readOnly=True`; symbol renames/comments go to `WriteOverlay` (`ghidra_overlay.json`) and `.ghidra-delta.jsonl`. Never auto-delete fresh `.lock` files.
3. **EvidenceLedger Gate:** No neural or automated symbol/struct commit may bypass `ReconstructionObligationLedger` verification (`VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`).
4. **Android Emulator Fleet Guard:** `EmulatorFleetGuard` strictly blocks protected farm devices (`emulator-5564` / `127.0.0.1:5565`, `MEmu_0` / `127.0.0.1:21503`) and denies unknown serials by default.
5. **SMT Soundness:** Unhandled instructions, floating-point operations, and loops exceeding the unroll bound must return `UNKNOWN` (`equivalent=False`), never false `UNSAT`.
6. **GitHub visibility split:** This repository has two remotes and the visibility of each is fixed.
   - `origin` is `https://github.com/yuatemycat/SuperGhidra`. It stays **public**. This is the profile the repo is published under.
   - `private` is `https://github.com/52191314/SuperGhidra`. It stays **private**.
   - Never make `52191314/SuperGhidra` public. Never make `yuatemycat/SuperGhidra` private. Never drop either remote.
   - A push of the same commits may go to both remotes. Visibility stays as above. `gh auth switch --user yuatemycat` before pushing `origin`. `gh auth switch --user 52191314` before pushing `private`. Switch the active `gh` account back to `52191314` when the push is done.
