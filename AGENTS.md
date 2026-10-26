# SuperGhidra Agent Progressive Discovery Router (`AGENTS.md`)

> **Token Budget Protocol (< 1,500 Tokens):** Do **NOT** read the entire repository. Follow the 3-step progressive discovery workflow below to bound context usage.

## 1. Mandatory Graph-First Discovery Protocol (`code-review-graph`)
Before reading raw `.py` files, query the structural AST graph via `code-review-graph` MCP tools:
1. **`get_minimal_context_tool(task="<your goal>")`** — Entry point; returns compact task-scoped context.
2. **`semantic_search_nodes_tool(query="<symbol or concept>")`** — Locate exact classes, functions, or types across domains.
3. **`get_impact_radius_tool(target="<file_or_symbol>")`** — Inspect blast radius before modifying shared interfaces.
4. Read **only** the target domain's `src/superghidra/<domain>/README.md`, then view specific line ranges of the target file.

---

## 2. Bounded 7-Domain System Map

```
SuperGhidra/
├── src/superghidra/                  # Canonical Python package
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
| **Daemon, TCP Oracle, L2 Cache, Resource Governor, SHM IPC, Cache DAG, or Parity Engine (Gaps 1-7, __usercall, Appcall, Sparse Datalog VSA, Section 5 Mitigations M1-M7)** | [`src/superghidra/core/README.md`](src/superghidra/core/README.md) | `src/superghidra/core/ghidra_oracle.py`<br>`src/superghidra/core/resource_governor.py`<br>`src/superghidra/core/shm_decompiler_bridge.py`<br>`src/superghidra/core/parity_engine.py`<br>`src/superghidra/core/mitigation_roadmap_engine.py` | `python -m pytest tests/core -q` |
| **Headless Tuning, Cascade Shield, or Native C++ Decompiler PGO** | [`src/superghidra/core/README.md`](src/superghidra/core/README.md) | `src/superghidra/core/headless_analyzer_tuner.py`<br>`src/superghidra/core/cross_platform_headless_harness.py`<br>`src/superghidra/core/native_decompiler_pgo_builder.py` | `python -m pytest tests/core tests/storage -q` |
| **LZ4/Zstd Buffer Compression, 64-bit Slot Directory, or `SuperGhidraCodec.jar`** | [`src/superghidra/storage/README.md`](src/superghidra/storage/README.md) | `src/superghidra/storage/storage_compression_prototype.py`<br>`src/superghidra/storage/ghidra_extension_packager.py`<br>`ghidra_extension_skeleton/` | `python -m pytest tests/storage -q` |
| **GPU ARM64 `ADRP+ADD/LDR` Sweeps or Function Prologue Seeding** | [`src/superghidra/acceleration/README.md`](src/superghidra/acceleration/README.md) | `src/superghidra/acceleration/gpu_adrp_scanner.py`<br>`src/superghidra/acceleration/gpu_function_seeder.py` | `python -m pytest tests/acceleration -q` |
| **Cross-Version Binary Diffing, Struct Shift Migration, CRDT Swarms, Whole-Binary Type Lattice, Next-Gen Benchmark Scorecard, or Phase 1 & 2 Kill-Shots 1-5 (Patchestry MLIR, Rellic Goto-Free, D-LiFT GRPO, CSR VSA, Template Collapser, Concolic Trace)** | [`src/superghidra/diff/README.md`](src/superghidra/diff/README.md) | `src/superghidra/diff/binary_diff_engine.py`<br>`src/superghidra/diff/struct_shift_migrator.py`<br>`src/superghidra/diff/benchmark_and_nextgen_engine.py`<br>`src/superghidra/diff/phase1_phase2_roadmap_engine.py` | `python -m pytest tests/diff -q` |
| **Zero-JVM P-Code Lifting, Z3 SMT Verification, ARM/Thumb/x86 Decoding, or E-Graph MBA & MLIR Goto-Free Restructuring** | [`src/superghidra/lifters/README.md`](src/superghidra/lifters/README.md) | `src/superghidra/lifters/pcode_lifter_bridge.py`<br>`src/superghidra/lifters/smt_pcode_verifier.py`<br>`src/superghidra/lifters/egraph_mlir_pipeline.py` | `python -m pytest tests/lifters -q` |
| **ELF/PE/Mach-O Loading, DWARF5/PDB Indexing/Export, or MSVC RTTI & MFC `CArchive`** | [`src/superghidra/formats/README.md`](src/superghidra/formats/README.md) | `src/superghidra/formats/binary_loader.py`<br>`src/superghidra/formats/dwarf_pdb_preindexer.py`<br>`src/superghidra/formats/synthetic_symbol_exporter.py`<br>`src/superghidra/formats/msvc_class_recovery.py`<br>`src/superghidra/formats/serialize_trace.py`<br>`src/superghidra/formats/mfc_archive.py` | `python -m pytest tests/formats -q` |
| **APK JNI Cross-Ref, Android Emulator Sidecar, Colab TPU/T4, Neural Skinning, or D-LiFT Z3 Neural Verification Backend & GRPO Engine** | [`src/superghidra/integrations/README.md`](src/superghidra/integrations/README.md) | `src/superghidra/integrations/apk_jni_cross_referencer.py`<br>`src/superghidra/integrations/emulator_memory_sidecar.py`<br>`src/superghidra/integrations/colab_cloud_orchestrator.py`<br>`src/superghidra/integrations/neural_decompiler_pipeline.py`<br>`src/superghidra/integrations/d_lift_verifier.py` | `python -m pytest tests/integrations -q` |
| **Adding a New Module, MCP Tool, Test Suite, or Agent Sub-Task** | [`templates/`](templates/) | `templates/NEW_MODULE_TEMPLATE.py`<br>`templates/NEW_MCP_TOOL_TEMPLATE.py`<br>`templates/TEST_CASE_TEMPLATE.py`<br>`templates/AGENT_TASK_BRIEF_TEMPLATE.md` | `python -m pytest tests/integrations/test_mcp_38_tools.py -q` |

---

## 4. Critical Architectural Invariants (Never Violate)
1. **Canonical Package Imports:** All internal and consumer imports use canonical package paths (`from superghidra.<domain>.<mod> import ...` or `superghidra.compat.<mod>`). Loose root `.py` shims have been retired in v0.4.0.
2. **Read-Only Ghidra Database Safety:** `ghidra_oracle.py` opens `.rep` projects with `readOnly=True`; symbol renames/comments go to `WriteOverlay` (`ghidra_overlay.json`) and `.ghidra-delta.jsonl`. Never auto-delete fresh `.lock` files.
3. **EvidenceLedger Gate:** No neural or automated symbol/struct commit may bypass `ReconstructionObligationLedger` verification (`VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`).
4. **Android Emulator Fleet Guard:** `EmulatorFleetGuard` strictly blocks protected devices (`emulator-5564` / `127.0.0.1:5565`, `MEmu_0` / `127.0.0.1:21503`) and denies unknown serials by default.
5. **SMT Soundness:** Unhandled instructions, floating-point operations, and loops exceeding the unroll bound must return `UNKNOWN` (`equivalent=False`), never false `UNSAT`.
6. **No placeholder results.** When a tool cannot produce a result from its input, it raises or exits non-zero. It never returns output that looks real but was not derived from the input. Enforced by the stub canary and the lifter provenance check.
---

## 5. Writing Style: Sound Like a Maintainer, Not a Brochure
Applies to everything a person will read: `README.md`, `CONTRIBUTING.md`, `ARCHITECTURE.md`, domain READMEs, `docs/`, docstrings, code comments, commit messages and PR text. The root `README.md` is the reference for tone. The routing tables in this file are lookup material and may stay terse.
1. **Plain and specific.** Write the way a maintainer would explain the code to a colleague: short sentences, concrete nouns, say what the code does and what it does not do.
2. **Numbers carry their context.** Give the figure, what it was measured on, and the caveat (`synthetic pages, not real projects`; `one Windows dev machine`). Never state a result that was not measured, and ensure published numbers come from a committed summary file through a render script.
3. **No hype or codenames in prose.** Avoid `seamless`, `robust`, `cutting-edge`, `state-of-the-art`, `blazing`, `game-changing`, `Next-Gen`, `Kill-Shot`, `zero-overhead`. Say what the thing does. Internal codenames may appear in identifiers, never as the way a feature is introduced.
4. **No filler.** No emoji headings, no bold on every noun, no "Thank you for your interest", no closing paragraph that restates the section, no reflexive three-item lists or "not just X, but Y".
5. **Commit messages:** conventional prefix (`feat(core):`), imperative mood, the *why* in the body when it is not obvious. Skip "This commit...".
6. **Facts are untouchable.** Rewording must not change an identifier, number, path, link, invariant or command. If a claim cannot be verified from the code or a benchmark report, cut it or mark it as unverified.
7. **Check before pushing prose:** `rg -i "seamless|robust|cutting-edge|state-of-the-art|blazing|game-chang|next-gen|kill-shot" README.md CONTRIBUTING.md ARCHITECTURE.md docs superghidra` should return nothing outside quoted identifiers.
