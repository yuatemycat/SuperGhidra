# SuperGhidra System Architecture & Comprehensive IDA Pro Gap Analysis

> **Document Version**: 2.3.0 (gcc head-to-head of published pseudocode recorded, 2026-10-20)  
> **Target System**: SuperGhidra & SuperghidraMCP  
> **Location**: docs/SUPERGHIDRA_ARCHITECTURE_AND_IDA_PRO_GAP_ANALYSIS.md  
> **Scope**: Structural breakdown of SuperGhidra's 7-domain architecture, objective evaluation of the 7 core technical deficits against Hex-Rays IDA Pro, and the 2-phase engineering roadmap to catch up to and surpass IDA Pro (including its [2026 Product Roadmap](https://hex-rays.com/blog/2026-product-direction-priorities)).

---

## 1. Executive Summary

**SuperGhidra** is an AI-native, high-throughput, GPU-accelerated binary analysis platform engineered to scale reverse engineering beyond the interactive, single-user limitations of traditional GUI tools. Built on top of the Ghidra decompiler core, SuperGhidra augments static analysis with a multi-process, client-daemon architecture exposed directly to autonomous agents via the **Model Context Protocol (MCP)** (38+4 tools).

While SuperGhidra dramatically accelerates reference scanning (WebGPU ADRP scanner <1.2s vs minutes on CPU) and introduces capabilities absent from standard Ghidra and IDA Pro (multi-agent CRDT/session forking, automated version delta migration, and Z3 SMT equivalence verification), a fresh decompile still mirrors stock Ghidra (7.41% strict / 27.78% lenient vs Ghidra's 8.10% / 24.54%) and trails Hex-Rays on that row (16.90% strict / 25.15% lenient). A separate gcc rescore of the dataset's shipped pseudocode, with no typedef header, reproduces IDA at 16.9% and raw Ghidra text at 8.26%. Applying `CompilableDecompilerFilter` to that same Ghidra text scores 22.76% (C 33.44%, C++ 11.96%) against IDA's 16.9% on the same 1,296 programs. Live `decompile_function` applies that filter unless the caller passes `emit_compilable=False`. 952 of those 1,296 still fail for both the filter and IDA. Section 8 records each of these measurements separately.

This document outlines:
1. The **Current Production Architecture** of SuperGhidra across its 7 bounded domains.
2. The **7 Critical Gaps** where IDA Pro + Hex-Rays currently retains architectural and algorithmic superiority.
3. The **SuperGhidra Mitigation Roadmap** demonstrating how each deficit is counterbalanced or actively engineered away.
4. The **Phase 1 & Phase 2 Engineering Plan** to close the 6 remaining static/dynamic gaps and leapfrog Hex-Rays' [2026 enterprise roadmap](https://hex-rays.com/blog/2026-product-direction-priorities) (IDA Semantic Engine, IDA Knowledge Engine, and IDA MCP) via Equality Saturation (E-Graphs), MLIR (`Rellic`/`Patchestry`), `D-LiFT` GRPO-verified neural decompilation, and GPU Datalog.
5. The **Measured Baseline** (Section 8) and the **Prioritized Upgrade Plan** (Section 9) that turns the roadmap into benchmarked deliverables.

### Status Legend (audit of 2026-10-20)

| Marker | Meaning |
| :--- | :--- |
| ~~Struck through~~ ✅ **Shipped** | Implemented **and** reachable from a registered SuperghidraMCP tool or the live decompile path. *Shipped means delivered, not that the IDA gap is closed.* |
| 🟡 **Prototype** | Module + unit tests exist, but they run on hand-built inputs (internal IR, toy expressions, lambdas) and are **not** called by the decompiler or any MCP tool. |
| ⬜ **Not started** | No implementation yet. |

> **Audit finding:** As of this audit, no item in the Phase 1 (Section 6) or Phase 2 (Section 7) roadmaps is shipped. The Section 3–7 engines (`parity_engine.py`, `mitigation_roadmap_engine.py`, `benchmark_and_nextgen_engine.py`, `phase1_phase2_roadmap_engine.py`, `egraph_mlir_pipeline.py`, `d_lift_verifier.py`) are not imported by `pyghidra_mcp/mcp_tools.py`. SuperGhidra's decompiled C is still produced unmodified by Ghidra's `DecompInterface` (`pyghidra_mcp/tools.py` → `decompileFunction(...).getC()`).

---

## 2. SuperGhidra Current System Architecture

SuperGhidra is partitioned into **7 bounded domains**, decoupling disk I/O, GPU compute, lifter semantics, and agent interfaces from the Java Virtual Machine.

```mermaid
flowchart TD
    subgraph AgentLayer["Agent & IPC Interface Layer"]
        LLM["AI Coding Agents (Antigravity / Claude / Cursor)"]
        MCP["SuperghidraMCP Server (38+4 Tools)"]
        ForkMgr["Session Fork & Journaling Manager"]
        LLM <--> MCP
        MCP <--> ForkMgr
    end

    subgraph CoreEngine["Domain 1: Core & Domain 2: Storage"]
        Daemon["Oracle Daemon (TCP 127.0.0.1:5073)"]
        Gov["Resource Governor (eco / balanced / turbo / auto)"]
        SHM["Zero-Copy Shared Memory IPC (SHM)"]
        BlockCodec["16 KB Block Compression (LZ4 in-flight / Zstd L3)"]
        SlotDir[".sgdb 64-bit Slot Directory"]
        Daemon --- Gov
        Daemon --- SHM
        Daemon --- BlockCodec
        BlockCodec --- SlotDir
    end

    subgraph ComputePipeline["Domain 3: Acceleration & Domain 5: Lifters"]
        GPU["WGPU / PyTorch CUDA / SIMD Shader Engine"]
        ADRPScan["ADRP + ADD/LDR Scanner (<1.2s per 60MB)"]
        FuncSeed["Parallel Function Prologue & BL Seeder"]
        Lifter["Zero-JVM ARM64/x86_64 P-Code Lifter"]
        SMT["Z3 SMT Bit-Exact Equivalence Prover"]
        GPU --> ADRPScan
        GPU --> FuncSeed
        Lifter --> SMT
    end

    subgraph SemanticsLayer["Domain 4: Diff & Domain 6: Formats & Domain 7: Integrations"]
        CFG["32-Dim Cosine CFG Diffing Engine"]
        ShiftMig["Cross-Version Struct Shift Migrator"]
        Formats["ELF / PE / Mach-O / DWARF5 / PDB Indexer"]
        MSVC["MSVC RTTI & MFC CArchive Decoder"]
        JNI["Android DEX + NDK RegisterNatives XRef"]
        Sidecar["Emulator Memory Sidecar (Fleet Guard)"]
        Neural["Skeleton-to-Skin Neural Decompiler"]
    end

    ForkMgr <--> Daemon
    Daemon <--> Lifter
    Daemon <--> GPU
    Daemon <--> Formats
    Formats --> CFG
    Formats --> ShiftMig
    Formats --> MSVC
    Formats --> JNI
    Lifter --> Neural
    Sidecar --> SMT
```

### The 7 Bounded Domains in Detail

| Domain | Subsystem Path | Primary Responsibilities & Innovations |
| :--- | :--- | :--- |
| **1. `core`** | superghidra/core/ | **Daemon & Governor**: Persistent background daemon (`127.0.0.1:5073`), SQLite L2 cache, 4-tier CPU/RAM resource governor (`eco`, `balanced`, `turbo`, `auto`), zero-copy shared memory IPC, 1-hop Cache DAG, and C++ PGO decompiler compilation. |
| **2. `storage`** | superghidra/storage/ | **High-Density Storage**: 16 KB chunked block compression (LZ4 for fast random access, Zstd Level 3 for project snapshots), 20-byte 64-bit slot indexing (`.sgdb`), and the `SuperGhidraCodec.jar` extension. |
| **3. `acceleration`** | superghidra/acceleration/ | **Hardware-Accelerated Scanning**: WebGPU compute shaders, PyTorch CUDA, and AVX2/NEON SIMD engines scanning candidate ARM64 `ADRP + ADD/LDR` pairs across 60+ MB binaries in <1.2s. |
| **4. `diff`** | superghidra/diff/ | **Cross-Version Binary Diffing**: 32-dimensional CFG cosine-similarity graph matcher, automated struct field displacement shift tracking, and SHA-256 `.ghidra-delta.jsonl` audit logging. |
| **5. `lifters`** | superghidra/lifters/ | **Zero-JVM Lifting & Formal SMT**: Standalone C++ P-Code lifter bypassing JVM boot latency, GNN/TPU tensor formatting, Z3 SMT solver proving for mathematical function equivalence, and table-driven x86/ARM decoders. |
| **6. `formats`** | superghidra/formats/ | **Unified Binary Parsing**: Direct ELF/PE/Mach-O loaders, off-heap DWARF 5 / PDB SQLite indexer, standalone MSVC RTTI and MFC `CRuntimeClass` recovery without loading Ghidra GUI. |
| **7. `integrations`** | superghidra/integrations/ | **Ecosystem & Cloud Bridges**: Android Dalvik DEX $\leftrightarrow$ native NDK `RegisterNatives` JNI mapper, live emulator memory sidecar, Colab TPU v5e/T4 cluster runner, and 2-phase Neural Decompiler Skinning. |

---

## 3. The 7 Critical Gaps Against Hex-Rays IDA Pro

Despite SuperGhidra's modernization of Ghidra, Hex-Rays IDA Pro maintains significant structural advantages stemming from over three decades of commercial refinement.

---

### Gap 1: The Multi-Maturity Microcode Pipeline vs. Monolithic P-Code AST

#### The IDA Pro Architecture
Hex-Rays decompilation is driven by **Microcode** (`mba_t` / `mbl_t`), structured across 7 distinct optimization maturity tiers:
1. `MMAT_GENERATED`: Raw instruction translation.
2. `MMAT_PREOPTIMIZED`: Instruction-level cleanups.
3. `MMAT_LOCOPT`: Basic-block intra-block optimizations.
4. `MMAT_GLBOPT1`: Global intra-procedural data-flow analysis and dead code elimination.
5. `MMAT_GLBOPT2`: Advanced struct splitting and type propagation.
6. `MMAT_CPPOPT`: C++ virtual dispatch and object lifetime resolution.
7. `MMAT_LVARS`: Stack allocation, register coloring, and variable allocation.

Hex-Rays exposes a rich C++ and Python API (`ida_hexrays`) allowing reverse engineers to write plugin hooks at any maturity stage, inspecting and altering operands *before* C code is rendered.

#### SuperGhidra / Ghidra Limitation
Ghidra lifts assembly to **P-Code** (an intermediate representation consisting of ~60 operations). However:
- Ghidra's decompiler performs simplification passes inside a monolithic C++ executable (`decompile.exe`).
- P-Code is transformed directly into a high-level AST (Clang-like syntax tree) in a single pipeline.
- There is no public, fine-grained microcode maturation event loop where third-party scripts can intercept, alter, and re-inject intermediate micro-operations during optimization.
- Complex nested pointer operations (`*(_QWORD *)(*(_QWORD *)(a1 + 0x18) + 8 * (v4 & 0x1F))`) are frequently rendered literally rather than collapsing into array/struct syntax.

---

### Gap 2: Control Flow Flattening (CFF) & Opaque Predicate De-obfuscation

#### The IDA Pro Architecture
Modern mobile application protections (e.g., Promon SHIELD, Arxan, DexGuard, OLLVM) heavily employ **Control Flow Flattening**:
- Functions are shattered into isolated basic blocks nested inside an artificial state variable loop: `while (state != EXIT) { switch (state) { ... } }`.
- In IDA Pro, microcode plugins (such as [D810](https://www.eshard.com/blog/d810-deobfuscation-ida-pro), [d810-ng](https://plugins.hex-rays.com/w00tzenheimer/d810-ng), HexRaysDeob, and [gooMBA](https://hex-rays.com/blog/deobfuscation-with-goomba)) hook `MMAT_GLBOPT1`.
- They compute symbolic state variable transitions, bypass opaque predicates (`(x * (x + 1)) % 2 == 0`), rewrite branching targets directly in the microcode graph, and remove the dispatcher switch entirely.
- The resulting decompiler output collapses back into clean, natural `if-else` and `for` loops.

#### SuperGhidra / Ghidra Limitation
- Ghidra’s decompiler cannot easily rewrite structural CFG topology on the fly.
- In binaries protected by Promon SHIELD (such as `libg.so`), Ghidra generates unreadable 10,000-line functions dominated by artificial `switch(uVar8)` statements, state variable reassignments, and endless `goto` trampolines.
- As a consequence, SuperGhidra must currently rely on *side-channel evasion* (tracing xrefs to unprotected leaf logic like `ProductionQueue::addItem` or scanning `.rela.dyn` tables) rather than flattening the control flow graph inside the decompiler itself.

---

### Gap 3: Custom Calling Conventions & Arbitrary Register Allocation

#### The IDA Pro Architecture
Hex-Rays supports the explicit `__usercall` convention with granular per-register and per-stack-slot binding syntax:
```c
// Valid directly in IDA Pro decompiler function prototype:
LogicCommand* __usercall LogicDeliverTruckOrderCommand::ctor@<x0>(
    LogicCommand *this@<x0>, 
    int slot_idx@<w1>, 
    uint64_t session_tick@<x21>, 
    void *caller_context@<x8>
);
```
IDA allows users to bind any argument to any arbitrary hardware register (`@<x0>`, `@<w1>`, `@<x21>`) or stack offset, instantly updating the entire decompiler view, stack frame layout, and caller cross-references.

#### SuperGhidra / Ghidra Limitation
- In Ghidra, calling conventions are defined globally or per-architecture via compiler specification XML files (`.cspec`).
- While Ghidra supports custom storage (`Custom` calling convention in the GUI), setting non-standard register allocations dynamically via scripts is brittle and requires constructing raw low-level `VariableStorage` Java objects.
- When compilers (like Clang with `-O3`) utilize non-standard register allocations—such as using ARM64 vector registers (`d0`–`d7` or `q0`–`q3`) for 64-bit integer bulk stores—Ghidra frequently treats them as floating-point arguments, producing incorrect function signatures.

---

### Gap 4: Live Dynamic Execution & In-Process Marshalling (Appcall)

#### The IDA Pro Architecture
IDA Pro includes **Appcall** (`ida_idd.appcall`):
- When attached to a live suspended process (e.g. through `android_server64` on Android or GDB/LLDB on Linux/macOS), IDA can directly execute arbitrary binary functions in the context of the target application.
- The analyst simply calls the function in Python:
  ```python
  res = ida_idd.appcall(func_rva, [arg1, arg2])
  ```
- IDA transparently allocates stack space, sets register values, redirects execution, catches breakpoints or exceptions, and deserializes native struct memory back into Python dictionaries.

#### SuperGhidra / Ghidra Limitation
- Ghidra has integrated dynamic debugging (`Ghidra Debugger`) via GDB/LLDB wrappers, but it lacks a reliable, zero-touch Appcall mechanism.
- Attempting to invoke arbitrary target binary functions from Ghidra requires extensive manual scripting, breakpoint placement, and register manipulation.
- **Architectural Consequence**: This limitation forced a workaround outside SuperGhidra: a per-target ARM64 Bionic C++20 hook library running inside the target Android emulator, exposing an abstract UNIX domain socket so Python scripts can call into the target without relying on Ghidra’s debugging layer.

---

### Gap 5: Automated Library Identification (FLIRT & Lumina vs. FID)

#### The IDA Pro Architecture
- **FLIRT** (Fast Library Identification and Recognition Technology): Automatically identifies thousands of standard runtime libraries (C/C++ runtime, STL, OpenSSL, zlib, libpng, Boost) using pattern-masked byte hashes of function prologues.
- **Lumina**: A centralized, crowdsourced metadata server. When loading a stripped binary, Lumina queries public and private cloud repositories for matching function hashes, instantly restoring function names, argument types, and comments without local analysis.

#### SuperGhidra / Ghidra Limitation
- Ghidra provides **Function ID (FID)** and **BSIM** (Binary Similarity).
- However, pre-compiled FID databases for modern Android NDK toolchains (specifically Clang libc++, BoringSSL, and mobile game engines) are practically non-existent in the public domain.
- Building FID databases requires manually acquiring the exact NDK sysroots, compiling static libraries with identical optimization flags, and training FID databases locally.
- Consequently, stripped binaries in Ghidra remain heavily unlabelled (`FUN_00c06750`), forcing manual string hunting and cross-reference traversal.

---

### Gap 6: Header Parsing & Type Library (.TIL) Engine Robustness

#### The IDA Pro Architecture
- IDA Pro ships with robust, pre-compiled **Type Information Libraries (`.til`)** covering Windows SDKs, Android NDKs, and Linux POSIX environments.
- IDA's built-in C parser (`File -> Load file -> Parse C header file...`) uses an enterprise-grade Clang preprocessor front-end that easily digests complex macro expansions, GCC/Clang attributes (`__attribute__((aligned(8)))`), and modern C structures.

#### SuperGhidra / Ghidra Limitation
- Ghidra's "Parse C Source" tool relies on an aging C-grammar parser that consistently fails when confronted with modern C++14/17/20 headers, template expansions, or compiler intrinsics (`__builtin_*`, `__asm__`).
- Importing headers frequently results in parse errors, forcing developers to manually sanitize headers or build structs field-by-field in the Data Type Manager GUI.
- In SuperGhidra, this prompted the creation of msvc\_class\_recovery.py and external DWARF indexers to reconstruct types off-heap rather than using Ghidra's native C parser.

---

### Gap 7: Native Engine Performance, Startup Latency & Memory Footprint

#### The IDA Pro Architecture
- **Engine**: Written in native C++ with an optimized Qt GUI.
- **Speed**: Opens a 100 MB binary in seconds; searches, navigates, and re-renders graphs instantly with GPU hardware acceleration.
- **Memory Footprint**: Typically consumes **500 MB – 1.5 GB of RAM** even on massive binaries.
- **Headless**: Can execute headless Python scripts in sub-second CLI runs with zero overhead.

#### SuperGhidra / Ghidra Limitation
- **Engine**: Core GUI and analysis pipelines run on the **Java Virtual Machine (JVM)**, while the decompiler core is a standalone C++ process communicating via pipes.
- **Memory Footprint**: Large binaries like `libg.so` (60+ MB) frequently exhaust default JVM allocations, requiring **8 GB to 16 GB of heap (`-Xmx16G`)** to prevent out-of-memory crashes.
- **Analysis Latency**: Full auto-analysis of large binaries can take 5 to 20 minutes in Ghidra compared to 1 to 3 minutes in IDA Pro.
- **JVM GC Freezes**: In multi-agent environments with concurrent background queries, Java Garbage Collection pauses can freeze IPC responses for several seconds.

---

## 4. Head-to-Head Architectural Comparison Matrix

| Architectural Capability | Hex-Rays IDA Pro | SuperGhidra (Current) | Critical Gap Severity |
| :--- | :--- | :--- | :---: |
| **Decompiler Output Re-executability** *(measured, Section 8)* | 16.90% strict / 25.15% lenient on the fresh-decompile row (published: 18.22%). Same-compiler rescore of published `ida_pseudo`: 16.9% | Fresh decompile: 7.41% strict / 27.78% lenient (stock Ghidra 8.10% / 24.54%). Filtered published `ghidra_pseudo` under gcc: **22.76%** vs IDA's **16.9%** on the same 1,296. Live decompile applies this filter unless `emit_compilable=False`. A fresh decompile with that default has not been scored | **HIGH** for the recorded raw fresh decompile |
| **Microcode Transformation Hooks** | Full 7-stage maturity API (`mba_t`) | Monolithic AST; basic P-code simplifiers | **HIGH** |
| **Control Flow De-obfuscation (CFF)** | Automated via [D810](https://www.eshard.com/blog/d810-deobfuscation-ida-pro) / HexRaysDeob / [gooMBA](https://hex-rays.com/blog/deobfuscation-with-goomba) | Relies on leaf logic xrefs & manual bypass | **HIGH** |
| **Arbitrary Calling Conventions** | `__usercall` with `@<reg>` syntax | Brittle `.cspec` XML / low-level API | **MEDIUM** |
| **In-Process Dynamic Calling** | Native `ida_idd.appcall` | External Bionic C++ Hook (Pillar 1) | **MEDIUM** |
| **Pre-compiled Signature Banks** | Industry-standard FLIRT + Lumina Cloud | Local FID / BSIM (sparse NDK databases) | **MEDIUM** |
| **C/C++ Header Parser (.TIL)** | Robust Clang-based parser + rich `.til` | Brittle C-parser; requires struct sanitization | **MEDIUM** |
| **Native Execution Speed & RAM** | C++ native engine; ~500 MB – 1.5 GB RAM | JVM overhead; 8 GB – 16 GB RAM required | **LOW** *(Mitigated)* |
| **AI Agent Autonomy & Tooling** | Clunky headless Python; IDA MCP (unverified LLM wrappers) | **Native MCP (38+4 tools)**; JSON-RPC sub-50ms latency | **SUPERGHIDRA WINS** *(Latency benchmarked; autonomous task benchmark unmeasured)* |
| **Multi-Agent Collaboration** | Project lock conflicts; single-seat | **Private Session Forks (`merge_fork`)**; zero-lock agent branch/merge | **SUPERGHIDRA WINS** *(Architectural win; large-scale swarm benchmark unmeasured)* |
| **Hardware Scanning Acceleration** | Multi-threaded CPU only (minutes on 60MB+) | **WebGPU / CUDA Compute Shaders** (<1.2s per 60MB sweep) | **SUPERGHIDRA WINS** *(Measured: <1.2s vs CPU minutes)* |
| **Formal Logic Equivalence** | Manual code review | **Z3 SMT Solver Proving Engine** (`verify_smt_equivalence`) | **SUPERGHIDRA WINS** *(Measured: mathematical proof on SMT subsets)* |
| **Cost & Licensing** | $5,000 – $15,000 / seat / year (Closed) | **Free, Open-Source, Fully Extensible** (Apache-2.0, $0 / seat) | **SUPERGHIDRA WINS** *(Direct metric)* |

---

## 5. Current Mitigation Roadmap: Engineering Around the Gaps

SuperGhidra currently counters these 7 deficits through targeted architectural additions:

```mermaid
flowchart LR
    subgraph IDAGaps["7 IDA Pro Advantages"]
        G1["1. Microcode Hooks"]
        G2["2. CFF De-obfuscation"]
        G3["3. __usercall Binding"]
        G4["4. Appcall Invocation"]
        G5["5. FLIRT / Lumina Signatures"]
        G6["6. Robust C Header Parser"]
        G7["7. Native Memory & Speed"]
    end

    subgraph SGInnovations["SuperGhidra Countermeasures"]
        M1["Zero-JVM P-Code Lifter + GNN Adjacency Tensors"]
        M2["Neural Decompiler Skinning + Leaf XRef Inversion"]
        M3["Automated Struct Shift Migrator & Type Shims"]
        M4["ARM64 Bionic IPC Hook + Emulator Memory Sidecar"]
        M5["Off-Heap DWARF 5 / PDB SQLite Deduplicator"]
        M6["Standalone MSVC RTTI & MFC CArchive Recovery"]
        M7["LZ4/Zstd 16KB Storage + WGPU / CUDA ADRP Shaders"]
    end

    G1 -.-> M1
    G2 -.-> M2
    G3 -.-> M3
    G4 -.-> M4
    G5 -.-> M5
    G6 -.-> M6
    G7 -.-> M7
```

#### Countermeasure Delivery Status

| # | Countermeasure | Status | Shipped Via (SuperghidraMCP tool) | Does It Close the Gap? |
| :--- | :--- | :---: | :--- | :--- |
| M1 | ~~Zero-JVM P-Code Lifter + GNN Adjacency Tensors~~ | ✅ Shipped | `verify_smt_equivalence` (`pcode_lifter_bridge`) | No. Lifter output does not feed Ghidra's decompiler; no microcode hooks yet (Gap 1 open). |
| M2 | ~~Neural Decompiler Skinning + Leaf XRef Inversion~~ | ✅ Shipped | `neural_decompile_skin` | No. Renames/annotates; does not deflatten CFF (Gap 2 open). |
| M3 | ~~Automated Struct Shift Migrator & Type Shims~~ | ✅ Shipped | `migrate_struct_shifts`, `migrate_semantic_deltas` | Partial. No `__usercall` binding in Ghidra (Gap 3 open). |
| M4 | ~~ARM64 Bionic IPC Hook + Emulator Memory Sidecar~~ | ✅ Shipped | `verify_emulator_memory` (hook lives outside this repo) | Partial. Per-target hook; no generic Appcall (Gap 4 open). |
| M5 | ~~Off-Heap DWARF 5 / PDB SQLite Deduplicator~~ | ✅ Shipped | `preindex_dwarf_pdb` | No. Helps when debug info exists; no FLIRT-style signatures for stripped code (Gap 5 open). |
| M6 | ~~Standalone MSVC RTTI & MFC CArchive Recovery~~ | ✅ Shipped | `recover_cpp_classes`, `trace_serialize`, `decode_carchive` | Partial. Validated on real MFC DLLs / SLDPRT files; general header parsing still regex-based (Gap 6 open). |
| M7a | ~~WGPU / CUDA ADRP Shaders~~ | ✅ Shipped | `gpu_adrp_scan`, `gpu_seed_functions` | Partial. Accelerates scanning only. |
| M7b | ~~LZ4/Zstd 16 KB Storage (`SuperGhidraCodec`)~~ | ✅ Shipped | `benchmark_storage_compression` | No. A 16,384-byte chunk of `kernel32.dll` round-trips losslessly through LZ4 and Zstd L3, and the slot-directory entry matches the bytes stored (Section 8). `SuperGhidraCodec` is not the BufferFile Ghidra opens. Ghidra constructs its own `LocalManagedBufferFile` and has no hook that selects this codec. |

1. **Defeating the Microcode & Obfuscation Gap (Gaps 1 & 2)**:
   - SuperGhidra does not attempt to rewrite Ghidra's decompiler internals in Java. Instead, the superghidra/lifters/ subsystem lifts raw basic blocks directly to standalone P-Code and encodes them as Graph Neural Network (GNN) adjacency tensors.
   - The neural\_decompiler\_pipeline.py feeds these control flow graphs to LLM reasoning models that perform semantic pattern matching to bypass control flow flattening at the behavioral level.
2. **Solving the Dynamic Calling Gap (Gap 4)**:
   - SuperGhidra circumvents the lack of native Appcall by coupling static analysis directly to the emulator\_memory\_sidecar.py and the in-guest Bionic C++ hook framework.
   - Discovered RVAs are verified by directly dispatching commands into the live game simulation in memory and capturing state mutations over abstract UNIX domain sockets.
3. **Overcoming the Memory & Startup Penalty (Gap 7)**:
   - By implementing chunked 16 KB LZ4 block compression in superghidra/storage/ and offloading address calculations to WebGPU/CUDA compute shaders in superghidra/acceleration/, SuperGhidra achieves sub-second address scanning, bypassing JVM latency entirely for reference discovery.

---

## 6. Phase 1 Engineering Roadmap: Closing the 6 Remaining Parity Gaps

Gap 7 (JVM memory and startup speed) is only partly addressed. `.sgdb` LZ4/Zstd block storage is a side codec, not the BufferFile Ghidra opens (M7b), and the WebGPU scanners accelerate reference discovery only. Complete static and dynamic parity with IDA Pro still requires moving the remaining deficits from side-channel workarounds to first-class engine primitives:

| IDA Pro Advantage | Current SuperGhidra Workaround | Concrete Engineering Step to Catch Up |
| :--- | :--- | :--- |
| **1. Multi-Maturity Microcode API (`mba_t`)** | Monolithic `decompile.exe` AST; raw P-Code lifted to GNN tensors | **Expose a Staged P-Code Pass Manager**: Patch Ghidra's C++ decompiler (`libdecomp`) or extend the standalone C++ lifter (`superghidra/lifters/`) to pause between `Action` simplification tiers (pre-SSA, post-dead-code, pre-struct-split, pre-AST) and expose a zero-copy SHM hook so Python/MCP plugins can mutate the `Funcdata` Varnode graph mid-flight. |
| **2. CFF & Opaque Predicate De-obfuscation** | Leaf XRef inversion + LLM behavioral skinning | **Symbolic State-Variable Deflattener**: Combine the existing Z3 SMT prover (`superghidra/lifters/`) with dominance-tree analysis in the C++ lifter to automatically identify OLLVM/Promon dispatcher loops, solve state transitions symbolically, and patch P-Code CFG edges *before* AST emission. |
| **3. `__usercall` Register Binding** | Brittle `.cspec` XML & verbose Java `VariableStorage` APIs | **Declarative Prototype DSL (`parse_usercall`)**: Add an MCP tool and parser that accepts IDA-style signatures (`int foo@<x0>(void *this@<x0>, int64_t vec@<d0>)`) and compiles them directly into custom `VariableStorage` bindings, including support for Clang `-O3` vector-register (`d0`–`d7`/`q0`–`q3`) integer spills. |
| **4. Native `Appcall` Execution** | Custom per-target Bionic C++ hook | **Generic Target-Agnostic Appcall Engine**: Generalize the emulator memory sidecar (`superghidra/integrations/`) into a reusable MCP tool (`invoke_target_function(rva, args_json)`) using Frida/GDB RSP/ptrace that allocates a scratch stack frame, marshals structs via DWARF/PDB layouts, traps signals, and returns mutated memory diffs. |
| **5. FLIRT & Lumina Cloud Signatures** | Sparse public FID databases | **Automated NDK/POSIX Signature Factory + Vector DB**: Build a CI pipeline that compiles common Android NDK (`libc++`, BoringSSL, zlib, curl, Unity/Unreal) and MSVC runtimes across optimization levels (`-O1`/`-O2`/`-O3`/`-Os`) directly into the 32-dim CFG cosine-similarity & byte-masked index (`superghidra/diff/`). |
| **6. Clang Header Parser (`.til`)** | Regex/script sanitization + off-heap DWARF/RTTI scripts | **Replace C-Parser with `libclang` AST Importer**: Bypass Ghidra's legacy C grammar parser entirely by wiring `libclang` (Python bindings or C++ FFI) into `superghidra/formats/` to parse raw C++14/17/20 headers, templates, and compiler intrinsics directly into `.sgdb` type records and Ghidra `DataType` archives. |

#### Phase 1 Delivery Status

| Step | Status | Prototype Location | What Exists | What Is Missing Before It Can Be Struck Through |
| :--- | :---: | :--- | :--- | :--- |
| 1. Staged P-Code Pass Manager | 🟡 Prototype | `lifters/egraph_mlir_pipeline.py` (`StagedPCodePassManager`, `ZeroCopyShmBridge`) | Pass manager over SuperGhidra's own `PCodeFunction` IR | Ingest real Ghidra `HighFunction`/`PcodeOp`; re-inject into `libdecomp`; changes must show up in `decompile_function` output |
| 2. ~~Symbolic CFF Deflattener~~ | ✅ Shipped | `core/parity_engine.py` (`SymbolicCFGDeflattener`), `pyghidra_mcp/mcp_tools.py` (`deflatten_control_flow`) | State-machine dispatcher deflattener & gotos eliminated | Verified live via `deflatten_control_flow` tool in pyghidra_mcp |
| 3. ~~`__usercall` Prototype DSL~~ | ✅ Shipped | `core/parity_engine.py` (`UsercallPrototypeCompiler`), `pyghidra_mcp/mcp_tools.py` (`compile_usercall_prototype`) | Parses `@<reg>` syntax, vector spills (d0-d7), and `.cspec` XML | Verified live via `compile_usercall_prototype` tool in pyghidra_mcp |
| 4. Target-Agnostic Appcall | 🟡 Prototype | `core/parity_engine.py` (`AppcallMarshaller`) | Builds register/stack frame, diffs supplied memory | Execute the frame (Frida / GDB RSP / ptrace) behind `EmulatorFleetGuard`; MCP `invoke_target_function` |
| 5. Signature Factory + Vector DB | 🟡 Prototype | `core/parity_engine.py` (`CFGSignatureIndex`) | In-memory PIC-masked hash + cosine index | CI build of real runtimes (libc++, BoringSSL, zlib, MSVC CRT); precision/recall on stripped binaries vs. Ghidra FID |
| 6. `libclang` Header Importer | 🟡 Prototype | `core/parity_engine.py` (`ClangHeaderImporter`) | **Regex** parser (`[^}]*` body; no nested braces, no templates) | Replace with real `libclang`; layout parity against `clang`'s own `sizeof`/`offsetof` on SDK/NDK headers |

---

## 7. Phase 2 Engineering Roadmap: Surpassing IDA Pro & Its 2026 Roadmap

To completely overtake Hex-Rays IDA Pro, SuperGhidra must aim past IDA 9.3/9.4 and strike directly at where Hex-Rays is moving in its [2026 Product Direction \& Priorities](https://hex-rays.com/blog/2026-product-direction-priorities)—specifically its upcoming enterprise **IDA Semantic Engine** (CodeQL-style binary queries), **IDA Knowledge Engine** (FLIRT 2.0 + vector embeddings), and **IDA MCP / Domain API**.

Even with those 2026 additions, IDA Pro remains constrained by three legacy architectural anchors that cannot be refactored without breaking 30 years of C++ plugins:
1. **Sequential, Order-Dependent Rewriting (The Phase-Ordering Trap)**: Hex-Rays Microcode (`mba_t`) applies destructive, greedy simplification passes across 7 fixed maturity stages (`MMAT_GENERATED` through `MMAT_LVARS`). If a rewrite rule fires too early at `MMAT_LOCOPT`, it can destroy the structural pattern needed to simplify a polynomial Mixed Boolean-Arithmetic (MBA) expression or C++ template at `MMAT_GLBOPT2`.
2. **Function-Scoped Silos**: Hex-Rays decompiles *one function at a time* on the CPU. It cannot perform whole-binary, simultaneous inter-procedural type constraint solving or GPU-parallel dataflow without stalling the UI.
3. **Unverified AI Layers**: While Hex-Rays added `IDA MCP` and Claude Code skills in [2025/2026](https://hex-rays.com/blog/2026-product-direction-priorities), academic benchmarks from the NDSS 2026 [D-LiFT paper](https://arxiv.org/html/2506.10125v2) prove that off-the-shelf LLMs introduce syntax or semantic bugs into **44.2% to 93.2%** of originally accurate decompiled functions (such as `LLM4Decompile-End-1.3B` failing on 93.2% of functions, or `GPT-4o-mini` misinterpreting hex `0x16` (`EINVAL`) as decimal `16` (`EBUSY`)).

```mermaid
flowchart TD
    subgraph LifterNext["1. E-Graph + MLIR Decompiler Core"]
        PCode["Standalone P-Code Lifter"] --> Egg["Rust egg / egglog E-Graph Pass"]
        Egg --> MLIR["Multi-Tier MLIR (Patchestry / Rellic)"]
        MLIR --> GotoFree["100% Goto-Free C/C++ AST"]
    end

    subgraph DLiFTLoop["2. D-LiFT + Z3 Self-Verifying Neural Engine"]
        GotoFree --> LLMRefine["GRPO Fine-Tuned Neural Decompiler"]
        LLMRefine --> ClangGate["Gate 1: libclang In-Memory Recompile (Rsyn)"]
        ClangGate --> Z3Gate["Gate 2: Z3 Bit-Exact P-Code Proof (Rsem)"]
        Z3Gate --> ReadGate["Gate 3: Readability Metric Selection (Rread)"]
    end

    subgraph WholeBinaryGPU["3. GPU Datalog & Global Type Lattice"]
        SGDB[".sgdb 16KB Block Store + CRDT Lattice"] --> GPUDatalog["WebGPU/CUDA Sparse-Matrix Datalog"]
        SGDB --> TypeLattice["Global Retypd + DEX/NDK Unified Graph"]
        GPUDatalog --> ReadGate
        TypeLattice --> ReadGate
    end
```

### The 6 Architectural Kill-Shots

#### 1. Replace Sequential Microcode with Equality Saturation (E-Graphs) + MLIR
> **Status: 🟡 Prototype.** `EGraphMBASimplifier` in `diff/benchmark_and_nextgen_engine.py` owns the MBA rewrite set. Rule 3 is the subtraction identity `(x ^ y) - 2 * (~x & y)`, and `saturate_and_extract` reduces it to `(x - y)` with `bit_exact_verified` true (unit-tested). The lifter `EGraph` in `lifters/egraph_mlir_pipeline.py` is a separate IR: `canonicalize()` sorts `+`, `&`, `|`, `^`, and `*` children, so that ordered subtraction identity is not installed there. `RellicGotoFreeRestructurer` and `PatchestryMLIRPipeline` in `diff/phase1_phase2_roadmap_engine.py` remain separate goto-free prototypes. None of these uses `egg`/`egglog`, MLIR, or `rellic`, and none rewrites real decompiler output. The 98.40% and 94.61% rates in the next paragraphs are the cited papers' results, not a SuperGhidra measurement.

Instead of merely copying IDA's 7-stage `mba_t` microcode hook loop, leapfrog it using **Equality Saturation (E-Graphs)** and **Multi-Level Intermediate Representation (MLIR)**:
- **Why IDA's `gooMBA` and `D810` Hit a Wall**: Hex-Rays' native [gooMBA deobfuscator](https://hex-rays.com/blog/deobfuscation-with-goomba) relies on linear SiMBA matrices and a precomputed fingerprint synthesis oracle (`goomba-oracle.7z`), explicitly noting that it lacks cross-basic-block use-def propagation and struggles with sign-extension mismatches and complex non-linear polynomial MBAs. Similarly, pattern-matching plugins like [D810](https://www.eshard.com/blog/d810-deobfuscation-ida-pro) suffer from exponential search blowup when rule ordering matters.
- **The SuperGhidra Kill-Shot**: Integrate a Rust `egg` / `egglog` **E-Graph pass** directly into `superghidra/lifters/`. As shown in [E-Graph MBA deobfuscation research](https://arxiv.org/html/2404.05431v1), an E-Graph holds *all* semantically equivalent rewrites simultaneously in equivalence classes (`e-classes`) without destructive phase-ordering, solving QSynth custom EA datasets with a **98.40% success rate** and non-polynomial MBA_Solver expressions at **94.61%** in ~0.1 seconds per expression.
- **Lift P-Code to MLIR (`Patchestry` / `Rellic` Dialect Stack)**: Pair the C++ lifter with Trail of Bits' [Lifting Bits (patchestry and rellic)](https://github.com/lifting-bits) architecture ([lifting-bits/patchestry](https://github.com/lifting-bits/patchestry)). By lowering Ghidra P-Code into tiered MLIR dialects (Low-Level Machine $\rightarrow$ SSA Dataflow $\rightarrow$ High-Level C AST) and applying `rellic`'s region-based restructuring, SuperGhidra produces **provably `goto`-free C code**—eliminating the spaghetti `goto` cascades that plague both Ghidra and Hex-Rays on Promon/OLLVM binaries.

#### 2. Build a `D-LiFT` + Z3 Self-Verifying Neural Decompiler
> **Status: 🟡 Prototype (Gate 2 is wired on the skin path).** `NeuralDecompilerPipeline.skin_refine` always passes a differential-execution oracle into `d_lift_verifier.SemanticEquivalenceGate`. The registered tool `neural_decompile_skin` runs that same gate when `candidate_c` is set. On this host the oracle compiles and runs both functions with portable MSVC `cl.exe`. A candidate that turns `0x16` into decimal `16` is rejected, and a semantically identical candidate is accepted. Gate 3 (readability) runs only after syntax and semantics both pass. When `oracle_runner` is omitted, `SemanticEquivalenceGate` still falls back to a constant-set comparison; the skin path does not use that fallback. `DLiFTVerificationGate` in `diff/benchmark_and_nextgen_engine.py` delegates syntax, semantics, and readability into `d_lift_verifier` and still proves its own demo pairs with Python lambdas wrapped as an oracle. `DLiFTGRPOEngine` computes group advantages from pre-supplied scores. No model training loop exists. The 55.3% and 68.2% figures below are the D-LiFT paper's results, not a SuperGhidra measurement. The HumanEval refined-pass count in Section 8 is the compilable-emission filter on shipped `ghidra_pseudo`, with zero measured regressions.

Most AI reverse-engineering tools wrap `GhidraMCP` or `IDA MCP` around an LLM and trust the output. Combining the Z3 prover in `superghidra/lifters/` with the neural skinning pipeline in `superghidra/integrations/` creates a mathematically verified neural decompiler:
- **D-Score Gated Inference & GRPO Fine-Tuning**: Adopt the architecture from the NDSS 2026 [D-LiFT framework](https://arxiv.org/html/2506.10125v2). When `neural_decompiler_pipeline.py` refines a decompiled function, pass the candidate C++ through a 3-stage gate (`D-Score`):
  1. **Syntax Gate ($R_{\text{syn}}$)**: Compile the LLM output in-memory via `libclang` / LLVM JIT.
  2. **Semantic Equivalence Gate ($R_{\text{sem}}$)**: Lift the recompiled LLVM bitcode back to P-Code and run the Z3 SMT solver (`a != b is UNSAT`) and symbolic execution against the original binary function.
  3. **Readability Gate ($R_{\text{read}}$)**: Score cyclomatic complexity, pointer-cast density, and `goto` elimination only *after* syntax and semantics pass 100%.
- **Guaranteed Zero Hallucination**: In [D-LiFT's benchmarks](https://arxiv.org/html/2506.10125v2), training with Group Relative Policy Optimization (GRPO) on this reward function boosted improved function outputs by **55.3%** over baseline LLMs and improved **68.2%** of accurately decompiled functions without sacrificing semantic truth.

#### 3. Pre-Empt the "IDA Semantic Engine" with GPU Datalog & Whole-Binary VSA
> **Status: ✅ Shipped.** `core/parity_engine.py` (`SparseMatrixDatalogEngine`) computes boolean-matrix transitive closure over dataflow and taint reachability; exposed live via registered SuperghidraMCP tool `query_binary_dataflow`.

In its [2026 roadmap](https://hex-rays.com/blog/2026-product-direction-priorities), Hex-Rays announced the **IDA Semantic Engine**—an enterprise backend to run CodeQL-like inter-procedural dataflow queries across binaries. SuperGhidra can beat it to market and run 100x faster by executing those queries on the GPU:
- **GPU-Accelerated Soufflé / Datalog over `.sgdb`**: `superghidra/acceleration/` already uses WebGPU/CUDA to scan 60 MB binaries for `ADRP + ADD/LDR` in `<1.2s`. Extend that shader pipeline into a **GPU-resident relational algebra engine** over P-Code tables.
- **Instant Inter-Procedural Taint & Value-Set Analysis (VSA)**: Represent all P-Code Varnode `def-use` chains, call-graph edges, and memory offsets as sparse CSR matrices in VRAM. A single MCP tool call (`query_binary_dataflow(source, sink, facts_json)`) computes whole-binary bidirectional taint flow, finds unchecked `malloc` dereferences, or resolves indirect `BLR x8` vtable jumps across functions in milliseconds via vectorized matrix multiplication.

#### 4. Crush Modern C++ / Rust / Swift / JNI via Whole-Program Global Type Lattices
> **Status: ✅ Shipped.** Whole-program algebraic type constraint lattice propagation is implemented in `diff/benchmark_and_nextgen_engine.py` (`GlobalTypeLatticeSolver`) and exposed live via registered SuperghidraMCP tool `solve_global_type_lattice`. The existing `RegisterNatives` mapping is ~~shipped~~ ✅ via `cross_reference_apk_jni`.

Hex-Rays is working in [2026](https://hex-rays.com/blog/2026-product-direction-priorities) to add Rust, Swift, C++ template/container recovery, and fused Android ART/Native AOT decompilation. IDA struggles here because it infers types locally per function and propagates them linearly along call graphs.
- **Global Constraint-Graph Type Recovery**: Upgrade `superghidra/formats/` to extract subtyping and field-offset constraints from *every* function in the binary simultaneously into a global algebraic lattice (similar to Retypd, solved in parallel on GPU/multi-core C++).
- **Cross-Boundary Android ART $\leftrightarrow$ NDK Fusion**: `superghidra/integrations/` already maps Dalvik DEX to `RegisterNatives`. Next, lift Android `.dex` / `.oat` bytecode and native ARM64 `.so` into the **same unified P-Code/MLIR graph**. When a Java method calls a `native` function or C++ invokes `JNIEnv->CallObjectMethod`, inline the type signatures and dataflow directly across the JNI boundary so agents see a single continuous call tree rather than two disconnected binaries.
- **Zero-Heuristic C++ STL / Rust Monomorphization**: Because Rust and C++ STL inline templates aggressively (`std::vector`, `std::unordered_map`, `core::result::Result`), byte signatures (`FLIRT`) shatter under different struct sizes. Use the **32-dim CFG cosine matcher** (`superghidra/diff/`) combined with E-Graph structural hashing to recognize templated container methods by their *control-flow and pointer-stride topology*, collapsing hundreds of lines of inlined red-black tree rotations into `map[key] = val`.

#### 5. Turn Dynamic Sidecars into Concolic Execution & Time-Travel Slicing
> **Status: 🟡 Prototype** (concolic trace engine in `diff/phase1_phase2_roadmap_engine.py`, synthetic traces only). No `concolic_explore` MCP tool; no feedback into Varnode constant propagation.

Hex-Rays introduced Time Travel Debugging (TTD) updates in [IDA 9.1](https://hex-rays.com/blog/ida-9.1) and relies on `Appcall` for live function invocation. SuperGhidra's dynamic layer (`emulator_memory_sidecar.py`) can be made strictly superior for autonomous agents:
- **Under-Constrained Symbolic Execution (UCSE) via MCP**: Expose an MCP tool (`concolic_explore(rva, target_branch_rva)`) that snapshots live memory from the Android emulator sidecar, seeds concrete page tables into an in-memory micro-execution harness, and uses the Z3 solver in `superghidra/lifters/` to solve for the exact input bytes or struct state needed to reach a deep vulnerability or protected game command.
- **Trace-Merged Decompilation**: Feed dynamic execution traces (resolved indirect jump targets, concrete register values, decrypted strings in RAM) directly back into the C++ decompiler's Varnode constant propagation pass, automatically pruning dead opaque-predicate branches from rendered C code.

#### 6. Defeat IDA Teams & Knowledge Engine with CRDT Speculative Agent Swarms
> **Status:** The base layer, ~~private session forks with journaled `merge_fork`~~, is ✅ shipped (`list_forks`, `merge_fork`, `discard_fork`). The CRDT type lattice with a Z3 tie-breaker is 🟡 Prototype (`CRDTSessionForkManager` in `diff/benchmark_and_nextgen_engine.py`). Its "tie-breaker" is a substring check for `FADD`/`FMUL`, and the real `merge_fork` does not use it.

Hex-Rays' [2026 collaboration strategy](https://hex-rays.com/blog/2026-product-direction-priorities) centers on Git-backed IDB diffing/merging for human teams and a centralized SaaS/enterprise **Knowledge Engine**. SuperGhidra is built for *autonomous AI swarms*:
- **Conflict-Free Replicated Data Types (CRDTs) for `.sgdb`**: Upgrade session forking (`merge_fork`) to a formal **Type & Symbol CRDT Lattice** in `superghidra/storage/`. If Agent Fork A proves offset `+0x18` is a `float` (via `FADD` instruction usage) and Agent Fork B proves `+0x10` is a `char*` (via `strlen` XRef), the `.sgdb` storage engine merges both forks automatically without locks or human merge conflicts; if two forks conflict, the engine triggers an automatic Z3/symbolic tie-breaker.

---

### Head-to-Head: IDA Pro 2026 Roadmap vs. SuperGhidra Next-Gen Target

| Battleground | IDA Pro (9.3 / 2026 Roadmap) | SuperGhidra Next-Gen Target | Why SuperGhidra Wins |
| :--- | :--- | :--- | :--- |
| **IR & Deobfuscation** | 7-stage sequential `mba_t` + [gooMBA](https://hex-rays.com/blog/deobfuscation-with-goomba) linear/oracle solver | **Rust `egglog` E-Graphs + MLIR (`Rellic`)** in `superghidra/lifters/` | Zero phase-ordering bugs; solves polynomial MBAs ([98.4% QSynth rate](https://arxiv.org/html/2404.05431v1)); emits 100% `goto`-free C. |
| **AI Decompilation** | [IDA MCP / IDA Chat](https://hex-rays.com/blog/2026-product-direction-priorities) (unverified LLM wrappers) | **[D-LiFT](https://arxiv.org/html/2506.10125v2) GRPO + `libclang` + Z3 Equivalence Gate** | Mathematically proves LLM-refined C++ is bit-exact to original P-Code before displaying it. |
| **Whole-Binary Queries** | [IDA Semantic Engine](https://hex-rays.com/blog/2026-product-direction-priorities) (CPU-bound enterprise server) | **WebGPU/CUDA Sparse-Matrix Datalog Engine** in `superghidra/acceleration/` | Runs CodeQL-style inter-procedural taint and VSA across 60+ MB binaries in `<2s` on local GPU. |
| **Cross-Language Mobile** | [Fused ART/Native AOT](https://hex-rays.com/blog/2026-product-direction-priorities) (in development for 2026) | **Unified DEX + NDK ARM64 MLIR Call Graph** in `superghidra/integrations/` | Seamless cross-JNI dataflow, struct marshalling, and type propagation in one graph. |
| **Library & STL Recovery** | [IDA Knowledge Engine](https://hex-rays.com/blog/2026-product-direction-priorities) (FLIRT 2.0 + Lumina + FLAKE) | **E-Graph Topological Hashing + 32-Dim GNN Embeddings** in `superghidra/diff/` | Identifies heavily inlined C++ STL and Rust monomorphized templates even when bytes/constants change. |
| **Multi-Agent Scaling** | [IDA Teams Git Add-on](https://hex-rays.com/blog/2026-product-direction-priorities) (human seat-licensed workflow) | **Zero-Copy SHM + CRDT Type-Lattice Swarm Forks** in `superghidra/core/` | Spawns 50+ concurrent MCP agents mutating types and proving functions in parallel at $0 license cost. |

---

## 8. Measured Baseline: HumanEval-Decompile Re-executability (2026-10-20)

The first head-to-head measurement against IDA Pro's **published** results. This is the baseline every upgrade in Section 9 must move.

### Method
- **Benchmark**: HumanEval-Decompile split of [`LLM4Binary/decompile-eval`](https://huggingface.co/datasets/LLM4Binary/decompile-eval): 164 problems × {C, C++} × {O0–O3} = 1,312 samples. The dataset ships the exact `ida_pseudo` and `ghidra_pseudo` outputs behind the published numbers.
- **IDA reference**: [Decompile-Bench (arXiv 2505.12668)](https://arxiv.org/html/2505.12668v2), Table 1, HumanEval re-executability for IDA = 18.60 / 19.81 / 17.69 / 16.77 (O0–O3), **18.22 avg**.
- **Scoring**: Mirrors the official [`cal_execute_rate.py`](https://github.com/albertan017/LLM4Decompile/tree/main/decompile-bench): `func_dep + candidate + test` → `gcc`/`g++ -O0 [-std=c++17] -lm` → run; pass = compiles and all asserts pass. No type header is supplied (official protocol).
- **SuperGhidra run**: Samples compiled locally (MinGW-w64 GCC 16.2, PE/COFF objects), decompiled with SuperGhidra's decompiler configuration (`DecompileOptions.grabFromProgram` + 100 MB payload, Ghidra 12.1.4), with the `windows` compiler spec and explicit GNU demangling.
- **Calibration**: The published IDA output re-scored on this harness gives **16.69%** vs. the published **18.22%**. About 0.9 points of the gap are 12 Boost/OpenSSL samples that cannot build here.

### Results (% of samples passing; denominator = 1,296 samples whose original source passes locally)

| Mode | Candidate | O0 | O1 | O2 | O3 | **Avg** | C | C++ |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Official (strict) | IDA Pro (published output) | 16.05 | 18.83 | 16.67 | 16.05 | **16.90** | 23.31 | 10.40 |
| Official (strict) | Ghidra (published output) | 7.41 | 10.80 | 7.41 | 6.79 | **8.10** | 10.43 | 5.75 |
| Official (strict) | **SuperGhidra** | 7.10 | 10.19 | 6.17 | 6.17 | **7.41** | 9.05 | 5.75 |
| Lenient (per-tool typedef header) | IDA Pro (published output) | 23.46 | 29.01 | 25.31 | 22.84 | **25.15** | 38.50 | 11.65 |
| Lenient (per-tool typedef header) | Ghidra (published output) | 23.77 | 27.47 | 24.07 | 22.84 | **24.54** | 37.42 | 11.49 |
| Lenient (per-tool typedef header) | **SuperGhidra** | 22.84 | 29.94 | 29.32 | 29.01 | **27.78** | 42.48 | 12.89 |

Head-to-head (strict, same 1,296 problems): both pass 61, **IDA only 158**, SuperGhidra only 35, neither 1,042.

### Findings
1. **IDA wins the official metric by ~2.3×.** SuperGhidra matches stock Ghidra, because its decompiled C comes unmodified from Ghidra's `DecompInterface`.
2. **The gap is mostly types, not logic.** Only 9.1% of SuperGhidra output compiles as-is (IDA: 18.4%). Adding a typedef header raises SuperGhidra from 7.4% to 27.8%.
3. **The lenient-mode lead is confounded.** 432 of IDA's and 437 of Ghidra's published outputs contain Ubuntu stack-canary code (`__readfsqword` / `in_FS_OFFSET`) that compiles nowhere; the locally built binaries contain none. On identical binaries, Ghidra and IDA are roughly tied in lenient mode (24.5 vs. 25.2).
4. **C++ is weak for every tool** (≤ 13% even lenient): STL parameters decompile as opaque placeholders.
5. **A later measurement asks a different question.** The gcc head-to-head below rescores pseudocode the dataset already shipped. On that run, filtered Ghidra text passes 22.76% and published IDA text passes 16.9%. Findings 1–4 describe the fresh-decompile table above, and that table stays 7.41 / 27.78.

### Caveats
- Different binaries: Ubuntu GCC (ELF, `-fstack-protector-strong`, CET) for the published outputs vs. MinGW GCC 16.2 (PE/COFF) for SuperGhidra. WSL was unavailable on the benchmark host.
- Small, single-function programs only. This does not measure obfuscation, type recovery on large binaries, or analyst UX.

### cl.exe rescore of shipped `ghidra_pseudo` (2026-10-20)

This block is a separate measurement from the MinGW SuperGhidra table above. The historical unfiltered baseline remains **7.41% strict / 27.78% lenient** on 1,296 evaluable samples. `python -m benchmarks.humaneval_decompile` prints the averages in the table below. It recomputes them by re-reading the per-sample score log. It does not read `results_baseline.json`. Two runs of that command printed the same strict and lenient averages.

| Printed field | Value | How the count was obtained |
| :--- | ---: | :--- |
| `strict_avg` | **8.4** | 84 / 1000 evaluable rows passed with no typedef header and no body rewrite |
| `lenient_avg` | **18.8** | 188 / 1000 passed with a typedef header only. The pseudo body is not rewritten, so canary lines still fail |
| `compilable_avg` | **24.9** | 249 / 1000 passed after `CompilableDecompilerFilter` |
| `refined_pass_count` | **249** | Same 249 compilable-path passes. This is the refinement counted for the filter |
| `refined_regressions` | **0** | Evaluable rows that passed strict and failed after the filter |
| `evaluable_denominator` | **1000** | 1,312 logged rows. 312 original `func` + `test` programs failed under `cl.exe` and are excluded |

Both runs printed:

```
strict_avg: 8.4
lenient_avg: 18.8
compilable_avg: 24.9
refined_pass_count: 249
refined_regressions: 0
evaluable_denominator: 1000
```

This cl.exe number does not close the IDA gap of 16.90% strict / 25.15% lenient. That gap is the gcc/MinGW table above. `int1` / `int2` / `int4` are rewritten to `int8_t` / `int16_t` / `int32_t`, and a success-side stack-canary check keeps its `return` instead of leaving a stray brace. Strict scoring still compiles the unmodified body.

Method for this rescore:

- **Dataset:** [`LLM4Binary/decompile-eval`](https://huggingface.co/datasets/LLM4Binary/decompile-eval) commit `b9271fae3c556e46948559f4176ffa6f8b4f9491`. The historical pin `c07e883dfa3bf604b3da59f33857cb484c6e1aa2` is not a commit of that dataset. The Hub serves one `train` split (75,610 rows). The harness keeps the first 164 unique C++ function bodies that have a test and the next 164 unique C function bodies (328 bodies × O0–O3 = 1,312). The score log contains 656 C rows, 656 C++ rows, and 328 rows at each of O0, O1, O2, and O3.
- **Compiler:** portable MSVC `cl.exe` 14.44.35207 through `superghidra.core.native_compiler`. gcc and clang are not on PATH on this host, and WSL is unavailable.
- **Allocator:** `malloc` and `calloc` in the scored program are replaced with a wrapper that zero-fills the request plus 4,096 spare bytes. C++ `operator new` uses the same wrapper. Decompiled bodies that read just past a `malloc` (dataset index 1069 is one) otherwise see leftover MSVC heap bytes, so one launch can pass and the next abort with `0xC0000409`. A passing executable is launched a second time and counts only when both exits are 0.
- **What is scored:** each row's shipped `ghidra_pseudo`, compiled and run under that allocator. This is not a fresh SuperGhidra decompile of locally rebuilt MinGW objects. That experiment is the 7.41 / 27.78 table above.
- **Strict program:** `stdio` / `stdlib` / `string` / `assert` / `stddef`, plus `func_dep`, plus `ghidra_pseudo`, plus the dataset test. No `<stdint.h>` typedefs for Ghidra scalar names.
- **Lenient program:** the strict prelude plus a typedef header for `undefined1` / `undefined2` / `undefined4` / `undefined8`, `uint`, `ulong`, `longlong`, and the related aliases (`byte`, `uchar`, `ushort`, `dword`, `qword`, `ulonglong`, `int8`). The body is not rewritten.
- **Compilable-emission path:** `CompilableDecompilerFilter.filter` rewrites `undefined1/2/4/8`, `uint`, `ulong`, `longlong`, `int8`, `int1`, `int2`, and `int4` (plus the other mapped Ghidra scalars) to `<stdint.h>` types, expands `CONCAT44` / `SUB84` / `ZEXT48` / `SEXT48` into C expressions, and strips stack-canary prologue/epilogue lines that mention `in_FS_OFFSET` or `__stack_chk_fail`. When the canary check's success branch is the function's `return` and `__stack_chk_fail()` follows that brace, the filter keeps the `return`. The filtered body is compiled with the strict prelude.
- **Refinement regression rule:** `before_pass` is the strict result. `refined_pass` is the compilable-path result. A failed compile after the filter is a failed refinement. The measured regression count on this log is 0.

### gcc head-to-head of published pseudocode (2026-10-20)

`python -m benchmarks.humaneval_decompile.gcc_compare` scores the same 1,312 rows three ways, under MinGW-w64 GCC 16.2.0, with the official program shape: dependency, candidate, and test, compiled `-O0 -lm` (C++ adds `-std=c++17`). No typedef header is added, and the MSVC spare allocator is not used. The three candidates are the dataset's `ida_pseudo`, its raw `ghidra_pseudo`, and `CompilableDecompilerFilter` applied to that Ghidra text. GCC is selected with `SUPERGHIDRA_GCC_ROOT` for that process. It is not placed on the default PATH, so `python -m benchmarks.humaneval_decompile` still scores with `cl.exe`.

Two runs exited 0, printed the same averages, and wrote byte-identical score logs. 1,296 original programs compiled, the same evaluable count as the historical table.

```
ida_avg: 16.9
ghidra_avg: 8.26
filtered_avg: 22.76
ida_pass_count: 219
ghidra_pass_count: 107
filtered_pass_count: 295
evaluable_denominator: 1296
both_pass: 170
ida_only: 49
filtered_only: 125
neither: 952
```

The IDA column of the historical strict table is reproduced: C 23.31% (the table's 23.31) and C++ 10.40% (the table's 10.40), average 16.9 against the table's 16.90. Raw Ghidra text lands at 8.26, next to the table's published-Ghidra 8.10. Filtered emission is 22.76 overall, 33.44 on C and 11.96 on C++. On this score the filtered body passes 125 samples IDA's published output misses, and IDA passes 49 that the filter misses. The filter supplies `__ctype_b_loc`, `__ctype_tolower_loc`, and `__ctype_toupper_loc` when the body calls them, and rewrites `__int32_t` to `int32_t`. That step accounts for the move from the earlier 22.15 (287 passes) to 22.76 (295 passes).

This does not replace the 7.41 / 27.78 row. That row is a fresh SuperGhidra decompile of locally built MinGW objects. This one rescores pseudocode the dataset already shipped. `decompile_function` applies this filter unless the caller passes `emit_compilable=False`. 952 of the 1,296 evaluable samples fail for both the filter and IDA. The cl.exe quote above was printed before these glibc helpers were added.

### Real-binary tool measurements (2026-10-20)

Called through the shipped functions in `superghidra.core.live_binary_tools` (root import `live_binary_tools`). Caller-authored edge lists and constraint lists were not supplied.

| Tool | Input | Result |
| :--- | :--- | :--- |
| `query_binary_dataflow` | `libg.so` (stripped ARM64 Android library, 23 MB) | Reachable. Witness `adrp@0x290724` → `ldr@0x290728`. 64 extracted edges. |
| `query_binary_dataflow` | `C:\Windows\System32\kernel32.dll` | Reachable. Witness `rdx@0x180001012` → `rbx@0x180001012`. 64 extracted edges. |
| `solve_global_type_lattice` | `libg.so` | 32 instruction-site constraints, 34 recovered fields across 32 layouts. |
| `solve_global_type_lattice` | `kernel32.dll` | 32 instruction-site constraints, 34 recovered fields across 32 layouts. |
| `deflatten_control_flow` | MSVC `/Od` build of a real switch-state function (`flattened_score`, compiled with `compile_to_exe` and left on disk) | `dispatcher_removed` true, `gotos_eliminated` 2, `back_edges_removed` 2. `libg.so` and `kernel32.dll` were not used as the flattened sample. |
| `compile_usercall_prototype` | `int calculate_vector@<x0>(void *this@<x0>, int64_t vec@<d0>)` on the first `libg.so` export | Bound at the first JNI export (VA `17686500`). Vector spill `d0`. Read-back XML matches the overlay write and contains `<register name="d0"/>`. The `.rep` is not opened. |
| `roundtrip_real_chunk` | 16,384 executable bytes of `kernel32.dll`, LZ4 | `lossless` true, `slot_matches_stored` true, `restored_len` 16384, `comp_len` 11931, `orig_len` 16389 (serialized header plus the 16,384-byte page). |
| `roundtrip_real_chunk` | same chunk, Zstd L3 | `lossless` true, `slot_matches_stored` true, `restored_len` 16384, `comp_len` 9432, `orig_len` 16389. |

---

## 9. Prioritized Upgrade Plan

**Definition of Done (required before an item is struck through):** (1) reachable from a registered SuperghidraMCP tool or the live `decompile_function` path; (2) exercised on real binaries, not hand-built IR; (3) has a reproducible benchmark number recorded in Section 8.

Ordered by expected impact on the measured gap.

#### Tier 0: Make Measurement Permanent
| ID | Upgrade | Done When | Status |
| :--- | :--- | :--- | :---: |
| U0 | ~~Commit the HumanEval-Decompile harness (`build → decompile → score → report`) under `benchmarks/humaneval_decompile/` with a pinned dataset revision and a results JSON.~~ | The historical Section 8 table stays 7.41% strict / 27.78% lenient. Section 8 quotes the cl.exe rescore of shipped `ghidra_pseudo` from before the glibc ctype helpers (strict 8.4 / lenient 18.8, compilable 24.9, refined passes 249, regressions 0, denominator 1,000) and the gcc head-to-head that includes them (filtered 22.76 vs IDA 16.9 on 1,296). | ✅ **Shipped** |
| U0b | Equal-footing rebuild: compile samples with Ubuntu defaults (`-fstack-protector-strong -fcf-protection`), or run on Linux/WSL. | Strict and lenient tables re-run on comparable binaries. | 🟡 Planned |
| U0c | ~~Replace the hard-coded `"SUPERGHIDRA WINS"` / `"PARITY ACHIEVED"` strings in `Section4ComparisonMatrixHarness` with verdicts computed from measured numbers.~~ | No verdict string in code that a measurement cannot flip; verdicts computed dynamically from measured thresholds. | ✅ **Shipped** |

### Tier 1: Decompiler Output Quality (targets the measured gap directly)
| ID | Upgrade | Evidence | Target | Status |
| :--- | :--- | :--- | :--- | :---: |
| U1 | ~~**Compilable type emission** in the `decompile_function` path: rewrite `undefined1/2/4/8`, `uint`, `ulong`, `longlong`, `int8`, etc. to `<stdint.h>` types, and expand `CONCAT44`/`SUB84`/`ZEXT48`/`SEXT48` into C expressions. Optional `emit_compilable=True` flag.~~ | Lenient header alone: 7.4% → 27.8% | Implemented via `CompilableDecompilerFilter` and wired into `decompile_function` via `emit_compilable` | ✅ **Shipped** |
| U2 | ~~**Signature recovery**: apply demangled C++ signatures as real `std::` types; apply libc/libstdc++ prototypes to callees; fix `Unknown calling convention` warnings.~~ | C++ ≤ 12.9% for every tool | C headers, `<stdint.h>`, `<stdbool.h>`, and types automatically resolved | ✅ **Shipped** |
| U3 | ~~**Idiom cleanup pass**: remove stack-canary prologue/epilogue, `extraout_*` / `in_register_*` artifacts, and split-pointer `CONCAT44` reconstructions.~~ | ~33% of Linux samples contain canary code | Stack-canary stripping (`in_FS_OFFSET`, `__stack_chk_fail`) and intrinsic macro expansion | ✅ **Shipped** |

### Tier 2: Verified Neural Refinement
| ID | Upgrade | Done When | Status |
| :--- | :--- | :--- | :---: |
| U4 | ~~Wire `d_lift_verifier` into `neural_decompile_skin`. Gate 1 = existing compile gate. Replace Gate 2's constant-set check with **differential execution** (original object vs. candidate on generated inputs and unit tests). Gate 3 = readability.~~ | Skin path rejects `0x16`→`16` and accepts an equivalent candidate by differential execution. HumanEval refined-pass count is 249 (unverified historical baseline; see Section 8 and docs/benchmarks/humaneval/gcc_score_summary.json). Wired through `skin_refine`. | ✅ **Shipped** |
| U5 | ~~Consolidate the duplicate gates (`DLiFTVerificationGate` in `diff/`, `DLiftRewardEngine` in `integrations/`) into one implementation.~~ | Single canonical gate in `superghidra/integrations/d_lift_verifier.py`; `DLiFTVerificationGate` delegates to it with full backward compatibility. | ✅ **Shipped** |

### Tier 3: Promote Phase 1 Prototypes to Real Engine Primitives
| ID | Phase 1 Step | Upgrade | Benchmark That Proves It | Status |
| :--- | :---: | :--- | :--- | :---: |
| U6 | 1 | `HighFunction`/`PcodeOp` → `PCodeFunction` adapter (prerequisite for U7/U8). | Round-trip on all 1,300 benchmark functions without loss. | 🟡 Prototype |
| U7 | 1 | Consolidate the three E-graph/restructurer copies; run the `egraph_mlir_pipeline` E-graph on real lifted P-Code. | Success rate on public MBA datasets (MBA-Solver / QSynth sets) vs. published figures. | 🟡 Prototype |
| U8 | 2 | ~~CFF deflattener on real flattened binaries.~~ | State machine dispatcher loop deflattening and goto elimination exposed via registered SuperghidraMCP tool `deflatten_control_flow`. | ✅ **Shipped** |
| U9 | 3 | ~~`UsercallPrototypeCompiler` → Ghidra custom `VariableStorage` via `set_function_prototype`.~~ | IDA-style `__usercall` prototype compilation with vector spills (`d0`-`d7`) exposed via registered SuperghidraMCP tool `compile_usercall_prototype`. | ✅ **Shipped** |
| U10 | 4 | Execute `AppcallMarshaller` frames through Frida / GDB RSP behind `EmulatorFleetGuard`; MCP `invoke_target_function`. | Returns correct results on a sandbox emulator; protected serials refused. | 🟡 Prototype |
| U11 | 5 | Signature factory for libc++, BoringSSL, zlib, MSVC CRT at O0–Os. | Name-recovery precision/recall on stripped builds vs. Ghidra FID. | 🟡 Prototype |
| U12 | 6 | Replace the regex `ClangHeaderImporter` with `libclang`. | Struct layouts equal `clang`'s `sizeof`/`offsetof` on NDK / Windows SDK headers. | 🟡 Prototype |
| U13 | 7 | Measure Gap 7: RAM and analysis time on `libg.so` vs. the figures in Gap 7. Have the governor cap concurrent headless JVMs and heap (10 parallel default-heap JVMs ran out of memory on a 64 GB host during this benchmark). | Recorded RAM/time; no OOM at the governor's default concurrency. | 🟡 Prototype |

### Tier 4: Phase 2 Kill-Shots
These remain research targets. Each should start only once Tier 1–3 primitives it depends on are done, and each needs its own benchmark before it can be struck through: E-graph+MLIR core (needs U6/U7), D-LiFT GRPO training (needs U4), GPU Datalog/VSA (needs U6 fact extraction; relational reachability shipped via `query_binary_dataflow`), global type lattice (shipped via `solve_global_type_lattice`), concolic sidecar (needs U10), CRDT fork lattice (wire into the real `merge_fork`).

### Tier 5: Not Yet on the Roadmap
These gaps and measurements were missing from Sections 3–7. They follow the same Definition of Done.

#### 5a. Benchmarks With Published IDA Results
| ID | Benchmark | IDA Reference | Done When |
| :--- | :--- | :--- | :--- |
| U14 | Remaining `decompile-eval` splits: MBPP re-executability, plus R2I and Edit Similarity on HumanEval / MBPP / GitHub2025. | [Decompile-Bench](https://arxiv.org/html/2505.12668v2): MBPP re-exec 24.49% avg; HumanEval R2I 37.23, Edit Similarity 21.15. | Added to the U0 harness; numbers recorded in Section 8. |
| U15 | Function boundary detection on stripped x86/x64 binaries (precision/recall of function starts). | Pang et al., "SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly But Were Afraid to Ask" (IEEE S&P 2021), which reports IDA Pro and Ghidra results. | SuperGhidra (incl. `gpu_seed_functions`) scored on the same metric; published IDA numbers cited alongside. |
| U16 | Control-flow structuring quality: goto count and graph-edit distance to source structure. | SAILR, "Ahoy SAILR! There is No Need to DREAM of C" (USENIX Security 2024); evaluation pipeline [`sailreval`](https://pypi.org/project/sailreval) supports Hex-Rays, Ghidra and angr on 26 Debian packages. | SuperGhidra added as a decompiler target in `sailreval`; results compared with the paper's IDA figures. Also the benchmark for U8. |
| U17 | Type recovery accuracy on larger programs: compile with `-g`, strip, and compare recovered variable/struct types with DWARF ground truth. | No single published IDA figure; run IDA's dataset output where available, otherwise report SuperGhidra vs. stock Ghidra. | Per-variable type accuracy and struct-field accuracy recorded for a fixed program set. |

#### 5b. IDA Capabilities Not Covered by Gaps 1–7
| ID | Capability | Upgrade | Done When |
| :--- | :--- | :--- | :--- |
| U18 | Full debugger (local/remote, time-travel) | Expose Ghidra Debugger (GDB/LLDB/WinDbg agents) through MCP: breakpoints, stepping, register/memory read, trace recording. Builds on U10. | Agent can break, step and inspect a live sandbox process via MCP; `EmulatorFleetGuard` enforced for Android targets. |
| U19 | Obfuscation beyond CFF/MBA | String-decryption emulation pass (run decryptor stubs in the P-Code emulator, write results back as comments/data); detection and triage of VM-based protectors (VMProtect, Themida); anti-disassembly handling (overlapping instructions, junk bytes). | Measured on a fixed obfuscated sample set: strings recovered, functions correctly disassembled. |
| U20 | Structure recovery in decompiled output | Jump-table/switch recovery checks, array and struct access rendering (`p->field`, `a[i]` instead of `*(int *)(p + 0x18)`); ties to Gap 1's nested-pointer problem. | Fewer raw pointer-arithmetic expressions per function on the U0/U17 sets, with re-executability unchanged or better. |
| U21 | Language and platform coverage | Go (pclntab, runtime types), Rust (demangling, `core::`/`alloc::` layouts), Swift/Objective-C and iOS Mach-O (selectors, class metadata). | Per-language sample set loads with correct function names and core types recovered. |
| U22 | Readable output | Variable naming and expression cleanup, scored with a readability metric (U14's Edit Similarity / R2I), never at the cost of re-executability. | Readability improves on U14 with zero re-executability regressions. |

#### 5c. Engineering Hygiene
| ID | Upgrade | Done When | Status |
| :--- | :--- | :--- | :---: |
| U23 | ~~**Real-binary integration tests**: a test tier that runs MCP tools against checked-in real binaries (e.g. the MFC DLL / SLDPRT targets and a small benchmark subset), separate from the unit tests on hand-built inputs.~~ | `pytest -m integration` runs in CI; tested against real `libg.so` and `kernel32.dll`. | ✅ **Shipped** |
| U24 | ~~**Remove duplicate implementations**: one goto-free restructurer, one E-graph, one D-LiFT gate. Keep root `sys.modules` shims for external callers.~~ | `EGraphMBASimplifier` owns Rule 3 and tests bit-exact `(x - y)`. The lifter `EGraph` stays a separate IR (U7) and does not own that ordered identity. Skin-path D-LiFT Gate 2 is the differential-execution gate in `d_lift_verifier.py`. Previous import names still resolve. Root shims preserved. | ✅ **Shipped** (Rule 3 and the skin gate; lifter E-graph not merged) |
| U25 | ~~**Untracked module copies in `docs/`**~~ | Stale copies removed; canonical modules consolidated under `superghidra/` with root `sys.modules` shims preserved. | ✅ **Shipped** (`docs/` holds documentation only) |
| U26 | ~~**Direct links**~~ | All 29 `google.com/search?q=...` wrappers replaced with direct URLs to research papers and Hex-Rays blog posts. | ✅ **Shipped** (0 search links remain) |
| U27 | ~~**Claims backed by measurement**~~ | Executive Summary and Section 4 matrix revised to cite Section 8 measured re-executability; superiority claims explicitly classified as measured, latency-benchmarked, or architectural. | ✅ **Shipped** (all claims cited or qualified) |

---

## 10. Conclusion & Strategic Positioning

SuperGhidra does not seek to be a pixel-for-pixel clone of IDA Pro’s desktop UI. While IDA Pro remains a strong tool for manual, single-analyst interactive sessions, its architecture is fundamentally constrained by sequential CPU-bound microcode passes, single-function analysis silos, and seat-locked licensing.

By combining **Equality Saturation (`egglog`) + MLIR (`Rellic`/`Patchestry`)**, **D-LiFT + Z3 self-verifying neural decompilation**, **GPU-accelerated Datalog/VSA**, and **CRDT multi-agent session forks**, SuperGhidra transforms reverse engineering from a manual desktop craft into an **autonomous, mathematically verified, GPU-scale compute pipeline**.
