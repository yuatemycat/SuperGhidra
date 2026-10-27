# SuperGhidra v0.5.0 Release Notes

SuperGhidra v0.5.0 establishes the persistent, lock-free reverse-engineering daemon, binary loader, and acceleration suite designed for autonomous agents and reverse engineers.

This release stabilizes the core daemon RPC, SQLite L2 query cache, multi-architecture binary parsing, and Windows C++ structure recovery, while marking the standalone zero-JVM decompiler as an experimental prototype ahead of the 1.0.0 Agent-First architecture.

---

## 1. Core Subsystems in v0.5.0

### Persistent Lock-Free Ghidra Oracle Daemon
- **In-Memory JVM Daemon**: Serves queries over TCP (`127.0.0.1:5073`) to keep OpenJDK and Ghidra's `DecompInterface` hot in memory, eliminating repetitive 5–15 second JVM cold-start penalties across agent queries.
- **Port-Scoped Token Security**: Security model enforces loopback-only binding by default (`127.0.0.1`, `::1`), bounded 2 MB request payloads, and per-port session tokens (`~/.superghidra/daemon.<port>.token`). Multiple daemons can run concurrently on different ports without cross-process token overwrite or lockout.
- **Lock-Free State Overlay**: JSON write-overlays (`ghidra_overlay.json`) and append-only event logs (`.ghidra-delta.jsonl`) record symbol renames, type definitions, and comments without mutating read-only `.rep` project databases.

### Persistent L2 SQLite WAL Cache
- **Microsecond Query Interception**: Caches decompiled C output, function signatures, disassembly blocks, references, and vtables in an on-disk SQLite WAL database.
- **Fine-Grained 1-Hop Invalidation DAG**: Dependency DAG invalidates only directly affected and 1-hop dependent functions on struct or signature edits instead of triggering global cache flushes.

### Multi-Architecture Binary Loading
- **Pure-Python Parser**: Parses ELF 32/64 (LE/BE), PE32/PE32+ (EXE/DLL), and Mach-O (thin and universal FAT binaries).
- **Sectionless Virtual Addressing**: Derives virtual addresses directly from program headers and load commands when section header tables are stripped or damaged.

### Windows Class & Data Structure Recovery
- **MSVC RTTI Recovery**: Reconstructs `CompleteObjectLocator`, `ClassHierarchyDescriptor`, `BaseClassDescriptor`, and type descriptor chains on PE binaries.
- **MFC Serialization Schema Recovery**: Reconstructs MFC `CRuntimeClass` structures and maps binary deserialization schemas directly from `Serialize()` method implementations.
- **CArchive Decoding**: Decodes MFC `CArchive` binary streams using recovered object schemas.

### GPU Compute Shader Acceleration
- **WGPU ARM64 Sweeps**: DirectX 12 and Vulkan compute shaders scanning ARM64 `ADRP + ADD/LDR` reference pairs across multi-megabyte shared libraries in under 1 second (127.25M–143.95M insn/s).
- **GPU Function Seeder**: Identifies candidate entry points without sequential disassembler sweeping.

### Cross-Version Binary Diffing & Struct Migration
- **CFG Bipartite Matching**: Matches basic blocks using cosine similarity over normalized token sequences.
- **Struct Displacement Shift Migrator**: Detects field movement across binary updates and emits compilable C++ patch diffs.

### SMT P-Code Formal Verification
- **Z3 Solver Backend**: Verifies functional equivalence of lifted P-code blocks against decompiled or modified C AST expressions.
- **Soundness Contract**: Loops exceeding unroll bounds, floating-point arithmetic, and unhandled instructions evaluate to `UNKNOWN` (`equivalent=False`), never returning false `UNSAT`.

---

## 2. Known Limitations & Prototype Boundaries

1. **Standalone Zero-JVM Decompiler is an Experimental Prototype**:
   - The Python-native P-code lifter and AST restructuring pipeline currently decompiles 11 of 154 exports (7.1%) and compiles 7 (4.5%) across four Windows test DLLs (`dbghelp.dll`, `msvcp140.dll`, `version.dll`, `winmm.dll`).
   - For complete decompilation, queries should route through the running Ghidra daemon (`python -m superghidra.core.ghidra_oracle decompile <addr>`). Standalone coverage improvements are targeted for the 1.x roadmap.
2. **Objective-C & Non-MSVC RTTI Recovery Scope**:
   - RTTI recovery currently targets MSVC C++ binaries on Windows PE. The pure-Python `macho_objc_recovery` module is an experimental prototype (currently recovers 0 classes on real-world frameworks such as Sparkle). Full production Objective-C runtime metadata, GCC/Clang Itanium ABI vtables/typeinfo, and Swift 5 nominal type recovery are planned for 1.x.
3. **PDB Export Scope**:
   - The synthetic PDB exporter writes valid MSF 7.0 containers with DBI streams, but lacks CodeView Type (TPI) streams. DWARF 5 export is the supported route for external symbol consumers.
4. **Buffer Compression Extension**:
   - The LZ4 and Zstandard buffer codec prototypes achieve 54% to 85% footprint reduction on synthetic Ghidra-like pages, but Ghidra's internal `LocalManagedBufferFile` requires extension loading to apply compression to live project files.

---

## 3. Path to 1.0.0: The Agent-First Architecture

SuperGhidra is not tagging `1.0.0` today because marquee agent-grade capabilities are still undergoing active design and implementation. The complete architectural roadmap for `1.0.0` is specified in [`docs/specs/SUPERGHIDRA_1_0_0_SPECIFICATION.md`](../specs/SUPERGHIDRA_1_0_0_SPECIFICATION.md), covering:

1. **Pillar 1: Summary-First MCP & Daemon Pagination**: Retained evidence paging (`parent_evidence_id`) in SQLite L2 cache and two-stage dossier retrieval (`analyze_function` → `inspect_analysis_view`).
2. **Pillar 2: Universal `EvidenceEnvelope` & Reconstruction Obligation Ledger**: Explicit tagging (`observed`, `inferred`, `unknown`) and gatekeeping before `merge_fork` commits.
3. **Pillar 3: Inter-Procedural High-P-Code Value Tracing**: Cross-call def-use graphs (`trace_native_values`) and bounds-proven AArch64 jump tables.
4. **Pillar 4: Crash-Resumable Compilable Export**: `superghidra decompile-all --resume` with inode locking and `decompile-index.json`.
5. **Pillar 5: Expanded Ghidra-Free Parsers**: `apple_dispatch.py` (Mach-O dyld chained fixups, Obj-C, `__swift5_types`), `il2cpp_metadata.py` (Unity v24-39), and `rust_go_metadata.py` (`.dep-v0`, `.go.buildinfo`).
6. **Pillar 6: The `superghidra[rea]` Provider Bridge**: High-speed drop-in adapter for REA-compatible agents.
