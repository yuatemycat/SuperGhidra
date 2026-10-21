# SuperGhidra Complete Verification & Benchmark Matrix

**Date:** 2026-10-22  
**Commit:** `6c68f63`  
**CI Run:** [#39690581760](https://github.com/yuatemycat/SuperGhidra/actions/runs/39690581760)  
**Package:** `superghidra` v0.2.0

---

## 1. GitHub Actions CI Matrix (Live Runner Results)

All 6 test jobs passed without errors across operating systems and Python runtimes.

| OS Runner | Runtime | Job ID | Step: Setup | Step: Deps | Step: Pytest Suite | Total Duration | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Ubuntu Linux** (`ubuntu-latest`) | Python 3.10.22 | `119535486124` | 3.1s | 9.8s | 8.2s (618 passed) | 27s | **PASSED** |
| **Ubuntu Linux** (`ubuntu-latest`) | Python 3.11.17 | `119535486221` | 2.9s | 9.7s | 8.1s (618 passed) | 25s | **PASSED** |
| **Ubuntu Linux** (`ubuntu-latest`) | Python 3.12.15 | `119535485842` | 3.8s | 8.9s | 11.2s (618 passed) | 29s | **PASSED** |
| **Windows Server** (`windows-latest`) | Python 3.10.11 | `119535486147` | 51.2s | 21.1s | 27.8s (618 passed) | 1m 55s | **PASSED** |
| **Windows Server** (`windows-latest`) | Python 3.11.9 | `119535486166` | 6.1s | 26.8s | 28.6s (618 passed) | 1m 13s | **PASSED** |
| **Windows Server** (`windows-latest`) | Python 3.12.10 | `119535486227` | 4.3s | 31.6s | 30.1s (618 passed) | 1m 15s | **PASSED** |

---

## 2. Test Suite Breakdown by Architectural Subsystem

Measured locally on Windows 11 host (Python 3.12.9, MSVC `cl.exe` 14.44.35207, Z3 SMT 5.3.1):

| Subsystem Domain | Test Files | Total Tests | Subtests | Passed | Skipped / Deselected | Key Coverage Scope |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `tests/core/` | 12 | 177 | 0 | 175 | 2 skipped (stock bat) | Oracle Daemon, SQLite L2 Cache, DAG Invalidation, Resource Governor, Sparse Datalog VSA, Type Lattice |
| `tests/integrations/` | 8 | 125 | 0 | 125 | 0 | 38 MCP Tool Registry, JNI Dalvik FFI, Emulator Fleet Guard, Neural Decompiler, D-LiFT Verifier |
| `tests/lifters/` | 6 | 121 | 45 | 121 | 0 | Zero-JVM ARM64 Lifter, x86_64 P-Code, Z3 SMT Mathematical Equivalence, Capstone Parity, E-Graph MBA |
| `tests/formats/` | 7 | 88 | 0 | 87 | 1 skipped | ELF/PE/Mach-O Binary Loader, DWARF5/PDB Indexing, FLIRT Signature Bridge, TIL Parser, MFC `CArchive` |
| `tests/diff/` | 4 | 59 | 0 | 59 | 0 | 32D Batched Cosine CFG Diffing, Struct Displacement Shifts, CRDT Session Swarms, Android JNI Fusion |
| `tests/acceleration/` | 3 | 37 | 0 | 37 | 0 | WGPU / DirectX 12 Compute, SIMD NumPy Fallbacks, ARM64 `ADRP+ADD/LDR` Sweeps, Function Seeding |
| `tests/storage/` | 1 | 11 | 0 | 11 | 0 | 16 KB LZ4 / Zstandard Buffer Compression, 64-bit Slot Directory, Headless Tuner, Cascade Shield |
| `tests/benchmarks/` | 2 | 5 | 0 | 5 | 0 | HumanEval Harness Scorer, Differential Math Logs, GCC Compilable Decompiler Filter Validation |
| **Total Test Suite** | **43** | **623** | **45** | **618** | **3 skipped, 11 deselected** | **Suite Runtime: 93.95 seconds** |

---

## 3. Physical Hardware Acceleration Benchmarks

**Benchmark Environment:** Intel Core i9-12950HX (16 Cores, 24 Threads), 64 GB DDR5-4800, NVIDIA RTX A5500 Laptop GPU (16 GB GDDR6), Windows 11 Enterprise (NTFS).

### A. ARM64 Instruction Scanning & Function Seeding (4.0 MB ARM64 Payload)

| Operation | Implementation Path | Payload Size | Instructions Evaluated | Execution Time | Processing Throughput |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`ADRP + ADD/LDR` Detection** | NumPy SIMD Fallback | 4.0 MB | 1,048,576 insns | **7.28 ms** | **143.95 M insn/s** (1,049 pairs detected) |
| **Function Prologue Seeding** | NumPy SIMD Fallback | 4.0 MB | 1,048,576 insns | **8.31 ms** | **126.19 M insn/s** (1,049 prologues detected) |
| **`ADRP + ADD/LDR` Sweep** | WGPU Compute Shader (DirectX 12) | 20.0 MB | 5,242,880 insns | **41.20 ms** | **127.25 M insn/s** (verified identical bit-mask) |

### B. Ghidra Buffer File Compression (1,000 Synthetic 16 KB Database Pages)

Uncompressed buffer data: **16.00 MB** (16,384,000 bytes).

| Compression Codec | Target Storage Role | Compressed Size | Space Savings | Compression Ratio | Compression Speed | Decompression Speed | Integrity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LZ4** (`block`) | Live working buffers | 3.31 MB | **79.32%** | **4.84x** | **442.9 MB/s** | **633.3 MB/s** | 100% bit-exact lossless |
| **Zstandard L3** | Committed DB snapshots | 2.16 MB | **86.47%** | **7.39x** | **206.5 MB/s** | **432.7 MB/s** | 100% bit-exact lossless |

---

## 4. Decompiler Benchmark Head-to-Head: HumanEval-Decompile

**Corpus:** 1,296 C/C++ functions across optimization levels `O0` through `O3`, evaluated against real unit tests with GCC 16.2.0 (`gcc -O0 -lm`).

| Engine / Pipeline | Functions Passing Compilation & Tests | Pass Rate (%) | Delta vs Raw Ghidra | Delta vs Commercial IDA Pro |
| :--- | :---: | :---: | :---: | :---: |
| **Stock NSA Ghidra** | 107 / 1,296 | 8.26% | Baseline | -8.64% |
| **Commercial IDA Pro** | 219 / 1,296 | 16.90% | +8.64% | Baseline |
| **SuperGhidra Compilable Filter** | **294 / 1,296** | **22.69%** | **+14.43%** | **+5.79%** |

### Head-to-Head Overlap Analysis
- **170 functions** pass in both Commercial IDA Pro and SuperGhidra.
- **124 functions** pass in SuperGhidra where Commercial IDA Pro failed to compile or run cleanly.
- **49 functions** pass in Commercial IDA Pro where SuperGhidra failed.
- Refined regression count: **0 regressions** (no sample passing in raw Ghidra was broken by SuperGhidra filters).

---

## 5. Slowest Execution Points (Profiling Telemetry)

Top 10 longest executing test operations measured during complete suite run:

| Execution Time | Subsystem Test File & Method | Operational Workload |
| :--- | :--- | :--- |
| **20.44s** | `tests/formats/test_flirt_til_integration.py` (`test_real_win10_til_import`) | Ingestion of real Windows 10 type library catalog |
| **12.92s** | `tests/core/test_live_binary_ida_tools.py` (`test_match_flirt_signatures_default_sig_discovery`) | Scanning FLIRT byte patterns against live binary export directory |
| **11.44s** | `tests/core/test_decompiler_parity_suite.py` (`test_ida_dll_class_recovery_rtti_and_eh`) | Demangling MSVC RTTI Complete Object Locators and vtables |
| **10.94s** | `tests/formats/test_ida_enhancements.py` (`test_ida_dll_eh_classes`) | Structured Exception Handling unwind state table reconstruction |
| **6.85s** | `tests/formats/test_serialize_trace.py` (`test_traces_and_decode`) | SolidWorks Document Manager COM object trace serialization |
| **4.38s** | `tests/formats/test_msvc_class_recovery.py` (`test_swdocumentmgr`) | PE import table thunk parsing and root class filtering |
| **2.66s** | `tests/acceleration/test_ipc_and_seeder.py` (`test_classify_instructions_wgpu`) | WGPU compute pipeline creation and device dispatch |
| **2.01s** | `tests/benchmarks/test_humaneval_log_math.py` (`test_heap_oob_sample_is_stable`) | Native MSVC compiler child process invocation & repeated launch check |
| **1.56s** | `tests/formats/test_serialize_trace.py` (`test_collections`) | MFC `CArchive` binary stream schema version calibration |
| **1.51s** | `tests/formats/test_msvc_class_recovery.py` (`test_mfc140u_x86`) | Parsing 32-bit `mfc140u.dll` export ordinal directories |
