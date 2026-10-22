# SuperGhidra Out-of-Distribution (OOD) Systems Benchmark Report

> **Audit Date:** October 2026  
> **Methodology:** Concrete compilation & differential execution against MSVC/GCC. Zero synthetic mocks.

## 1. Problem Statement: The LLM Benchmark Contamination Trap

Traditional neural decompiler benchmarks (such as HumanEval-Decompile) evaluate models on small programming
puzzles (e.g. `has_close_elements`, `separate_paren_groups`) that directly overlap with LLM pretraining datasets.
Under those contaminated sets, LLMs achieve 30-40% apparent pass rates by recalling memorized Python/C
source patterns, rather than performing genuine binary semantic lifting.

This benchmark tests **6 real-world systems workloads** that require low-level memory layouts, bitwise state
machines, unaligned pointer math, and concurrency invariants absent from textbook puzzle datasets.

## 2. Empirical Head-to-Head Results Matrix

| Workload ID | Category | Raw Ghidra Semantics | LLM Raw Syntax ($R_{syn}$) | LLM Semantic Pass ($R_{sem}$) | Gate 2 Hallucination Catch | SuperGhidra Verified | Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `SHA256_ROUND` | Cryptographic Primitives | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** | 530.5 ms |
| `CHACHA20_QR` | Cryptographic Primitives | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** | 545.7 ms |
| `RFC1071_CHECKSUM` | Network Protocols | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** | 634.5 ms |
| `LEB128_DECODE` | Binary Serialization | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** | 647.1 ms |
| `SPSC_RING_BUFFER` | Operating System Kernels | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** | 2944.5 ms |
| `SLAB_ALLOC_HEADER` | Memory Allocators | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** | 532.7 ms |

## 3. Summary Statistics & Key Findings

- **Evaluated Workloads:** 6 real-world systems kernels (Crypto, Protocols, Allocators, SPSC Ring Buffers).
- **LLM Raw Syntax Pass Rate ($R_{syn}$):** 6/6 (100.0%) — The LLM produces syntactically plausible C code that easily compiles.
- **LLM Semantic Pass Rate ($R_{sem}$):** 0/6 (0.0%) — Despite compiling, **0%** of raw LLM predictions passed differential execution due to subtle binary hallucinations.
- **SuperGhidra Gate 2 Catch Rate:** 6/6 (100.0%) — Every single LLM hallucination was caught and rejected before commit.
- **SuperGhidra Verified Semantic Pass Rate:** 6/6 (100.0%) — Verified candidates preserve 100% bit-exact correctness with readable names.

## 4. Discovered LLM Hallucination Failure Modes in Systems Binaries

1. **Rotation Degradation (`SHA256_ROUND`, `CHACHA20_QR`):** LLMs frequently confuse bitwise circular rotations (`(x >> n) | (x << (32 - n))`) with simple arithmetic shifts (`x >> n`), or invert shift direction (`<<` vs `>>`). While compiling cleanly, cryptographic outputs are corrupted immediately.
2. **Missing Accumulator Folds (`RFC1071_CHECKSUM`):** The LLM omits the final end-around carry loop `while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);`, producing invalid IP checksums.
3. **Sign-Extension Corruption (`LEB128_DECODE`):** Decompilers emit `unsigned char *`, but the LLM types the buffer as `char *`. Bit 7 triggers sign-extension to `0xFFFFFFFFFFFFFFE5`, corrupting multi-byte integers.
4. **Struct Alignment & Padding Amnesia (`SPSC_RING_BUFFER`):** The LLM calculates struct offsets naively assuming tight packing (0x0C) instead of honoring 64-bit natural pointer alignment padding (0x10).
5. **Predicate Inversion (`SLAB_ALLOC_HEADER`):** In low-level bitflag checks (`flags & 0x1`), the LLM inverts the `if` condition branch, turning free chunks into in-use allocations.