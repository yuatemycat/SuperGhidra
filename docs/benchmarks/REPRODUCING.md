# Reproducing SuperGhidra Benchmarks

This document describes how published performance figures were measured and provides the steps to reproduce them locally.

---

## 1. Measurement Baseline & Test Machine

Published benchmark figures in this repository were measured on a reference workstation with the following specifications:

- **Operating System:** Windows 11 Enterprise (64-bit)
- **CPU:** AMD Ryzen 7 5800H @ 3.20 GHz (8 cores, 16 threads)
- **Memory:** 32 GB DDR4 @ 3200 MT/s
- **Disk:** NVMe SSD (PCIe 3.0 x4)
- **Runtimes:** Python 3.12.x, OpenJDK 21.0.2, Ghidra 11.2-DEV (PyGhidra 2.0.0)
- **Compiler:** GCC 13.2.0 (x86_64-w64-mingw32 / aarch64-linux-gnu-gcc)

All figures state the measurement hardware and dataset size in their respective reports.

---

## 2. Micro-Benchmarks (Open & Fully Reproducible)

You can run all core micro-benchmarks on your own machine without requiring external or proprietary binaries:

```bash
python scripts/reproduce_benchmarks.py
```

To output machine-readable JSON:

```bash
python scripts/reproduce_benchmarks.py --json
```

### Measured Subsystems
1. **ELF & PE Binary Loaders:** Measures parsing latency and MB/s throughput over redistributable sample binaries ([`sample_arm64.so`](../../tests/fixtures/binaries/sample_arm64.so) and [`sample_x64.dll`](../../tests/fixtures/binaries/sample_x64.dll)).
2. **Compilable Decompiler Filter:** Measures throughput of C sanitization (stripping compiler intrinsics, rewriting types, normalizing pointer strides) on synthetic decompilation fragments.
3. **ARM64 ADRP Scanner:** Measures SIMD NumPy scanning throughput for ADRP + ADD/LDR register pair resolution over ARM64 code.
4. **Buffer Compression (LZ4 / Zstd):** Measures 16 KB page compression ratios and throughput over synthetic Ghidra DB buffer pages.

---

## 3. HumanEval Decompiler Benchmarks

HumanEval scores are derived from compiling the 164 HumanEval problem functions with GCC into native binaries across optimization levels (`-O0`, `-O1`, `-O2`, `-O3`), decompiling them, and evaluating functional equivalence.

The exact summary is recorded in [`docs/benchmarks/humaneval/gcc_score_summary.json`](humaneval/gcc_score_summary.json):
- **Evaluable functions:** 1,300
- **Corpus pass rate:** 22.62% (294 / 1,300)
- **Held-out test split:** 25.26% (98 / 388)

To verify that published markdown reports match the committed summary:

```bash
python -m unittest tests/benchmarks/test_published_numbers.py
```

---

## 4. Proprietary & Game Binary Benchmarks

Certain real-world stress tests (such as live binary upgrades or 50 MB mobile binaries) reference external binaries not redistributable in git.

To run these tests against your own binaries, set the corresponding environment variables:

```bash
export SUPERGHIDRA_TEST_BINARY_ARM64="/path/to/your/libgame.so"
export SUPERGHIDRA_TEST_BINARY_X64="/path/to/your/app.dll"
```

When these variables are unset, test suites fall back to the redistributable fixtures in `tests/fixtures/binaries/` and execute green in CI.
