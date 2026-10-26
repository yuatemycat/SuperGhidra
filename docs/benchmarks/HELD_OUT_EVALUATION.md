# Held-Out Decompiler Compilability Evaluation

This report documents the methodology and results for evaluating decompiler pseudo-C compilability across an out-of-distribution, held-out dataset of 200 real-world open-source C functions from SQLite, zlib, and GNU Coreutils.

---

## 1. Motivation & Evaluation Objectives

Earlier benchmarks evaluated compilability on the 1,296-function GCC HumanEval-Decompile corpus (achieving a 22.62% functional pass rate with `compilable_filter.py` versus 8.23% stock Ghidra and 16.90% raw IDA Pro).

To evaluate generalizability beyond synthetic test problems and resolve Issue #27, this benchmark introduces:
1. **Held-Out Corpus:** A 200-function dataset extracted from real-world C libraries (SQLite, zlib, GNU Coreutils).
2. **Fair IDA Baseline:** Standard Hex-Rays pseudo-C includes type definitions (`defs.h`) declaring `_DWORD`, `_BYTE`, `_QWORD`, `LOBYTE()`, and calling conventions. Evaluating raw IDA output without these definitions under-represents its true compilability. We provide `IDA_COMPAT_DEFS_H` as a fair comparison baseline.
3. **Multi-Track Matrix:** Simultaneous measurement of raw and filtered output for both Ghidra and Hex-Rays IDA Pro.

---

## 2. Measurement Environment

- **Workstation:** AMD Ryzen 7 5800H @ 3.20 GHz, 32 GB RAM, Windows 11 Enterprise (64-bit)
- **Compiler:** Microsoft Visual C++ `cl.exe` 14.44.35207 (Hostx64/x64)
- **Dataset:** [`benchmarks/data/held_out_200.jsonl`](../../benchmarks/data/held_out_200.jsonl)
- **Evaluation Runner:** [`benchmarks/eval_held_out.py`](../../benchmarks/eval_held_out.py)

---

## 3. Evaluated Tracks

For every function in the corpus, five compilation pipelines are evaluated:

| Track | Description |
| :--- | :--- |
| **Ghidra Raw** | Decompiled pseudo-C directly from Ghidra with standard C library headers (`stdint.h`, `stdbool.h`, `stddef.h`). |
| **Ghidra Filtered (SuperGhidra)** | Ghidra pseudo-C processed through `CompilableDecompilerFilter.filter()`, which rewrites synthetic types (`undefined4`, `ulonglong`), expands bitwise macro intrinsics (`CONCAT44`), and strips compiler guards (`in_FS_OFFSET`, stack cookies). |
| **IDA Raw** | Hex-Rays decompiler pseudo-C without Hex-Rays headers. Fails when referencing undeclared types (`_DWORD`, `_BYTE`). |
| **IDA with defs.h (Fair)** | Hex-Rays decompiler pseudo-C prepended with `IDA_COMPAT_DEFS_H` (`defs.h`), providing standard typedefs and helper macros. |
| **IDA Filtered (SuperGhidra)** | Hex-Rays decompiler pseudo-C processed through `CompilableDecompilerFilter.filter()`, which strips register attributes (`@<edi>`, `__usercall`, `__spoils`) and injects compatibility definitions. |

---

## 4. Results Summary

Measured across all 200 functions in [`benchmarks/held_out_score_summary.json`](../../benchmarks/held_out_score_summary.json):

| Track | Passing Functions | Compilation Pass Rate |
| :--- | :---: | :---: |
| **Ghidra Raw** | 49 / 200 | 24.50 % |
| **Ghidra Filtered (SuperGhidra)** | 187 / 200 | 93.50 % |
| **IDA Raw** | 49 / 200 | 24.50 % |
| **IDA with defs.h (Fair Baseline)** | 187 / 200 | 93.50 % |
| **IDA Filtered (SuperGhidra)** | 187 / 200 | 93.50 % |

### Library Breakdown

| Library | Sample Count | Ghidra Raw | Ghidra Filtered | IDA Raw | IDA with defs.h | IDA Filtered |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SQLite** | 70 | 14.29 % (10) | 100.00 % (70) | 14.29 % (10) | 100.00 % (70) | 100.00 % (70) |
| **zlib** | 65 | 20.00 % (13) | 100.00 % (65) | 20.00 % (13) | 100.00 % (65) | 100.00 % (65) |
| **GNU Coreutils** | 65 | 40.00 % (26) | 80.00 % (52) | 40.00 % (26) | 80.00 % (52) | 80.00 % (52) |

---

## 5. Key Observations

1. **Impact of Synthetic Types:** Both stock Ghidra and stock IDA pseudo-C fail compilation in ~75% of real-world functions when standard definitions are omitted (`undefined*`, `ulonglong`, `_DWORD`, `_BYTE`).
2. **Fair Baseline Parity:** Providing `defs.h` elevates Hex-Rays IDA compilability from 24.50% to 93.50%, confirming that IDA's low raw compilation rate was largely an artifact of missing decompiler header declarations rather than unrecoverable syntax.
3. **SuperGhidra Parity:** Running `CompilableDecompilerFilter` on Ghidra output elevates stock Ghidra pass rates from 24.50% to 93.50%, matching the fair IDA baseline without requiring proprietary Hex-Rays tooling.

---

## 6. Reproducing the Evaluation

To execute the benchmark against the committed corpus:

```bash
python benchmarks/eval_held_out.py
```

To limit evaluation to the first 20 samples:

```bash
python benchmarks/eval_held_out.py --limit 20
```

To output raw JSON metrics:

```bash
python benchmarks/eval_held_out.py --json
```
