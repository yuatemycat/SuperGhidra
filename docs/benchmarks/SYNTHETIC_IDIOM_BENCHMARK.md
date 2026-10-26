# Synthetic Decompiler Idiom Benchmark (200 Variations)

This report documents the methodology and results for evaluating `CompilableDecompilerFilter` on a synthetic regression suite of 200 test variations across 17 decompiler idiom templates.

---

## 1. Scope & Methodology

This benchmark measures whether decompiler pseudo-C normalizations produce valid, compilable C under standard native compilers (MSVC `cl.exe` and GCC).

Important methodology clarifications:
1. **Synthetic Idiom Corpus:** The dataset (`benchmarks/data/held_out_200.jsonl`) consists of 200 parameterized variations derived from 17 core systems C idiom patterns (bit rotations, varint encoding, hash combination, byte extraction, checksum accumulation, etc.).
2. **Synthetic Tool Snippets:** The evaluation does not execute live instances of Ghidra or IDA Pro on binary libraries. Instead, `ghidra_pseudo` and `ida_pseudo` contain synthetic representations of idioms emitted by Ghidra (such as `undefined4`, `ulonglong`, `CONCAT44`, `in_FS_OFFSET`) and Hex-Rays (such as `_DWORD`, `_BYTE`, `_QWORD`, `LOBYTE()`, `__PAIR64__`, `__fastcall`).
3. **Normalization Regression:** The benchmark tests whether `CompilableDecompilerFilter` correctly rewrites synthetic decompiler types into standard C types (`uint32_t`, `uint64_t`, bitwise shifts, standard headers) so the code compiles.

---

## 2. Measurement Environment

- **Workstation:** AMD Ryzen 7 5800H @ 3.20 GHz, 32 GB RAM, Windows 11 Enterprise (64-bit)
- **Compiler:** Microsoft Visual C++ `cl.exe` 14.44.35207 (Hostx64/x64) and GCC 13.2.0 (Ubuntu x86_64)
- **Dataset:** [`benchmarks/data/held_out_200.jsonl`](../../benchmarks/data/held_out_200.jsonl)
- **Evaluation Runner:** [`benchmarks/eval_held_out.py`](../../benchmarks/eval_held_out.py)

---

## 3. Evaluated Tracks

For each of the 200 synthetic idiom variations, five compilation pipelines are evaluated:

| Track | Description |
| :--- | :--- |
| **Ghidra Raw** | Synthetic Ghidra pseudo-C with standard C headers (`stdint.h`, `stdbool.h`, `stddef.h`). Fails on undeclared types like `undefined4` and `CONCAT44`. |
| **Ghidra Filtered (SuperGhidra)** | Synthetic Ghidra pseudo-C processed through `CompilableDecompilerFilter.filter()`, which rewrites `undefined*` and `ulonglong`, expands `CONCAT44`, and strips stack cookie guards. |
| **IDA Raw** | Synthetic Hex-Rays pseudo-C without header definitions. Fails on undeclared types like `_DWORD` and `_BYTE`. |
| **IDA with defs.h (Fair Baseline)** | Synthetic Hex-Rays pseudo-C prepended with `IDA_COMPAT_DEFS_H` (`defs.h`), providing standard typedefs and helper macros. |
| **IDA Filtered (SuperGhidra)** | Synthetic Hex-Rays pseudo-C processed through `CompilableDecompilerFilter.filter()`, which strips calling convention keywords and injects compatibility definitions. |

---

## 4. Results Summary

Measured across all 200 synthetic variations in [`benchmarks/held_out_score_summary.json`](../../benchmarks/held_out_score_summary.json):

| Track | Passing Variations | Compilation Pass Rate |
| :--- | :---: | :---: |
| **Ghidra Raw** | 49 / 200 | 24.50 % |
| **Ghidra Filtered (SuperGhidra)** | 187 / 200 | 93.50 % |
| **IDA Raw** | 49 / 200 | 24.50 % |
| **IDA with defs.h (Fair Baseline)** | 187 / 200 | 93.50 % |
| **IDA Filtered (SuperGhidra)** | 187 / 200 | 93.50 % |

### Breakdown by Category

| Category | Variation Count | Ghidra Raw | Ghidra Filtered | IDA Raw | IDA with defs.h | IDA Filtered |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **sqlite-derived idioms** | 70 | 14.29 % (10) | 100.00 % (70) | 14.29 % (10) | 100.00 % (70) | 100.00 % (70) |
| **zlib-derived idioms** | 65 | 20.00 % (13) | 100.00 % (65) | 20.00 % (13) | 100.00 % (65) | 100.00 % (65) |
| **coreutils-derived idioms** | 65 | 40.00 % (26) | 80.00 % (52) | 40.00 % (26) | 80.00 % (52) | 80.00 % (52) |

---

## 5. Observations

1. **Undeclared Decompiler Types:** Both stock Ghidra and IDA pseudo-C fail compilation in ~75% of synthetic idiom variations when standard definitions are omitted (`undefined*`, `ulonglong`, `_DWORD`, `_BYTE`).
2. **Header Injection Parity:** Supplying `defs.h` enables compilation of synthetic IDA snippets (from 24.50% to 93.50%). Similarly, `CompilableDecompilerFilter` normalizes Ghidra pseudo-C to 93.50% without requiring proprietary headers.
3. **Caveat on Real-World Parity:** This benchmark specifically tests type and macro rewriting on 17 idiom templates. It is not an end-to-end decompilation comparison on arbitrary compiled binaries. Real decompilation from binary machine code requires full decompilation pipelines.

---

## 6. Reproducing the Evaluation

To execute the benchmark runner:

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
