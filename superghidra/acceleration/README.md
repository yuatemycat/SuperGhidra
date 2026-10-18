# `superghidra.acceleration` — WGPU/CUDA/SIMD ARM64 ADRP Scanner & Parallel Function Seeder

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/acceleration/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`gpu_adrp_scanner.py`](gpu_adrp_scanner.py) | `GPUAdrpScanner`, `ADRPMatch`, `NumPyAdrpEngine`, `decode_adrp_target`, `decode_add_imm`, `decode_ldr_imm`, `benchmark_scanner` | Sweeps ARM64 `.text` sections for `ADRP` + `ADD`/`LDR` pairs across `+4`, `+8`, `+12` byte windows via WGPU compute shaders, PyTorch CUDA, or vectorized NumPy SIMD fallback. |
| [`gpu_function_seeder.py`](gpu_function_seeder.py) | `GPUFunctionSeeder`, `FunctionSeed` | Parallel 32-bit instruction classifier discovering ARM64 function entry points (`PACIASP`, `STP x29, x30, [sp, #-imm]!`, `SUB sp, sp, #imm`, `BTI`, `BL` targets, and `.rodata`/`.data.rel.ro` code pointers). |

## 2. Key Data Structures & Invariants
- **`ADRPMatch` Resolution:**
  - `target_page = (adrp_pc & ~0xFFF) + sign_extend_21(immhi:immlo) * 4096`.
  - `decode_ldr_imm` strictly rejects `STR` instructions (`opc == 0` when `v == 0`, or `opc & 1 == 0` for SIMD/FP `Q` loads) and scales 128-bit `LDR Q` unsigned offsets by `16` (`size == 0 and v == 1 and (opc & 2) != 0`).
  - Backend equivalence invariant: `wgpu`, `cuda`, and `numpy`/`cpu` backends must return identical sorted `ADRPMatch` results without silently truncating hits when candidate buffers fill.
- **`FunctionSeed` Multi-Source Scoring:** Combines prologue flags, incoming `BL` call targets, `RET` boundary precursors, and data section function pointers into calibrated confidence scores.

## 3. Quick-Test Command
```powershell
python -m pytest tests/acceleration -q
```
