# `superghidra.lifters` — Zero-JVM P-Code Lifter, Z3 SMT Verifier & Multi-Arch Decoders

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/lifters/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`pcode_lifter_bridge.py`](pcode_lifter_bridge.py) | `ARM64PcodeLifter`, `X86_64PcodeLifter`, `PcodeOp`, `PcodeOpcode`, `Varnode`, `AddressSpace`, `PcodeGraphBuilder` | Pure-Python Zero-JVM ARM64 (22 instruction classes) and x86_64 P-Code IR lifters, plus fixed-shape TPU/GNN adjacency tensor builder. |
| [`smt_pcode_verifier.py`](smt_pcode_verifier.py) | `SMTPcodeVerifier`, `PcodeSymbolicSimulator`, `CSymbolicEvaluator`, `CCodeParser`, `SymbolicState`, `VerificationResult`, `CIntrinsic` | Microsoft Z3 bit-vector theorem prover verifying formal semantic equivalence between lifted P-Code and decompiled C ASTs. |
| [`arm_thumb_decode.py`](arm_thumb_decode.py) | `DecodedInsn`, `decode_arm32`, `decode_thumb`, `decode_block`, `extract_cfgs_from_arm_section`, `extract_memory_accesses` | ARM32 (A32) and Thumb/Thumb-2 (T16/T32) instruction decoder, IT-block condition tracker, CFG builder, and struct memory access extractor. |
| [`x86_decode.py`](x86_decode.py) | `X86Insn`, `MemOperand`, `decode`, `decode_stream` | Table-driven 16/32/64-bit x86 decoder supporting REX/VEX/EVEX/XOP, ModRM/SIB/RIP-relative operands, SSE, AVX, and AVX-512. |

## 2. Key Data Structures & Invariants
- **Register 31 Disambiguation (ARM64):** `ARM64PcodeLifter` strictly distinguishes `XZR`/`WZR` (zero constant in `AddressSpace.CONST`) from `SP`/`WSP` (`REG_SP_OFFSET = 0x100` in `AddressSpace.REGISTER`).
- **Z3 SMT Soundness Contract:**
  - `UNSAT` (`equivalent=True`) is returned **only** when bit-exact equivalence is mathematically proven across all 64-bit inputs.
  - `SAT` (`equivalent=False`) provides a concrete `counterexample` and `model_inputs`.
  - Floating-point ops (`FLOAT_*`), indirect/unmodeled calls, `UNIMPLEMENTED` P-Code ops, or loops exceeding `max_loop_unroll` taint symbolic state and return `UNKNOWN` (`equivalent=False`).
- **32-Bit x86 Prefix Invariant:** Bytes `0x40..0x4F` are `INC`/`DEC` instructions in 32-bit mode (`mode=32`) and REX prefixes only in 64-bit mode (`mode=64`).

## 3. Quick-Test Command
```powershell
python -m pytest tests/lifters -q
```
