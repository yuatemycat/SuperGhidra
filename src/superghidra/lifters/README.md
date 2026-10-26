# `superghidra.lifters` — P-Code Lifter, Z3 SMT Verifier & Multi-Arch Decoders

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/lifters/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`pcode_lifter_bridge.py`](pcode_lifter_bridge.py) | `UnifiedPcodeLifter`, `PypcodeSleighBackend`, `DaemonPcodeBackend`, `ARM64PcodeLifter`, `X86_64PcodeLifter`, `PcodeOp`, `PcodeOpcode`, `Varnode`, `AddressSpace`, `AddrSpace`, `PcodeGraphBuilder` | Multi-tier P-Code IR lifting across `pypcode` SLEIGH bindings, persistent Ghidra daemon TCP JSON RPC (`127.0.0.1:5073`), and built-in pure-Python ARM64 and `x86_decode`-backed x86_64/x86 lifters, plus Varnode adjacency tensor builder. |
| [`smt_pcode_verifier.py`](smt_pcode_verifier.py) | `SMTPcodeVerifier`, `PcodeSymbolicSimulator`, `CSymbolicEvaluator`, `CCodeParser`, `SymbolicState`, `VerificationResult`, `EquivalenceResult`, `CIntrinsic` | Microsoft Z3 bit-vector theorem prover verifying formal semantic equivalence between lifted P-Code (or raw x86_64/ARM64 byte sequences via `verify_byte_sequences`) and decompiled C ASTs. |
| [`arm_thumb_decode.py`](arm_thumb_decode.py) | `DecodedInsn`, `decode_arm32`, `decode_thumb`, `decode_block`, `extract_cfgs_from_arm_section`, `extract_memory_accesses` | ARM32 (A32) and Thumb/Thumb-2 (T16/T32) instruction decoder, IT-block condition tracker, CFG builder, and struct memory access extractor. |
| [`x86_decode.py`](x86_decode.py) | `X86Insn`, `MemOperand`, `decode`, `iter_decode` | Table-driven 16/32/64-bit x86 decoder supporting REX/VEX/EVEX/XOP, ModRM/SIB/RIP-relative operands, SSE, AVX, and AVX-512. |

## 2. Multi-Tier P-Code Lifting (`UnifiedPcodeLifter`)
- **Resolution Order (`backend="auto"`):**
  1. `PypcodeSleighBackend`: uses `pypcode` SLEIGH bindings when installed (`"x86:LE:64:default"`, `"x86:LE:32:default"`, `"AArch64:LE:64:v8A"`, `"ARM:LE:32:v8"`, or short aliases `"x86_64"`, `"x86"`, `"arm64"`, `"arm"`), mapping SLEIGH register offsets via `ctx.registers` reverse lookup into SuperGhidra's canonical `AddrSpace` and register offsets.
  2. `DaemonPcodeBackend`: queries the persistent SuperGhidra Oracle Daemon over TCP JSON RPC (`{"cmd": "pcode", "address": ..., "max_insns": ...}`) and translates returned P-code dicts into canonical `PcodeOp`s.
  3. Built-in pure-Python lifters: `ARM64PcodeLifter` for `arm64` and `X86_64PcodeLifter` (backed by `superghidra.lifters.x86_decode` for ModRM/SIB/displacement/immediate decoding) for `x86_64` and `x86`.
- `lift_with_provenance(code, base_addr, max_insns, backend)` returns `(ops, backend_used)` so callers can inspect whether `"pypcode"`, `"daemon"`, or `"builtin"` produced the IR.

## 3. Key Data Structures & Invariants
- **Register 31 Disambiguation (ARM64):** `ARM64PcodeLifter` strictly distinguishes `XZR`/`WZR` (zero constant in `AddressSpace.CONST`) from `SP`/`WSP` (`31 * 8` in `AddressSpace.REGISTER`).
- **Z3 SMT Soundness Contract:**
  - `UNSAT` (`equivalent=True`) is returned **only** when bit-exact equivalence is mathematically proven across all 64-bit inputs.
  - `SAT` (`equivalent=False`) provides a concrete `counterexample` and `model_inputs`.
  - Floating-point ops (`FLOAT_*`), indirect/unmodeled calls, `UNIMPLEMENTED` P-Code ops, or loops exceeding `max_loop_unroll` taint symbolic state and return `UNKNOWN` (`equivalent=False`).
- **32-Bit x86 Prefix Invariant:** Bytes `0x40..0x4F` are `INC`/`DEC` instructions in 32-bit mode (`mode=32`) and REX prefixes only in 64-bit mode (`mode=64`).

## 4. Quick-Test Command
```powershell
python -m pytest tests/lifters -q
```
