# Swarm Issue Triage & Engineering Roadmap

This document outlines four targeted issues addressing the substantiated gaps identified in the architectural audit. Each issue includes root causes, implementation specifications, acceptance criteria, and benchmark verification requirements.

---

## Issue #12: Adaptive Small-Binary Hybrid Dispatcher in GPUAdrpScanner
* **Subsystem**: `superghidra/acceleration/gpu_adrp_scanner.py`
* **Root Cause**: On binaries under ~5 MB, WGPU staging buffer allocation and command submission latency (~0.8-1.0 ms) makes GPU scanning slower than CPU NumPy SIMD (which runs directly from CPU cache at >1.4 GB/s).
* **Specification**:
  * Introduce an automatic adaptive threshold `GPU_SCAN_SIZE_THRESHOLD_BYTES = 5 * 1024 * 1024` (5 MB) in `GPUAdrpScanner`.
  * When `backend="auto"`, if binary input size is less than the threshold, automatically route through `NumPyAdrpEngine.scan()`.
  * For inputs $\ge$ 5 MB, route through `_wgpu_engine.scan()`, retaining the high-throughput 4 GB/s GPU pipeline.
  * Allow explicit override via `backend="wgpu"` or `backend="numpy"`.
* **Acceptance Criteria**:
  * 1 MB binary scan latency drops under 0.8 ms on auto mode.
  * 20 MB binary scan retains full GPU throughput (>3.5 GB/s).
  * Unit tests pass in `tests/acceleration/`.

---

## Issue #13: PDB Type-Stream (TPI/IPI) CodeView Leaf Record Serialization
* **Subsystem**: `superghidra/formats/synthetic_symbol_exporter.py`
* **Root Cause**: While MSF 7.0 container emission and the 4,096-bucket GSI public symbol hash stream were implemented in branch `feat/pdb-gsi-hash-stream`, the TPI (Type Program Info) and IPI (Item Program Info) streams omit standard CodeView leaf type records (`LF_STRUCTURE`, `LF_FIELDLIST`, `LF_PROCEDURE`, `LF_ARGLIST`, `LF_POINTER`), preventing debuggers from recovering struct layouts.
* **Specification**:
  * Implement standard CodeView leaf type records in `PDBExporter`:
    * `LF_POINTER` (`0x1002`)
    * `LF_PROCEDURE` (`0x1008`)
    * `LF_ARGLIST` (`0x1201`)
    * `LF_FIELDLIST` (`0x1203`)
    * `LF_MEMBER` (`0x150d`)
    * `LF_STRUCTURE` (`0x1505`)
  * Write these records sequentially into the TPI stream buffer with proper 16-bit length prefix and 32-bit type indices (`0x1000 + i`).
  * Update the TPI stream header (`TPI_HEADER`) with `ti_min = 0x1000`, `ti_max = 0x1000 + count`, and `type_records_bytes`.
* **Acceptance Criteria**:
  * Exported PDB contains valid TPI records verifiable by `dwarf_pdb_preindexer.py`.
  * Unit test validates type stream parsing and struct field offset recovery.

---

## Issue #14: ARM64 Cryptographic Extension Instruction Lifter
* **Subsystem**: `superghidra/lifters/pcode_lifter_bridge.py`
* **Root Cause**: Binaries performing cryptographic operations (e.g., in security sandboxes, TLS stacks, DRM engines) trigger `UNIMPLEMENTED` when encountering ARMv8-A cryptographic extension opcodes.
* **Specification**:
  * Add instruction lifters for ARM64 crypto opcodes:
    * `AESE` (`0x4e284800` mask): AES single round encryption.
    * `AESD` (`0x4e285800` mask): AES single round decryption.
    * `AESMC` (`0x4e286800` mask): AES MixColumns.
    * `AESIMC` (`0x4e287800` mask): AES Inverse MixColumns.
    * `SHA1C`, `SHA1P`, `SHA1M`, `SHA1H`, `SHA256H`, `SHA256H2`: SHA-1 and SHA-256 state updates.
  * Map these instructions to descriptive P-code `CALLOTHER` intrinsics (`"arm64_aese"`, `"arm64_aesd"`, `"arm64_aesmc"`, `"arm64_aesimc"`, `"arm64_sha256h"`, etc.).
* **Acceptance Criteria**:
  * P-code lifter decodes crypto instructions into valid PcodeOps with target vector register inputs/outputs.
  * Unit test verifies lifting of all implemented crypto opcodes without raising `UNIMPLEMENTED`.

---

## Issue #15: Interactive Ghidra GUI Overlay Sync Bridge
* **Subsystem**: `superghidra/integrations/ghidra_gui_overlay_sync.py`
* **Root Cause**: Reverse engineers working inside the native Ghidra GUI cannot interactively view or apply agent symbol renames and function comments stored in `ghidra_overlay.json`.
* **Specification**:
  * Implement `ghidra_gui_overlay_sync.py`:
    * Generates a standalone Python (`ghidra_sync_script.py`) or Java GhidraScript compatible with the Ghidra Script Manager.
    * Reads `ghidra_overlay.json` or `.ghidra-delta.jsonl`.
    * Applies `currentProgram.getSymbolTable().createLabel(...)` for renames.
    * Sets plate/pre/post comments via `currentProgram.getListing().setComment(...)`.
    * Implements interactive dry-run mode and visual diff output for the GUI user.
* **Acceptance Criteria**:
  * Generated script runs cleanly in Headless Ghidra and Ghidra Script Manager.
  * Unit tests verify correct generation of Ghidra script commands from overlay JSON.
