# `superghidra.diff` — Cosine CFG Diff Engine, Struct Shift Migrator, Evidence Ledger & Semantic Delta Log

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/diff/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`binary_diff_engine.py`](binary_diff_engine.py) | `BatchedBinaryMatcher`, `CFGFeatureExtractor`, `DiffResult`, `FunctionCFG`, `BasicBlock`, `InstructionInfo`, `FunctionMatch`, `extract_cfgs_from_binary`, `extract_cfgs_from_arm64_bytes` | Extracts L2-normalized 32-dimensional topological/opcode CFG vectors and pairs functions across stripped binaries via mutual Top-1 or greedy cosine similarity. |
| [`struct_shift_migrator.py`](struct_shift_migrator.py) | `StructShiftMigrator`, `MemoryAccess`, `ShiftType`, `FieldMigration`, `StructInsertion`, `MigrationReport`, `migrate_struct_shifts`, `decode_arm64_memory_access`, `decode_x86_64_memory_accesses` | Detects cross-version struct layout drift (`delta = new_offset - old_offset`) across ARM64, ARM32/Thumb-2, and x86/x64 (including SSE/AVX) binaries and emits C++ header patches. |
| [`evidence_ledger.py`](evidence_ledger.py) | `ReconstructionObligationLedger`, `ProofObligation`, `ObligationType`, `ObligationStatus`, `VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`, `CheckResult` | Formal mathematical safety gate verifying VTable slot indices, constructor allocation sizes, and field natural alignments before allowing symbol commits. |
| [`semantic_delta_log.py`](semantic_delta_log.py) | `SemanticDeltaLog`, `DeltaMigrationEngine`, `DeltaMigrationReport`, `SemanticEvent`, `DeltaEventType` | Append-only git-mergeable `.ghidra-delta.jsonl` event log with SHA-256 cryptographic proof hashes and cross-binary migration replay. |

## 2. Key Data Structures & Invariants
- **EvidenceLedger Soundness Invariant:**
  - `RENAME` obligations require substantive structural proof (e.g., verified call-target RVA, string reference, or SMT equivalence)—`parameter_count` alone is never sufficient.
  - Any exception during verifier execution marks the obligation `REJECTED` (`is_safe=False`).
  - Stack-pointer (`sp`/`x29`/`rsp`/`rbp`) relative `STP`/`LDP` frame saves are never counted as heap struct field displacements.
- **Unmatched Diff Invariant:** `StructShiftMigrator` never pairs unrelated functions by positional index when CFG similarity and export names fail to match.
- **Delta Log Replay Invariant:** `SemanticDeltaLog` preserves chronological `A -> B -> A` rename cycles accurately upon replay.

## 3. Quick-Test Command
```powershell
python -m pytest tests/diff -q
```
