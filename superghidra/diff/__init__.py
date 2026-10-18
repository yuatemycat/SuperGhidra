"""SuperGhidra Diff Domain: Batched Cosine CFG Diffing, Struct Shift Migrator, Evidence Ledger & Semantic Delta Log."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "BatchedBinaryMatcher": ("superghidra.diff.binary_diff_engine", "BatchedBinaryMatcher"),
    "CFGFeatureExtractor": ("superghidra.diff.binary_diff_engine", "CFGFeatureExtractor"),
    "DiffResult": ("superghidra.diff.binary_diff_engine", "DiffResult"),
    "FunctionCFG": ("superghidra.diff.binary_diff_engine", "FunctionCFG"),
    "FunctionMatch": ("superghidra.diff.binary_diff_engine", "FunctionMatch"),
    "decode_arm64_instruction": ("superghidra.diff.binary_diff_engine", "decode_arm64_instruction"),
    "extract_cfgs_from_arm64_bytes": ("superghidra.diff.binary_diff_engine", "extract_cfgs_from_arm64_bytes"),
    "extract_cfgs_from_binary": ("superghidra.diff.binary_diff_engine", "extract_cfgs_from_binary"),
    "MemoryAccess": ("superghidra.diff.struct_shift_migrator", "MemoryAccess"),
    "ShiftType": ("superghidra.diff.struct_shift_migrator", "ShiftType"),
    "FieldMigration": ("superghidra.diff.struct_shift_migrator", "FieldMigration"),
    "StructInsertion": ("superghidra.diff.struct_shift_migrator", "StructInsertion"),
    "MigrationReport": ("superghidra.diff.struct_shift_migrator", "MigrationReport"),
    "StructShiftMigrator": ("superghidra.diff.struct_shift_migrator", "StructShiftMigrator"),
    "migrate_struct_shifts": ("superghidra.diff.struct_shift_migrator", "migrate_struct_shifts"),
    "decode_arm64_memory_access": ("superghidra.diff.struct_shift_migrator", "decode_arm64_memory_access"),
    "parse_disassembly_line": ("superghidra.diff.struct_shift_migrator", "parse_disassembly_line"),
    "ReconstructionObligationLedger": ("superghidra.diff.evidence_ledger", "ReconstructionObligationLedger"),
    "ProofObligation": ("superghidra.diff.evidence_ledger", "ProofObligation"),
    "VTableSlotVerifier": ("superghidra.diff.evidence_ledger", "VTableSlotVerifier"),
    "FieldDisplacementVerifier": ("superghidra.diff.evidence_ledger", "FieldDisplacementVerifier"),
    "AllocationSizeVerifier": ("superghidra.diff.evidence_ledger", "AllocationSizeVerifier"),
    "CheckResult": ("superghidra.diff.evidence_ledger", "CheckResult"),
    "SemanticDeltaLog": ("superghidra.diff.semantic_delta_log", "SemanticDeltaLog"),
    "DeltaMigrationEngine": ("superghidra.diff.semantic_delta_log", "DeltaMigrationEngine"),
    "DeltaMigrationReport": ("superghidra.diff.semantic_delta_log", "DeltaMigrationReport"),
    "SemanticEvent": ("superghidra.diff.semantic_delta_log", "SemanticEvent"),
    "DeltaEventType": ("superghidra.diff.semantic_delta_log", "DeltaEventType"),
}

__all__ = list(_EXPORTS.keys())


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        mod_path, attr_name = _EXPORTS[name]
        mod = importlib.import_module(mod_path)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
