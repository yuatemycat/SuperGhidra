"""SuperGhidra Acceleration Domain: WGPU/CUDA/SIMD ARM64 ADRP Scanner & Parallel Function Seeder."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "GPUAdrpScanner": ("superghidra.acceleration.gpu_adrp_scanner", "GPUAdrpScanner"),
    "ADRPMatch": ("superghidra.acceleration.gpu_adrp_scanner", "ADRPMatch"),
    "decode_adrp_target": ("superghidra.acceleration.gpu_adrp_scanner", "decode_adrp_target"),
    "decode_add_imm": ("superghidra.acceleration.gpu_adrp_scanner", "decode_add_imm"),
    "decode_ldr_imm": ("superghidra.acceleration.gpu_adrp_scanner", "decode_ldr_imm"),
    "benchmark_scanner": ("superghidra.acceleration.gpu_adrp_scanner", "benchmark_scanner"),
    "GPUFunctionSeeder": ("superghidra.acceleration.gpu_function_seeder", "GPUFunctionSeeder"),
    "FunctionSeed": ("superghidra.acceleration.gpu_function_seeder", "FunctionSeed"),
    # ARM64 Bounds-Proven Jump Table Recovery (1.0.0 Milestone 3)
    "ARM64JumpTableProver": ("superghidra.acceleration.jump_table_prover", "ARM64JumpTableProver"),
    "JumpTableCandidate": ("superghidra.acceleration.jump_table_prover", "JumpTableCandidate"),
    "RecoveredJumpTable": ("superghidra.acceleration.jump_table_prover", "RecoveredJumpTable"),
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
