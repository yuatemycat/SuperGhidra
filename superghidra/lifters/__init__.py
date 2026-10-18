"""SuperGhidra Lifters Domain: Zero-JVM P-Code Lifter, Z3 SMT Equivalence Verifier & ARM/x86 Instruction Decoders."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "ARM64PcodeLifter": ("superghidra.lifters.pcode_lifter_bridge", "ARM64PcodeLifter"),
    "X86_64PcodeLifter": ("superghidra.lifters.pcode_lifter_bridge", "X86_64PcodeLifter"),
    "PcodeOp": ("superghidra.lifters.pcode_lifter_bridge", "PcodeOp"),
    "PcodeOpcode": ("superghidra.lifters.pcode_lifter_bridge", "PcodeOpcode"),
    "Varnode": ("superghidra.lifters.pcode_lifter_bridge", "Varnode"),
    "AddressSpace": ("superghidra.lifters.pcode_lifter_bridge", "AddressSpace"),
    "PcodeGraphBuilder": ("superghidra.lifters.pcode_lifter_bridge", "PcodeGraphBuilder"),
    "VerificationResult": ("superghidra.lifters.smt_pcode_verifier", "VerificationResult"),
    "SymbolicState": ("superghidra.lifters.smt_pcode_verifier", "SymbolicState"),
    "PcodeSymbolicSimulator": ("superghidra.lifters.smt_pcode_verifier", "PcodeSymbolicSimulator"),
    "CASTNode": ("superghidra.lifters.smt_pcode_verifier", "CASTNode"),
    "CVar": ("superghidra.lifters.smt_pcode_verifier", "CVar"),
    "CConst": ("superghidra.lifters.smt_pcode_verifier", "CConst"),
    "CBinary": ("superghidra.lifters.smt_pcode_verifier", "CBinary"),
    "CUnary": ("superghidra.lifters.smt_pcode_verifier", "CUnary"),
    "CTernary": ("superghidra.lifters.smt_pcode_verifier", "CTernary"),
    "CDeref": ("superghidra.lifters.smt_pcode_verifier", "CDeref"),
    "CFieldAccess": ("superghidra.lifters.smt_pcode_verifier", "CFieldAccess"),
    "CIntrinsic": ("superghidra.lifters.smt_pcode_verifier", "CIntrinsic"),
    "CAssignment": ("superghidra.lifters.smt_pcode_verifier", "CAssignment"),
    "CIfElse": ("superghidra.lifters.smt_pcode_verifier", "CIfElse"),
    "CWhile": ("superghidra.lifters.smt_pcode_verifier", "CWhile"),
    "CReturn": ("superghidra.lifters.smt_pcode_verifier", "CReturn"),
    "CBlock": ("superghidra.lifters.smt_pcode_verifier", "CBlock"),
    "CCodeParser": ("superghidra.lifters.smt_pcode_verifier", "CCodeParser"),
    "CSymbolicEvaluator": ("superghidra.lifters.smt_pcode_verifier", "CSymbolicEvaluator"),
    "SMTPcodeVerifier": ("superghidra.lifters.smt_pcode_verifier", "SMTPcodeVerifier"),
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
