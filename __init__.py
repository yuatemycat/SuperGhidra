"""SuperGhidra: High-Performance GPU Disassembly and Binary Reconstruction Toolkit."""

from .gpu_adrp_scanner import GPUAdrpScanner, ADRPMatch, benchmark_scanner
from .evidence_ledger import (
    ReconstructionObligationLedger,
    ProofObligation,
    ObligationStatus,
    ObligationType,
    LedgerVerificationError,
)
from .binary_diff_engine import (
    FunctionCFG,
    BasicBlock,
    InstructionInfo,
    CFGFeatureExtractor,
    BatchedBinaryMatcher,
    DiffResult,
    FunctionMatch,
)

__all__ = [
    "GPUAdrpScanner",
    "ADRPMatch",
    "benchmark_scanner",
    "ReconstructionObligationLedger",
    "ProofObligation",
    "ObligationStatus",
    "ObligationType",
    "LedgerVerificationError",
    "FunctionCFG",
    "BasicBlock",
    "InstructionInfo",
    "CFGFeatureExtractor",
    "BatchedBinaryMatcher",
    "DiffResult",
    "FunctionMatch",
]
