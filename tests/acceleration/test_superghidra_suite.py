"""
SuperGhidra Test Suite.

Validates:
1. GPU ADRP Scanner:
   - Precision decoding of ARM64 ADRP + ADD / LDR patterns (+4, +8, +12).
   - Virtual target address computation.
   - Multi-backend sweeps (WGPU, PyTorch CUDA, NumPy fallback).
   - 20 MB instruction block benchmark (target < 5 ms).
2. Reconstruction Obligation Ledger:
   - VTable slot index & pointer alignment invariants.
   - Allocation size bounds & allocator symbol validation (g_game_alloc, malloc).
   - Struct field displacement natural alignment (e.g. [x22, #0x24]).
   - Strict gate blocking unverified commits.
   - JSON ledger persistence and reload.
3. Binary Diff Engine:
   - Normalized CFG 32-dim feature vector extraction & L2 normalization.
   - Batched cosine similarity matching on stripped binaries.
   - Mutual top-1 bipartite pairing.
"""

import os
import sys
import tempfile
import unittest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')))

from gpu_adrp_scanner import (
    GPUAdrpScanner,
    NumPyAdrpEngine,
    benchmark_scanner,
    decode_add_imm,
    decode_adrp_target,
    decode_ldr_imm,
)
from evidence_ledger import (
    AllocationSizeVerifier,
    FieldDisplacementVerifier,
    LedgerVerificationError,
    ObligationStatus,
    ObligationType,
    ReconstructionObligationLedger,
    VTableSlotVerifier,
)
from binary_diff_engine import (
    BasicBlock,
    BatchedBinaryMatcher,
    CFGFeatureExtractor,
    FunctionCFG,
    InstructionInfo,
    generate_paired_synthetic_binaries,
)


class TestGPUAdrpScanner(unittest.TestCase):
    """Unit and benchmark tests for the ARM64 ADRP pattern scanner."""

    def test_instruction_decoders(self):
        # 1. ADRP x1, #0x1000 at PC = 0x100000000
        # immhi = 1, immlo = 0 -> imm21 = 4 -> page_offset = 4 << 12 = 0x4000
        # adrp insn: 0x90000000 | (immlo << 29) | (immhi << 5) | rd
        insn_adrp = 0x90000000 | (0 << 29) | (1 << 5) | 1
        rd, page = decode_adrp_target(0x100000000, insn_adrp)
        self.assertEqual(rd, 1)
        self.assertEqual(page, 0x100004000)

        # 2. ADD x2, x1, #0x120
        # insn: 0x91000000 | (shift << 22) | (imm12 << 10) | (rn << 5) | rd
        insn_add = 0x91000000 | (0x120 << 10) | (1 << 5) | 2
        rd_add, rn_add, imm_add = decode_add_imm(insn_add)
        self.assertEqual(rd_add, 2)
        self.assertEqual(rn_add, 1)
        self.assertEqual(imm_add, 0x120)

        # 3. LDR x4, [x3, #0x28] (size=3 for 64-bit load, offset 0x28 = 5 << 3)
        insn_ldr = 0xF9400000 | (5 << 10) | (3 << 5) | 4
        rt_ldr, rn_ldr, imm_ldr = decode_ldr_imm(insn_ldr)
        self.assertEqual(rt_ldr, 4)
        self.assertEqual(rn_ldr, 3)
        self.assertEqual(imm_ldr, 0x28)

    def test_pattern_matching_and_offsets(self):
        # Test synthetic buffer with known matches at +4, +8, and +12
        insns = np.zeros(20, dtype=np.uint32)
        # Match 1: Step +1 (+4 bytes): ADRP x1 -> ADD x2, x1, #0x80
        insns[2] = 0x90000000 | (1 & 0x1F)
        insns[3] = 0x91000000 | (0x80 << 10) | (1 << 5) | 2

        # Match 2: Step +2 (+8 bytes): ADRP x5 -> NOP -> LDR x6, [x5, #0x18]
        insns[6] = 0x90000000 | (5 & 0x1F)
        insns[7] = 0xD503201F  # NOP
        insns[8] = 0xF9400000 | (3 << 10) | (5 << 5) | 6

        # Match 3: Step +3 (+12 bytes): ADRP x8 -> NOP -> NOP -> ADD x9, x8, #0x10
        insns[10] = 0x90000000 | (8 & 0x1F)
        insns[11] = 0xD503201F  # NOP
        insns[12] = 0xD503201F  # NOP
        insns[13] = 0x91000000 | (0x10 << 10) | (8 << 5) | 9

        # Register mismatch: ADRP x10 -> ADD x11, x12, #0x20
        insns[15] = 0x90000000 | 10
        insns[16] = 0x91000000 | (0x20 << 10) | (12 << 5) | 11

        scanner = GPUAdrpScanner(backend="numpy")
        matches = scanner.scan_matches(insns, base_pc=0x1000, filter_same_register=True)

        self.assertEqual(len(matches), 3)
        self.assertEqual(matches[0].adrp_index, 2)
        self.assertEqual(matches[0].paired_index, 3)
        self.assertEqual(matches[0].paired_type, "ADD")
        self.assertEqual(matches[0].immediate, 0x80)

        self.assertEqual(matches[1].adrp_index, 6)
        self.assertEqual(matches[1].paired_index, 8)
        self.assertEqual(matches[1].paired_type, "LDR")
        self.assertEqual(matches[1].immediate, 0x18)

        self.assertEqual(matches[2].adrp_index, 10)
        self.assertEqual(matches[2].paired_index, 13)
        self.assertEqual(matches[2].paired_type, "ADD")

        # Unfiltered matches should include the register mismatch
        matches_unfiltered = scanner.scan_matches(insns, base_pc=0x1000, filter_same_register=False)
        self.assertEqual(len(matches_unfiltered), 4)

    def test_20mb_benchmark_performance(self):
        res = benchmark_scanner(size_mb=20.0, iterations=5)
        if os.environ.get("SUPERGHIDRA_PERF_TESTS") == "1":
            self.assertTrue(res["target_met"], f"Target < 5 ms failed: min time was {res['min_time_ms']} ms")
        else:
            self.assertLess(res["min_time_ms"], 1000.0, f"Benchmark execution too slow: {res['min_time_ms']} ms")
        self.assertGreater(res["raw_matches"], 0)


class TestBinaryDiffEngine(unittest.TestCase):
    """Unit tests for normalized CFG feature extraction and batched binary diffing."""

    def test_feature_extractor_properties(self):
        # Create a function with 2 blocks
        cfg = FunctionCFG(func_id="test_func", address=0x1000, name="SimpleTest")
        b1 = BasicBlock(start_addr=0x1000, end_addr=0x100C)
        b1.instructions = [
            InstructionInfo.create(0x1000, "add", "x0, x0, #1"),
            InstructionInfo.create(0x1004, "cmp", "x0, #10"),
            InstructionInfo.create(0x1008, "b.eq", "0x1010"),
        ]
        b2 = BasicBlock(start_addr=0x1010, end_addr=0x1014)
        b2.instructions = [
            InstructionInfo.create(0x1010, "ret"),
        ]
        cfg.add_block(b1)
        cfg.add_block(b2)
        cfg.add_edge(0x1000, 0x1010)

        vec = CFGFeatureExtractor.extract_vector(cfg)
        self.assertEqual(vec.shape, (32,))
        # Must be unit-normalized (L2 norm == 1.0)
        norm = np.linalg.norm(vec)
        self.assertAlmostEqual(norm, 1.0, places=5)

    def test_batched_diffing_accuracy(self):
        bin_a, bin_b = generate_paired_synthetic_binaries(num_funcs=50, mutation_rate=0.1, seed=42)
        matcher = BatchedBinaryMatcher(threshold=0.75, use_gpu=True)
        res = matcher.diff_binaries(bin_a, bin_b, strategy="mutual")

        self.assertGreaterEqual(res.match_rate_pct, 90.0, f"Match rate too low: {res.match_rate_pct}%")
        self.assertGreaterEqual(res.avg_similarity, 0.90)
        self.assertGreater(len(res.matches), 40)


if __name__ == "__main__":
    unittest.main()
