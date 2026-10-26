"""
Regression test suite for G2b fixes in SuperGhidra:
1. Rename obligation with only parameter_count is NOT verified (soundness).
2. Exception in verification => not safe (is_safe=False, status=REJECTED).
3. SP-relative (and FP-relative) STP/LDP not counted as struct field evidence.
4. STR after ADRP not counted as ADRP+LDR pair.
5. LDR Q scales unsigned immediate offset by 16.
6. NumPy scanner path with a forced tiny cap returns full sorted results identical to uncapped.
7. StructShiftMigrator with no matching functions returns unmatched instead of inventing pairs.
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from superghidra.acceleration.gpu_adrp_scanner import (
    GPUAdrpScanner,
    decode_ldr_imm,
)
from superghidra.diff.evidence_ledger import (
    FieldDisplacementVerifier,
    LedgerVerificationError,
    ObligationStatus,
    ObligationType,
    ReconstructionObligationLedger,
)
from superghidra.diff.struct_shift_migrator import (
    MemoryAccess,
    StructShiftMigrator,
)


class TestG2bRegressions(unittest.TestCase):
    """Focused regression tests for verified bugs 1 through 6."""

    def test_rename_with_only_parameter_count_not_verified(self):
        """Bug 1: FUNCTION_RENAME with only parameter_count must stay UNVERIFIED/PENDING."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = os.path.join(tmpdir, "test_ledger.json")
            ledger = ReconstructionObligationLedger(ledger_file=ledger_path)

            obl = ledger.propose(
                obligation_type=ObligationType.FUNCTION_RENAME,
                target_name="sub_100450000",
                proposed_name="CalculateScore",
                evidence={"parameter_count": 2},
            )

            verified = ledger.verify(obl.obligation_id)
            self.assertFalse(verified)
            self.assertNotEqual(obl.status, ObligationStatus.VERIFIED)
            self.assertIn(obl.status, (ObligationStatus.PENDING, ObligationStatus.UNVERIFIED))
            self.assertFalse(obl.is_safe)

            with self.assertRaises(LedgerVerificationError):
                ledger.commit(obl.obligation_id)

    def test_exception_in_verification_not_safe(self):
        """Bug 2: Exceptions during verification must mark obligation unsafe and rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = os.path.join(tmpdir, "test_ledger.json")
            ledger = ReconstructionObligationLedger(ledger_file=ledger_path)

            obl = ledger.propose(
                obligation_type=ObligationType.STRUCT_DEFINITION,
                target_name="PlayerStruct",
                proposed_name="Player",
                evidence={"field_displacements": [{"name": "health", "offset": 0, "access_size": 4}]},
            )

            with patch("superghidra.diff.evidence_ledger.FieldDisplacementVerifier.verify", side_effect=RuntimeError("Z3/Hardware crash")):
                verified = ledger.verify(obl.obligation_id)

            self.assertFalse(verified)
            self.assertEqual(obl.status, ObligationStatus.REJECTED)
            self.assertFalse(obl.is_safe)
            failure_msgs = [r["message"] for r in obl.verification_results if not r.get("passed", True)]
            self.assertTrue(any("Z3/Hardware crash" in msg for msg in failure_msgs))

    def test_sp_relative_stp_not_counted_as_field_evidence(self):
        """Bug 3: SP-relative STP must not be collected as struct field backing."""
        # STP x29, x30, [sp, #-16]! -> Rn = 31 (SP)
        sp_stp = 0xA9BF7BFD
        code_bytes = struct.pack("<I", sp_stp)

        claimed = [{"name": "field_sp", "offset": 0, "access_size": 8}]
        res = FieldDisplacementVerifier.extract_and_verify_arm64(code_bytes, claimed)
        self.assertFalse(res.passed)

        # STP x0, x1, [x2, #16] -> Rn = 2 (valid object pointer), offset 16, size 8
        # insn encoding: opc=10 (64-bit), V=0, L=0, imm7=2 (2*8=16), Rt2=1, Rn=2, Rt=0
        # 10 101 0 010 0 0000010 00001 00010 00000 -> 0xA9010440
        obj_stp = 0xA9010440
        code_bytes_obj = struct.pack("<I", obj_stp)
        claimed_obj = [{"name": "field_obj", "offset": 16, "access_size": 8}]
        res_obj = FieldDisplacementVerifier.extract_and_verify_arm64(code_bytes_obj, claimed_obj)
        self.assertTrue(res_obj.passed)

    def test_str_after_adrp_not_counted_as_pair(self):
        """Bug 4: STR after ADRP must NOT be paired as an ADRP reference."""
        # ADRP x0, #0
        adrp_x0 = 0x90000000
        # STR x1, [x0, #0x20] (GPR unsigned immediate store: opc=00, V=0)
        # size=11, 111, V=0, 01, opc=00, imm12=4, Rn=0, Rt=1 -> 0xF9001001
        str_x1 = 0xF9001001
        nop = 0xD503201F
        buf = struct.pack("<IIII", adrp_x0, str_x1, nop, nop)

        scanner = GPUAdrpScanner(backend="numpy")
        matches = scanner.scan_matches(buf)
        self.assertEqual(len(matches), 0)

        # LDR x1, [x0, #0x20] (GPR unsigned immediate load: opc=01, V=0) -> 0xF9401001
        ldr_x1 = 0xF9401001
        buf_ldr = struct.pack("<IIII", adrp_x0, ldr_x1, nop, nop)
        matches_ldr = scanner.scan_matches(buf_ldr)
        self.assertEqual(len(matches_ldr), 1)
        self.assertEqual(matches_ldr[0].paired_type, "LDR")
        self.assertEqual(matches_ldr[0].immediate, 0x20)

    def test_ldr_q_scale_16(self):
        """Bug 4: LDR Q vector immediate offset must be scaled by 16."""
        # LDR Q0, [X1, #0x10] -> imm12 = 1, size=00, V=1, opc=11, Rn=1, Rt=0
        # (insn & 0xFFC00000) == 0x3DC00000, imm12=1 => 1 * 16 = 16 (0x10)
        insn_ldr_q = 0x3DC00420
        rt, rn, offset = decode_ldr_imm(insn_ldr_q)
        self.assertEqual(rn, 1)
        self.assertEqual(rt, 0)
        self.assertEqual(offset, 16)

        # LDR Q2, [X3, #0x20] -> imm12 = 2 => 2 * 16 = 32 (0x20)
        insn_ldr_q2 = 0x3DC00862
        rt2, rn2, offset2 = decode_ldr_imm(insn_ldr_q2)
        self.assertEqual(rn2, 3)
        self.assertEqual(rt2, 2)
        self.assertEqual(offset2, 32)

    def test_numpy_path_forced_tiny_cap_returns_full_sorted_results(self):
        """Bug 5: NumPy path returns full sorted results even when a tiny cap is forced."""
        # Create stream with 4 distinct ADRP + ADD pairs and trailing padding
        insns = []
        for i in range(4):
            # ADRP x(i), #0
            insns.append(0x90000000 | i)
            # ADD x(i), x(i), #((i+1)*4)
            add_insn = 0x91000000 | (i << 5) | i | (((i + 1) * 4) << 10)
            insns.append(add_insn)
        insns.extend([0xD503201F, 0xD503201F, 0xD503201F])

        data = np.array(insns, dtype=np.uint32)

        scanner_uncapped = GPUAdrpScanner(backend="numpy")
        matches_uncapped = scanner_uncapped.scan_matches(data)
        self.assertEqual(len(matches_uncapped), 4)

        scanner_capped = GPUAdrpScanner(backend="numpy", max_matches=2)
        matches_capped = scanner_capped.scan_matches(data)
        self.assertEqual(len(matches_capped), 4)

        # Both paths must return identically sorted matches
        offsets_uncapped = [m.adrp_offset for m in matches_uncapped]
        offsets_capped = [m.adrp_offset for m in matches_capped]
        self.assertEqual(offsets_capped, offsets_uncapped)
        self.assertEqual(offsets_capped, sorted(offsets_capped))

    def test_migrator_no_match_returns_unmatched(self):
        """Bug 6: When functions have no match, migrator must NOT invent a match."""
        migrator = StructShiftMigrator()

        # v1 has function with reads on x0
        migrator._v1_functions["func_player_v1"] = [
            MemoryAccess(pc=0x1000, mnemonic="LDR", base_reg="x0", target_reg="w1", displacement=0x10, access_size=4, is_write=False, instruction_text="ldr w1, [x0, #0x10]"),
            MemoryAccess(pc=0x1004, mnemonic="LDR", base_reg="x0", target_reg="w2", displacement=0x14, access_size=4, is_write=False, instruction_text="ldr w2, [x0, #0x14]"),
        ]

        # v2 has completely unrelated function with writes on x5
        migrator._v2_functions["func_network_v2"] = [
            MemoryAccess(pc=0x2000, mnemonic="STR", base_reg="x5", target_reg="x6", displacement=0x80, access_size=8, is_write=True, instruction_text="str x6, [x5, #0x80]"),
            MemoryAccess(pc=0x2004, mnemonic="STR", base_reg="x5", target_reg="x7", displacement=0x88, access_size=8, is_write=True, instruction_text="str x7, [x5, #0x88]"),
        ]

        report = migrator.analyze_shifts(struct_name="TestStruct")
        self.assertEqual(report.matched_functions, 0)
        self.assertEqual(len(report.field_migrations), 0)
        self.assertEqual(len(report.insertions), 0)


if __name__ == "__main__":
    unittest.main()
