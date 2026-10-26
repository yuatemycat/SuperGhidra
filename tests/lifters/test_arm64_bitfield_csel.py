"""
tests/lifters/test_arm64_bitfield_csel.py
========================================

Unit tests for ARM64 bitfield instructions (UBFM, SBFM, LSL, LSR, UXTB, UXTH, UBFX, UBFIZ, SBFX)
and conditional selection instructions (CSEL, CSINC, CSINV, CSNEG) with Z3 SMT equivalence verification.
Resolves GitHub Issue #26.
"""

from __future__ import annotations

import unittest

from superghidra.lifters.pcode_lifter_bridge import (
    ARM64PcodeLifter,
    PcodeOpcode,
)
from superghidra.lifters.smt_pcode_verifier import SMTPcodeVerifier


class TestARM64BitfieldAndCsel(unittest.TestCase):
    def setUp(self):
        self.lifter = ARM64PcodeLifter()
        self.verifier = SMTPcodeVerifier()

    def test_ubfm_aliases(self):
        # 1. LSL x0, x1, #5 (immr = 59, imms = 58)
        insn_lsl = (1 << 31) | 0x53000000 | (59 << 16) | (58 << 10) | (1 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_lsl)
        self.assertEqual(ops[0].opcode, PcodeOpcode.INT_LEFT)
        res = self.verifier.verify_equivalence(ops, "return x1 << 5;", check_memory=False)
        self.assertTrue(res.equivalent)

        # 2. LSR x0, x1, #3 (immr = 3, imms = 63)
        insn_lsr = (1 << 31) | 0x53000000 | (3 << 16) | (63 << 10) | (1 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_lsr)
        self.assertEqual(ops[0].opcode, PcodeOpcode.INT_RIGHT)
        res = self.verifier.verify_equivalence(ops, "return x1 >> 3;", check_memory=False)
        self.assertTrue(res.equivalent)

        # 3. UXTB w0, w1 (sf=0, immr=0, imms=7)
        insn_uxtb = 0x53000000 | (0 << 16) | (7 << 10) | (1 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_uxtb)
        self.assertEqual(ops[0].opcode, PcodeOpcode.INT_AND)
        res = self.verifier.verify_equivalence(ops, "return w1 & 0xFF;", check_memory=False)
        self.assertTrue(res.equivalent)

    def test_ubfx_and_ubfiz(self):
        # UBFX x0, x1, #8, #16
        insn_ubfx = (1 << 31) | 0x53000000 | (1 << 22) | (8 << 16) | (23 << 10) | (1 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_ubfx)
        res = self.verifier.verify_equivalence(ops, "return (x1 >> 8) & 0xffff;", check_memory=False)
        self.assertTrue(res.equivalent)

        # UBFIZ x0, x1, #8, #16
        insn_ubfiz = (1 << 31) | 0x53000000 | (1 << 22) | (56 << 16) | (15 << 10) | (1 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_ubfiz)
        res = self.verifier.verify_equivalence(ops, "return (x1 & 0xffff) << 8;", check_memory=False)
        self.assertTrue(res.equivalent)

    def test_sbfm_aliases(self):
        # ASR x0, x1, #4
        insn_asr = (1 << 31) | 0x13000000 | (1 << 22) | (4 << 16) | (63 << 10) | (1 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_asr)
        self.assertEqual(ops[0].opcode, PcodeOpcode.INT_SRIGHT)
        res = self.verifier.verify_equivalence(ops, "return (int64_t)x1 >> 4;", check_memory=False)
        self.assertTrue(res.equivalent)

    def test_csel_and_variants(self):
        # CMP x1, x2 (SUBS xzr, x1, x2)
        insn_cmp = 0xEB02003F

        # 1. CSEL x0, x3, x4, eq: (x1 == x2) ? x3 : x4
        insn_csel = (1 << 31) | 0x1a800000 | (4 << 16) | (0 << 12) | (3 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_cmp) + self.lifter.lift_instruction(0x1004, insn_csel)
        res = self.verifier.verify_equivalence(ops, "return (x1 == x2) ? x3 : x4;", check_memory=False)
        self.assertTrue(res.equivalent)

        # 2. CSINC x0, x3, x4, ne: (x1 != x2) ? x3 : (x4 + 1)
        insn_csinc = (1 << 31) | 0x1a800000 | (4 << 16) | (1 << 12) | (1 << 10) | (3 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_cmp) + self.lifter.lift_instruction(0x1004, insn_csinc)
        res = self.verifier.verify_equivalence(ops, "return (x1 != x2) ? x3 : (x4 + 1);", check_memory=False)
        self.assertTrue(res.equivalent)

        # 3. CSINV x0, x3, x4, lt: (x1 < x2) ? x3 : ~x4
        insn_csinv = (1 << 31) | (1 << 30) | 0x1a800000 | (4 << 16) | (0xB << 12) | (3 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_cmp) + self.lifter.lift_instruction(0x1004, insn_csinv)
        res = self.verifier.verify_equivalence(ops, "return (x1 < x2) ? x3 : ~x4;", check_memory=False)
        self.assertTrue(res.equivalent)

        # 4. CSNEG x0, x3, x4, gt: (x1 > x2) ? x3 : -x4
        insn_csneg = (1 << 31) | (1 << 30) | 0x1a800000 | (4 << 16) | (0xC << 12) | (1 << 10) | (3 << 5) | 0
        ops = self.lifter.lift_instruction(0x1000, insn_cmp) + self.lifter.lift_instruction(0x1004, insn_csneg)
        res = self.verifier.verify_equivalence(ops, "return (x1 > x2) ? x3 : -x4;", check_memory=False)
        self.assertTrue(res.equivalent)


if __name__ == "__main__":
    unittest.main()
