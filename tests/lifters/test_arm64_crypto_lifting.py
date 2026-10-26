"""
tests/lifters/test_arm64_crypto_lifting.py
==========================================

Unit and integration tests for ARM64 Cryptographic Extensions instruction lifting:
- AESE, AESD, AESMC, AESIMC (AES single round and mix columns)
- SHA1C, SHA1P, SHA1M, SHA1H, SHA1SU0, SHA1SU1 (SHA-1 state and schedule updates)
- SHA256H, SHA256H2, SHA256SU0, SHA256SU1 (SHA-256 state and schedule updates)

Verifies:
1. All crypto instructions lift into valid PcodeOps with opcode CALLOTHER.
2. The intrinsic name matches the ARM64 instruction mnemonic.
3. No UNIMPLEMENTED opcode or LiftError is generated.
4. Target vector register indices (Vd, Vn, Vm) accurately match instruction bitfields.
5. Multi-instruction blocks lift cleanly and sequence correctly.
6. SMT symbolic state handles CALLOTHER intrinsics soundly as unmodeled operations.
"""

import unittest

from superghidra.lifters.pcode_lifter_bridge import (
    AddressSpace,
    ARM64PcodeLifter,
    PcodeOpcode,
    Varnode,
)
from superghidra.lifters.smt_pcode_verifier import (
    PcodeSymbolicSimulator,
    SymbolicState,
)


class TestARM64CryptoLifting(unittest.TestCase):
    """Test suite for ARM64 Cryptographic Extension instruction lifting in pcode_lifter_bridge."""

    def setUp(self):
        self.lifter = ARM64PcodeLifter()

    def _reg_idx(self, vn: Varnode) -> int:
        """Helper to extract SIMD/vector register index from a Varnode."""
        self.assertEqual(vn.space, AddressSpace.REGISTER)
        return ARM64PcodeLifter.fp_reg_index(vn)

    # --------------------------------------------------------------------------
    # 1. AES Instructions (AESE, AESD, AESMC, AESIMC)
    # --------------------------------------------------------------------------

    def test_aese_lifting(self):
        """Verify AESE (AES single round encryption): Vd.16B, Vn.16B."""
        # AESE V1.16B, V2.16B -> 0x4e284841 (rd=1, rn=2)
        insn = 0x4E284800 | (2 << 5) | 1
        ops = self.lifter.lift_instruction(0x1000, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertNotEqual(op.opcode, PcodeOpcode.UNIMPLEMENTED)
        self.assertEqual(op.inputs[0].space, AddressSpace.CONST)
        self.assertEqual(op.inputs[0].offset, "arm64_aese")
        # Check vector registers
        self.assertEqual(self._reg_idx(op.output), 1)
        self.assertEqual(self._reg_idx(op.inputs[1]), 1)  # Vd state in
        self.assertEqual(self._reg_idx(op.inputs[2]), 2)  # Vn round key in

    def test_aesd_lifting(self):
        """Verify AESD (AES single round decryption): Vd.16B, Vn.16B."""
        # AESD V5.16B, V31.16B -> rd=5, rn=31
        insn = 0x4E285800 | (31 << 5) | 5
        ops = self.lifter.lift_instruction(0x2000, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_aesd")
        self.assertEqual(self._reg_idx(op.output), 5)
        self.assertEqual(self._reg_idx(op.inputs[1]), 5)
        self.assertEqual(self._reg_idx(op.inputs[2]), 31)

    def test_aesmc_lifting(self):
        """Verify AESMC (AES MixColumns): Vd.16B, Vn.16B."""
        # AESMC V0.16B, V15.16B -> rd=0, rn=15
        insn = 0x4E286800 | (15 << 5) | 0
        ops = self.lifter.lift_instruction(0x3000, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_aesmc")
        self.assertEqual(self._reg_idx(op.output), 0)
        self.assertEqual(self._reg_idx(op.inputs[1]), 15)

    def test_aesimc_lifting(self):
        """Verify AESIMC (AES Inverse MixColumns): Vd.16B, Vn.16B."""
        # AESIMC V31.16B, V0.16B -> rd=31, rn=0
        insn = 0x4E287800 | (0 << 5) | 31
        ops = self.lifter.lift_instruction(0x4000, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_aesimc")
        self.assertEqual(self._reg_idx(op.output), 31)
        self.assertEqual(self._reg_idx(op.inputs[1]), 0)

    # --------------------------------------------------------------------------
    # 2. SHA-1 Instructions (SHA1C, SHA1P, SHA1M, SHA1H, SHA1SU0, SHA1SU1)
    # --------------------------------------------------------------------------

    def test_sha1c_lifting(self):
        """Verify SHA1C (SHA-1 hash update choose): Qd, Sn, Vm.4S."""
        # SHA1C Q3, S4, V7.4S -> rd=3, rn=4, rm=7
        insn = 0x5E000000 | (7 << 16) | (4 << 5) | 3
        ops = self.lifter.lift_instruction(0x5000, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha1c")
        self.assertEqual(self._reg_idx(op.output), 3)
        self.assertEqual(self._reg_idx(op.inputs[1]), 3)  # Qd
        self.assertEqual(self._reg_idx(op.inputs[2]), 4)  # Sn
        self.assertEqual(self._reg_idx(op.inputs[3]), 7)  # Vm

    def test_sha1p_lifting(self):
        """Verify SHA1P (SHA-1 hash update parity): Qd, Sn, Vm.4S."""
        insn = 0x5E001000 | (12 << 16) | (11 << 5) | 10
        ops = self.lifter.lift_instruction(0x5004, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha1p")
        self.assertEqual(self._reg_idx(op.output), 10)
        self.assertEqual(self._reg_idx(op.inputs[1]), 10)
        self.assertEqual(self._reg_idx(op.inputs[2]), 11)
        self.assertEqual(self._reg_idx(op.inputs[3]), 12)

    def test_sha1m_lifting(self):
        """Verify SHA1M (SHA-1 hash update majority): Qd, Sn, Vm.4S."""
        insn = 0x5E002000 | (20 << 16) | (19 << 5) | 18
        ops = self.lifter.lift_instruction(0x5008, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha1m")
        self.assertEqual(self._reg_idx(op.output), 18)
        self.assertEqual(self._reg_idx(op.inputs[1]), 18)
        self.assertEqual(self._reg_idx(op.inputs[2]), 19)
        self.assertEqual(self._reg_idx(op.inputs[3]), 20)

    def test_sha1h_lifting(self):
        """Verify SHA1H (SHA-1 fixed rotate): Sd, Sn."""
        # SHA1H S1, S2 -> rd=1, rn=2
        insn = 0x5E280800 | (2 << 5) | 1
        ops = self.lifter.lift_instruction(0x500C, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha1h")
        self.assertEqual(self._reg_idx(op.output), 1)
        self.assertEqual(self._reg_idx(op.inputs[1]), 2)

    def test_sha1su0_and_sha1su1_lifting(self):
        """Verify SHA1SU0 and SHA1SU1 schedule update instructions."""
        # SHA1SU0: V0.4S, V1.4S, V2.4S
        insn_su0 = 0x5E003000 | (2 << 16) | (1 << 5) | 0
        ops_su0 = self.lifter.lift_instruction(0x5010, insn_su0)
        self.assertEqual(ops_su0[0].opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(ops_su0[0].inputs[0].offset, "arm64_sha1su0")
        self.assertEqual(self._reg_idx(ops_su0[0].output), 0)
        self.assertEqual(self._reg_idx(ops_su0[0].inputs[1]), 0)
        self.assertEqual(self._reg_idx(ops_su0[0].inputs[2]), 1)
        self.assertEqual(self._reg_idx(ops_su0[0].inputs[3]), 2)

        # SHA1SU1: V5.4S, V6.4S
        insn_su1 = 0x5E281800 | (6 << 5) | 5
        ops_su1 = self.lifter.lift_instruction(0x5014, insn_su1)
        self.assertEqual(ops_su1[0].opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(ops_su1[0].inputs[0].offset, "arm64_sha1su1")
        self.assertEqual(self._reg_idx(ops_su1[0].output), 5)
        self.assertEqual(self._reg_idx(ops_su1[0].inputs[1]), 5)
        self.assertEqual(self._reg_idx(ops_su1[0].inputs[2]), 6)

    # --------------------------------------------------------------------------
    # 3. SHA-256 Instructions (SHA256H, SHA256H2, SHA256SU0, SHA256SU1)
    # --------------------------------------------------------------------------

    def test_sha256h_lifting(self):
        """Verify SHA256H (SHA-256 hash update part 1): Qd, Qn, Vm.4S."""
        # SHA256H Q8, Q9, V10.4S -> rd=8, rn=9, rm=10
        insn = 0x5E004000 | (10 << 16) | (9 << 5) | 8
        ops = self.lifter.lift_instruction(0x6000, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha256h")
        self.assertEqual(self._reg_idx(op.output), 8)
        self.assertEqual(self._reg_idx(op.inputs[1]), 8)
        self.assertEqual(self._reg_idx(op.inputs[2]), 9)
        self.assertEqual(self._reg_idx(op.inputs[3]), 10)

    def test_sha256h2_lifting(self):
        """Verify SHA256H2 (SHA-256 hash update part 2): Qd, Qn, Vm.4S."""
        insn = 0x5E005000 | (25 << 16) | (24 << 5) | 23
        ops = self.lifter.lift_instruction(0x6004, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha256h2")
        self.assertEqual(self._reg_idx(op.output), 23)
        self.assertEqual(self._reg_idx(op.inputs[1]), 23)
        self.assertEqual(self._reg_idx(op.inputs[2]), 24)
        self.assertEqual(self._reg_idx(op.inputs[3]), 25)

    def test_sha256su0_lifting(self):
        """Verify SHA256SU0 (SHA-256 schedule update 0): Vd.4S, Vn.4S."""
        # SHA256SU0 V16.4S, V17.4S -> rd=16, rn=17
        insn = 0x5E282800 | (17 << 5) | 16
        ops = self.lifter.lift_instruction(0x6008, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha256su0")
        self.assertEqual(self._reg_idx(op.output), 16)
        self.assertEqual(self._reg_idx(op.inputs[1]), 16)
        self.assertEqual(self._reg_idx(op.inputs[2]), 17)

    def test_sha256su1_lifting(self):
        """Verify SHA256SU1 (SHA-256 schedule update 1): Vd.4S, Vn.4S, Vm.4S."""
        insn = 0x5E006000 | (30 << 16) | (29 << 5) | 28
        ops = self.lifter.lift_instruction(0x600C, insn)

        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual(op.opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(op.inputs[0].offset, "arm64_sha256su1")
        self.assertEqual(self._reg_idx(op.output), 28)
        self.assertEqual(self._reg_idx(op.inputs[1]), 28)
        self.assertEqual(self._reg_idx(op.inputs[2]), 29)
        self.assertEqual(self._reg_idx(op.inputs[3]), 30)

    # --------------------------------------------------------------------------
    # 4. Multi-Instruction Block Lifting
    # --------------------------------------------------------------------------

    def test_crypto_block_lifting(self):
        """Verify lifting a composite crypto basic block (AESE followed by AESMC)."""
        import struct
        # insn 1: AESE V0.16B, V1.16B (0x4E284820)
        insn1 = 0x4E284800 | (1 << 5) | 0
        # insn 2: AESMC V0.16B, V0.16B (0x4E286800)
        insn2 = 0x4E286800 | (0 << 5) | 0
        block_bytes = struct.pack("<II", insn1, insn2)

        ops = self.lifter.lift_block(0x10000, block_bytes)
        self.assertEqual(len(ops), 2)
        self.assertEqual(ops[0].opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(ops[0].inputs[0].offset, "arm64_aese")
        self.assertEqual(ops[0].pc, 0x10000)

        self.assertEqual(ops[1].opcode, PcodeOpcode.CALLOTHER)
        self.assertEqual(ops[1].inputs[0].offset, "arm64_aesmc")
        self.assertEqual(ops[1].pc, 0x10004)

    # --------------------------------------------------------------------------
    # 5. SMT Soundness Verification for CALLOTHER
    # --------------------------------------------------------------------------

    def test_smt_soundness_on_crypto_callother(self):
        """Verify SMT symbolic simulator marks CALLOTHER as unknown to preserve soundness."""
        insn = 0x4E284800 | (2 << 5) | 1  # AESE
        ops = self.lifter.lift_instruction(0x1000, insn)

        sim = PcodeSymbolicSimulator()
        state = SymbolicState()
        sim.execute_block(state, ops)

        # Simulator must mark state as UNKNOWN due to unmodeled intrinsic side-effects
        self.assertTrue(state.is_unknown)
        self.assertIn("CALLOTHER", state.unknown_reason)


if __name__ == "__main__":
    unittest.main()
