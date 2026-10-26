"""
test_g2_regressions.py
======================
Regression tests for ARM64 lifter decoding, register mapping hygiene,
and SMT soundness verifications (Agent G2a).
"""

import struct
import unittest
import z3

from superghidra.lifters.pcode_lifter_bridge import (
    ARM64PcodeLifter,
    PcodeOp,
    PcodeOpcode,
    AddressSpace,
    Varnode,
    FLAG_N_OFFSET,
    FLAG_Z_OFFSET,
    FLAG_C_OFFSET,
    FLAG_V_OFFSET,
)
from superghidra.lifters.smt_pcode_verifier import (
    SMTPcodeVerifier,
    SymbolicState,
    PcodeSymbolicSimulator,
    CSymbolicEvaluator,
    CCodeParser,
    ProofObligation,
    ObligationType,
    ObligationStatus,
    ReconstructionObligationLedger,
)


class TestG2aRegressions(unittest.TestCase):
    def setUp(self):
        self.lifter = ARM64PcodeLifter()
        self.verifier = SMTPcodeVerifier()

    def test_bug1_ldr_register_offset_lifting(self):
        """0xF8627820 = `ldr x0, [x1, x2, lsl #3]` lifts to LOAD from x1 + (x2 << 3)."""
        insn = 0xF8627820
        ops = self.lifter.lift_instruction(0x1000, insn)
        self.assertTrue(len(ops) >= 3)

        opcodes = [op.opcode for op in ops]
        self.assertIn(PcodeOpcode.INT_LEFT, opcodes)
        self.assertIn(PcodeOpcode.INT_ADD, opcodes)
        self.assertIn(PcodeOpcode.LOAD, opcodes)

        # Output of the load must be x0 (register offset 0)
        load_op = [op for op in ops if op.opcode == PcodeOpcode.LOAD][0]
        self.assertIsNotNone(load_op.output)
        self.assertEqual(load_op.output.space, AddressSpace.REGISTER)
        self.assertEqual(load_op.output.offset, 0)
        self.assertEqual(load_op.output.size, 8)

        # Unallocated / atomic pattern in 0x38000000 class must emit UNIMPLEMENTED, never a store
        insn_atomic = 0x38200000
        ops_atomic = self.lifter.lift_instruction(0x1004, insn_atomic)
        self.assertEqual(len(ops_atomic), 1)
        self.assertEqual(ops_atomic[0].opcode, PcodeOpcode.UNIMPLEMENTED)

    def test_bug2_stp_pre_index_writeback(self):
        """0xA9BF7BFD = `stp x29, x30, [sp, #-16]!` stores at sp-16 and sets sp = sp-16."""
        insn = 0xA9BF7BFD
        ops = self.lifter.lift_instruction(0x1000, insn)
        stores = [op for op in ops if op.opcode == PcodeOpcode.STORE]
        self.assertEqual(len(stores), 2)

        # Must write back to SP (offset 31 * 8 = 248)
        sp_writes = [
            op for op in ops
            if op.output and op.output.space == AddressSpace.REGISTER and op.output.offset == 31 * 8
        ]
        self.assertTrue(len(sp_writes) >= 1)

    def test_bug2_ldp_post_index_writeback(self):
        """0xA8C17BFD = `ldp x29, x30, [sp], #16` loads from old sp then sp += 16."""
        insn = 0xA8C17BFD
        ops = self.lifter.lift_instruction(0x1000, insn)
        loads = [op for op in ops if op.opcode == PcodeOpcode.LOAD]
        self.assertEqual(len(loads), 2)

        # Post-index must write back SP += 16
        sp_writes = [
            op for op in ops
            if op.output and op.output.space == AddressSpace.REGISTER and op.output.offset == 31 * 8
        ]
        self.assertTrue(len(sp_writes) >= 1)

    def test_bug2_ldpsw_sign_extension(self):
        """LDPSW sign-extends loaded 32-bit values into 64-bit destination registers."""
        # ldpsw x2, x3, [sp, #8] (opc=01, V=0, L=1, mode=10 signed offset)
        # size=4, scale=4, imm7=2 (+8 bytes), rt=2, rn=31, rt2=3
        insn_ldpsw = 0x69410FE2
        ops = self.lifter.lift_instruction(0x1000, insn_ldpsw)
        sexts = [op for op in ops if op.opcode == PcodeOpcode.INT_SEXT]
        self.assertEqual(len(sexts), 2)
        for s in sexts:
            self.assertEqual(s.output.size, 8)

    def test_bug3_prfm_lifted_as_nop(self):
        """PRFM (prefetch memory) must lift to NOP (empty op list), not a load."""
        # Unscaled PRFM: size=3, opc=2, bit 26=0
        insn_prfm_unscaled = 0xF8800000
        ops_unscaled = self.lifter.lift_instruction(0x1000, insn_prfm_unscaled)
        self.assertEqual(ops_unscaled, [])

        # Unsigned immediate PRFM: size=3, opc=2, bit 26=0
        insn_prfm_imm = 0xF9800000
        ops_imm = self.lifter.lift_instruction(0x1000, insn_prfm_imm)
        self.assertEqual(ops_imm, [])

    def test_bug4_register_ranges_non_overlapping(self):
        """FP/vector registers, GPRs, and architectural flags must NOT overlap."""
        intervals = []

        # 32 GPRs (x0..x31), 8 bytes each
        for i in range(32):
            intervals.append((f"x{i}", i * 8, i * 8 + 8))

        # 32 FP/vector registers (v0..v31), 16 bytes each
        for i in range(32):
            v_node = ARM64PcodeLifter._fp_varnode(i, 16)
            intervals.append((f"v{i}", v_node.offset, v_node.offset + 16))

        # Architectural NZCV flags (1 byte each)
        intervals.append(("flag_n", FLAG_N_OFFSET, FLAG_N_OFFSET + 1))
        intervals.append(("flag_z", FLAG_Z_OFFSET, FLAG_Z_OFFSET + 1))
        intervals.append(("flag_c", FLAG_C_OFFSET, FLAG_C_OFFSET + 1))
        intervals.append(("flag_v", FLAG_V_OFFSET, FLAG_V_OFFSET + 1))

        # Verify no pair overlaps
        for i in range(len(intervals)):
            name_a, start_a, end_a = intervals[i]
            for j in range(i + 1, len(intervals)):
                name_b, start_b, end_b = intervals[j]
                self.assertTrue(
                    end_a <= start_b or end_b <= start_a,
                    f"Register collision detected between {name_a} [0x{start_a:x}, 0x{end_a:x}) "
                    f"and {name_b} [0x{start_b:x}, 0x{end_b:x})"
                )

    def test_bug6a_unknown_obligation_type_returns_unknown(self):
        """Unknown obligation type must return equivalent=False and status='UNKNOWN'."""
        class DummyObligation:
            obligation_id = "obl_unk_999"
            obligation_type = "UNKNOWN_NEW_OBLIGATION_TYPE"
            evidence = {}
            verification_results = []
            status = ObligationStatus.PENDING

        res = self.verifier.verify_obligation(DummyObligation())
        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "UNKNOWN")

    def test_bug6b_struct_field_proof_non_circular(self):
        """Struct field obligation without real instruction bytes or P-code must return UNKNOWN."""
        obl = ProofObligation(
            obligation_id="obl_field_circ",
            obligation_type=ObligationType.STRUCT_FIELD_RENAME,
            target_name="field_0x20",
            proposed_name="m_stamina",
            evidence={
                "offset": 0x20,
                "access_size": 4,
                "c_expression": "player->m_stamina",
                # Note: NO machine_bytes or pcode_ops provided!
            },
        )
        res = self.verifier.verify_obligation(obl)
        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "UNKNOWN")

    def test_bug6c_call_in_pcode_returns_unknown(self):
        """CALL opcode in P-code must yield UNKNOWN status, never false equivalence."""
        ops = [
            PcodeOp(PcodeOpcode.CALL, [Varnode(AddressSpace.RAM, 0x10045000, 8)], pc=0x1000),
            PcodeOp(PcodeOpcode.COPY, [Varnode(AddressSpace.REGISTER, 0, 8)], Varnode(AddressSpace.REGISTER, 0, 8), pc=0x1004),
        ]
        res = self.verifier.verify_equivalence(ops, "return x0;", check_memory=False)
        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "UNKNOWN")

    def test_bug6d_distinct_unknown_c_expressions_not_proven_equal(self):
        """Two distinct unknown C expressions/calls must not be proven equal to each other."""
        evaluator = CSymbolicEvaluator()
        parser = CCodeParser()
        st1 = SymbolicState("s1_")
        st2 = SymbolicState("s2_")

        expr_a = parser._parse_expr("foo(x0)")
        expr_b = parser._parse_expr("bar(x0)")

        val_a = evaluator.eval_expr(st1, expr_a)
        val_b = evaluator.eval_expr(st2, expr_b)

        # SMT query: val_a == val_b should NOT be identically equal
        solver = z3.Solver()
        solver.add(val_a != val_b)
        self.assertEqual(solver.check(), z3.sat)

        # When evaluated in verification, unsupported calls must yield UNKNOWN
        ops = [PcodeOp(PcodeOpcode.COPY, [Varnode(AddressSpace.CONST, 42, 8)], Varnode(AddressSpace.REGISTER, 0, 8), pc=0x1000)]
        res = self.verifier.verify_equivalence(ops, "return foo(x0);", check_memory=False)
        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "UNKNOWN")

    def test_bug6e_unknown_binary_and_struct_field_soundness(self):
        """Unmapped struct fields and unknown operators must evaluate to UNKNOWN."""
        ops = [PcodeOp(PcodeOpcode.COPY, [Varnode(AddressSpace.CONST, 0, 8)], Varnode(AddressSpace.REGISTER, 0, 8), pc=0x1000)]
        # Unmapped struct field (offset is None)
        res_field = self.verifier.verify_equivalence(ops, "return player->unmapped_field;", check_memory=False)
        self.assertFalse(res_field.equivalent)
        self.assertEqual(res_field.status, "UNKNOWN")

    def test_bug6f_float_operations_marked_unknown(self):
        """Floating-point operations must return UNKNOWN in bitvector SMT domain."""
        ops = [
            PcodeOp(
                PcodeOpcode.FLOAT_ADD,
                [Varnode(AddressSpace.REGISTER, 0x400, 8), Varnode(AddressSpace.REGISTER, 0x410, 8)],
                Varnode(AddressSpace.REGISTER, 0x400, 8),
                pc=0x1000
            )
        ]
        res = self.verifier.verify_equivalence(ops, "return d0 + d1;", check_memory=False, tracked_registers=[0x400])
        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "UNKNOWN")

    def test_bug6g_loop_unroll_limit_marked_unknown(self):
        """Truncated loops at the unroll limit must return UNKNOWN (bounded is not a proof)."""
        # An infinite loop: 0x1000: BRANCH 0x1000
        ops_infinite_loop = [
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 1, 8)], Varnode(AddressSpace.REGISTER, 0, 8), pc=0x1000),
            PcodeOp(PcodeOpcode.BRANCH, [Varnode(AddressSpace.RAM, 0x1000, 8)], pc=0x1004),
        ]
        res = self.verifier.verify_equivalence(ops_infinite_loop, "return 5;", check_memory=False)
        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
