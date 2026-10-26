"""
tests/lifters/test_egraph_mlir_pipeline.py
===========================================
Unit and integration tests for Section 1 of SuperGhidra:
- 7-tier Staged P-Code Pass Manager & Zero-Copy SHM Bridge
- Equality Saturation (E-Graph) Mixed Boolean-Arithmetic (MBA) Deobfuscator
- Bit-Exact Equivalence Prover (Z3 SMT + 64-bit SiMBA Algebraic Verification)
- Symbolic Control-Flow Flattening (CFF) Deflattener & Opaque Predicate Pruner
- Multi-tier MLIR Lowering & Region-based Goto-free C AST Restructurer
"""

import unittest

from superghidra.lifters.egraph_mlir_pipeline import (
    HAS_Z3,
    AddressSpace,
    EGraph,
    EGraphMBADeobfuscatorPass,
    ENode,
    EquivalenceProver,
    ExprTree,
    MLIRGotoFreeRestructurer,
    PCodeBasicBlock,
    PCodeFunction,
    PCodeMaturityStage,
    PCodeOp,
    PCodeOpCode,
    RellicGotoFreeRestructurer,
    StagedPCodePassManager,
    SymbolicCFFDeflattenerPass,
    Varnode,
    ZeroCopyShmBridge,
    build_obfuscated_test_function,
)


class TestStagedPCodePassManagerAndSHM(unittest.TestCase):
    """Tests for StagedPCodePassManager and ZeroCopyShmBridge (Phase 1, Gap 1)."""

    def setUp(self):
        self.shm = ZeroCopyShmBridge(size_bytes=64 * 1024)
        self.manager = StagedPCodePassManager(self.shm)

    def tearDown(self):
        self.shm.close()

    def test_pass_manager_runs_all_7_stages(self):
        func = build_obfuscated_test_function()
        stages_visited = []

        def record_stage(f: PCodeFunction, stage: PCodeMaturityStage):
            stages_visited.append(stage)

        for stage in PCodeMaturityStage:
            self.manager.register_hook(stage, f"hook_{stage.name}", record_stage)

        res = self.manager.run_pipeline(func)
        self.assertIs(res, func)

        expected_stages = list(PCodeMaturityStage)
        self.assertEqual(len(expected_stages), 7)
        self.assertEqual(stages_visited, expected_stages)

        # Telemetry should record all 7 stages
        self.assertEqual(len(self.manager.telemetry), 7)
        for entry in self.manager.telemetry:
            self.assertEqual(entry["hooks_run"], 1)
            self.assertGreater(entry["shm_bytes"], 0)
            self.assertGreaterEqual(entry["elapsed_ms"], 0.0)

    def test_zero_copy_shm_serialization_and_header(self):
        func = build_obfuscated_test_function()
        bytes_written = self.shm.write_snapshot(func, PCodeMaturityStage.PCMAT_SSA)
        self.assertGreater(bytes_written, 0)

        header = self.shm.read_header()
        self.assertEqual(header["version"], 2)
        self.assertEqual(header["stage"], PCodeMaturityStage.PCMAT_SSA)
        self.assertEqual(header["num_blocks"], len(func.blocks))

        total_ops = sum(len(b.ops) for b in func.blocks.values())
        self.assertEqual(header["num_ops"], total_ops)
        self.assertGreater(header["timestamp_ns"], 0)

    def test_zero_copy_shm_corrupted_magic_raises(self):
        self.shm._mmap.seek(0)
        self.shm._mmap.write(b"BADMAGIC")
        with self.assertRaises(ValueError) as ctx:
            self.shm.read_header()
        self.assertIn("Invalid SHM magic", str(ctx.exception))


class TestEGraphMBADeobfuscation(unittest.TestCase):
    """Tests for Equality Saturation (E-Graph) MBA identities and cost reduction."""

    def setUp(self):
        self.egraph = EGraph()
        self.x = Varnode(AddressSpace.REGISTER, 0x00, 8, symbol="x")
        self.y = Varnode(AddressSpace.REGISTER, 0x08, 8, symbol="y")
        self.z = Varnode(AddressSpace.REGISTER, 0x10, 8, symbol="z")

    def test_mba_sum_identity_xor_and(self):
        """(x ^ y) + 2 * (x & y) ==> x + y"""
        cid_x = self.egraph.add_varnode(self.x)
        cid_y = self.egraph.add_varnode(self.y)

        cid_xor = self.egraph.add(ENode("^", (cid_x, cid_y)))
        cid_and = self.egraph.add(ENode("&", (cid_x, cid_y)))
        cid_two = self.egraph.add_const(2)
        cid_mul = self.egraph.add(ENode("*", (cid_two, cid_and)))
        cid_root = self.egraph.add(ENode("+", (cid_xor, cid_mul)))

        # Before saturation, best tree cost reflects the complex expression
        orig_tree = self.egraph.extract_best(cid_root)
        self.assertGreater(orig_tree.cost(), 7)

        # Saturate
        iters = self.egraph.saturate(max_iters=10)
        self.assertGreater(iters, 0)

        # Extract best minimal tree
        best_tree = self.egraph.extract_best(cid_root)
        self.assertEqual(best_tree.op, "+")
        child_ops = sorted([arg.op for arg in best_tree.args])
        self.assertEqual(child_ops, ["var", "var"])
        self.assertLess(best_tree.cost(), orig_tree.cost())

        # Verify equivalence
        verified, _, method = EquivalenceProver.verify_trees_equivalent(orig_tree, best_tree)
        self.assertTrue(verified, f"Equivalence check failed with method {method}")

    def test_mba_sum_identity_or_and(self):
        """(x | y) + (x & y) ==> x + y"""
        cid_x = self.egraph.add_varnode(self.x)
        cid_y = self.egraph.add_varnode(self.y)

        cid_or = self.egraph.add(ENode("|", (cid_x, cid_y)))
        cid_and = self.egraph.add(ENode("&", (cid_x, cid_y)))
        cid_root = self.egraph.add(ENode("+", (cid_or, cid_and)))

        orig_tree = self.egraph.extract_best(cid_root)
        self.egraph.saturate(max_iters=10)
        best_tree = self.egraph.extract_best(cid_root)

        self.assertEqual(best_tree.op, "+")
        self.assertLess(best_tree.cost(), orig_tree.cost())
        verified, _, _ = EquivalenceProver.verify_trees_equivalent(orig_tree, best_tree)
        self.assertTrue(verified)

    def test_mba_diff_identity_2or_sub_xor(self):
        """2 * (x | y) - (x ^ y) ==> x + y"""
        cid_x = self.egraph.add_varnode(self.x)
        cid_y = self.egraph.add_varnode(self.y)

        cid_or = self.egraph.add(ENode("|", (cid_x, cid_y)))
        cid_two = self.egraph.add_const(2)
        cid_mul = self.egraph.add(ENode("*", (cid_two, cid_or)))
        cid_xor = self.egraph.add(ENode("^", (cid_x, cid_y)))
        cid_root = self.egraph.add(ENode("-", (cid_mul, cid_xor)))

        orig_tree = self.egraph.extract_best(cid_root)
        self.egraph.saturate(max_iters=10)
        best_tree = self.egraph.extract_best(cid_root)

        self.assertEqual(best_tree.op, "+")
        self.assertLess(best_tree.cost(), orig_tree.cost())
        verified, _, _ = EquivalenceProver.verify_trees_equivalent(orig_tree, best_tree)
        self.assertTrue(verified)

    def test_mba_xor_identity_or_sub_and(self):
        """(x | y) - (x & y) ==> x ^ y"""
        cid_x = self.egraph.add_varnode(self.x)
        cid_y = self.egraph.add_varnode(self.y)

        cid_or = self.egraph.add(ENode("|", (cid_x, cid_y)))
        cid_and = self.egraph.add(ENode("&", (cid_x, cid_y)))
        cid_root = self.egraph.add(ENode("-", (cid_or, cid_and)))

        orig_tree = self.egraph.extract_best(cid_root)
        self.egraph.saturate(max_iters=10)
        best_tree = self.egraph.extract_best(cid_root)

        self.assertEqual(best_tree.op, "^")
        self.assertLess(best_tree.cost(), orig_tree.cost())
        verified, _, _ = EquivalenceProver.verify_trees_equivalent(orig_tree, best_tree)
        self.assertTrue(verified)

    def test_parity_opaque_predicate_collapse(self):
        """Parity Theorem: (x * (x + 1)) & 1 ==> 0"""
        cid_x = self.egraph.add_varnode(self.x)
        cid_one = self.egraph.add_const(1)

        cid_plus1 = self.egraph.add(ENode("+", (cid_x, cid_one)))
        cid_mul = self.egraph.add(ENode("*", (cid_x, cid_plus1)))
        cid_and = self.egraph.add(ENode("&", (cid_mul, cid_one)))

        self.egraph.saturate(max_iters=10)
        best_tree = self.egraph.extract_best(cid_and)

        self.assertEqual(best_tree.op, "const")
        self.assertIsNotNone(best_tree.leaf)
        self.assertEqual(best_tree.leaf.offset, 0)

    def test_constant_folding(self):
        """Fold arithmetic and bitwise constants in E-Graph."""
        c10 = self.egraph.add_const(10)
        c25 = self.egraph.add_const(25)
        cid_add = self.egraph.add(ENode("+", (c10, c25)))
        cid_sub = self.egraph.add(ENode("-", (c25, c10)))
        cid_xor = self.egraph.add(ENode("^", (c10, c10)))

        self.egraph.saturate(max_iters=5)

        tree_add = self.egraph.extract_best(cid_add)
        self.assertEqual(tree_add.op, "const")
        self.assertEqual(tree_add.leaf.offset, 35)

        tree_sub = self.egraph.extract_best(cid_sub)
        self.assertEqual(tree_sub.op, "const")
        self.assertEqual(tree_sub.leaf.offset, 15)

        tree_xor = self.egraph.extract_best(cid_xor)
        self.assertEqual(tree_xor.op, "const")
        self.assertEqual(tree_xor.leaf.offset, 0)


class TestEquivalenceProver(unittest.TestCase):
    """Tests for Z3 SMT and SiMBA algebraic equivalence prover."""

    def setUp(self):
        self.x = Varnode(AddressSpace.REGISTER, 0x00, 8, symbol="x")
        self.y = Varnode(AddressSpace.REGISTER, 0x08, 8, symbol="y")

    def test_smt_prover_equivalent_trees(self):
        # t1 = x + y
        t_x = ExprTree(op="var", leaf=self.x)
        t_y = ExprTree(op="var", leaf=self.y)
        t_add = ExprTree(op="+", args=(t_x, t_y))

        # t2 = (x ^ y) + 2 * (x & y)
        t_xor = ExprTree(op="^", args=(t_x, t_y))
        t_and = ExprTree(op="&", args=(t_x, t_y))
        t_two = ExprTree(op="const", leaf=Varnode(AddressSpace.CONST, 2, 8))
        t_mul = ExprTree(op="*", args=(t_two, t_and))
        t_mba = ExprTree(op="+", args=(t_xor, t_mul))

        verified, elapsed_ms, method = EquivalenceProver.verify_trees_equivalent(t_add, t_mba)
        self.assertTrue(verified)
        self.assertGreaterEqual(elapsed_ms, 0.0)
        if HAS_Z3:
            self.assertEqual(method, "Z3-SMT-UNSAT")
        else:
            self.assertEqual(method, "SiMBA-Basis+256Vec-Verified")

    def test_smt_prover_non_equivalent_trees(self):
        t_x = ExprTree(op="var", leaf=self.x)
        t_y = ExprTree(op="var", leaf=self.y)
        t_add = ExprTree(op="+", args=(t_x, t_y))
        t_sub = ExprTree(op="-", args=(t_x, t_y))

        verified, _, method = EquivalenceProver.verify_trees_equivalent(t_add, t_sub)
        self.assertFalse(verified)
        if HAS_Z3:
            self.assertEqual(method, "Z3-SMT-UNSAT")
        else:
            self.assertEqual(method, "Counterexample-Found")


class TestEGraphMBADeobfuscatorPass(unittest.TestCase):
    """Tests for EGraphMBADeobfuscatorPass on P-Code functions."""

    def test_mba_pass_transforms_pcode_block(self):
        func = build_obfuscated_test_function()
        mba_pass = EGraphMBADeobfuscatorPass()

        # Run pass on block 1 and block 2
        mba_pass(func, PCodeMaturityStage.PCMAT_EGRAPH_MBA)

        # Confirm simplifications occurred
        self.assertGreater(len(mba_pass.simplifications_log), 0)
        targets = [log["target"] for log in mba_pass.simplifications_log]
        self.assertIn("mba_sum", targets)

        # Check block 1 ops: complex sequence replaced with simplified ops
        blk1 = func.blocks[1]
        sum_op = [op for op in blk1.ops if op.output and op.output.symbol == "mba_sum"][0]
        self.assertEqual(sum_op.opcode, PCodeOpCode.INT_ADD)


class TestSymbolicCFFDeflattener(unittest.TestCase):
    """Tests for SymbolicCFFDeflattenerPass and opaque predicate pruning."""

    def test_opaque_predicate_evaluation_and_dead_block_pruning(self):
        func = build_obfuscated_test_function()

        # First run MBA pass to simplify the opaque predicate ((x*(x+1)) & 1) == 0 -> 0 == 0 -> True
        mba_pass = EGraphMBADeobfuscatorPass()
        mba_pass(func, PCodeMaturityStage.PCMAT_EGRAPH_MBA)

        cff_pass = SymbolicCFFDeflattenerPass()
        cff_pass(func, PCodeMaturityStage.PCMAT_DEFLATTEN)

        # Pruned opaque branches log should record block 1
        self.assertEqual(len(cff_pass.pruned_opaque_branches), 1)
        pruned_info = cff_pass.pruned_opaque_branches[0]
        self.assertEqual(pruned_info["block_id"], 1)
        self.assertEqual(pruned_info["proven_value"], "True")
        self.assertEqual(pruned_info["kept_succ"], 2)
        self.assertEqual(pruned_info["pruned_succ"], 3)

        # Block 1 should now end with unconditional BRANCH to block 2
        blk1 = func.blocks[1]
        self.assertEqual(blk1.ops[-1].opcode, PCodeOpCode.BRANCH)
        self.assertEqual(blk1.succs, [2])

        # Block 3 (the dead trap) must have been pruned from func.blocks
        self.assertNotIn(3, func.blocks)
        self.assertIn(1, func.blocks)
        self.assertIn(2, func.blocks)


class TestMLIRGotoFreeRestructurer(unittest.TestCase):
    """Tests for MLIRGotoFreeRestructurer lowering and goto-free C code generation."""

    def test_straightline_block_mlir_and_c(self):
        x = Varnode(AddressSpace.REGISTER, 0x00, 8, symbol="x")
        y = Varnode(AddressSpace.REGISTER, 0x08, 8, symbol="y")
        res = Varnode(AddressSpace.REGISTER, 0x10, 8, symbol="res")

        ops = [
            PCodeOp(1, PCodeOpCode.INT_ADD, res, [x, y], 0x1000),
            PCodeOp(2, PCodeOpCode.RETURN, None, [res], 0x1004),
        ]
        func = PCodeFunction(
            name="simple_add",
            entry_rva=0x1000,
            params=[x, y],
            blocks={1: PCodeBasicBlock(1, 0x1000, ops, succs=[], preds=[])},
        )

        restructurer = MLIRGotoFreeRestructurer()
        mlir_ir, clean_c = restructurer.restructure_function(func)

        # Assert MLIR dialect structure
        self.assertIn("module @superghidra_patchestry", mlir_ir)
        self.assertIn("vast.hl.func @simple_add", mlir_ir)
        self.assertIn("pcode.int_add", mlir_ir)
        self.assertIn("vast.hl.return", mlir_ir)

        # Assert clean C structure
        self.assertIn("uint64_t simple_add(uint64_t x, uint64_t y) {", clean_c)
        self.assertIn("res = x + y;", clean_c)
        self.assertIn("return res;", clean_c)
        self.assertNotIn("goto", clean_c)

    def test_diamond_if_else_mlir_and_c(self):
        cond = Varnode(AddressSpace.REGISTER, 0x00, 8, symbol="cond")
        zero = Varnode(AddressSpace.CONST, 0, 8)
        c_vn = Varnode(AddressSpace.UNIQUE, 0x50, 1)

        # Block 1: Branch if cond == 0
        b1_ops = [
            PCodeOp(1, PCodeOpCode.INT_EQUAL, c_vn, [cond, zero], 0x1000),
            PCodeOp(2, PCodeOpCode.CBRANCH, None, [Varnode(AddressSpace.CONST, 2, 8), c_vn], 0x1004),
        ]
        # Block 2 (True branch): return 42
        b2_ops = [
            PCodeOp(1, PCodeOpCode.RETURN, None, [Varnode(AddressSpace.CONST, 42, 8)], 0x1010)
        ]
        # Block 3 (False branch): return 99
        b3_ops = [
            PCodeOp(1, PCodeOpCode.RETURN, None, [Varnode(AddressSpace.CONST, 99, 8)], 0x1020)
        ]

        func = PCodeFunction(
            name="diamond_branch",
            entry_rva=0x1000,
            params=[cond],
            blocks={
                1: PCodeBasicBlock(1, 0x1000, b1_ops, succs=[3, 2], preds=[]),
                2: PCodeBasicBlock(2, 0x1010, b2_ops, succs=[], preds=[1]),
                3: PCodeBasicBlock(3, 0x1020, b3_ops, succs=[], preds=[1]),
            },
        )

        restructurer = MLIRGotoFreeRestructurer()
        mlir_ir, clean_c = restructurer.restructure_function(func)

        self.assertIn("scf.if", mlir_ir)
        self.assertIn("if (cond == 0)", clean_c)
        self.assertIn("return 0x2a;", clean_c)
        self.assertIn("return 0x63;", clean_c)
        self.assertNotIn("goto", clean_c)

    def test_multiway_switch_trampoline_restructures_to_if_then_else(self):
        cmd = Varnode(AddressSpace.REGISTER, 0x00, 8, symbol="cmd")
        b1_ops = [
            PCodeOp(1, PCodeOpCode.INT_EQUAL, Varnode(AddressSpace.UNIQUE, 0x10, 1), [cmd, Varnode(AddressSpace.CONST, 1, 8)], 0x1000),
            PCodeOp(2, PCodeOpCode.INT_EQUAL, Varnode(AddressSpace.UNIQUE, 0x11, 1), [cmd, Varnode(AddressSpace.CONST, 2, 8)], 0x1004),
        ]
        func = PCodeFunction(
            name="dispatch_switch",
            entry_rva=0x1000,
            params=[cmd],
            blocks={
                1: PCodeBasicBlock(1, 0x1000, b1_ops, succs=[2, 3, 4], preds=[]),
                2: PCodeBasicBlock(2, 0x1010, [PCodeOp(10, PCodeOpCode.RETURN, None, [Varnode(AddressSpace.CONST, 10, 8)], 0x1010)], succs=[], preds=[1]),
                3: PCodeBasicBlock(3, 0x1020, [PCodeOp(20, PCodeOpCode.RETURN, None, [Varnode(AddressSpace.CONST, 20, 8)], 0x1020)], succs=[], preds=[1]),
                4: PCodeBasicBlock(4, 0x1030, [PCodeOp(30, PCodeOpCode.RETURN, None, [Varnode(AddressSpace.CONST, 99, 8)], 0x1030)], succs=[], preds=[1]),
            },
        )
        restructurer = RellicGotoFreeRestructurer()
        mlir_ir, clean_c = restructurer.restructure_function(func)
        self.assertIn("if (cmd == 1)", clean_c)
        self.assertIn("if (cmd == 2)", clean_c)
        self.assertIn("return 0xa;", clean_c)
        self.assertIn("return 0x14;", clean_c)
        self.assertIn("return 0x63;", clean_c)
        self.assertNotIn("goto", clean_c)

    def test_unnatural_switch_trampoline_collapses_without_gotos(self):
        mode = Varnode(AddressSpace.REGISTER, 0x00, 8, symbol="mode")
        c_vn = Varnode(AddressSpace.UNIQUE, 0x50, 1)
        # Block 1 branches to trampoline Block 10 (true) or Block 20 (false)
        b1_ops = [
            PCodeOp(1, PCodeOpCode.INT_EQUAL, c_vn, [mode, Varnode(AddressSpace.CONST, 0, 8)], 0x1000),
            PCodeOp(2, PCodeOpCode.CBRANCH, None, [Varnode(AddressSpace.CONST, 10, 8), c_vn], 0x1004),
        ]
        # Trampoline Block 10 jumps to Worker Block 2
        t10_ops = [PCodeOp(3, PCodeOpCode.BRANCH, None, [Varnode(AddressSpace.CONST, 2, 8)], 0x1010)]
        # Trampoline Block 20 jumps to Worker Block 3
        t20_ops = [PCodeOp(4, PCodeOpCode.BRANCH, None, [Varnode(AddressSpace.CONST, 3, 8)], 0x1020)]
        b2_ops = [PCodeOp(5, PCodeOpCode.RETURN, None, [Varnode(AddressSpace.CONST, 100, 8)], 0x1030)]
        b3_ops = [PCodeOp(6, PCodeOpCode.RETURN, None, [Varnode(AddressSpace.CONST, 200, 8)], 0x1040)]

        func = PCodeFunction(
            name="trampoline_switch",
            entry_rva=0x1000,
            params=[mode],
            blocks={
                1: PCodeBasicBlock(1, 0x1000, b1_ops, succs=[20, 10], preds=[]),
                10: PCodeBasicBlock(10, 0x1010, t10_ops, succs=[2], preds=[1]),
                20: PCodeBasicBlock(20, 0x1020, t20_ops, succs=[3], preds=[1]),
                2: PCodeBasicBlock(2, 0x1030, b2_ops, succs=[], preds=[10]),
                3: PCodeBasicBlock(3, 0x1040, b3_ops, succs=[], preds=[20]),
            },
        )
        restructurer = RellicGotoFreeRestructurer()
        mlir_ir, clean_c = restructurer.restructure_function(func)
        self.assertIn("if (mode == 0)", clean_c)
        self.assertIn("return 0x64;", clean_c)
        self.assertIn("return 0xc8;", clean_c)
        self.assertNotIn("goto", clean_c)

    def test_pass_manager_restructure_goto_free(self):
        x = Varnode(AddressSpace.REGISTER, 0x00, 8, symbol="x")
        func = PCodeFunction(
            name="pass_mgr_test",
            entry_rva=0x1000,
            params=[x],
            blocks={
                1: PCodeBasicBlock(1, 0x1000, [PCodeOp(1, PCodeOpCode.RETURN, None, [x], 0x1000)], succs=[], preds=[])
            },
        )
        pm = StagedPCodePassManager()
        mlir, c_code = pm.restructure_goto_free(func)
        self.assertIn("uint64_t pass_mgr_test(uint64_t x) {", c_code)
        self.assertIn("return x;", c_code)
        self.assertNotIn("goto", c_code)


class TestFullIntegratedPipeline(unittest.TestCase):
    """End-to-end integration test matching real-world OLLVM/Promon obfuscated binaries."""

    def test_end_to_end_pass_manager_pipeline(self):
        func = build_obfuscated_test_function()
        shm = ZeroCopyShmBridge()
        manager = StagedPCodePassManager(shm)

        mba_pass = EGraphMBADeobfuscatorPass()
        cff_pass = SymbolicCFFDeflattenerPass()

        manager.register_hook(PCodeMaturityStage.PCMAT_EGRAPH_MBA, "mba", mba_pass)
        manager.register_hook(PCodeMaturityStage.PCMAT_DEFLATTEN, "cff", cff_pass)

        # Run the full 7-stage pipeline
        manager.run_pipeline(func)

        # Verify telemetry
        self.assertEqual(len(manager.telemetry), 7)

        # Verify MBA simplification happened in block 1 (mba_sum)
        simplified_targets = [entry["target"] for entry in mba_pass.simplifications_log]
        self.assertIn("mba_sum", simplified_targets)

        # Verify dead trap block 3 was eliminated by CFF pass
        self.assertNotIn(3, func.blocks)

        # Verify restructurer produces clean goto-free C code
        restructurer = MLIRGotoFreeRestructurer()
        mlir_ir, clean_c = restructurer.restructure_function(func)

        self.assertIn("uint64_t verify_session_signature(uint64_t x, uint64_t y, uint64_t z) {", clean_c)
        self.assertNotIn("goto", clean_c)
        self.assertNotIn("0xDEADDEAD", clean_c)  # Dead trap payload pruned
        shm.close()


if __name__ == "__main__":
    unittest.main()
