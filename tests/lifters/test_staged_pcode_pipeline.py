"""
tests/lifters/test_staged_pcode_pipeline.py
===========================================

Unit and integration tests for the 5-Stage P-Code Decompiler Pass Manager:
  - STAGE_LIFTED / STAGE_SSA: P-Code IR construction
  - STAGE_EGRAPH_MBA: Equality Saturation (E-Graph) MBA simplification
  - STAGE_DEFLATTENED: Symbolic CFF dispatcher loop elimination
  - STAGE_RESTRUCTURED: Rellic goto-free MLIR AST and C emission
  - live binary tool `staged_decompile_function`
"""

import unittest
from superghidra.lifters.egraph_mlir_pipeline import (
    StagedPCodePassManager,
    StagedDecompileResult,
    PCodeFunction,
    PCodeBasicBlock,
    PCodeOp,
    PCodeOpCode,
    Varnode,
    AddressSpace,
    build_obfuscated_test_function,
)
from superghidra.core.live_binary_tools import staged_decompile_function


class TestStagedPCodePipeline(unittest.TestCase):
    """Test StagedPCodePassManager and live binary staged decompile tool."""

    def test_run_all_passes_on_obfuscated_function(self):
        func = build_obfuscated_test_function()
        manager = StagedPCodePassManager()
        res: StagedDecompileResult = manager.run_all_passes(func)

        # Assert all 7 stages executed
        self.assertEqual(len(res.stages_executed), 7)
        self.assertIn("PCMAT_EGRAPH_MBA", res.stages_executed)
        self.assertIn("PCMAT_DEFLATTEN", res.stages_executed)

        # Assert MBA expressions were simplified by E-Graph
        self.assertTrue(res.mba_simplified)
        self.assertGreater(res.mba_simplifications_count, 0)

        # Assert opaque predicate branches were pruned
        self.assertGreater(res.pruned_branches_count, 0)

        # Assert 100% goto-free C code was emitted
        self.assertTrue(res.is_goto_free)
        self.assertNotIn("goto ", res.c_code)
        self.assertIn("int64_t verify_session_signature", res.c_code)

    def test_staged_decompile_function_live_tool(self):
        # x86_64 machine bytes:
        # mov rax, rbx ; add rax, rbx ; ret
        # 48 89 D8 ; 48 01 D8 ; C3
        code = bytes.fromhex("4889D84801D8C3")
        res = staged_decompile_function(code, func_rva=0x401000, arch="x86_64", func_name="add_regs")

        self.assertEqual(res["function_name"], "add_regs")
        self.assertEqual(res["entry_rva"], 0x401000)
        self.assertTrue(res["is_goto_free"])
        self.assertNotIn("goto ", res["c_code"])
        self.assertIn("add_regs", res["c_code"])
        self.assertIn("stages_executed", res)
        self.assertGreater(len(res["telemetry"]), 0)


if __name__ == "__main__":
    unittest.main()
