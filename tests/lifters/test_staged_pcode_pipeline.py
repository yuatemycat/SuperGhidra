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

from superghidra.core.live_binary_tools import LiftError, staged_decompile_function
from superghidra.lifters.egraph_mlir_pipeline import (
    StagedDecompileResult,
    StagedPCodePassManager,
    build_obfuscated_test_function,
)


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

        # Exact output checks (issue #3)
        body = res["c_code"].split("{", 1)[1].rsplit("}", 1)[0]
        self.assertIn("rax = rbx;", body)
        self.assertIn("rax = rax + rbx;", body)
        self.assertNotIn("rcx", body)

    def test_decompile_mov_rbx_rax(self):
        # 48 89 c3 c3 (mov rbx, rax ; ret)
        res = staged_decompile_function(bytes.fromhex("4889C3C3"), func_rva=0x1000)
        body = res["c_code"].split("{", 1)[1].rsplit("}", 1)[0]
        self.assertIn("rbx = rax;", body)

    def test_decompile_mov_rax_rbx_8b(self):
        # 48 8b c3 c3 (mov rax, rbx, 8B form ; ret)
        res = staged_decompile_function(bytes.fromhex("488BC3C3"), func_rva=0x1000)
        body = res["c_code"].split("{", 1)[1].rsplit("}", 1)[0]
        self.assertIn("rax = rbx;", body)

    def test_decompile_mov_rax_r8(self):
        # 4c 89 c0 c3 (mov rax, r8 ; ret)
        res = staged_decompile_function(bytes.fromhex("4C89C0C3"), func_rva=0x1000)
        body = res["c_code"].split("{", 1)[1].rsplit("}", 1)[0]
        self.assertIn("rax = r8;", body)

    def test_decompile_sub_rax_rbx(self):
        # 48 29 d8 c3 (sub rax, rbx ; ret)
        res = staged_decompile_function(bytes.fromhex("4829D8C3"), func_rva=0x1000)
        body = res["c_code"].split("{", 1)[1].rsplit("}", 1)[0]
        self.assertIn("rax = rax - rbx;", body)

    def test_decompile_xor_rax_rax(self):
        # 48 31 c0 c3 (xor rax, rax ; ret -> rax = 0;)
        res = staged_decompile_function(bytes.fromhex("4831C0C3"), func_rva=0x1000)
        body = res["c_code"].split("{", 1)[1].rsplit("}", 1)[0]
        self.assertTrue("rax = 0;" in body or "rax = rax ^ rax;" in body)

    def test_decompile_unhandled_lea_raises(self):
        # 48 8d 0d 00 00 00 00 c3 (lea rcx, [rip+0] ; ret)
        code = bytes.fromhex("488D0D00000000C3")
        with self.assertRaises(LiftError) as ctx:
            staged_decompile_function(code, func_rva=0x2000)
        self.assertTrue(len(ctx.exception.unhandled) > 0)
        self.assertEqual(ctx.exception.unhandled[0][0], 0x2000)

    def test_decompile_32bit_mov_raises(self):
        # b8 01 00 00 00 c3 (mov eax, 1 ; ret)
        code = bytes.fromhex("B801000000C3")
        with self.assertRaises(LiftError):
            staged_decompile_function(code, func_rva=0x1000)

    def test_decompile_missing_ret_raises(self):
        # 48 89 d8 (mov rax, rbx without ret)
        code = bytes.fromhex("4889D8")
        with self.assertRaises(LiftError):
            staged_decompile_function(code, func_rva=0x1000)

    def test_decompile_empty_bytes_raises(self):
        with self.assertRaises(LiftError):
            staged_decompile_function(b"", func_rva=0x1000)

    def test_decompile_prologue_and_epilogue(self):
        # push rbp ; mov rbp, rsp ; sub rsp, 0x20 ; add rsp, 0x20 ; pop rbp ; ret
        # 55 4889E5 4883EC20 4883C420 5D C3
        code = bytes.fromhex("554889E54883EC204883C4205DC3")
        res = staged_decompile_function(code, func_rva=0x1000)
        self.assertTrue(res["is_goto_free"])
        self.assertIn("uint64_t rbp = 0;", res["c_code"])
        self.assertIn("uint64_t rsp = 0;", res["c_code"])
        self.assertIn("rbp = *(uint64_t *)(rsp);", res["c_code"])

    def test_decompile_memory_displacement_and_declared_registers(self):
        # mov rax, [rcx + 0x18] ; mov [rcx + 0x20], rax ; mov edx, [rcx + 0x08] ; ret
        # 488B4118 48894120 8B5108 C3
        code = bytes.fromhex("488B4118488941208B5108C3")
        res = staged_decompile_function(code, func_rva=0x1000)
        self.assertTrue(res["is_goto_free"])
        self.assertIn("uint64_t rax = 0;", res["c_code"])
        self.assertIn("*(uint64_t *)(rcx_0x18)", res["c_code"])
        self.assertIn("*(uint64_t *)(rcx_0x20) = rax;", res["c_code"])

    def test_decompile_arm64_unsupported_raises(self):
        with self.assertRaises(LiftError):
            staged_decompile_function(bytes.fromhex("4889D8C3"), func_rva=0x1000, arch="arm64")


if __name__ == "__main__":
    unittest.main()
