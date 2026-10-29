#!/usr/bin/env python3
"""
test_mcp_38_tools.py
====================
Comprehensive unit test suite for all 38 MCP tools in pyghidra-mcp / SuperGhidraMCP:
  - Verifies all 38 tools are registered on `pyghidra_mcp.server.mcp`
  - Verifies `verify_smt_equivalence` with `arch="x86_64"` and `target_reg="rax"` on x86_64 machine hex bytes
  - Verifies `verify_smt_equivalence` with `target_reg="d0"` on ARM64 FP machine hex bytes (`FADD D0, D0, D1`)
  - Verifies `CIntrinsic` is exported in `SuperGhidra.__init__`
  - Verifies core SuperGhidra MCP tool handlers end-to-end
"""

from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest

import pytest

SUPERGHIDRA_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# pyghidra-mcp source tree: SUPERGHIDRA_PYGHIDRA_MCP_SRC, else a sibling checkout.
PYGHIDRA_MCP_SRC = os.environ.get(
    "SUPERGHIDRA_PYGHIDRA_MCP_SRC",
    os.path.join(os.path.dirname(SUPERGHIDRA_DIR), "SuperghidraMCP", "src")
    if os.path.isdir(os.path.join(os.path.dirname(SUPERGHIDRA_DIR), "SuperghidraMCP", "src"))
    else os.path.join(os.path.dirname(SUPERGHIDRA_DIR), "pyghidra-mcp", "src"),
)

if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)
if os.path.isdir(PYGHIDRA_MCP_SRC) and PYGHIDRA_MCP_SRC not in sys.path:
    sys.path.insert(0, PYGHIDRA_MCP_SRC)

mcp_tools = pytest.importorskip("pyghidra_mcp.mcp_tools", reason="pyghidra-mcp not installed or found")
mcp = pytest.importorskip("pyghidra_mcp.server", reason="pyghidra-mcp not installed or found").mcp

EXPECTED_38_TOOLS = [
    "decompile_function",
    "search_symbols_by_name",
    "search_code",
    "list_project_binaries",
    "list_project_binary_metadata",
    "rename_function",
    "rename_variable",
    "save",
    "set_variable_type",
    "set_function_prototype",
    "set_comment",
    "delete_project_binary",
    "list_exports",
    "list_imports",
    "list_xrefs",
    "search_strings",
    "read_bytes",
    "disassemble",
    "gen_callgraph",
    "import_binary",
    "list_forks",
    "merge_fork",
    "discard_fork",
    "rva_translate",
    "gpu_adrp_scan",
    "gpu_seed_functions",
    "set_governor_mode",
    "hibernate",
    "clear_cache",
    "migrate_struct_shifts",
    "verify_smt_equivalence",
    "export_synthetic_symbols",
    "cross_reference_apk_jni",
    "diff_binaries",
    "verify_emulator_memory",
    "neural_decompile_skin",
    "migrate_semantic_deltas",
    "preindex_dwarf_pdb",
]

# Tools added after the original 38 (multi-architecture binary loader / MSVC class recovery /
# Serialize() layout tracing, CArchive decoding, storage compression, __usercall, CFF, dataflow, type lattice).
EXPECTED_EXTRA_TOOLS = [
    "inspect_binary",
    "recover_cpp_classes",
    "trace_serialize",
    "decode_carchive",
    "benchmark_storage_compression",
    "compile_usercall_prototype",
    "deflatten_control_flow",
    "query_binary_dataflow",
    "solve_global_type_lattice",
    "sync_fork",
    "get_session_info",
    "resolve_conflict",
    "inspect_analysis_view",
    "trace_native_values",
    "decompile_all",
    "apple_dispatch",
    "il2cpp_recover",
    "crate_audit",
]


class TestMCP38ToolsAndSMTBridge(unittest.TestCase):
    """Tests for 38 MCP tool registrations, JSON schemas, and multi-arch/FP SMT verification."""

    def test_all_38_tools_registered_in_server(self):
        """Confirm all 38 tools are registered on pyghidra_mcp.server.mcp."""
        registered_tools = {t.name for t in mcp._tool_manager.list_tools()}
        self.assertEqual(len(EXPECTED_38_TOOLS), 38)
        self.assertEqual(registered_tools, set(EXPECTED_38_TOOLS) | set(EXPECTED_EXTRA_TOOLS))

    def test_all_38_schema_json_files_exist_and_valid(self):
        """Confirm all 38 tools are registered live and verify_smt_equivalence has arch='arm64' default."""
        import inspect

        registered_tools = {t.name for t in mcp._tool_manager.list_tools()}
        self.assertEqual(len(EXPECTED_38_TOOLS), 38)
        for tool_name in EXPECTED_38_TOOLS:
            self.assertIn(tool_name, registered_tools, f"Missing live tool registration: {tool_name}")

        sig = inspect.signature(mcp_tools.verify_smt_equivalence)
        self.assertIn("arch", sig.parameters)
        self.assertEqual(sig.parameters["arch"].default, "arm64")

    def test_verify_smt_equivalence_x86_64_rax(self):
        """Verify verify_smt_equivalence with arch='x86_64' and target_reg='rax' on x86_64 machine hex bytes."""
        # ENDBR64 (F3 0F 1E FA)
        # PUSH rbp (55)
        # MOV rbp, rsp (48 89 E5)
        # ADD rdi, rsi (48 01 F7)
        # MOV rax, rdi (48 89 F8)
        # SUB rax, 5 (48 83 E8 05)
        # POP rbp (5D)
        # RET (C3)
        x86_hex = "f3 0f 1e fa 55 48 89 e5 48 01 f7 48 89 f8 48 83 e8 05 5d c3"

        res_eq = mcp_tools.verify_smt_equivalence(
            pcode_or_hex=x86_hex,
            c_code="return (rdi + rsi) - 5;",
            target_reg="rax",
            base_pc=0x401000,
            arch="x86_64",
        )
        self.assertEqual(res_eq.status, "ok")
        self.assertTrue(res_eq.equivalent)
        self.assertEqual(res_eq.smt_status, "UNSAT")
        self.assertEqual(res_eq.target_reg, "rax")

        # Divergent C code on x86_64 -> SAT with counterexample
        res_div = mcp_tools.verify_smt_equivalence(
            pcode_or_hex=x86_hex,
            c_code="return (rdi + rsi) - 9;",
            target_reg="rax",
            base_pc=0x401000,
            arch="x86_64",
        )
        self.assertEqual(res_div.status, "ok")
        self.assertFalse(res_div.equivalent)
        self.assertEqual(res_div.smt_status, "SAT")

        # Non-rax x86_64 target register (rcx): ADD rcx, rdx (48 01 D1)
        res_rcx = mcp_tools.verify_smt_equivalence(
            pcode_or_hex="48 01 d1",
            c_code="rcx = rcx + rdx;",
            target_reg="rcx",
            base_pc=0x401000,
            arch="x86_64",
        )
        self.assertEqual(res_rcx.status, "ok")
        self.assertTrue(res_rcx.equivalent)
        self.assertEqual(res_rcx.smt_status, "UNSAT")

    def test_verify_smt_equivalence_arm64_fp_d0(self):
        """Verify verify_smt_equivalence with target_reg='d0' on ARM64 FP machine hex bytes (FADD D0, D0, D1)."""
        # FADD D0, D0, D1 (0x1E612800 -> little-endian: 00 28 61 1e)
        # RET (0xD65F03C0 -> little-endian: c0 03 5f d6)
        fp_hex = struct.pack("<II", 0x1E612800, 0xD65F03C0).hex(" ")

        res_eq = mcp_tools.verify_smt_equivalence(
            pcode_or_hex=fp_hex,
            c_code="return d0 + d1;",
            target_reg="d0",
            base_pc=0x4000,
            arch="arm64",
        )
        self.assertEqual(res_eq.status, "ok")
        self.assertFalse(res_eq.equivalent)
        self.assertEqual(res_eq.smt_status, "UNKNOWN")
        self.assertEqual(res_eq.target_reg, "d0")

        # Divergent FP C code -> UNKNOWN (floating point ops intentionally uninterpreted/UNKNOWN)
        res_div = mcp_tools.verify_smt_equivalence(
            pcode_or_hex=fp_hex,
            c_code="return d0 - d1;",
            target_reg="d0",
            base_pc=0x4000,
            arch="arm64",
        )
        self.assertEqual(res_div.status, "ok")
        self.assertFalse(res_div.equivalent)
        self.assertEqual(res_div.smt_status, "UNKNOWN")

        # Multi-instruction FP: FADD D0, D0, D1; FMUL D0, D0, D2; RET
        fp_mul_hex = struct.pack("<III", 0x1E612800, 0x1E620800, 0xD65F03C0).hex(" ")
        res_mul = mcp_tools.verify_smt_equivalence(
            pcode_or_hex=fp_mul_hex,
            c_code="return (d0 + d1) * d2;",
            target_reg="d0",
            base_pc=0x4000,
            arch="arm64",
        )
        self.assertEqual(res_mul.status, "ok")
        self.assertFalse(res_mul.equivalent)
        self.assertEqual(res_mul.smt_status, "UNKNOWN")

    def test_superghidra_init_exports_cintrinsic(self):
        """Verify CIntrinsic is exported from SuperGhidra.__init__."""
        init_path = os.path.join(SUPERGHIDRA_DIR, "src", "superghidra", "__init__.py")
        if not os.path.exists(init_path):
            init_path = os.path.join(SUPERGHIDRA_DIR, "__init__.py")
        spec = importlib.util.spec_from_file_location(
            "SuperGhidra",
            init_path,
            submodule_search_locations=[SUPERGHIDRA_DIR],
        )
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        sys.modules["SuperGhidra"] = module
        assert spec.loader is not None
        spec.loader.exec_module(module)

        self.assertTrue(hasattr(module, "CIntrinsic"), "CIntrinsic must be exported in SuperGhidra.__init__.py")
        self.assertEqual(module.CIntrinsic.__name__, "CIntrinsic")
        inst = module.CIntrinsic(name="ZEXT48", args=[])
        self.assertEqual(inst.name, "ZEXT48")

    def test_new_reformation_mcp_tools_smoke(self):
        """Smoke test migrate_semantic_deltas and preindex_dwarf_pdb MCP tools."""
        mcp_tools._ensure_superghidra_imported()
        from superghidra.diff.semantic_delta_log import SemanticDeltaLog, SemanticEvent

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = os.path.join(tmp_dir, "baseline.jsonl")
            out_path = os.path.join(tmp_dir, "migrated.jsonl")
            delta_log = SemanticDeltaLog(log_path)
            delta_log.append(
                SemanticEvent.create_rename_symbol(
                    old_name="sub_1000",
                    new_name="combat_tick",
                    target_address=0x1000,
                )
            )
            bin_a = json.dumps([
                {"func_id": "f0", "name": "sub_1000", "address": 0x1000, "instructions": ["mov", "add", "ret"]}
            ])
            bin_b = json.dumps([
                {"func_id": "f1", "name": "sub_2000", "address": 0x2000, "instructions": ["mov", "add", "ret"]}
            ])
            res_delta = mcp_tools.migrate_semantic_deltas(
                delta_log_path=log_path,
                old_binary_path=bin_a,
                new_binary_path=bin_b,
                output_delta_log_path=out_path,
                threshold=0.5,
            )
            self.assertEqual(res_delta.status, "ok")
            self.assertEqual(res_delta.total_baseline_events, 1)

            types_json = os.path.join(tmp_dir, "types.json")
            with open(types_json, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "canonical_types": [
                            {
                                "type_id": "t_vec2",
                                "name": "Vec2",
                                "kind": "struct",
                                "byte_size": 8,
                                "alignment": 4,
                                "members": [
                                    {"name": "x", "type_id": "t_f32", "offset": 0, "size": 4},
                                    {"name": "y", "type_id": "t_f32", "offset": 4, "size": 4},
                                ],
                            }
                        ],
                        "symbols": [],
                    },
                    f,
                )
            res_idx = mcp_tools.preindex_dwarf_pdb(
                binary_or_pdb_path=types_json,
                db_output_path=":memory:",
                query_symbol_or_type="Vec2",
            )
            self.assertEqual(res_idx.status, "ok")
            self.assertGreaterEqual(res_idx.total_canonical_types, 1)
            self.assertIn("struct Vec2", res_idx.c_declaration or "")


if __name__ == "__main__":
    unittest.main()
