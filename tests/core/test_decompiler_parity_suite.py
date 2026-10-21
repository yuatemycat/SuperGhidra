"""
tests/core/test_decompiler_parity_suite.py
==========================================

Comprehensive test suite verifying SuperGhidra's live binary analysis tools:
  1. `match_flirt_signatures` (FLIRT library pattern matching)
  2. `import_type_library` (TIL type library & C declarations ingestion)
  3. `query_binary_dataflow` (Sparse-matrix Datalog inter-procedural reachability)
  4. `solve_global_type_lattice` (Whole-program global type lattice constraint solver)
  5. `recover_classes` (MSVC RTTI & Exception Handling C++ class recovery)

Evaluates tools against:
  - Synthetic / Mock binaries (x86_64 PEs with synthetic .text, .rdata, RTTI structures)
  - Real Win32 system binaries (`C:\\Windows\\System32\\kernel32.dll`)
  - Real Hex-Rays IDA Pro core library (`E:\\01_Apps\\Installed\\IDA_PRO\\ida.dll`)
"""

from __future__ import annotations

import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from typing import Any, Dict

from superghidra.core.live_binary_tools import (
    STRUCT_CATALOG,
    get_struct_catalog,
    import_type_library,
    match_flirt_signatures,
    query_binary_dataflow,
    roundtrip_real_chunk,
    solve_global_type_lattice,
)
from superghidra.formats.msvc_class_recovery import (
    ClassRecoveryReport,
    recover_classes,
)
from tests.formats.test_msvc_class_recovery import BASE, build_pe_sections


KERNEL32_PATH = Path(r"C:\Windows\System32\kernel32.dll")
IDA_DLL_PATH = Path(r"E:\01_Apps\Installed\IDA_PRO\ida.dll")
REAL_SIG_PATH = Path(r"E:\01_Apps\Installed\IDA_PRO\sig\pc\bc31cls.sig")


# =============================================================================
# 1. MOCK / SYNTHETIC BINARY TOOL SUITE
# =============================================================================

class TestMockBinaryParityTools(unittest.TestCase):
    """Verifies all 5 parity tools on synthetic PE binaries and C declarations."""

    def test_mock_dataflow_reachability(self):
        """Construct synthetic PE with register mov chain and test Datalog reachability."""
        # Instruction sequence in .text:
        # mov rax, rbx ; mov rcx, rax ; mov rdx, rcx ; ret
        # Edges expected: rbx -> rax, rax -> rcx, rcx -> rdx
        code = bytes.fromhex("4889D8 4889C1 4889CA C3")
        raw_pe = build_pe_sections([
            (b".text", 0x1000, code, 0x60000020),
        ])

        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(raw_pe)
            tmp_path = f.name

        try:
            res = query_binary_dataflow(tmp_path)
            self.assertTrue(res["is_reachable"], "Default query should find reachability across chained movs")
            self.assertGreaterEqual(res["edge_count"], 2)
            self.assertGreaterEqual(res["path_length"], 1)
            self.assertGreaterEqual(len(res["traversed_nodes"]), 2)

            # Query with unreachable sink
            unreachable_res = query_binary_dataflow(
                tmp_path,
                source_var=res["source_var"],
                sink_var="nonexistent_var@0x0",
            )
            self.assertFalse(unreachable_res["is_reachable"])
            self.assertEqual(unreachable_res["path_length"], 0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_mock_type_lattice_displacement_constraints(self):
        """Construct synthetic PE with memory displacement accesses and solve lattice."""
        # Instruction sequence:
        # mov [rcx + 0x18], rax  (8-byte disp 0x18)
        # mov [rcx + 0x20], rbx  (8-byte disp 0x20)
        # mov rdx, [rcx + 0x28]  (8-byte disp 0x28)
        # ret
        code = bytes.fromhex("48894118 48895920 488B5128 C3")
        raw_pe = build_pe_sections([
            (b".text", 0x1000, code, 0x60000020),
        ])

        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(raw_pe)
            tmp_path = f.name

        try:
            res = solve_global_type_lattice(tmp_path)
            self.assertGreaterEqual(res["constraint_count"], 2)
            self.assertGreaterEqual(res["iterations"], 1)
            self.assertIn("resolved_variables", res)
            self.assertIn("recovered_struct_layouts", res)
            self.assertGreaterEqual(len(res["source_addresses"]), 2)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_mock_flirt_signature_matching(self):
        """Construct synthetic PE with function prologue and match against synthetic signature."""
        # Prologue: push ebp; mov ebp, esp; sub esp, 0x20; mov [ebp-4], ecx
        code = bytes.fromhex("558BEC83EC20894DFC90C3")
        raw_pe = build_pe_sections([
            (b".text", 0x1000, code, 0x60000020),
        ])

        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(raw_pe)
            tmp_path = f.name

        sig_dump = (
            "Pattern: 558BEC83EC20\n"
            "\t0000:mock_runtime_allocator\n"
        )

        try:
            res = match_flirt_signatures(tmp_path, sig_path=sig_dump)
            self.assertEqual(res["total_patterns"], 1)
            self.assertEqual(res["matched_count"], 1)
            self.assertEqual(res["matches"][0]["symbol_name"], "mock_runtime_allocator")
            self.assertEqual(res["matches"][0]["confidence"], 1.0)
            self.assertIn("0x180001000", res["matched_functions"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_mock_type_library_ingestion_and_catalog(self):
        """Ingest synthetic C declarations and verify StructLayoutSpec catalog."""
        c_code = (
            "enum DeviceStatus : uint32_t { STATUS_OFF = 0, STATUS_ON = 1 };\n"
            "struct DeviceConfig {\n"
            "    uint32_t device_id;\n"
            "    uint32_t baud_rate;\n"
            "    uint64_t flags;\n"
            "};\n"
            "typedef uint32_t dev_handle_t;\n"
        )
        res = import_type_library(c_code)
        self.assertEqual(res["enums_count"], 1)
        self.assertEqual(res["structs_count"], 1)
        self.assertEqual(res["typedefs_count"], 1)
        self.assertIn("DeviceConfig", STRUCT_CATALOG)

        spec = STRUCT_CATALOG["DeviceConfig"]
        self.assertEqual(spec.name, "DeviceConfig")
        self.assertEqual(spec.byte_size, 16)
        self.assertEqual(spec.alignment, 8)

    def test_mock_class_recovery(self):
        """Construct synthetic PE with RTTI metadata and verify class recovery."""
        va = lambda rva: BASE + rva  # noqa: E731
        text = bytearray(b"\xC3" * 0x40)
        rdata = bytearray(0x200)

        # TD: .?AVMyCustomService@@ at RVA 0x2000 (pVFTable: 8, spare: 8, name at +16)
        rdata[0x10:0x10 + 22] = b".?AVMyCustomService@@\x00"
        td_rva = 0x2000

        # CompleteObjectLocator at RVA 0x2040 (sig, off, cdOff, pTypeDesc, pClassDesc, pSelf)
        struct.pack_into("<IIIiii", rdata, 0x40, 1, 0, 0, td_rva, 0x2070, 0x2040)

        # ClassHierarchyDescriptor at RVA 0x2070 (sig, attr, numBases, pBaseClassArray)
        struct.pack_into("<IIIi", rdata, 0x70, 0, 0, 1, 0x2090)

        # BaseClassArray at RVA 0x2090
        struct.pack_into("<i", rdata, 0x90, 0x20A0)

        # BaseClassDescriptor at RVA 0x20A0 (pTypeDesc, numContainedBases, mdisp, pdisp, vdisp, attr, pClassDesc)
        struct.pack_into("<iIiiiIi", rdata, 0xA0, td_rva, 0, 0, -1, 0, 0, 0x2070)

        raw_pe = build_pe_sections([
            (b".text", 0x1000, bytes(text), 0x60000020),
            (b".rdata", 0x2000, bytes(rdata), 0x40000040),
        ])

        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(raw_pe)
            tmp_path = f.name

        try:
            rep = recover_classes(tmp_path)
            self.assertEqual(rep.arch, "x86_64")
            names = [c.name for c in rep.rtti_classes]
            self.assertIn("MyCustomService", names)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


# =============================================================================
# 2. REAL KERNEL32.DLL BINARY SUITE
# =============================================================================

class TestRealKernel32ParityTools(unittest.TestCase):
    """Evaluates live binary tools on real Win32 core library (kernel32.dll)."""

    def setUp(self):
        if not KERNEL32_PATH.is_file():
            self.skipTest(f"kernel32.dll not present at {KERNEL32_PATH}")

    def test_kernel32_dataflow_reachability(self):
        t0 = time.perf_counter()
        res = query_binary_dataflow(str(KERNEL32_PATH))
        t_elapsed = time.perf_counter() - t0

        self.assertTrue(res["is_reachable"], "Dataflow in kernel32.dll must be reachable")
        self.assertGreaterEqual(res["edge_count"], 10, "kernel32 should have >= 10 dataflow edges")
        self.assertGreaterEqual(res["path_length"], 1)
        self.assertGreaterEqual(len(res["traversed_nodes"]), 2)
        self.assertLess(t_elapsed, 2.0, f"Datalog reachability took too long: {t_elapsed:.3f}s")

    def test_kernel32_global_type_lattice(self):
        t0 = time.perf_counter()
        res = solve_global_type_lattice(str(KERNEL32_PATH))
        t_elapsed = time.perf_counter() - t0

        self.assertGreaterEqual(res["constraint_count"], 10, "kernel32 should yield >= 10 type constraints")
        self.assertGreaterEqual(res["iterations"], 1)
        self.assertIn("resolved_variables", res)
        self.assertLess(t_elapsed, 2.0, f"Lattice solving took too long: {t_elapsed:.3f}s")

    def test_kernel32_flirt_scan(self):
        # Fast scan against real Borland/PC signatures
        sig_arg = str(REAL_SIG_PATH) if REAL_SIG_PATH.is_file() else None
        res = match_flirt_signatures(str(KERNEL32_PATH), sig_path=sig_arg)
        self.assertIn("total_patterns", res)
        self.assertIn("matches", res)
        self.assertEqual(res["binary_path"], str(KERNEL32_PATH))

    def test_kernel32_class_recovery_pure_c_binary(self):
        rep = recover_classes(str(KERNEL32_PATH))
        self.assertIsInstance(rep, ClassRecoveryReport)
        self.assertEqual(rep.arch, "x86_64")
        # kernel32 is a C library, so RTTI class count is expected to be 0 without error
        self.assertEqual(len(rep.rtti_classes), 0)


# =============================================================================
# 3. REAL IDA.DLL (35 MB CORE REVERSE ENGINEERING ENGINE) SUITE
# =============================================================================

class TestRealIdaDllParityTools(unittest.TestCase):
    """Evaluates live binary tools on real Hex-Rays IDA Pro core library (ida.dll)."""

    def setUp(self):
        if not IDA_DLL_PATH.is_file():
            self.skipTest(f"ida.dll not present at {IDA_DLL_PATH}")

    def test_ida_dll_dataflow_reachability(self):
        t0 = time.perf_counter()
        res = query_binary_dataflow(str(IDA_DLL_PATH))
        t_elapsed = time.perf_counter() - t0

        self.assertTrue(res["is_reachable"], "Dataflow in ida.dll must be reachable")
        self.assertGreaterEqual(res["edge_count"], 10)
        self.assertGreaterEqual(res["path_length"], 1)
        self.assertLess(t_elapsed, 3.0, f"Datalog reachability on ida.dll took {t_elapsed:.3f}s")

    def test_ida_dll_global_type_lattice(self):
        t0 = time.perf_counter()
        res = solve_global_type_lattice(str(IDA_DLL_PATH))
        t_elapsed = time.perf_counter() - t0

        self.assertGreaterEqual(res["constraint_count"], 10)
        self.assertGreaterEqual(res["iterations"], 1)
        self.assertLess(t_elapsed, 3.0, f"Lattice solving on ida.dll took {t_elapsed:.3f}s")

    def test_ida_dll_class_recovery_rtti_and_eh(self):
        t0 = time.perf_counter()
        rep = recover_classes(str(IDA_DLL_PATH))
        t_elapsed = time.perf_counter() - t0

        self.assertGreaterEqual(len(rep.rtti_classes), 5, "ida.dll must yield >= 5 C++ classes")
        rtti_map = rep.rtti_by_name()

        # Check recovery of key IDA exception classes via EH tables
        self.assertIn("interr_exc_t", rtti_map)
        self.assertIn("loader_failure_t", rtti_map)
        self.assertIn("omf_probing_failure_t", rtti_map)
        self.assertIn("_com_error", rtti_map)

        # Check object sizes and inheritance hierarchy
        interr = rtti_map["interr_exc_t"]
        self.assertEqual(interr.object_size, 32)
        self.assertIn("std::exception", interr.bases)

        loader_fail = rtti_map["loader_failure_t"]
        self.assertEqual(loader_fail.object_size, 24)
        self.assertIn("std::exception", loader_fail.bases)

        self.assertLess(t_elapsed, 25.0, f"Class recovery on ida.dll took {t_elapsed:.3f}s")

    def test_ida_dll_flirt_matching_with_real_sig(self):
        if not REAL_SIG_PATH.is_file():
            self.skipTest(f"Signature file missing: {REAL_SIG_PATH}")
        t0 = time.perf_counter()
        res = match_flirt_signatures(str(IDA_DLL_PATH), sig_path=str(REAL_SIG_PATH))
        t_elapsed = time.perf_counter() - t0

        self.assertEqual(res["total_patterns"], 162)
        self.assertIn("matches", res)
        self.assertLess(t_elapsed, 3.0, f"FLIRT matching on ida.dll took {t_elapsed:.3f}s")

    def test_ida_dll_storage_chunk_compression_roundtrip(self):
        # LZ4 chunk test
        lz4_res = roundtrip_real_chunk(str(IDA_DLL_PATH), codec="lz4")
        self.assertTrue(lz4_res["lossless"], "LZ4 compression must be perfectly lossless")
        self.assertTrue(lz4_res["slot_matches_stored"])
        self.assertEqual(lz4_res["chunk_len"], 16384)
        self.assertGreaterEqual(lz4_res["orig_len"], 16384)
        self.assertLess(lz4_res["comp_len"], lz4_res["orig_len"])
        self.assertGreater(lz4_res["orig_len"] / lz4_res["comp_len"], 1.1)

        # Zstd chunk test
        zstd_res = roundtrip_real_chunk(str(IDA_DLL_PATH), codec="zstd")
        self.assertTrue(zstd_res["lossless"], "Zstd compression must be perfectly lossless")
        self.assertTrue(zstd_res["slot_matches_stored"])
        self.assertEqual(zstd_res["chunk_len"], 16384)
        self.assertGreaterEqual(zstd_res["orig_len"], 16384)
        self.assertLess(zstd_res["comp_len"], zstd_res["orig_len"])


# =============================================================================
# 4. SAFETY & RESILIENCE INVARIANTS
# =============================================================================

class TestParityToolsSafetyAndInvariants(unittest.TestCase):
    """Verifies graceful handling of empty inputs, missing files, and corrupted declarations."""

    def test_nonexistent_binary_raises_error(self):
        with self.assertRaises((FileNotFoundError, ValueError)):
            query_binary_dataflow(r"Z:\NonExistent\Dummy.dll")

    def test_flirt_empty_sig_handling(self):
        raw_pe = build_pe_sections([
            (b".text", 0x1000, b"\xC3" * 16, 0x60000020),
        ])
        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(raw_pe)
            tmp_path = f.name
        try:
            res = match_flirt_signatures(tmp_path, sig_path="Pattern: \n")
            self.assertEqual(res["matched_count"], 0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_type_library_corrupted_c_resilience(self):
        # Malformed C string should not raise unhandled exception
        res = import_type_library("@@ INVALID SYNTAX !!! {{ }} ;;;")
        self.assertIsInstance(res, dict)
        self.assertIn("enums_count", res)
        self.assertIn("structs_count", res)


if __name__ == "__main__":
    unittest.main()
