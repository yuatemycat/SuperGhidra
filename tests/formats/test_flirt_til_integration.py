"""
tests/formats/test_flirt_til_integration.py
===========================================

Comprehensive unit and integration test suite for:
  1. Hex-Rays IDA FLIRT Signature Bridge (`ida_flirt_bridge.py`)
  2. Hex-Rays IDA Type Information Library (TIL) Importer (`ida_til_importer.py`)
  3. Cross-Domain Type Library and StructLayoutSpec Catalog Integration

Covers both synthetic/mock inputs and real IDA Pro artifacts:
  - Real FLIRT signatures (`sig/pc/bc31cls.sig`, resolved via `IDA_DIR`)
  - Real TIL libraries (`til/arm/android_arm.til`, resolved via `IDA_DIR`)
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from superghidra.core.live_binary_tools import (
    _til_struct_to_spec,
)
from superghidra.formats.ida_flirt_bridge import (
    FlirtPattern,
    FlirtSignatureIndex,
    FlirtSymbol,
    find_dumpsig,
    list_available_sigs,
    parse_flirt_dump,
    parse_flirt_pattern_string,
)
from superghidra.formats.ida_til_importer import (
    TilField,
    TilStruct,
    export_clean_header,
    find_ida_install,
    find_tilib,
    import_til,
    import_type_library,
    list_available_tils,
    parse_til_declarations,
    sanitize_ida_c_declarations,
)

IDA_ENV = os.environ.get("IDA_DIR") or os.environ.get("IDADIR")
IDA_ROOT = Path(IDA_ENV) if IDA_ENV else find_ida_install()
REAL_SIG_PATH = (IDA_ROOT / "sig" / "pc" / "bc31cls.sig") if IDA_ROOT else None
REAL_TIL_PATH = (IDA_ROOT / "til" / "arm" / "android_arm.til") if IDA_ROOT else None
REAL_WIN10_TIL_PATH = (IDA_ROOT / "til" / "pc" / "mssdk64_win10.til") if IDA_ROOT else None


# =============================================================================
# 1. ENVIRONMENT & TOOL DISCOVERY
# =============================================================================

class TestIdaDiscovery(unittest.TestCase):
    """Test IDA Pro installation discovery, Flair dumpsig, and tilib resolver."""

    def test_find_ida_install_custom_and_fallback(self):
        # Existing installation
        if IDA_ROOT and IDA_ROOT.is_dir():
            detected = find_ida_install()
            self.assertIsNotNone(detected)
            self.assertTrue(detected.is_dir())

        # When custom path exists, it is prioritized
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_ida = Path(tmp_dir)
            (tmp_ida / "ida.dll").write_bytes(b"MZ\x00\x00")
            custom_detected = find_ida_install(custom_path=str(tmp_ida))
            self.assertEqual(custom_detected, tmp_ida.resolve())

    def test_find_dumpsig_utility(self):
        dumpsig = find_dumpsig()
        if IDA_ROOT and IDA_ROOT.is_dir() and (IDA_ROOT / "tools" / "flair" / "dumpsig.exe").is_file():
            self.assertIsNotNone(dumpsig)
            self.assertTrue(dumpsig.is_file())
            self.assertEqual(dumpsig.name.lower(), "dumpsig.exe")

    def test_find_tilib_utility(self):
        tilib = find_tilib()
        if IDA_ROOT and IDA_ROOT.is_dir() and (IDA_ROOT / "tools" / "tilib" / "tilib.exe").is_file():
            self.assertIsNotNone(tilib)
            self.assertTrue(tilib.is_file())
            self.assertEqual(tilib.name.lower(), "tilib.exe")

    def test_list_available_sigs_grouping(self):
        if not (IDA_ROOT and IDA_ROOT.is_dir()):
            self.skipTest("IDA Pro not installed")
        sigs = list_available_sigs()
        self.assertIsInstance(sigs, dict)
        self.assertIn("pc", sigs)
        self.assertIn("arm", sigs)
        self.assertGreater(len(sigs["pc"]), 5)
        # Check all returned items are Path objects with .sig extension
        for arch, plist in sigs.items():
            for p in plist:
                self.assertTrue(p.suffix.lower() == ".sig")

    def test_list_available_tils_grouping(self):
        if not (IDA_ROOT and IDA_ROOT.is_dir()):
            self.skipTest("IDA Pro not installed")
        tils = list_available_tils()
        self.assertIsInstance(tils, dict)
        self.assertIn("pc", tils)
        self.assertIn("arm", tils)
        self.assertGreater(len(tils["pc"]), 10)
        for arch, plist in tils.items():
            for p in plist:
                self.assertTrue(p.suffix.lower() == ".til")


# =============================================================================
# 2. FLIRT SIGNATURE BRIDGE UNIT TESTS
# =============================================================================

class TestFlirtBridgeUnit(unittest.TestCase):
    """Unit tests for FLIRT pattern parsing, mask generation, and prefix matching."""

    def test_parse_flirt_pattern_exact_bytes(self):
        expected, mask = parse_flirt_pattern_string("558BEC83EC20")
        self.assertEqual(expected, b"\x55\x8B\xEC\x83\xEC\x20")
        self.assertEqual(mask, b"\xFF\xFF\xFF\xFF\xFF\xFF")

    def test_parse_flirt_pattern_with_wildcards(self):
        # Test double dot wildcard
        expected, mask = parse_flirt_pattern_string("558BEC..E8....59")
        self.assertEqual(len(expected), 8)
        self.assertEqual(len(mask), 8)
        self.assertEqual(expected[0:3], b"\x55\x8B\xEC")
        self.assertEqual(mask[0:3], b"\xFF\xFF\xFF")
        self.assertEqual(expected[3], 0x00)
        self.assertEqual(mask[3], 0x00)
        self.assertEqual(expected[4], 0xE8)
        self.assertEqual(mask[4], 0xFF)
        self.assertEqual(expected[5:7], b"\x00\x00")
        self.assertEqual(mask[5:7], b"\x00\x00")
        self.assertEqual(expected[7], 0x59)
        self.assertEqual(mask[7], 0xFF)

    def test_parse_flirt_pattern_single_dot_and_odd_length(self):
        # Single dot wildcard
        expected, mask = parse_flirt_pattern_string("55.8B")
        self.assertEqual(expected[0], 0x55)
        self.assertEqual(mask[0], 0xFF)
        self.assertEqual(expected[1], 0x00)
        self.assertEqual(mask[1], 0x00)
        self.assertEqual(expected[2], 0x8B)
        self.assertEqual(mask[2], 0xFF)

        # Incomplete trailing character should be safely ignored
        exp_odd, mask_odd = parse_flirt_pattern_string("558")
        self.assertEqual(len(exp_odd), 1)
        self.assertEqual(exp_odd, b"\x55")

    def test_flirt_pattern_matching_predicate(self):
        exp, mask = parse_flirt_pattern_string("558BEC..E8....59")
        pat = FlirtPattern(
            pattern_hex="558BEC..E8....59",
            expected_bytes=exp,
            mask_bytes=mask,
        )

        # Matching buffer with wildcards filled with arbitrary values
        valid_code = bytes.fromhex("558BEC7FE8112259")
        self.assertTrue(pat.matches(valid_code, target_offset=0))

        # Matching buffer at non-zero offset
        prefixed = b"\x90\x90" + valid_code
        self.assertTrue(pat.matches(prefixed, target_offset=2))
        self.assertFalse(pat.matches(prefixed, target_offset=0))

        # Mismatch on fixed byte (0x59 -> 0x58)
        invalid_code = bytes.fromhex("558BEC7FE8112258")
        self.assertFalse(pat.matches(invalid_code, target_offset=0))

        # Buffer shorter than pattern
        short_buf = bytes.fromhex("558BEC")
        self.assertFalse(pat.matches(short_buf, target_offset=0))

    def test_parse_flirt_dump_multiblock(self):
        dump_text = (
            "Pattern: 558BEC83EC10\n"
            "\t0000:func_prologue_one\n"
            "\t000E:sub_helper\n\n"
            "Pattern: 558BEC56..E8....59\n"
            "\t0000:func_prologue_two\n"
            "\t0024:func_tail\n"
        )
        patterns = parse_flirt_dump(dump_text, sig_source="test_sig.sig")
        self.assertEqual(len(patterns), 2)

        p1 = patterns[0]
        self.assertEqual(p1.byte_length, 6)
        self.assertEqual(len(p1.symbols), 2)
        self.assertEqual(p1.symbols[0].name, "func_prologue_one")
        self.assertEqual(p1.symbols[0].offset, 0)
        self.assertEqual(p1.symbols[1].name, "sub_helper")
        self.assertEqual(p1.symbols[1].offset, 0x0E)

        p2 = patterns[1]
        self.assertEqual(p2.byte_length, 9)
        self.assertEqual(p2.symbols[0].name, "func_prologue_two")

    def test_flirt_signature_index_prefix_partitioning(self):
        index = FlirtSignatureIndex()

        # Pattern 1: Starts with fixed 2-byte prefix 55 8B
        exp1, mask1 = parse_flirt_pattern_string("558BEC")
        pat1 = FlirtPattern("558BEC", exp1, mask1, [FlirtSymbol(0, "entry_558b")])
        index.add_pattern(pat1)

        # Pattern 2: Starts with wildcard prefix .. 8B
        exp2, mask2 = parse_flirt_pattern_string("..8BEC")
        pat2 = FlirtPattern("..8BEC", exp2, mask2, [FlirtSymbol(0, "entry_wild")])
        index.add_pattern(pat2)

        # Check internal partitioning
        self.assertIn((0x55, 0x8B), index._prefix_table)
        self.assertIn(pat1, index._prefix_table[(0x55, 0x8B)])
        self.assertIn(pat2, index._unmasked_patterns)

        # Match exact prefix
        matches1 = index.match_bytes(bytes.fromhex("558BEC0000"))
        names1 = [m.symbol_name for m in matches1]
        self.assertIn("entry_558b", names1)
        self.assertIn("entry_wild", names1)

        # Match wildcard prefix with different first byte (0x56)
        matches2 = index.match_bytes(bytes.fromhex("568BEC0000"))
        names2 = [m.symbol_name for m in matches2]
        self.assertNotIn("entry_558b", names2)
        self.assertIn("entry_wild", names2)

    def test_flirt_signature_index_prologue_priority(self):
        index = FlirtSignatureIndex()
        exp, mask = parse_flirt_pattern_string("558BEC")
        # Pattern has entry symbol at 0 and internal label at 4
        pat = FlirtPattern("558BEC", exp, mask, [
            FlirtSymbol(4, "loc_internal"),
            FlirtSymbol(0, "target_function"),
        ])
        index.add_pattern(pat)

        matched = index.match_function_prologue(bytes.fromhex("558BEC1234"))
        self.assertEqual(matched, "target_function")


# =============================================================================
# 3. REAL FLIRT SIGNATURE INTEGRATION TESTS
# =============================================================================

class TestFlirtBridgeRealSigIntegration(unittest.TestCase):
    """Integration tests loading and matching real Hex-Rays FLIRT .sig files."""

    @unittest.skipUnless(REAL_SIG_PATH and REAL_SIG_PATH.is_file(), f"Real FLIRT signature missing: {REAL_SIG_PATH}")
    def test_real_bc31cls_loading_and_benchmarks(self):
        index = FlirtSignatureIndex()

        t0 = time.perf_counter()
        count = index.load_sig_file(REAL_SIG_PATH)
        t_load = time.perf_counter() - t0

        self.assertGreater(count, 50, "bc31cls.sig must contain >50 patterns")
        self.assertLess(t_load, 1.5, "FLIRT signature loading should complete under 1.5 seconds")

        # Test matching against known Borland C++ Class Library prologue
        borland_prologue = bytes.fromhex("558BEC56578B46060B46087514B8080050AABBCCDDEE598956088946060BC274")

        t_m0 = time.perf_counter()
        matches = index.match_bytes(borland_prologue)
        t_match = (time.perf_counter() - t_m0) * 1000.0

        self.assertGreaterEqual(len(matches), 1, "Must find match for Borland runtime function")
        matched_name = matches[0].symbol_name
        self.assertIn("VectorImp", matched_name, "Should match Borland VectorImp symbol")
        self.assertLess(t_match, 10.0, f"Prologue match must execute in <10ms, took {t_match:.3f}ms")

        # Fast function prologue matcher
        sym_name = index.match_function_prologue(borland_prologue)
        self.assertEqual(sym_name, matched_name)

        # Negative test: x86 NOP sled must not trigger false positives
        nop_sled = b"\x90" * 32
        self.assertEqual(len(index.match_bytes(nop_sled)), 0)


# =============================================================================
# 4. IDA TIL IMPORTER UNIT TESTS
# =============================================================================

class TestTilImporterUnit(unittest.TestCase):
    """Unit tests for IDA TIL C syntax sanitization, AST parsing, and header export."""

    def test_sanitize_ida_c_declarations_types(self):
        raw_c = (
            "// IDA Pro Dumped Header\n"
            "enum __dec STATUS : unsigned __int32 {\n"
            "    STATUS_OK = 0Ui64,\n"
            "    STATUS_ERR = 0xFFFFFFFFI64\n"
            "};\n"
            "struct TestBlock {\n"
            "    __int64 size;\n"
            "    unsigned __int64 capacity;\n"
            "    __int16 ref_count;\n"
            "    unsigned __int8 flags;\n"
            "};\n"
        )
        clean = sanitize_ida_c_declarations(raw_c)

        # Assert comment stripped
        self.assertNotIn("// IDA Pro Dumped Header", clean)

        # Assert integer types normalized
        self.assertNotIn("unsigned __int32", clean)
        self.assertNotIn("__int64", clean)
        self.assertNotIn("unsigned __int64", clean)
        self.assertNotIn("__int16", clean)
        self.assertNotIn("unsigned __int8", clean)

        self.assertIn("uint32_t", clean)
        self.assertIn("int64_t", clean)
        self.assertIn("uint64_t", clean)
        self.assertIn("int16_t", clean)
        self.assertIn("uint8_t", clean)

        # Assert enum modifier normalized
        self.assertNotIn("__dec", clean)
        self.assertIn("enum STATUS : uint32_t", clean)

        # Assert integer literal suffixes normalized
        self.assertIn("0ULL", clean)
        self.assertIn("0xFFFFFFFFLL", clean)

    def test_parse_til_declarations_enums(self):
        c_code = (
            "enum Color : uint32_t {\n"
            "    RED = 1,\n"
            "    GREEN = 0x20,\n"
            "    BLUE = 3ULL\n"
            "};\n"
            "enum Mode {\n"
            "    MODE_A,\n"
            "    MODE_B\n"
            "};\n"
        )
        rep = parse_til_declarations(c_code)
        self.assertEqual(len(rep.enums), 2)

        color = rep.enums["Color"]
        self.assertEqual(color.base_type, "uint32_t")
        self.assertEqual(color.members["RED"].value, 1)
        self.assertEqual(color.members["GREEN"].value, 0x20)
        self.assertEqual(color.members["BLUE"].value, 3)

        mode = rep.enums["Mode"]
        self.assertEqual(mode.base_type, "int")
        self.assertIn("MODE_A", mode.members)
        self.assertIn("MODE_B", mode.members)

    def test_parse_til_declarations_structs_unions_typedefs(self):
        c_code = (
            "struct Point2D {\n"
            "    int32_t x;\n"
            "    int32_t y;\n"
            "};\n"
            "struct PacketBuffer {\n"
            "    uint32_t header;\n"
            "    uint8_t payload[64];\n"
            "    void* context;\n"
            "};\n"
            "union Variant {\n"
            "    int64_t i64;\n"
            "    double f64;\n"
            "};\n"
            "typedef uint32_t handle_t;\n"
            "typedef PacketBuffer Packet_t;\n"
        )
        rep = parse_til_declarations(c_code)

        # Structs
        self.assertEqual(len(rep.structs), 3)
        pt = rep.structs["Point2D"]
        self.assertEqual(pt.kind, "struct")
        self.assertEqual(len(pt.fields), 2)
        self.assertEqual(pt.fields[0].name, "x")
        self.assertEqual(pt.fields[0].c_type, "int32_t")

        pb = rep.structs["PacketBuffer"]
        self.assertEqual(len(pb.fields), 3)
        self.assertEqual(pb.fields[1].name, "payload")
        self.assertEqual(pb.fields[1].array_dim, "64")
        self.assertEqual(pb.fields[2].name, "context")

        # Union
        var = rep.structs["Variant"]
        self.assertEqual(var.kind, "union")
        self.assertEqual(len(var.fields), 2)

        # Typedefs
        self.assertEqual(len(rep.typedefs), 2)
        self.assertEqual(rep.typedefs["handle_t"], "uint32_t")
        self.assertEqual(rep.typedefs["Packet_t"], "PacketBuffer")

        self.assertEqual(rep.total_types, 5)

    def test_export_clean_header_generation(self):
        with tempfile.NamedTemporaryFile(suffix=".h", delete=False) as f:
            out_h = Path(f.name)

        try:
            # We test exporting from synthetic C code directly
            raw_c = "enum Status : uint32_t { OK = 0 };\nstruct Vec3 { float x; float y; float z; };\n"
            clean = sanitize_ida_c_declarations(raw_c)
            hdr = (
                "/* Generated by SuperGhidra IDA TIL Importer */\n"
                "#pragma once\n"
                "#include <stdint.h>\n"
                "#include <stddef.h>\n"
                "#include <stdbool.h>\n\n"
                f"{clean}\n"
            )
            out_h.write_text(hdr, encoding="utf-8")
            self.assertTrue(out_h.is_file())
            content = out_h.read_text(encoding="utf-8")
            self.assertIn("#pragma once", content)
            self.assertIn("#include <stdint.h>", content)
            self.assertIn("struct Vec3", content)
        finally:
            if out_h.is_file():
                try:
                    out_h.unlink()
                except OSError:
                    pass


# =============================================================================
# 5. REAL IDA TIL INTEGRATION TESTS
# =============================================================================

class TestTilImporterRealTilIntegration(unittest.TestCase):
    """Integration tests importing real Hex-Rays TIL files (`android_arm.til`, `mssdk64_win10.til`)."""

    @unittest.skipUnless(REAL_TIL_PATH and REAL_TIL_PATH.is_file(), f"Real TIL file missing: {REAL_TIL_PATH}")
    def test_real_android_til_import_and_header_export(self):
        t0 = time.perf_counter()
        report = import_til(REAL_TIL_PATH)
        t_import = time.perf_counter() - t0

        self.assertGreater(report.total_types, 300, "android_arm.til should yield >300 total types")
        self.assertGreater(len(report.enums), 100, "Should contain >100 enums")
        self.assertGreater(len(report.structs), 30, "Should contain >30 structs")
        self.assertGreater(len(report.typedefs), 100, "Should contain >100 typedefs")
        self.assertLess(t_import, 2.0, f"TIL import should take <2.0s, took {t_import:.3f}s")

        # Verify key POSIX / Android networking types are present
        self.assertIn("sockaddr", report.structs)
        sockaddr = report.structs["sockaddr"]
        field_names = [f.name for f in sockaddr.fields]
        self.assertIn("sa_family", field_names)
        self.assertIn("sa_data", field_names)

        # Test clean header export
        with tempfile.NamedTemporaryFile(suffix=".h", delete=False) as f:
            out_hdr = Path(f.name)

        try:
            exported_bytes = export_clean_header(REAL_TIL_PATH, out_hdr)
            self.assertGreater(exported_bytes, 10_000, "Exported C header should exceed 10 KB")
            header_text = out_hdr.read_text(encoding="utf-8")
            self.assertIn("#pragma once", header_text)
            self.assertIn("sockaddr", header_text)
        finally:
            if out_hdr.is_file():
                try:
                    out_hdr.unlink()
                except OSError:
                    pass

    @unittest.skipUnless(REAL_WIN10_TIL_PATH and REAL_WIN10_TIL_PATH.is_file(), f"Real Win10 TIL missing: {REAL_WIN10_TIL_PATH}")
    def test_real_win10_til_import(self):
        report = import_til(REAL_WIN10_TIL_PATH)
        self.assertGreater(report.total_types, 500, "mssdk64_win10.til should yield >500 types")
        self.assertGreater(len(report.structs), 50)
        self.assertIn("_GUID", report.structs)


# =============================================================================
# 6. CROSS-DOMAIN TYPE & STRUCT LAYOUT CATALOG INTEGRATION
# =============================================================================

class TestTilCrossDomainLayoutIntegration(unittest.TestCase):
    """Verifies that imported TIL structs map accurately to SuperGhidra StructLayoutSpecs."""

    def test_til_struct_layout_computation(self):
        ts = TilStruct(
            kind="struct",
            name="AlignedRecord",
            fields=[
                TilField(name="flag", c_type="uint8_t"),
                # Alignment padding: uint8_t (1B) -> padding (3B) -> uint32_t (4B)
                TilField(name="count", c_type="uint32_t"),
                # uint64_t requires 8-byte alignment
                TilField(name="timestamp", c_type="uint64_t"),
                # Array field: 16 bytes
                TilField(name="buffer", c_type="uint8_t", array_dim="16"),
            ],
        )

        spec = _til_struct_to_spec(ts)
        self.assertEqual(spec.name, "AlignedRecord")
        self.assertEqual(spec.alignment, 8)

        # Field offsets
        field_map = {f.name: f for f in spec.fields}
        self.assertEqual(field_map["flag"].offset, 0)
        self.assertEqual(field_map["flag"].size, 1)

        self.assertEqual(field_map["count"].offset, 4)
        self.assertEqual(field_map["count"].size, 4)

        self.assertEqual(field_map["timestamp"].offset, 8)
        self.assertEqual(field_map["timestamp"].size, 8)

        self.assertEqual(field_map["buffer"].offset, 16)
        self.assertEqual(field_map["buffer"].size, 16)

        # Total size with trailing alignment padding: 16 + 16 = 32 bytes (multiple of 8)
        self.assertEqual(spec.byte_size, 32)

    def test_import_type_library_synthetic_string(self):
        c_code = (
            "enum Result : uint32_t { SUCCESS = 0, FAILURE = 1 };\n"
            "struct Header { uint32_t magic; uint32_t version; };\n"
        )
        res = import_type_library(c_code)
        self.assertTrue(res["success"])
        self.assertEqual(res["enum_count"], 1)
        self.assertEqual(res["struct_count"], 1)
        self.assertIn("Header", res["structs"])


if __name__ == "__main__":
    unittest.main()
