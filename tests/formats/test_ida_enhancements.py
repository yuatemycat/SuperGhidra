"""
tests/formats/test_ida_enhancements.py
======================================

Unit and integration tests for:
1. MSVC Exception Handling (EH) metadata recovery in `msvc_class_recovery.py`
2. IDA TIL Type Library Importer in `ida_til_importer.py`
3. IDA FLIRT Signature Bridge in `ida_flirt_bridge.py`
"""

import os
from pathlib import Path
import struct
import tempfile
import unittest

from superghidra.formats.msvc_class_recovery import (
    RttiClass,
    VTable,
    _View,
    _scan_rtti,
    demangle_rtti_name,
    recover_classes,
)
from superghidra.formats.ida_til_importer import (
    find_ida_install,
    find_tilib,
    list_available_tils,
    sanitize_ida_c_declarations,
    parse_til_declarations,
    TilReport,
    import_til,
    export_clean_header,
)
from superghidra.formats.ida_flirt_bridge import (
    find_dumpsig,
    list_available_sigs,
    parse_flirt_pattern_string,
    parse_flirt_dump,
    FlirtPattern,
    FlirtSignatureIndex,
)
from tests.formats.test_msvc_class_recovery import build_pe_sections, BASE


class TestMsvcEhRecovery(unittest.TestCase):
    """Test MSVC Exception Handling metadata recovery (ThrowInfo / CatchableTypeArray)."""

    def test_synthetic_catchable_type_array(self):
        """Construct synthetic PE with CatchableType and CatchableTypeArray structures."""
        va = lambda rva: BASE + rva  # noqa: E731
        text = bytearray(b"\xC3" * 0x40)

        # Build .rdata with:
        # 1. TypeDescriptor for MyCustomException and std::exception
        # 2. CatchableType for both
        # 3. CatchableTypeArray chaining MyCustomException -> std::exception
        rdata = bytearray(0x300)

        # TD 1: .?AVMyCustomException@@ at RVA 0x2000
        # (pVFTable: 8 bytes, spare: 8 bytes, name at +16)
        rdata[0x10:0x10 + 24] = b".?AVMyCustomException@@\x00"
        td1_rva = 0x2000

        # TD 2: .?AVexception@std@@ at RVA 0x2040
        rdata[0x50:0x50 + 20] = b".?AVexception@std@@\x00"
        td2_rva = 0x2040

        # CatchableType 1: MyCustomException at RVA 0x2080 (props, pType, mdisp, pdisp, vdisp, size, copyFn)
        struct.pack_into("<Iiiiiii", rdata, 0x80, 0, td1_rva, 0, 0, 0, 48, 0)
        ct1_rva = 0x2080

        # CatchableType 2: exception at RVA 0x20A0
        struct.pack_into("<Iiiiiii", rdata, 0xA0, 0, td2_rva, 0, 0, 0, 24, 0)
        ct2_rva = 0x20A0

        # CatchableTypeArray at RVA 0x20D0 (count = 2, [ct1_rva, ct2_rva])
        struct.pack_into("<iii", rdata, 0xD0, 2, ct1_rva, ct2_rva)

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
            rtti_map = rep.rtti_by_name()
            self.assertIn("MyCustomException", rtti_map)
            exc = rtti_map["MyCustomException"]
            self.assertEqual(exc.name, "MyCustomException")
            self.assertEqual(exc.object_size, 48)
            self.assertIn("std::exception", exc.bases)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @unittest.skipUnless(os.path.isfile(r"E:\01_Apps\Installed\IDA_PRO\ida.dll"), "IDA Pro ida.dll required")
    def test_ida_dll_eh_classes(self):
        """Integration test: Verify exception classes are recovered from real ida.dll."""
        rep = recover_classes(r"E:\01_Apps\Installed\IDA_PRO\ida.dll")
        rtti_map = rep.rtti_by_name()
        # Verify classes recovered via Exception Handling tables
        self.assertIn("interr_exc_t", rtti_map)
        self.assertIn("loader_failure_t", rtti_map)
        self.assertIn("omf_probing_failure_t", rtti_map)
        self.assertIn("_com_error", rtti_map)

        # Check inheritance and sizes
        self.assertEqual(rtti_map["interr_exc_t"].object_size, 32)
        self.assertIn("std::exception", rtti_map["interr_exc_t"].bases)
        self.assertEqual(rtti_map["loader_failure_t"].object_size, 24)
        self.assertIn("std::exception", rtti_map["loader_failure_t"].bases)


class TestIdaTilImporter(unittest.TestCase):
    """Test parsing and sanitizing IDA Type Information Libraries (.til)."""

    def test_sanitize_ida_c_declarations(self):
        raw = (
            "enum __dec STATUS : unsigned __int32 { OK = 0, ERR = 0xFFUi64 };\n"
            "struct Buffer { __int64 len; unsigned __int8 data[16]; };\n"
        )
        clean = sanitize_ida_c_declarations(raw)
        self.assertNotIn("__dec", clean)
        self.assertNotIn("unsigned __int32", clean)
        self.assertIn("uint32_t", clean)
        self.assertIn("int64_t", clean)
        self.assertIn("uint8_t", clean)
        self.assertIn("0xFFULL", clean)

    def test_parse_til_declarations(self):
        c_code = (
            "enum Color : uint32_t { RED = 1, GREEN = 2, BLUE = 3 };\n"
            "struct Point { int32_t x; int32_t y; };\n"
            "typedef uint32_t size_t;\n"
        )
        report = parse_til_declarations(c_code, til_path="test.til")
        self.assertEqual(report.total_types, 3)
        self.assertIn("Color", report.enums)
        self.assertEqual(report.enums["Color"].members["GREEN"].value, 2)
        self.assertIn("Point", report.structs)
        self.assertEqual(len(report.structs["Point"].fields), 2)
        self.assertEqual(report.structs["Point"].fields[0].name, "x")
        self.assertIn("size_t", report.typedefs)
        self.assertEqual(report.typedefs["size_t"], "uint32_t")

    @unittest.skipUnless(os.path.isfile(r"E:\01_Apps\Installed\IDA_PRO\til\arm\android_arm.til"), "android_arm.til required")
    def test_import_real_android_til(self):
        """Integration test: Import android_arm.til from real IDA installation."""
        report = import_til(r"E:\01_Apps\Installed\IDA_PRO\til\arm\android_arm.til")
        self.assertGreater(report.total_types, 100)
        self.assertGreater(len(report.enums), 50)
        self.assertGreater(len(report.structs), 20)


class TestIdaFlirtBridge(unittest.TestCase):
    """Test FLIRT signature pattern parsing and matching."""

    def test_parse_flirt_pattern_string(self):
        pat_hex = "558BEC..E8....59"
        expected, mask = parse_flirt_pattern_string(pat_hex)
        self.assertEqual(len(expected), 8)
        self.assertEqual(len(mask), 8)
        self.assertEqual(expected[0:3], b"\x55\x8B\xEC")
        self.assertEqual(mask[0:3], b"\xFF\xFF\xFF")
        self.assertEqual(expected[3], 0x00)
        self.assertEqual(mask[3], 0x00)  # Wildcard

    def test_flirt_signature_index_matching(self):
        index = FlirtSignatureIndex()
        expected, mask = parse_flirt_pattern_string("558BEC56..E8....59")
        pattern = FlirtPattern(
            pattern_hex="558BEC56..E8....59",
            expected_bytes=expected,
            mask_bytes=mask,
            sig_source="test.sig",
        )
        from superghidra.formats.ida_flirt_bridge import FlirtSymbol
        pattern.symbols.append(FlirtSymbol(offset=0, name="target_func"))
        index.add_pattern(pattern)

        # Test matching buffer with arbitrary wildcard byte (0x7F) and target bytes
        probe = bytes.fromhex("558BEC567FE8123459C3")
        matches = index.match_bytes(probe)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].symbol_name, "target_func")
        self.assertEqual(index.match_function_prologue(probe), "target_func")

        # Test mismatch
        mismatch_probe = bytes.fromhex("5589E5567FE8123459C3")
        self.assertEqual(len(index.match_bytes(mismatch_probe)), 0)

    @unittest.skipUnless(os.path.isfile(r"E:\01_Apps\Installed\IDA_PRO\sig\pc\bc31cls.sig"), "bc31cls.sig required")
    def test_real_flirt_sig_loading(self):
        """Integration test: Load real bc31cls.sig and match sample prologue."""
        index = FlirtSignatureIndex()
        count = index.load_sig_file(r"E:\01_Apps\Installed\IDA_PRO\sig\pc\bc31cls.sig")
        self.assertGreater(count, 50)

        # Match known prologue
        code = bytes.fromhex("558BEC56578B46060B46087514B8080050AABBCCDDEE598956088946060BC274")
        matches = index.match_bytes(code)
        self.assertGreaterEqual(len(matches), 1)
        self.assertIn("VectorImp", matches[0].symbol_name)


if __name__ == "__main__":
    unittest.main()
