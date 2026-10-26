#!/usr/bin/env python3
"""
test_reformation_spec.py
========================
SuperGhidra Comprehensive Test Suite for APK/DEX/ELF JNI Cross-Referencer.

Verifies:
1. Direct Binary Android DEX Parser (`load_from_dex_bytes`):
   - Header table parsing (strings, types, protos, methods, class_defs, class_data).
   - ULEB128 decoding for method offsets and access flags.
   - Accurate extraction of ACC_NATIVE methods across direct and virtual slots.
   - Automatic identification and tagging of overloaded native methods.
2. Direct Binary ELF64 / ELF32 Parser (`load_from_elf_bytes` & `load_from_elf_file`):
   - Section header table parsing (.dynsym, .dynstr, .symtab, .strtab, .rodata, .data.rel.ro, .text).
   - Dynamic symbol table extraction and image base normalization.
   - .rodata string table scanning and string virtual address indexing.
   - JNINativeMethod table scanning and RegisterNatives discovery.
   - 100% resolution rate between Java native declarations and native code addresses.
3. APK / ZIP Container Parser (`load_from_apk_or_dex`):
   - In-memory/temp APK archive parsing containing classes*.dex and native shared libraries.
   - Standalone .dex and .so file loading.
4. Export Generators:
   - Ghidra Python postScript label and plate comment generation.
   - Structured JSON manifest export.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# Ensure SuperGhidra workspace is in sys.path
SUPERGHIDRA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)

from superghidra.integrations.apk_jni_cross_referencer import (
    APKJNICrossReferencer,
    JavaNativeMethod,
    JNICrossReferenceMatch,
    JNIRegisteredNative,
    construct_static_jni_symbol,
    mangle_jni_identifier,
)


class TestAPKJNICrossReferencerDEX(unittest.TestCase):
    """Unit tests for binary DEX parsing and Java native method extraction."""

    def test_01_dex_magic_validation(self):
        """Verifies that non-DEX bytes raise a ValueError."""
        xr = APKJNICrossReferencer()
        with self.assertRaises(ValueError):
            xr.load_from_dex_bytes(b"INVALID_MAGIC_HEADER_BYTES_1234567890")

    def test_02_dex_native_method_extraction(self):
        """Tests parsing native methods from a synthesized binary DEX."""
        methods_to_encode = [
            ("com.example.app.GameApp", "nativeInit", "()V", 0x0109),  # ACC_PUBLIC | ACC_STATIC | ACC_NATIVE
            ("com.example.app.GameApp", "updateDisplay", "(II)V", 0x0101),  # ACC_PUBLIC | ACC_NATIVE
            ("com.example.app.NativeDialog", "onDialogDismissed", "(ILjava/lang/String;)Z", 0x0101),
        ]
        dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes(methods_to_encode)
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))

        xr = APKJNICrossReferencer()
        count = xr.load_from_dex_bytes(dex_bytes)
        self.assertEqual(count, 3)
        self.assertEqual(len(xr.native_methods), 3)

        method_names = {m.method_name for m in xr.native_methods}
        self.assertEqual(method_names, {"nativeInit", "updateDisplay", "onDialogDismissed"})

        # Check static method flag
        init_m = next(m for m in xr.native_methods if m.method_name == "nativeInit")
        self.assertTrue(init_m.is_static)
        self.assertEqual(init_m.class_name, "com.example.app.GameApp")
        self.assertEqual(init_m.signature, "()V")

        # Check virtual method flag
        disp_m = next(m for m in xr.native_methods if m.method_name == "updateDisplay")
        self.assertFalse(disp_m.is_static)
        self.assertEqual(disp_m.signature, "(II)V")

    def test_03_dex_overloaded_methods(self):
        """Verifies that methods sharing the same class and name are marked as is_overloaded."""
        methods = [
            ("com.example.math.Matrix", "multiply", "(II)I", 0x0101),
            ("com.example.math.Matrix", "multiply", "(DD)D", 0x0101),  # Overload
            ("com.example.math.Matrix", "determinant", "()D", 0x0101),  # Non-overload
        ]
        dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes(methods)

        xr = APKJNICrossReferencer()
        xr.load_from_dex_bytes(dex_bytes)

        mul_methods = [m for m in xr.native_methods if m.method_name == "multiply"]
        self.assertEqual(len(mul_methods), 2)
        for m in mul_methods:
            self.assertTrue(m.is_overloaded)

        det_m = next(m for m in xr.native_methods if m.method_name == "determinant")
        self.assertFalse(det_m.is_overloaded)

    def test_04_dex_complex_signatures(self):
        """Tests parsing complex JNI signatures (arrays, objects, primitives)."""
        methods = [
            ("com.example.crypto.Keystore", "encryptPayload", "([B[BLjava/lang/String;)[B", 0x0109),
            ("com.example.crypto.Keystore", "validateToken", "(JLjava/lang/String;)Z", 0x0109),
        ]
        dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes(methods)

        xr = APKJNICrossReferencer()
        xr.load_from_dex_bytes(dex_bytes)
        self.assertEqual(len(xr.native_methods), 2)

        enc_m = next(m for m in xr.native_methods if m.method_name == "encryptPayload")
        self.assertEqual(enc_m.signature, "([B[BLjava/lang/String;)[B")

        val_m = next(m for m in xr.native_methods if m.method_name == "validateToken")
        self.assertEqual(val_m.signature, "(JLjava/lang/String;)Z")


class TestAPKJNICrossReferencerELF(unittest.TestCase):
    """Unit tests for binary ELF parsing and JNI cross-reference resolution."""

    def test_01_elf_magic_validation(self):
        """Verifies that non-ELF bytes raise a ValueError."""
        xr = APKJNICrossReferencer()
        with self.assertRaises(ValueError):
            xr.load_from_elf_bytes(b"NOT_AN_ELF_FILE_12345678901234567890")

    def test_02_elf64_exports_and_register_natives(self):
        """Tests extracting static exports and RegisterNatives tables from ELF64."""
        exports = {
            "Java_com_example_app_GameApp_nativeInit": 0x101100,
            "Java_com_example_app_GameApp_onLowMemory": 0x101200,
        }
        reg_natives = [
            ("updateDisplay", "(II)V", 0x101300),
            ("processPacket", "([B)I", 0x101400),
        ]
        elf_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes(
            exports=exports,
            registered_natives=reg_natives,
            image_base=0x100000,
            is_64bit=True
        )

        xr = APKJNICrossReferencer(image_base=0x100000, is_64bit=True)
        stats = xr.load_from_elf_bytes(elf_bytes)

        self.assertEqual(stats["exports_loaded"], 2)
        self.assertEqual(stats["registered_natives_found"], 2)
        self.assertIn("Java_com_example_app_GameApp_nativeInit", xr.elf_exports)
        self.assertEqual(xr.elf_exports["Java_com_example_app_GameApp_nativeInit"], 0x101100)
        self.assertEqual(len(xr.registered_natives), 2)

        # Check registered native fields
        reg1 = next(r for r in xr.registered_natives if r.method_name == "updateDisplay")
        self.assertEqual(reg1.signature, "(II)V")
        self.assertEqual(reg1.fn_ptr, 0x101300)

    def test_03_elf32_support(self):
        """Tests parsing 32-bit ELF binaries with 16-byte symbols and 12-byte JNINativeMethod entries."""
        exports = {
            "Java_com_arm32_NativeBridge_init": 0x101050,
        }
        reg_natives = [
            ("arm32Callback", "(I)V", 0x101080),
        ]
        elf32_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes(
            exports=exports,
            registered_natives=reg_natives,
            image_base=0x100000,
            is_64bit=False
        )

        xr = APKJNICrossReferencer(image_base=0x100000, is_64bit=False)
        stats = xr.load_from_elf_bytes(elf32_bytes)

        self.assertEqual(stats["exports_loaded"], 1)
        self.assertEqual(stats["registered_natives_found"], 1)
        self.assertIn("Java_com_arm32_NativeBridge_init", xr.elf_exports)

    def test_04_full_cross_reference_resolution_100_percent(self):
        """
        Tests end-to-end cross-reference resolution between Java DEX and Native ELF,
        achieving 100% resolution across both STATIC_EXPORT and REGISTER_NATIVES bindings.
        """
        # 1. Define Java methods
        dex_methods = [
            ("com.example.app.GameApp", "nativeInit", "()V", 0x0109),
            ("com.example.app.GameApp", "onLowMemory", "()V", 0x0109),
            ("com.example.app.GameApp", "updateDisplay", "(II)V", 0x0101),
            ("com.example.app.GameApp", "processPacket", "([B)I", 0x0101),
        ]
        dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes(dex_methods)

        # 2. Define ELF exports and RegisterNatives
        exports = {
            "Java_com_example_app_GameApp_nativeInit": 0x101100,
            "Java_com_example_app_GameApp_onLowMemory": 0x101200,
        }
        reg_natives = [
            ("updateDisplay", "(II)V", 0x101300),
            ("processPacket", "([B)I", 0x101400),
        ]
        elf_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes(
            exports=exports,
            registered_natives=reg_natives,
            image_base=0x100000,
            is_64bit=True
        )

        xr = APKJNICrossReferencer(image_base=0x100000, is_64bit=True)
        xr.load_from_dex_bytes(dex_bytes)
        xr.load_from_elf_bytes(elf_bytes)

        # 3. Resolve cross-references
        matches = xr.resolve_cross_references()
        self.assertEqual(len(matches), 4)

        match_map = {m.java_method.method_name: m for m in matches}

        # Verify static export matches
        self.assertEqual(match_map["nativeInit"].binding_type, "STATIC_EXPORT")
        self.assertEqual(match_map["nativeInit"].target_address, 0x101100)
        self.assertEqual(match_map["nativeInit"].target_rva, 0x1100)
        self.assertGreaterEqual(match_map["nativeInit"].confidence, 0.98)

        self.assertEqual(match_map["onLowMemory"].binding_type, "STATIC_EXPORT")
        self.assertEqual(match_map["onLowMemory"].target_address, 0x101200)

        # Verify RegisterNatives dynamic matches
        self.assertEqual(match_map["updateDisplay"].binding_type, "REGISTER_NATIVES")
        self.assertEqual(match_map["updateDisplay"].target_address, 0x101300)
        self.assertEqual(match_map["updateDisplay"].confidence, 1.0)

        self.assertEqual(match_map["processPacket"].binding_type, "REGISTER_NATIVES")
        self.assertEqual(match_map["processPacket"].target_address, 0x101400)
        self.assertEqual(match_map["processPacket"].confidence, 1.0)


class TestAPKContainerLoader(unittest.TestCase):
    """Unit tests for loading unified APK/ZIP containers and standalone files."""

    def test_01_apk_archive_loading(self):
        """Tests parsing a synthetic APK container holding classes.dex and lib/arm64-v8a/libgame.so."""
        dex_methods = [
            ("com.game.Core", "boot", "()V", 0x0109),
            ("com.game.Core", "renderFrame", "(F)V", 0x0101),
        ]
        dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes(dex_methods)

        exports = {"Java_com_game_Core_boot": 0x101500}
        reg_natives = [("renderFrame", "(F)V", 0x101600)]
        elf_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes(
            exports=exports,
            registered_natives=reg_natives,
            image_base=0x100000,
            is_64bit=True
        )

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp_apk:
            apk_path = tmp_apk.name

        try:
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("classes.dex", dex_bytes)
                zf.writestr("lib/arm64-v8a/libgame.so", elf_bytes)

            xr = APKJNICrossReferencer(image_base=0x100000)
            stats = xr.load_from_apk_or_dex(apk_path)

            self.assertEqual(stats["dex_methods"], 2)
            self.assertEqual(stats["elf_exports"], 1)
            self.assertEqual(stats["registered_natives"], 1)

            matches = xr.resolve_cross_references()
            self.assertEqual(len(matches), 2)
            self.assertEqual(matches[0].java_method.method_name, "boot")
            self.assertEqual(matches[0].binding_type, "STATIC_EXPORT")
            self.assertEqual(matches[1].java_method.method_name, "renderFrame")
            self.assertEqual(matches[1].binding_type, "REGISTER_NATIVES")

        finally:
            if os.path.exists(apk_path):
                os.remove(apk_path)

    def test_02_standalone_file_paths(self):
        """Tests load_from_elf_file and load_from_apk_or_dex on standalone files."""
        exports = {"Java_com_test_File_ping": 0x101800}
        elf_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes(exports=exports)

        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as tmp_so:
            so_path = tmp_so.name
            tmp_so.write(elf_bytes)

        try:
            xr = APKJNICrossReferencer()
            res = xr.load_from_elf_file(so_path)
            self.assertEqual(res["exports_loaded"], 1)
            self.assertIn("Java_com_test_File_ping", xr.elf_exports)
        finally:
            if os.path.exists(so_path):
                os.remove(so_path)


class TestGhidraScriptAndJsonExport(unittest.TestCase):
    """Unit tests for Ghidra Python postScript and JSON manifest exports."""

    def test_01_script_and_json_export(self):
        dex_methods = [
            ("com.example.app.GameApp", "nativeInit", "()V", 0x0109),
        ]
        dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes(dex_methods)
        exports = {"Java_com_example_app_GameApp_nativeInit": 0x101100}
        elf_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes(exports=exports)

        xr = APKJNICrossReferencer(image_base=0x100000)
        xr.load_from_dex_bytes(dex_bytes)
        xr.load_from_elf_bytes(elf_bytes)
        matches = xr.resolve_cross_references()
        self.assertEqual(len(matches), 1)

        # Test Python script export
        script = xr.export_ghidra_python_script()
        self.assertIn("createLabel", script)
        self.assertIn("setPlateComment", script)
        self.assertIn("0x101100", script)
        self.assertIn("JNI_GameApp_nativeInit", script)

        # Test JSON export
        json_str = xr.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["method_name"], "nativeInit")
        self.assertEqual(parsed[0]["binding_type"], "STATIC_EXPORT")
        self.assertEqual(parsed[0]["target_address"], "0x101100")


if __name__ == "__main__":
    unittest.main()
