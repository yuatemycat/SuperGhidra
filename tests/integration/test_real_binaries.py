"""
Real-binary integration test suite (U23).
Tests SuperGhidra subsystems against real ELF and PE binaries on disk.
"""

from __future__ import annotations

import os
import unittest
import pytest

from superghidra.formats.binary_loader import load_binary, BinaryImage
from superghidra.acceleration.gpu_adrp_scanner import GPUAdrpScanner
from superghidra.lifters.x86_decode import iter_decode, X86Insn
from superghidra.storage.storage_compression_prototype import StorageCompressionBenchmark
from superghidra.core.compilable_filter import CompilableDecompilerFilter


from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "binaries"
SAMPLE_ARM64 = str(FIXTURES_DIR / "sample_arm64.so")
SAMPLE_X64 = str(FIXTURES_DIR / "sample_x64.dll")

# Large stripped ARM64 ELF to test against; falls back to redistributable sample_arm64.so for CI.
REAL_ARM64_ELF = os.environ.get("SUPERGHIDRA_TEST_ARM64_ELF") or (SAMPLE_ARM64 if os.path.exists(SAMPLE_ARM64) else "")
REAL_KERNEL32 = r"C:\Windows\System32\kernel32.dll" if os.path.exists(r"C:\Windows\System32\kernel32.dll") else (SAMPLE_X64 if os.path.exists(SAMPLE_X64) else "")
REAL_MFC64 = r"C:\Windows\System32\mfc140u.dll"


@pytest.mark.integration
class TestRealBinariesIntegration(unittest.TestCase):
    """Integration tests running against real on-disk production binaries."""

    @unittest.skipUnless(os.path.exists(REAL_ARM64_ELF), "Production libtarget.so not found")
    def test_real_arm64_elf_loader_and_scan(self):
        """Loads real 23MB libtarget.so, verifies ELF format, and runs ADRP scanner on code."""
        img = load_binary(REAL_ARM64_ELF)
        self.assertEqual(img.format, "elf")
        self.assertEqual(img.arch, "arm64")

        # Find executable section or segment (handles stripped ELF)
        exec_sec = next((s for s in (img.sections + img.segments) if s.executable), None)
        self.assertIsNotNone(exec_sec)
        text_bytes = img.read_va(exec_sec.vaddr, min(100_000, exec_sec.file_size))

        # Run GPU/CPU ADRP scanner
        import numpy as np
        insns = np.frombuffer(text_bytes[: (len(text_bytes) // 4) * 4], dtype=np.uint32)
        scanner = GPUAdrpScanner(backend="numpy")
        matches = scanner.scan_matches(insns, base_pc=exec_sec.vaddr)
        self.assertIsInstance(matches, list)

        # Test storage compression on real binary pages
        from superghidra.storage.storage_compression_prototype import CompressedLocalManagedBufferFile, DataBuffer
        comp_file = CompressedLocalManagedBufferFile(codec="lz4")
        chunk = text_bytes[:16384]
        dbuf = DataBuffer(buffer_id=0, data=bytearray(chunk))
        comp_file.put(dbuf, 0)
        retrieved = comp_file.get(None, 0)
        self.assertEqual(bytes(retrieved.data), chunk)

    @unittest.skipUnless(os.path.exists(REAL_KERNEL32), "Windows kernel32.dll not found")
    def test_real_pe_kernel32_loader_and_decode(self):
        """Loads real kernel32.dll, verifies PE format and x86_64 decoding."""
        img = load_binary(REAL_KERNEL32)
        self.assertEqual(img.format, "pe")
        self.assertEqual(img.arch, "x86_64")
        self.assertGreater(len(img.exports), 0)

        text_sec = next((s for s in (img.sections + img.segments) if s.executable), None)
        self.assertIsNotNone(text_sec)
        code_bytes = img.read_va(text_sec.vaddr, 1024)

        insns = list(iter_decode(code_bytes, address=text_sec.vaddr, mode=64))
        self.assertGreater(len(insns), 10)

    def test_compilable_filter_on_ghidra_ast(self):
        """Verifies compilable filter cleans Ghidra pseudo-C constructs."""
        raw_ast = (
            "undefined8 ProcessMsg(undefined4 msg_id, ulonglong param) {\n"
            "    long in_FS_OFFSET;\n"
            "    long canary = *(long *)(in_FS_OFFSET + 0x28);\n"
            "    uint64_t full = CONCAT44(msg_id, (uint32_t)param);\n"
            "    if (canary != *(long *)(in_FS_OFFSET + 0x28)) __stack_chk_fail();\n"
            "    return full;\n"
            "}"
        )
        filtered = CompilableDecompilerFilter.filter(raw_ast, emit_compilable=True)
        self.assertIn("#include <stdint.h>", filtered)
        self.assertNotIn("undefined8", filtered)
        self.assertNotIn("in_FS_OFFSET", filtered)
        self.assertNotIn("__stack_chk_fail", filtered)
        self.assertIn("(((uint64_t)(msg_id) << 32)", filtered)


if __name__ == "__main__":
    unittest.main()
