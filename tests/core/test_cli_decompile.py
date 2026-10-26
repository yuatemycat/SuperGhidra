"""
tests/core/test_cli_decompile.py
================================

CLI tests for `superghidra decompile`:
Subprocess tests checking argument parsing, address translation, and exit codes.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.formats.test_binary_loader import build_pe


class TestCliDecompile(unittest.TestCase):
    """Subprocess CLI execution and exit-code validation for `superghidra decompile`."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run_cli(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "superghidra", "decompile"] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parents[2]),
        )

    def test_raw_blob_rva_success(self):
        # Raw blob with code at file offset 0x1000:
        # mov rax, rbx ; add rax, rbx ; ret
        # 48 89 d8 48 01 d8 c3
        code = bytes.fromhex("4889D84801D8C3")
        blob = b"\x00" * 0x1000 + code
        bin_path = self.dir_path / "toy.bin"
        bin_path.write_bytes(blob)

        proc = self._run_cli([str(bin_path), "--rva", "0x1000", "--arch", "x86_64"])
        self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
        self.assertIn("rax = rbx;", proc.stdout)

    def test_raw_blob_out_of_range_address_exit_2(self):
        # Out-of-range address on raw blob -> exit 2, empty stdout, stderr names address
        blob = b"\x00" * 0x1000 + bytes.fromhex("4889D84801D8C3")
        bin_path = self.dir_path / "toy.bin"
        bin_path.write_bytes(blob)

        proc = self._run_cli([str(bin_path), "--rva", "0x140001000", "--arch", "x86_64"])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout.strip(), "")
        self.assertIn("0x140001000", proc.stderr)

    def test_raw_blob_unhandled_lea_exit_3(self):
        # Raw blob with lea at target offset -> exit 3, stderr lists address, -o file not created
        # 48 8d 0d 00 00 00 00 c3 (lea rcx, [rip+0] ; ret)
        blob = b"\x00" * 0x1000 + bytes.fromhex("488D0D00000000C3")
        bin_path = self.dir_path / "toy_lea.bin"
        bin_path.write_bytes(blob)
        out_file = self.dir_path / "decompiled_output.c"

        proc = self._run_cli([str(bin_path), "--rva", "0x1000", "-o", str(out_file)])
        self.assertEqual(proc.returncode, 3)
        self.assertIn("0x1000", proc.stderr)
        self.assertFalse(out_file.exists(), "Output file must not be created on LiftError")

    def test_synthetic_pe_rva_vs_file_offset(self):
        # Synthetic PE where .text RVA 0x1000 is at file offset 0x400
        # Code at text_rva: mov rax, rbx ; ret (48 89 d8 c3)
        text_code = bytes.fromhex("4889D8C3")
        pe_bytes, image_base = build_pe(bits=64, text=text_code)
        pe_path = self.dir_path / "synthetic.dll"
        pe_path.write_bytes(pe_bytes)

        # --rva 0x1000 must lift the bytes at offset 0x400
        proc = self._run_cli([str(pe_path), "--rva", "0x1000"])
        self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
        self.assertIn("rax = rbx;", proc.stdout)

    def test_synthetic_pe_va_flag(self):
        # Same synthetic PE, using --va instead of --rva
        text_code = bytes.fromhex("4889D8C3")
        pe_bytes, image_base = build_pe(bits=64, text=text_code)
        pe_path = self.dir_path / "synthetic.dll"
        pe_path.write_bytes(pe_bytes)

        target_va = hex(image_base + 0x1000)
        proc = self._run_cli([str(pe_path), "--va", target_va])
        self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
        self.assertIn("rax = rbx;", proc.stdout)

    def test_pe_arch_mismatch_exit_2(self):
        # x86_64 PE with --arch arm64 -> exit 2 (arch mismatch)
        text_code = bytes.fromhex("4889D8C3")
        pe_bytes, _ = build_pe(bits=64, text=text_code)
        pe_path = self.dir_path / "synthetic_x64.dll"
        pe_path.write_bytes(pe_bytes)

        proc = self._run_cli([str(pe_path), "--rva", "0x1000", "--arch", "arm64"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("arm64", proc.stderr.lower())
        self.assertIn("x86_64", proc.stderr.lower())

    def test_real_system_binary_integration(self):
        """Integration test on real/sample binary: non-zero exit and 0x42 not in stdout."""
        fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures" / "binaries"
        sample_x64 = str(fixtures_dir / "sample_x64.dll")
        if os.path.exists("C:\\Windows\\System32\\kernel32.dll"):
            target = "C:\\Windows\\System32\\kernel32.dll"
        elif os.path.exists("/bin/ls"):
            target = "/bin/ls"
        else:
            target = sample_x64
        proc = self._run_cli([target, "--rva", "0x1000"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("0x42", proc.stdout)


if __name__ == "__main__":
    unittest.main()
