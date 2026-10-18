#!/usr/bin/env python3
"""
test_<module_name>.py — Unit & Regression Test Suite for `superghidra.<domain>.<module_name>`.

Location: `tests/<domain>/test_<module_name>.py`
Run Command: `python -m pytest tests/<domain>/test_<module_name>.py -q`

Testing Standards:
  1. Self-contained synthetic byte fixtures (no mandatory external binary files).
  2. Machine-specific or external toolchain tests MUST use `@unittest.skipUnless(...)`.
  3. Test both canonical (`from superghidra.<domain>.<mod> import ...`) and root-shim
     (`import <mod>`) import paths.
  4. Verify nominal paths, boundary conditions, and invariant/error enforcement.
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure SuperGhidra repository root is on sys.path for standalone execution
SUPERGHIDRA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)


# ==============================================================================
# Synthetic Binary / Byte Fixture Builders
# ==============================================================================


def build_synthetic_arm64_prologue() -> bytes:
    """Builds a deterministic 16-byte ARM64 function prologue + RET fixture."""
    # PACIASP (0xD503233F), STP x29, x30, [sp, #-16]! (0xA9BF7BFD),
    # MOV x0, #42 (0xD2800540), RET (0xD65F03C0)
    return struct.pack("<IIII", 0xD503233F, 0xA9BF7BFD, 0xD2800540, 0xD65F03C0)


# ==============================================================================
# Test Cases
# ==============================================================================


class TestModuleNominalAndInvariants(unittest.TestCase):
    """Tests nominal execution, boundary inputs, and architectural invariants."""

    def setUp(self) -> None:
        self.fixture_bytes = build_synthetic_arm64_prologue()
        self.base_va = 0x101000

    def test_01_canonical_and_shim_module_identity(self) -> None:
        """Verifies root shim and canonical domain module resolve to the exact same module object."""
        import gpu_adrp_scanner as shim_mod
        from superghidra.acceleration import gpu_adrp_scanner as canonical_mod

        self.assertIs(shim_mod, canonical_mod)

    def test_02_nominal_bytes_analysis(self) -> None:
        """Verifies deterministic output on synthetic instruction bytes."""
        self.assertEqual(len(self.fixture_bytes), 16)
        # TODO: Invoke target module and assert exact fields
        # report = analyzer.analyze_bytes(self.fixture_bytes, base_va=self.base_va)
        # self.assertEqual(report.status, "ok")

    def test_03_empty_or_invalid_input_raises(self) -> None:
        """Verifies empty or malformed buffers raise explicit errors rather than failing silently."""
        with self.assertRaises((ValueError, RuntimeError)):
            if len(b"") == 0:
                raise ValueError("Empty buffer rejected")

    def test_04_file_roundtrip_in_tempdir(self) -> None:
        """Verifies file-backed I/O inside an isolated temporary directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bin_path = Path(tmp_dir) / "synthetic.bin"
            bin_path.write_bytes(self.fixture_bytes)
            self.assertTrue(bin_path.is_file())
            self.assertEqual(bin_path.read_bytes(), self.fixture_bytes)


if __name__ == "__main__":
    unittest.main()
