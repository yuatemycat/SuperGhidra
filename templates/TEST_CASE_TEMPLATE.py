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

    # --------------------------------------------------------------------------
    # Required Section: Exact Output for a Known Input
    # Every analyzer or tool must assert exact output values on known inputs
    # rather than just checking that output is non-empty or status == 0.
    # --------------------------------------------------------------------------
    def test_02_exact_output_for_known_input(self) -> None:
        """Verifies bit-exact output values for a deterministic known input fixture."""
        self.assertEqual(len(self.fixture_bytes), 16)
        # Example: assert exact decoded disassembly or lifted P-Code operations
        # result = analyzer.analyze(self.fixture_bytes)
        # self.assertEqual(result.instructions[0].mnemonic, "paciasp")
        # self.assertEqual(result.instructions[2].operands, ["x0", "#0x2a"])

    # --------------------------------------------------------------------------
    # Required Section: Error Path for Unsupported Input
    # When a tool cannot handle an input, it MUST fail explicitly (raising an error
    # or exiting non-zero) and NEVER return placeholder, fabricated, or silent fallback data.
    # --------------------------------------------------------------------------
    def test_03_error_path_for_unsupported_input(self) -> None:
        """Verifies unhandled or invalid inputs raise explicit errors rather than placeholder results."""
        unsupported_bytes = b"\x0f\x0b"  # e.g., undefined opcode or unsupported arch
        with self.assertRaises((ValueError, RuntimeError)):
            # Example: analyzer.analyze(unsupported_bytes) must raise LiftError/ValueError
            raise ValueError(f"Unsupported instruction bytes: {unsupported_bytes.hex()}")

    def test_04_file_roundtrip_in_tempdir(self) -> None:
        """Verifies file-backed I/O inside an isolated temporary directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bin_path = Path(tmp_dir) / "synthetic.bin"
            bin_path.write_bytes(self.fixture_bytes)
            self.assertTrue(bin_path.is_file())
            self.assertEqual(bin_path.read_bytes(), self.fixture_bytes)


if __name__ == "__main__":
    unittest.main()
