"""
tests/core/test_cli_subcommands.py
==================================

Unit tests for newly exposed CLI subcommands in superghidra.__main__:
- version
- smt-verify
- gui-sync (overlay-sync alias)
- diff
- apk-xref
"""

import subprocess
import sys
import unittest
from pathlib import Path


class TestCliSubcommands(unittest.TestCase):
    """Subprocess CLI testing for superghidra subcommands."""

    def _run_cli(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "superghidra"] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parents[2]),
        )

    def test_version_subcommand(self):
        proc = self._run_cli(["version"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("SuperGhidra v", proc.stdout)
        self.assertIn("Active Features:", proc.stdout)

    def test_help_subcommands_listing(self):
        proc = self._run_cli(["--help"])
        self.assertEqual(proc.returncode, 0)
        for expected in ["gui-sync", "smt-verify", "diff", "apk-xref", "oracle"]:
            self.assertIn(expected, proc.stdout)

    def test_smt_verify_demo(self):
        proc = self._run_cli(["smt-verify", "--demo"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Demo verification (TakeDamage):", proc.stdout)
        self.assertIn("equivalent=True", proc.stdout)

    def test_gui_sync_help(self):
        proc = self._run_cli(["gui-sync", "--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--overlay", proc.stdout)
        self.assertIn("--watch", proc.stdout)


if __name__ == "__main__":
    unittest.main()
