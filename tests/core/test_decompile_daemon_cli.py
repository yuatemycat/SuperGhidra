"""
Unit and integration tests for 'superghidra decompile' daemon routing (Issue #25).
"""

from __future__ import annotations

import io
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from superghidra.__main__ import main
from superghidra.core.ghidra_oracle import (
    GhidraDaemonServer,
    MockGhidraOracleSession,
)

SAMPLE_X64 = Path(__file__).resolve().parents[1] / "fixtures" / "binaries" / "sample_x64.dll"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestDecompileDaemonRouting(unittest.TestCase):
    """Verifies that cmd_decompile routes requests to the daemon when online and formats output."""

    @classmethod
    def setUpClass(cls):
        cls.mock_session = MockGhidraOracleSession()
        cls.port = find_free_port()
        cls.server = GhidraDaemonServer(cls.mock_session, host="127.0.0.1", port=cls.port)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()

        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.server_thread.join(timeout=2.0)

    def test_decompile_routes_to_mock_daemon_and_applies_c_filter(self):
        """Verifies CLI sends request to mock daemon, unpacks functions, and filters C code."""
        stdout_buf = io.StringIO()
        args = [
            "decompile",
            str(SAMPLE_X64),
            "--rva",
            "0x1000",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--daemon",
        ]
        with patch("sys.stdout", stdout_buf):
            ret = main(args)

        self.assertEqual(ret, 0)
        output = stdout_buf.getvalue()
        # The mock returns func_00001000, and filter_c_code normalizes/includes headers
        self.assertIn("func_00001000", output)
        self.assertIn("return (a1 * 2) + a2;", output)

    def test_decompile_with_raw_bypasses_c_filter(self):
        """Verifies --raw emits unmodified decompiled output directly from daemon."""
        stdout_buf = io.StringIO()
        args = [
            "decompile",
            str(SAMPLE_X64),
            "--rva",
            "0x1000",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--daemon",
            "--raw",
        ]
        with patch("sys.stdout", stdout_buf):
            ret = main(args)

        self.assertEqual(ret, 0)
        output = stdout_buf.getvalue()
        self.assertIn("// Mock decompilation for", output)

    def test_decompile_writes_to_output_file(self):
        """Verifies -o / --output writes decompiled code to file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "decompiled.c"
            args = [
                "decompile",
                str(SAMPLE_X64),
                "--rva",
                "0x1000",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--daemon",
                "-o",
                str(out_file),
            ]
            ret = main(args)
            self.assertEqual(ret, 0)
            self.assertTrue(out_file.is_file())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("func_00001000", content)

    def test_decompile_binary_mismatch_refused_by_daemon(self):
        """Verifies daemon refuses decompile when requested binary mismatches loaded program."""
        stderr_buf = io.StringIO()
        orig_name = self.mock_session.program_name
        try:
            self.mock_session.program_name = "different_app.dll"
            args = [
                "decompile",
                str(SAMPLE_X64),
                "--rva",
                "0x1000",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--daemon",
            ]
            with patch("sys.stderr", stderr_buf):
                ret = main(args)

            self.assertEqual(ret, 2)
            err = stderr_buf.getvalue()
            self.assertIn("Daemon binary mismatch", err)
            self.assertIn("different_app.dll", err)
        finally:
            self.mock_session.program_name = orig_name

    def test_decompile_defaults_to_standalone_without_daemon_flag(self):
        """Verifies CLI runs standalone lifter by default when --daemon is omitted."""
        stdout_buf = io.StringIO()
        args = [
            "decompile",
            str(SAMPLE_X64),
            "--rva",
            "0x1020",
        ]
        with patch("sys.stdout", stdout_buf):
            ret = main(args)

        self.assertEqual(ret, 0)
        output = stdout_buf.getvalue()
        self.assertIn("uint64_t target_func", output)
        self.assertIn("rax = rax + rbx", output)

    def test_decompile_offline_with_daemon_flag_exits_nonzero(self):
        """Verifies --daemon flag with offline daemon exits non-zero."""
        stderr_buf = io.StringIO()
        # Find an unused port and ensure nothing is listening
        offline_port = find_free_port()
        args = [
            "decompile",
            str(SAMPLE_X64),
            "--rva",
            "0x1000",
            "--host",
            "127.0.0.1",
            "--port",
            str(offline_port),
            "--daemon",
        ]
        with patch("sys.stderr", stderr_buf):
            ret = main(args)

        self.assertNotEqual(ret, 0)
        err = stderr_buf.getvalue()
        self.assertIn("Ghidra daemon is offline", err)


if __name__ == "__main__":
    unittest.main()
