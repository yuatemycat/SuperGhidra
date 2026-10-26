#!/usr/bin/env python3
"""
Unit tests for MockGhidraOracleSession and standalone offline daemon mode.
Verifies that the daemon protocol, JSON-RPC endpoints, session token auth,
write-overlay persistence, and resource governor can be fully tested without
a Ghidra or JVM installation.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from superghidra.core.ghidra_oracle import (
    GhidraDaemonServer,
    MockGhidraOracleSession,
    client_send_request,
)


class TestMockDaemonSession(unittest.TestCase):
    """Verifies that MockGhidraOracleSession correctly handles all oracle query interfaces."""

    def setUp(self):
        self.session = MockGhidraOracleSession(resource_mode="balanced")

    def test_mock_query_rva(self):
        res = self.session.query_rva("0x00100500")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["va"], "0x00100500")
        self.assertEqual(res["rva"], "0x00000500")

    def test_mock_query_decompile(self):
        res = self.session.query_decompile(["0x00101000", "0x00102000"])
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(res["functions"]), 2)
        self.assertIn("func_00101000", res["functions"][0]["code"])
        self.assertIn("Mock decompilation", res["functions"][0]["code"])

    def test_mock_query_vtable(self):
        res = self.session.query_vtable("0x00105000", count=4)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(res["vtable"]), 4)
        self.assertEqual(res["vtable"][0]["slot"], 0)

    def test_mock_query_disassemble(self):
        res = self.session.query_disassemble("0x00101000", count=5)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["count"], 5)
        self.assertEqual(len(res["instructions"]), 5)

    def test_mock_overlay_mutations(self):
        res_rename = self.session.set_rename("0x00101000", "g_target_func")
        self.assertEqual(res_rename["status"], "ok")
        self.assertEqual(self.session.overlay.renames["0x00101000"], "g_target_func")

        res_comment = self.session.set_comment("0x00101000", "Hook target")
        self.assertEqual(res_comment["status"], "ok")
        self.assertEqual(self.session.overlay.comments["0x00101000"], "Hook target")

    def test_mock_query_status(self):
        st = self.session.query_status()
        self.assertEqual(st["status"], "ok")
        self.assertTrue(st["mock_mode"])
        self.assertEqual(st["mode"], "balanced")


class TestMockDaemonServerNetwork(unittest.TestCase):
    """Verifies that GhidraDaemonServer runs end-to-end with MockGhidraOracleSession over TCP."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.prev_data_dir = os.environ.get("SUPERGHIDRA_DATA_DIR")
        os.environ["SUPERGHIDRA_DATA_DIR"] = self.tmp_dir.name
        self.prev_env_tok = os.environ.pop("SUPERGHIDRA_SESSION_TOKEN", None)

        self.session = MockGhidraOracleSession(resource_mode="balanced")
        self.token = "test-mock-token-secret-12345"
        # Bind on an ephemeral free port
        self.server = GhidraDaemonServer(
            session=self.session,
            host="127.0.0.1",
            port=0,
            token=self.token,
        )
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        for _ in range(50):
            if self.server.running and self.server.port != 0:
                break
            time.sleep(0.01)
        self.port = self.server.port

    def tearDown(self):
        if self.server.running:
            self.server.stop()
        self.server_thread.join(timeout=1.0)
        self.tmp_dir.cleanup()
        if self.prev_data_dir is not None:
            os.environ["SUPERGHIDRA_DATA_DIR"] = self.prev_data_dir
        else:
            os.environ.pop("SUPERGHIDRA_DATA_DIR", None)
        if self.prev_env_tok is not None:
            os.environ["SUPERGHIDRA_SESSION_TOKEN"] = self.prev_env_tok

    def test_ping_and_status_without_token(self):
        res_ping = client_send_request("ping", {}, host="127.0.0.1", port=self.port)
        self.assertEqual(res_ping["status"], "ok")
        self.assertEqual(res_ping["message"], "pong")

        res_status = client_send_request("status", {}, host="127.0.0.1", port=self.port)
        self.assertEqual(res_status["status"], "ok")
        self.assertTrue(res_status["mock_mode"])

    def test_decompile_and_rva_over_tcp(self):
        res_rva = client_send_request("rva", {"addr": "0x00102000"}, host="127.0.0.1", port=self.port)
        self.assertEqual(res_rva["status"], "ok")
        self.assertEqual(res_rva["rva"], "0x00002000")

        res_dec = client_send_request("decompile", {"targets": ["0x00102000"]}, host="127.0.0.1", port=self.port)
        self.assertEqual(res_dec["status"], "ok")
        self.assertEqual(len(res_dec["functions"]), 1)
        self.assertIn("func_00102000", res_dec["functions"][0]["code"])

    def test_mutating_command_enforces_token_auth(self):
        # Without token should be rejected (401)
        res_unauth = client_send_request("rename", {"addr": "0x00102000", "name": "bad"}, host="127.0.0.1", port=self.port)
        self.assertEqual(res_unauth["status"], "error")
        self.assertEqual(res_unauth.get("code"), 401)

        # With token should succeed
        res_auth = client_send_request(
            "rename",
            {"addr": "0x00102000", "name": "good_func"},
            host="127.0.0.1",
            port=self.port,
            token=self.token,
        )
        self.assertEqual(res_auth["status"], "ok")
        self.assertEqual(res_auth["new_name"], "good_func")

        # Verify overlay reflects mutation
        res_overlay = client_send_request("overlay", {"action": "list"}, host="127.0.0.1", port=self.port)
        self.assertEqual(res_overlay["status"], "ok")
        self.assertEqual(res_overlay["overlay"]["renames"]["0x00102000"], "good_func")

    def test_stop_command_over_tcp(self):
        res_stop = client_send_request("stop", {}, host="127.0.0.1", port=self.port, token=self.token)
        self.assertEqual(res_stop["status"], "ok")
        self.server_thread.join(timeout=1.0)
        self.assertFalse(self.server.running)


if __name__ == "__main__":
    unittest.main()
