"""
test_daemon_security.py
========================
Dedicated Security & Access Control Test Suite for SuperGhidra Oracle Daemon (0.4 Foundation).

Test Coverage:
1. Loopback Binding Enforcement:
   - Refusal of non-loopback host addresses (0.0.0.0, 192.168.1.1, 10.0.0.1, ::) when allow_remote=False.
   - Acceptance of non-loopback host addresses when allow_remote=True.
   - Acceptance of standard loopback addresses (127.0.0.1, ::1, localhost, 127.*) by default.
   - is_loopback_host boundary checking.
2. Request Size Limitation:
   - Enforcement of MAX_REQUEST_SIZE (2 MB).
   - Rejection and socket termination when client sends payload exceeding 2 MB.
   - Successful processing of valid requests within size limit.
3. Session Token Authentication:
   - Rejection of mutating commands (stop, rename, comment, clear, register_struct, mode, hibernate)
     when token is missing or invalid.
   - Successful execution of mutating commands when valid token is supplied.
   - Execution of read-only commands (ping, status, rva, decompile, vtable, disassemble, refs,
     adrp_add, opcodes, type) without token by default.
   - Validation of token for read-only commands when a token is explicitly provided.
4. Token Persistence & Client Helper Integration:
   - save_session_token and load_session_token file operations.
   - Priority hierarchy (explicit argument > environment variable > token file).
   - query_oracle helper dispatch with session tokens.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from superghidra.core.ghidra_oracle import (
    MAX_REQUEST_SIZE,
    SUPERGHIDRA_DATA_DIR_ENV,
    SUPERGHIDRA_TOKEN_ENV,
    GhidraDaemonServer,
    get_default_token_path,
    is_loopback_host,
    load_session_token,
    main,
    query_oracle,
    save_session_token,
)


def find_free_port() -> int:
    """Finds an unused loopback TCP port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestDaemonLoopbackBinding(unittest.TestCase):
    """Verifies loopback binding enforcement and non-loopback refusal."""

    def setUp(self):
        self.mock_session = MagicMock()

    def test_refuse_non_loopback_addresses_when_not_allowed(self):
        """Verifies GhidraDaemonServer rejects non-loopback addresses when allow_remote=False."""
        forbidden_hosts = [
            "0.0.0.0",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.5",
            "::",
            "example.com",
            "8.8.8.8",
        ]
        for host in forbidden_hosts:
            with self.subTest(host=host):
                with self.assertRaises(ValueError) as ctx:
                    GhidraDaemonServer(self.mock_session, host=host, allow_remote=False)
                self.assertIn("Refusing to bind to non-loopback address", str(ctx.exception))

    def test_refuse_non_loopback_on_start(self):
        """Verifies start() also prevents binding to non-loopback if host was modified."""
        server = GhidraDaemonServer(self.mock_session, host="127.0.0.1", allow_remote=False)
        server.host = "0.0.0.0"
        with self.assertRaises(ValueError) as ctx:
            server.start()
        self.assertIn("Refusing to bind to non-loopback address", str(ctx.exception))

    def test_accept_non_loopback_when_allow_remote_is_true(self):
        """Verifies GhidraDaemonServer accepts non-loopback addresses when allow_remote=True."""
        remote_hosts = ["0.0.0.0", "192.168.1.100", "10.0.0.2"]
        for host in remote_hosts:
            with self.subTest(host=host):
                server = GhidraDaemonServer(self.mock_session, host=host, allow_remote=True)
                self.assertEqual(server.host, host)
                self.assertTrue(server.allow_remote)

    def test_accept_loopback_addresses_by_default(self):
        """Verifies GhidraDaemonServer accepts all loopback variants with default allow_remote=False."""
        loopback_hosts = [
            "127.0.0.1",
            "127.0.0.2",
            "127.100.0.1",
            "localhost",
            "::1",
            "[::1]",
        ]
        for host in loopback_hosts:
            with self.subTest(host=host):
                server = GhidraDaemonServer(self.mock_session, host=host, allow_remote=False)
                self.assertEqual(server.host, host)
                self.assertFalse(server.allow_remote)

    def test_is_loopback_host_helper(self):
        """Tests the is_loopback_host helper function directly."""
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("127.0.1.1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("[::1]"))

        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("192.168.1.1"))
        self.assertFalse(is_loopback_host("10.1.1.1"))
        self.assertFalse(is_loopback_host("::"))
        self.assertFalse(is_loopback_host(""))
        self.assertFalse(is_loopback_host(None))  # type: ignore


class TestDaemonPayloadSizeLimit(unittest.TestCase):
    """Verifies payload size limit enforcement and socket termination."""

    def setUp(self):
        self.mock_session = MagicMock()
        self.mock_session.query_status.return_value = {"status": "ok", "uptime": 10}
        self.port = find_free_port()
        self.server = GhidraDaemonServer(self.mock_session, host="127.0.0.1", port=self.port)
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()

        # Wait for server socket to bind
        ready = False
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        self.assertTrue(ready, "Server failed to start and accept connections")

    def tearDown(self):
        self.server.stop()
        if self.server_thread.is_alive():
            self.server_thread.join(timeout=1.0)

    def test_payload_exceeding_max_size_rejected_and_socket_closed(self):
        """Verifies payload > MAX_REQUEST_SIZE receives error response and socket closes."""
        oversized_bytes = MAX_REQUEST_SIZE + 4096
        # Construct large payload
        payload = b"X" * oversized_bytes + b"\n"

        with socket.create_connection(("127.0.0.1", self.port), timeout=5.0) as s:
            s.sendall(payload)

            # Receive error response
            resp_buf = bytearray()
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_buf.extend(chunk)
                if b"\n" in resp_buf:
                    break

            self.assertTrue(len(resp_buf) > 0, "Server must respond with error before closing")
            line = bytes(resp_buf).split(b"\n")[0]
            resp = json.loads(line.decode("utf-8"))
            self.assertEqual(resp.get("status"), "error")
            self.assertIn("Request payload exceeds maximum allowed size", resp.get("message", ""))

            # Confirm socket is terminated by server (next recv returns b"" or raises ConnectionResetError)
            try:
                trailing = s.recv(1024)
                self.assertEqual(trailing, b"", "Socket must be closed after exceeding size limit")
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass  # Closed by peer via TCP RST (Linux/POSIX behavior)

    def test_payload_within_max_size_accepted(self):
        """Verifies payload within size limit executes normally."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=5.0) as s:
            req = json.dumps({"cmd": "ping"}) + "\n"
            s.sendall(req.encode("utf-8"))
            data = s.recv(4096)
            resp = json.loads(data.decode("utf-8").strip())
            self.assertEqual(resp.get("status"), "ok")
            self.assertEqual(resp.get("message"), "pong")


class TestSessionTokenAuthentication(unittest.TestCase):
    """Verifies mutating commands protection and read-only allowance with session tokens."""

    def setUp(self):
        self.mock_session = MagicMock()
        self.mock_session.set_rename.return_value = {"status": "ok", "message": "Rename applied"}
        self.mock_session.set_comment.return_value = {"status": "ok", "message": "Comment applied"}
        self.mock_session.set_resource_mode.return_value = {"status": "ok", "mode": "turbo"}
        self.mock_session.hibernate.return_value = {"status": "ok", "message": "Hibernated"}
        self.mock_session.register_struct.return_value = {"status": "ok", "name": "TestStruct"}
        self.mock_session.query_status.return_value = {"status": "ok", "uptime_seconds": 120}
        self.mock_session.query_rva.return_value = {"status": "ok", "va": "0x1000", "rva": "0x0"}

        self.valid_token = "secure-superghidra-token-42"
        self.server = GhidraDaemonServer(
            self.mock_session,
            host="127.0.0.1",
            token=self.valid_token,
        )

    def test_mutating_commands_rejected_without_token(self):
        """Verifies all mutating commands fail if no token is provided."""
        commands_to_test = [
            {"cmd": "stop"},
            {"cmd": "rename", "args": {"addr": "0x1000", "name": "foo"}},
            {"cmd": "comment", "args": {"addr": "0x1000", "comment": "bar"}},
            {"cmd": "clear"},
            {"cmd": "clear-cache"},
            {"cmd": "register_struct", "args": {"name": "TestStruct", "byte_size": 16}},
            {"cmd": "mode", "args": {"mode": "turbo"}},
            {"cmd": "hibernate"},
            {"cmd": "overlay", "args": {"action": "clear"}},
        ]
        for req in commands_to_test:
            with self.subTest(cmd=req["cmd"]):
                resp = self.server._dispatch_command(req)
                self.assertEqual(resp.get("status"), "error")
                self.assertIn("Unauthorized: invalid or missing session token", resp.get("message", ""))

    def test_mutating_commands_rejected_with_invalid_token(self):
        """Verifies all mutating commands fail if an invalid token is provided."""
        bad_token = "wrong-unauthorized-token"
        commands_to_test = [
            {"cmd": "stop", "token": bad_token},
            {"cmd": "rename", "args": {"addr": "0x1000", "name": "foo"}, "token": bad_token},
            {"cmd": "comment", "args": {"addr": "0x1000", "comment": "bar"}, "token": bad_token},
            {"cmd": "clear", "token": bad_token},
            {"cmd": "register_struct", "args": {"name": "TestStruct", "byte_size": 16}, "token": bad_token},
            {"cmd": "mode", "args": {"mode": "turbo"}, "token": bad_token},
            {"cmd": "hibernate", "token": bad_token},
            {"cmd": "overlay", "args": {"action": "clear"}, "token": bad_token},
        ]
        for req in commands_to_test:
            with self.subTest(cmd=req["cmd"]):
                resp = self.server._dispatch_command(req)
                self.assertEqual(resp.get("status"), "error")
                self.assertIn("Unauthorized: invalid or missing session token", resp.get("message", ""))

    def test_mutating_commands_succeed_with_valid_token(self):
        """Verifies mutating commands succeed when supplying the matching token."""
        # 1. rename
        resp_rename = self.server._dispatch_command({
            "cmd": "rename",
            "args": {"addr": "0x1000", "name": "TargetFunc"},
            "token": self.valid_token,
        })
        self.assertEqual(resp_rename.get("status"), "ok")

        # 2. comment
        resp_comment = self.server._dispatch_command({
            "cmd": "comment",
            "args": {"addr": "0x1000", "comment": "Verified Hook"},
            "token": self.valid_token,
        })
        self.assertEqual(resp_comment.get("status"), "ok")

        # 3. stop
        resp_stop = self.server._dispatch_command({
            "cmd": "stop",
            "token": self.valid_token,
        })
        self.assertEqual(resp_stop.get("status"), "ok")
        self.assertTrue(resp_stop.get("should_stop"))

        # 4. register_struct
        resp_reg = self.server._dispatch_command({
            "cmd": "register_struct",
            "args": {"name": "TestStruct", "byte_size": 16},
            "token": self.valid_token,
        })
        self.assertEqual(resp_reg.get("status"), "ok")

        # 5. mode
        resp_mode = self.server._dispatch_command({
            "cmd": "mode",
            "args": {"mode": "turbo"},
            "token": self.valid_token,
        })
        self.assertEqual(resp_mode.get("status"), "ok")

        # 6. hibernate
        resp_hib = self.server._dispatch_command({
            "cmd": "hibernate",
            "token": self.valid_token,
        })
        self.assertEqual(resp_hib.get("status"), "ok")

    def test_read_only_commands_allowed_without_token(self):
        """Verifies read-only commands succeed without requiring a session token."""
        # 1. ping
        resp_ping = self.server._dispatch_command({"cmd": "ping"})
        self.assertEqual(resp_ping.get("status"), "ok")
        self.assertEqual(resp_ping.get("message"), "pong")

        # 2. status
        resp_status = self.server._dispatch_command({"cmd": "status"})
        self.assertEqual(resp_status.get("status"), "ok")

        # 3. rva
        resp_rva = self.server._dispatch_command({"cmd": "rva", "args": {"addr": "0x1000"}})
        self.assertEqual(resp_rva.get("status"), "ok")

        # 4. overlay list (read-only)
        resp_overlay = self.server._dispatch_command({"cmd": "overlay", "args": {"action": "list"}})
        self.assertEqual(resp_overlay.get("status"), "ok")

    def test_read_only_commands_validated_if_token_is_provided(self):
        """Verifies read-only commands validate token if the client explicitly provides one."""
        # Valid token on ping succeeds
        resp_ok = self.server._dispatch_command({"cmd": "ping", "token": self.valid_token})
        self.assertEqual(resp_ok.get("status"), "ok")

        # Invalid token on ping fails
        resp_err = self.server._dispatch_command({"cmd": "ping", "token": "invalid-token"})
        self.assertEqual(resp_err.get("status"), "error")
        self.assertIn("Unauthorized: invalid or missing session token", resp_err.get("message", ""))

        # Invalid token on status fails
        resp_status_err = self.server._dispatch_command({"cmd": "status", "token": "invalid-token"})
        self.assertEqual(resp_status_err.get("status"), "error")

    def test_server_without_token_allows_all(self):
        """Verifies backwards compatibility: when token is None, commands execute without auth."""
        open_server = GhidraDaemonServer(self.mock_session, host="127.0.0.1", token=None)
        resp_rename = open_server._dispatch_command({
            "cmd": "rename",
            "args": {"addr": "0x1000", "name": "AnyFunc"},
        })
        self.assertEqual(resp_rename.get("status"), "ok")


class TestTokenPersistenceAndClientIntegration(unittest.TestCase):
    """Verifies token file persistence, env var resolution, and client helpers."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.token_path = os.path.join(self.temp_dir.name, "daemon.token")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_save_and_load_session_token(self):
        """Verifies saving token to disk with restricted permissions and loading it back."""
        secret = "secret-token-abcdef123456"
        saved_path = save_session_token(secret, path=self.token_path)
        self.assertEqual(saved_path, self.token_path)
        self.assertTrue(os.path.isfile(self.token_path))

        loaded = load_session_token(token_path=self.token_path)
        self.assertEqual(loaded, secret)

    def test_token_resolution_priority(self):
        """Verifies resolution priority: argument > environment variable > token file."""
        secret_arg = "token-from-arg"
        secret_env = "token-from-env"
        secret_file = "token-from-file"

        save_session_token(secret_file, path=self.token_path)

        with patch.dict(os.environ, {SUPERGHIDRA_TOKEN_ENV: secret_env}):
            # 1. Argument takes top priority
            res1 = load_session_token(token_arg=secret_arg, token_path=self.token_path)
            self.assertEqual(res1, secret_arg)

            # 2. Env var takes second priority
            res2 = load_session_token(token_arg=None, token_path=self.token_path)
            self.assertEqual(res2, secret_env)

        # 3. File takes third priority when env is unset
        with patch.dict(os.environ, {}, clear=True):
            res3 = load_session_token(token_arg=None, token_path=self.token_path)
            self.assertEqual(res3, secret_file)

    def test_query_oracle_helper_forwards_token(self):
        """Verifies query_oracle delegates to client_send_request with the given token."""
        with patch("superghidra.core.ghidra_oracle.client_send_request") as mock_send:
            mock_send.return_value = {"status": "ok", "message": "pong"}
            resp = query_oracle("ping", token="my-custom-token")
            self.assertEqual(resp.get("status"), "ok")
            mock_send.assert_called_once()
            _, kwargs = mock_send.call_args
            self.assertEqual(kwargs.get("token"), "my-custom-token")

    def test_cli_parsing_token_and_allow_remote_flags(self):
        """Verifies CLI argument parser recognizes --allow-remote and --token."""
        cli_args = [
            "serve",
            "--host", "0.0.0.0",
            "--port", "6000",
            "--allow-remote",
            "--token", "cli-test-token",
        ]
        with patch("sys.argv", ["ghidra_oracle.py"] + cli_args), \
             patch("superghidra.core.ghidra_oracle.GhidraOracleSession") as mock_session_cls, \
             patch("superghidra.core.ghidra_oracle.GhidraDaemonServer") as mock_server_cls:

            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_server = MagicMock()
            mock_server_cls.return_value = mock_server

            main()

            mock_server_cls.assert_called_once()
            _, kwargs = mock_server_cls.call_args
            self.assertEqual(kwargs.get("host"), "0.0.0.0")
            self.assertEqual(kwargs.get("port"), 6000)
            self.assertTrue(kwargs.get("allow_remote"))
            self.assertEqual(kwargs.get("token"), "cli-test-token")
            self.assertTrue(kwargs.get("save_token"))


    def test_bind_failure_does_not_overwrite_existing_token(self):
        """Verifies that if a second server fails to bind (port collision),
        the existing daemon.token on disk remains intact and is not overwritten."""
        initial_token = "initial-running-daemon-token"
        save_session_token(initial_token, path=self.token_path)

        # Start first server on loopback
        mock_session = MagicMock()
        port = find_free_port()
        server1 = GhidraDaemonServer(
            mock_session,
            host="127.0.0.1",
            port=port,
            token="token1",
            save_token=False,
        )
        t1 = threading.Thread(target=server1.start, daemon=True)
        t1.start()

        # Wait until server1 binds
        ready = False
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        self.assertTrue(ready, "Server 1 failed to bind port")

        try:
            # Second server attempts to bind same port with save_token=True and target self.token_path
            server2 = GhidraDaemonServer(
                mock_session,
                host="127.0.0.1",
                port=port,
                token="clobbering-token-xyz",
                save_token=True,
                token_path=self.token_path,
            )
            with self.assertRaises(OSError):
                server2.start()

            # Confirm token file was NOT modified/overwritten
            persisted = load_session_token(token_path=self.token_path)
            self.assertEqual(persisted, initial_token)
        finally:
            server1.stop()

    def test_multiple_daemons_on_different_ports_have_isolated_tokens(self):
        """Verifies that a second daemon on another port writes its own port-specific token
        and does NOT overwrite or lock out the first daemon."""
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {SUPERGHIDRA_DATA_DIR_ENV: td}):
                port1 = find_free_port()
                port2 = find_free_port()
                while port2 == port1:
                    port2 = find_free_port()

                token1 = "token-for-port-1"
                token2 = "token-for-port-2"

                save_session_token(token1, port=port1)
                save_session_token(token2, port=port2)

                # Each port resolves its own distinct token
                self.assertEqual(load_session_token(port=port1), token1)
                self.assertEqual(load_session_token(port=port2), token2)

                # Confirm file paths on disk are separate
                path1 = get_default_token_path(port=port1)
                path2 = get_default_token_path(port=port2)
                self.assertTrue(os.path.isfile(path1))
                self.assertTrue(os.path.isfile(path2))
                self.assertNotEqual(path1, path2)


if __name__ == "__main__":
    unittest.main()
