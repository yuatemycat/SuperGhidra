"""
test_oracle_governor_cache.py
==============================
Dedicated Test Suite for SuperGhidra Oracle Governor, Hibernate Mechanics,
and Persistent L2 SQLite Cache (Sections 1, 2, 8 of Architectural Spec).

Test Coverage:
1. L2SQLiteCache Functionality:
   - Initializing WAL mode SQLite DB in temporary and default paths.
   - Storing and retrieving cached results for 'decompile', 'vtable', 'disassemble', 'adrp_add', 'opcodes'.
   - Ensuring `l2_cached` is set, timestamp fidelity, and data integrity.
   - Cache key case-insensitivity and normalization.
   - Cache clearing and multi-factor eviction (by key, by type, by age, by capacity).
2. GhidraOracleSession Governor & Hibernate Logic:
   - Resource mode switching: 'eco', 'balanced', 'turbo', 'auto'.
   - Adaptive idle_timeout_sec, throttle_ms, and LRUCache capacities.
   - Hibernate mechanics (flushCache, stopProcess, is_hibernating flag, GC trigger).
   - Session re-arming after hibernation (_ensure_decompiler_active).
3. CLI Argument Parsing & Fast-Path Tests:
   - client_send_request for 'rva' with offline fallback (zero JVM required).
   - client_send_request L2 cache bypass for 'decompile', 'vtable', 'adrp_add', 'opcodes'.
   - Command-line argument parsing for all core commands (rva, decompile, vtable,
     disassemble, adrp_add, opcodes, hibernate, mode, rename, comment).
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

# Ensure local SuperGhidra directory is first in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from ghidra_oracle import (
    DEFAULT_HOST,
    DEFAULT_IMAGE_BASE,
    DEFAULT_PORT,
    GhidraOracleSession,
    L2SQLiteCache,
    WriteOverlay,
    client_send_request,
    main,
    normalize_address_pair,
)


class TestL2SQLiteCache(unittest.TestCase):
    """Verifies all persistent L2 SQLite caching, WAL mode, storage, and eviction logic."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_oracle_cache.db")
        self.cache = L2SQLiteCache(db_path=self.db_path)

    def tearDown(self):
        self.cache.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_init_wal_mode(self):
        """Verifies DB initialization with PRAGMA journal_mode = WAL and synchronous = NORMAL."""
        self.assertTrue(os.path.exists(self.db_path), "Database file must be created on disk")
        with self.cache._conn_ctx() as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(mode.lower(), "wal", "SQLite database must be configured in WAL mode")
            sync = conn.execute("PRAGMA synchronous").fetchone()[0]
            self.assertIn(sync, (1, "1", "NORMAL", "normal"), "PRAGMA synchronous must be NORMAL")

    def test_store_and_retrieve_all_query_types(self):
        """Tests storing and retrieving results for decompile, vtable, disassemble, adrp_add, and opcodes."""
        now = time.time()

        # 1. 'decompile' query
        decomp_payload = {
            "status": "ok",
            "results": [
                {
                    "target": "0x00CF2D84",
                    "va": "0x00CF2D84",
                    "rva": "0x00BF2D84",
                    "name": "FUN_00cf2d84",
                    "code": "void FUN_00cf2d84(void) { return; }",
                    "comment": "Hooked function",
                    "style": "normalize",
                }
            ],
        }
        self.cache.put("decompile", "0x00CF2D84", decomp_payload, timestamp=now)
        decomp_ret = self.cache.get("decompile", "0x00cf2d84")
        self.assertIsNotNone(decomp_ret)
        self.assertTrue(decomp_ret.get("l2_cached"))
        self.assertAlmostEqual(decomp_ret.get("l2_timestamp"), now, places=2)
        self.assertEqual(decomp_ret["results"][0]["code"], "void FUN_00cf2d84(void) { return; }")
        self.assertEqual(decomp_ret["results"][0]["name"], "FUN_00cf2d84")

        # 2. 'vtable' query
        vtable_payload = {
            "status": "ok",
            "vtable_va": "0x00D01000",
            "vtable_rva": "0x00C01000",
            "name": "vtable_PlayerEntity",
            "count": 2,
            "entries": [
                {
                    "slot": 0,
                    "slot_va": "0x00D01000",
                    "slot_rva": "0x00C01000",
                    "fn_va": "0x00CF2D84",
                    "fn_rva": "0x00BF2D84",
                    "name": "FUN_00cf2d84",
                },
                {
                    "slot": 1,
                    "slot_va": "0x00D01008",
                    "slot_rva": "0x00C01008",
                    "fn_va": "0x00CF3000",
                    "fn_rva": "0x00BF3000",
                    "name": "FUN_00cf3000",
                },
            ],
        }
        self.cache.put("vtable", "0x00D01000", vtable_payload, timestamp=now)
        vtable_ret = self.cache.get("vtable", "0x00d01000")
        self.assertIsNotNone(vtable_ret)
        self.assertTrue(vtable_ret.get("l2_cached"))
        self.assertEqual(vtable_ret["vtable_va"], "0x00D01000")
        self.assertEqual(len(vtable_ret["entries"]), 2)

        # 3. 'disassemble' query
        disasm_payload = {
            "status": "ok",
            "target_va": "0x00CF2D84",
            "target_rva": "0x00BF2D84",
            "count": 2,
            "instructions": [
                {
                    "va": "0x00CF2D84",
                    "rva": "0x00BF2D84",
                    "bytes": "fd7bb1a9",
                    "mnemonic": "stp",
                    "operands": "x29, x30, [sp, #-0x10]!",
                },
                {
                    "va": "0x00CF2D88",
                    "rva": "0x00BF2D88",
                    "bytes": "c0035fd6",
                    "mnemonic": "ret",
                    "operands": "",
                },
            ],
        }
        self.cache.put("disassemble", "0x00CF2D84", disasm_payload, timestamp=now)
        disasm_ret = self.cache.get("disassemble", "0x00cf2d84")
        self.assertIsNotNone(disasm_ret)
        self.assertTrue(disasm_ret.get("l2_cached"))
        self.assertEqual(disasm_ret["instructions"][1]["mnemonic"], "ret")

        # 4. 'adrp_add' query
        adrp_payload = {
            "status": "ok",
            "symbol": "s_PlayerConfig",
            "target_va": "0x00E05000",
            "target_rva": "0x00D05000",
            "direct_refs_count": 3,
            "page_refs_count": 1,
        }
        self.cache.put("adrp_add", "s_PlayerConfig", adrp_payload, timestamp=now)
        adrp_ret = self.cache.get("adrp_add", "s_playerconfig")
        self.assertIsNotNone(adrp_ret)
        self.assertTrue(adrp_ret.get("l2_cached"))
        self.assertEqual(adrp_ret["symbol"], "s_PlayerConfig")
        self.assertEqual(adrp_ret["direct_refs_count"], 3)

        # 5. 'opcodes' query
        opcodes_payload = {
            "status": "ok",
            "min": 500,
            "max": 550,
            "count": 1,
            "total_indexed_gates": 120,
            "gates": [
                {
                    "opcode": 501,
                    "opcode_hex": "0x01F5",
                    "va": "0x00CF4000",
                    "rva": "0x00BF4000",
                    "asm": "mov w0, #0x1f5; ret",
                }
            ],
        }
        self.cache.put("opcodes", "500_550", opcodes_payload, timestamp=now)
        opcodes_ret = self.cache.get("opcodes", "500_550")
        self.assertIsNotNone(opcodes_ret)
        self.assertTrue(opcodes_ret.get("l2_cached"))
        self.assertEqual(opcodes_ret["gates"][0]["opcode"], 501)

    def test_case_insensitivity_and_key_normalization(self):
        """Verifies that queries are stored and fetched case-insensitively."""
        data = {"status": "ok", "message": "case test"}
        self.cache.put("decompile", "0x00CF2D84", data)

        self.assertIsNotNone(self.cache.get("decompile", "0x00cf2d84"))
        self.assertIsNotNone(self.cache.get("decompile", "0x00CF2D84"))
        self.assertIsNotNone(self.cache.get("decompile", "0X00CF2D84"))

    def test_cache_miss_returns_none(self):
        """Verifies that non-existent cache keys return None without exception."""
        self.assertIsNone(self.cache.get("decompile", "0xdeadbeef"))
        self.assertIsNone(self.cache.get("nonexistent_type", "0x0"))

    def test_cache_clear(self):
        """Verifies that clear() wipes all records and count() returns 0."""
        self.cache.put("decompile", "0x1000", {"data": 1})
        self.cache.put("vtable", "0x2000", {"data": 2})
        self.cache.put("disassemble", "0x3000", {"data": 3})
        self.assertEqual(self.cache.count(), 3)

        deleted = self.cache.clear()
        self.assertEqual(deleted, 3)
        self.assertEqual(self.cache.count(), 0)
        self.assertIsNone(self.cache.get("decompile", "0x1000"))
        self.assertIsNone(self.cache.get("vtable", "0x2000"))

    def test_cache_evict_by_key(self):
        """Verifies targeted eviction of a single query_type + query_key pair."""
        self.cache.put("decompile", "0x1000", {"k": 1})
        self.cache.put("decompile", "0x2000", {"k": 2})
        self.assertEqual(self.cache.count(), 2)

        evicted = self.cache.evict(query_type="decompile", query_key="0x1000")
        self.assertEqual(evicted, 1)
        self.assertIsNone(self.cache.get("decompile", "0x1000"))
        self.assertIsNotNone(self.cache.get("decompile", "0x2000"))

    def test_cache_evict_by_query_type(self):
        """Verifies eviction of all entries matching a specific query_type."""
        self.cache.put("decompile", "0x1000", {"k": 1})
        self.cache.put("decompile", "0x2000", {"k": 2})
        self.cache.put("vtable", "0x3000", {"k": 3})
        self.assertEqual(self.cache.count(), 3)

        evicted = self.cache.evict(query_type="decompile")
        self.assertEqual(evicted, 2)
        self.assertEqual(self.cache.count(), 1)
        self.assertIsNone(self.cache.get("decompile", "0x1000"))
        self.assertIsNone(self.cache.get("decompile", "0x2000"))
        self.assertIsNotNone(self.cache.get("vtable", "0x3000"))

    def test_cache_evict_by_age(self):
        """Verifies TTL / timestamp-based eviction (older_than_sec)."""
        now = time.time()
        # Entry 1: 100 seconds ago
        self.cache.put("decompile", "0x1000", {"k": 1}, timestamp=now - 100.0)
        # Entry 2: 50 seconds ago
        self.cache.put("decompile", "0x2000", {"k": 2}, timestamp=now - 50.0)
        # Entry 3: Just now (0 seconds ago)
        self.cache.put("decompile", "0x3000", {"k": 3}, timestamp=now)

        # Evict entries older than 60 seconds (should evict Entry 1 only)
        evicted = self.cache.evict(older_than_sec=60.0)
        self.assertEqual(evicted, 1)
        self.assertIsNone(self.cache.get("decompile", "0x1000"))
        self.assertIsNotNone(self.cache.get("decompile", "0x2000"))
        self.assertIsNotNone(self.cache.get("decompile", "0x3000"))

    def test_cache_evict_by_capacity_limit(self):
        """Verifies FIFO/LRU capacity-based eviction when max_entries is exceeded."""
        now = time.time()
        for i in range(10):
            self.cache.put("decompile", f"0x{i:04X}", {"index": i}, timestamp=now + i)
        self.assertEqual(self.cache.count(), 10)

        # Evict excess entries to enforce max_entries = 4 (should evict 6 oldest)
        evicted = self.cache.evict(max_entries=4)
        self.assertEqual(evicted, 6)
        self.assertEqual(self.cache.count(), 4)
        # Oldest 6 (0x0000 - 0x0005) must be gone
        for i in range(6):
            self.assertIsNone(self.cache.get("decompile", f"0x{i:04X}"))
        # Newest 4 (0x0006 - 0x0009) must remain
        for i in range(6, 10):
            self.assertIsNotNone(self.cache.get("decompile", f"0x{i:04X}"))


class TestGhidraOracleSessionGovernor(unittest.TestCase):
    """Verifies GhidraOracleSession Governor mode adaptation and hibernate mechanics without live PyGhidra."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "session_test_cache.db")
        self.cache = L2SQLiteCache(db_path=self.db_path)
        self.overlay_path = os.path.join(self.temp_dir.name, "session_overlay.json")
        self.overlay = WriteOverlay(filepath=self.overlay_path)

        # Instantiate uninitialized session (does not boot Ghidra/JVM)
        self.session = GhidraOracleSession(
            resource_mode="balanced",
            l2_cache=self.cache,
            overlay=self.overlay,
        )

    def tearDown(self):
        self.session.close()
        self.cache.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_session_initial_state_defaults(self):
        """Verifies that an uninitialized session has clean default governor state."""
        self.assertEqual(self.session.resource_mode, "balanced")
        self.assertEqual(self.session.idle_timeout_sec, 120.0)
        self.assertEqual(self.session.throttle_ms, 10)
        self.assertEqual(self.session.decompile_cache.capacity, 512)
        self.assertEqual(self.session.vtable_cache.capacity, 512)
        self.assertFalse(self.session.is_hibernating)

    def test_set_resource_mode_eco(self):
        """Verifies Eco mode: 15s idle timeout, 50ms throttle, 128 cache capacity."""
        res = self.session.set_resource_mode("eco")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(self.session.resource_mode, "eco")
        self.assertEqual(self.session.idle_timeout_sec, 15.0)
        self.assertEqual(self.session.throttle_ms, 50)
        self.assertEqual(self.session.decompile_cache.capacity, 128)
        self.assertEqual(self.session.vtable_cache.capacity, 128)
        self.assertEqual(res["idle_timeout_sec"], 15.0)
        self.assertEqual(res["throttle_ms"], 50)
        self.assertEqual(res["cache_capacity"], 128)

    def test_set_resource_mode_balanced(self):
        """Verifies Balanced mode: 120s idle timeout, 10ms throttle, 512 cache capacity."""
        self.session.set_resource_mode("eco")
        res = self.session.set_resource_mode("balanced")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(self.session.resource_mode, "balanced")
        self.assertEqual(self.session.idle_timeout_sec, 120.0)
        self.assertEqual(self.session.throttle_ms, 10)
        self.assertEqual(self.session.decompile_cache.capacity, 512)
        self.assertEqual(self.session.vtable_cache.capacity, 512)

    def test_set_resource_mode_turbo(self):
        """Verifies Turbo mode: 0.0s idle timeout (never hibernate), 0ms throttle, 2048 cache capacity."""
        res = self.session.set_resource_mode("turbo")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(self.session.resource_mode, "turbo")
        self.assertEqual(self.session.idle_timeout_sec, 0.0)
        self.assertEqual(self.session.throttle_ms, 0)
        self.assertEqual(self.session.decompile_cache.capacity, 2048)
        self.assertEqual(self.session.vtable_cache.capacity, 2048)

    def test_set_resource_mode_auto(self):
        """Verifies Auto mode: 60s idle timeout, 10ms throttle, 1024 cache capacity."""
        res = self.session.set_resource_mode("auto")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(self.session.resource_mode, "auto")
        self.assertEqual(self.session.idle_timeout_sec, 60.0)
        self.assertEqual(self.session.throttle_ms, 10)
        self.assertEqual(self.session.decompile_cache.capacity, 1024)
        self.assertEqual(self.session.vtable_cache.capacity, 1024)

    def test_set_resource_mode_invalid(self):
        """Verifies that invalid resource mode names return an error without altering state."""
        prev_mode = self.session.resource_mode
        res = self.session.set_resource_mode("quantum_boost")
        self.assertEqual(res["status"], "error")
        self.assertIn("Unknown mode", res["message"])
        self.assertEqual(self.session.resource_mode, prev_mode)

    def test_hibernate_mechanics(self):
        """Verifies hibernate() method calls flushCache(), stopProcess(), and sets is_hibernating flag."""
        mock_decompiler = MagicMock()
        mock_decompiler.flushCache = MagicMock()
        mock_decompiler.stopProcess = MagicMock()
        self.session.decompiler = mock_decompiler
        self.session.is_hibernating = False

        res = self.session.hibernate()
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res["is_hibernating"])
        self.assertTrue(self.session.is_hibernating)

        mock_decompiler.flushCache.assert_called_once()
        mock_decompiler.stopProcess.assert_called_once()

    def test_hibernate_without_active_decompiler(self):
        """Verifies hibernate() executes safely even if decompiler is None."""
        self.session.decompiler = None
        self.session.is_hibernating = False

        res = self.session.hibernate()
        self.assertEqual(res["status"], "ok")
        self.assertTrue(self.session.is_hibernating)

    def test_ensure_decompiler_active_resumes_hibernation(self):
        """Verifies _ensure_decompiler_active re-arms decompiler and unsets is_hibernating."""
        self.session.is_hibernating = True
        mock_decompiler = MagicMock()
        self.session.decompiler = mock_decompiler
        mock_program = MagicMock()
        self.session.program = mock_program

        self.session._ensure_decompiler_active()
        self.assertFalse(self.session.is_hibernating)
        mock_decompiler.openProgram.assert_called_once_with(mock_program)


class TestCLIArgumentParsingAndFastPath(unittest.TestCase):
    """Verifies client_send_request fast-paths (offline RVA fallback, L2 cache bypass) and CLI arg parsing."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "client_fastpath_cache.db")
        self.cache = L2SQLiteCache(db_path=self.db_path)

    def tearDown(self):
        self.cache.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_rva_offline_fallback(self):
        """Verifies client_send_request fast path for 'rva' when daemon is offline (zero JVM required)."""
        # Point to unused port so daemon is guaranteed offline
        unused_port = 59999
        res = client_send_request(
            cmd="rva",
            args={"addr": "0x00CF2D84"},
            host="127.0.0.1",
            port=unused_port,
            auto_spawn=False,
            l2_cache=self.cache,
        )

        self.assertEqual(res["status"], "ok")
        self.assertTrue(res.get("local_fallback"))
        self.assertEqual(res["va"], "0x00CF2D84")
        self.assertEqual(res["rva"], "0x00BF2D84")
        self.assertEqual(res["va_int"], 0x00CF2D84)
        self.assertEqual(res["rva_int"], 0x00BF2D84)
        self.assertEqual(res["image_base"], f"0x{DEFAULT_IMAGE_BASE:08X}")
        self.assertIn("time_ms", res)

    def test_client_send_request_l2_cache_bypass_decompile(self):
        """Verifies that client_send_request serves decompile results directly from L2 SQLite cache when offline."""
        mock_decompile_result = {
            "status": "ok",
            "results": [
                {
                    "target": "0x00CF2D84",
                    "va": "0x00CF2D84",
                    "rva": "0x00BF2D84",
                    "name": "FUN_00cf2d84",
                    "code": "int FUN_00cf2d84(void) { return 42; }",
                    "cached": True,
                }
            ],
        }
        self.cache.put("decompile", "0x00cf2d84", mock_decompile_result)

        unused_port = 59999
        # Auto-spawn is False and port is closed: if it tried to connect, it would fail
        res = client_send_request(
            cmd="decompile",
            args={"targets": ["0x00cf2d84"]},
            host="127.0.0.1",
            port=unused_port,
            auto_spawn=False,
            l2_cache=self.cache,
        )

        self.assertEqual(res["status"], "ok")
        self.assertTrue(res.get("l2_cached"))
        self.assertEqual(res["results"][0]["code"], "int FUN_00cf2d84(void) { return 42; }")

    def test_client_send_request_l2_cache_bypass_vtable(self):
        """Verifies L2 cache bypass for 'vtable' queries."""
        mock_vtable = {
            "status": "ok",
            "vtable_va": "0x00D01000",
            "vtable_rva": "0x00C01000",
            "count": 1,
            "entries": [{"slot": 0, "fn_va": "0x00CF2D84"}],
        }
        self.cache.put("vtable", "0x00d01000", mock_vtable)

        unused_port = 59999
        res = client_send_request(
            cmd="vtable",
            args={"addr": "0x00d01000"},
            host="127.0.0.1",
            port=unused_port,
            auto_spawn=False,
            l2_cache=self.cache,
        )
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res.get("l2_cached"))
        self.assertEqual(res["vtable_va"], "0x00D01000")

    def test_client_send_request_l2_cache_bypass_adrp_add(self):
        """Verifies L2 cache bypass for 'adrp_add' queries."""
        mock_adrp = {
            "status": "ok",
            "symbol": "g_TestVar",
            "target_va": "0x00E00000",
            "direct_refs_count": 5,
        }
        self.cache.put("adrp_add", "g_testvar", mock_adrp)

        unused_port = 59999
        res = client_send_request(
            cmd="adrp_add",
            args={"target": "g_testvar"},
            host="127.0.0.1",
            port=unused_port,
            auto_spawn=False,
            l2_cache=self.cache,
        )
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res.get("l2_cached"))
        self.assertEqual(res["symbol"], "g_TestVar")

    def test_client_send_request_l2_cache_bypass_opcodes(self):
        """Verifies L2 cache bypass for 'opcodes' queries."""
        mock_opcodes = {
            "status": "ok",
            "min": 100,
            "max": 150,
            "count": 2,
            "gates": [{"opcode": 101, "va": "0x00CF1000"}],
        }
        self.cache.put("opcodes", "100_150", mock_opcodes)

        unused_port = 59999
        res = client_send_request(
            cmd="opcodes",
            args={"min": 100, "max": 150},
            host="127.0.0.1",
            port=unused_port,
            auto_spawn=False,
            l2_cache=self.cache,
        )
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res.get("l2_cached"))
        self.assertEqual(res["gates"][0]["opcode"], 101)

    def test_cli_argument_parsing_commands(self):
        """Verifies main() CLI argument parsing routes correctly to client_send_request."""
        test_cases = [
            (["rva", "0x00CF2D84"], "rva", {"addr": "0x00CF2D84"}),
            (["decompile", "0x00CF2D84", "0x00CF3000"], "decompile", {"targets": ["0x00CF2D84", "0x00CF3000"]}),
            (["vtable", "0x00D01000", "16"], "vtable", {"addr": "0x00D01000", "count": 16}),
            (["disassemble", "0x00CF2D84", "20"], "disassemble", {"addr": "0x00CF2D84", "count": 20}),
            (["refs", "0x00CF2D84", "15"], "refs", {"addr": "0x00CF2D84", "count": 15}),
            (["adrp_add", "s_Config"], "adrp_add", {"target": "s_Config"}),
            (["opcodes", "200", "250"], "opcodes", {"min": 200, "max": 250}),
            (["rename", "0x00CF2D84", "hook_player_init"], "rename", {"addr": "0x00CF2D84", "name": "hook_player_init"}),
            (["comment", "0x00CF2D84", "Entry", "point", "hook"], "comment", {"addr": "0x00CF2D84", "comment": "Entry point hook"}),
            (["hibernate"], "hibernate", {}),
            (["mode", "turbo"], "mode", {"mode": "turbo"}),
            (["status"], "status", {}),
            (["stop"], "stop", {}),
        ]

        for cli_args, expected_cmd, expected_req_args in test_cases:
            with self.subTest(command=expected_cmd):
                with patch("sys.argv", ["ghidra_oracle.py"] + cli_args + ["--json"]), \
                     patch("ghidra_oracle.client_send_request") as mock_send, \
                     patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:

                    mock_send.return_value = {"status": "ok", "message": f"{expected_cmd} test success"}
                    main()

                    mock_send.assert_called_once()
                    actual_cmd = mock_send.call_args[0][0]
                    actual_args = mock_send.call_args[0][1]
                    self.assertEqual(actual_cmd, expected_cmd)
                    self.assertEqual(actual_args, expected_req_args)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
