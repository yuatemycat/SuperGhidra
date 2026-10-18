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
SCRIPT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from ghidra_oracle import (
    DEFAULT_HOST,
    DEFAULT_IMAGE_BASE,
    DEFAULT_PORT,
    GhidraOracleSession,
    GhidraDaemonServer,
    L2SQLiteCache,
    WriteOverlay,
    client_send_request,
    main,
    normalize_address_pair,
    DependencyCacheDAG,
    SemanticDeltaLog,
    DeltaEventType,
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



class TestOracleDAGDeltaAndOverlayIntegration(unittest.TestCase):
    """Verifies WriteOverlay C-code rewrite, selective 1-hop DAG invalidation, and SemanticDeltaLog."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.overlay_path = os.path.join(self.temp_dir.name, "test_overlay.json")
        self.delta_log_path = os.path.join(self.temp_dir.name, "test_delta.jsonl")
        self.db_path = os.path.join(self.temp_dir.name, "test_cache.db")

        self.overlay = WriteOverlay(filepath=self.overlay_path)
        self.cache = L2SQLiteCache(db_path=self.db_path)
        self.session = GhidraOracleSession(
            overlay=self.overlay,
            l2_cache=self.cache,
        )
        # Point session delta log to temp dir
        self.session.delta_log = SemanticDeltaLog(self.delta_log_path)

    def tearDown(self):
        self.cache.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_write_overlay_apply_to_c_code(self):
        """Verifies replacing FUN_<va_hex> or FUN_<rva_hex> and known symbols inside C code."""
        # 0x00101234 (VA) -> RVA 0x00001234 (image_base = 0x100000)
        self.overlay.set_rename("0x00101234", "Player_TakeDamage")
        self.overlay.set_rename("0x00105678", "Enemy_Spawn")
        self.overlay.set_rename("sub_custom", "Helper_Func")

        sample_c = (
            "void FUN_00101234(int damage) {\n"
            "    FUN_00001234(damage);\n"
            "    fun_00105678();\n"
            "    sub_custom();\n"
            "    FUN_00999999(); // Unmodified callee\n"
            "}"
        )

        transformed = self.overlay.apply_to_c_code(sample_c, image_base=DEFAULT_IMAGE_BASE)

        self.assertIn("void Player_TakeDamage(int damage)", transformed)
        self.assertIn("Player_TakeDamage(damage);", transformed)
        self.assertIn("Enemy_Spawn();", transformed)
        self.assertIn("Helper_Func();", transformed)
        self.assertIn("FUN_00999999();", transformed)
        self.assertNotIn("FUN_00101234", transformed)
        self.assertNotIn("FUN_00001234", transformed)
        self.assertNotIn("fun_00105678", transformed)
        self.assertNotIn("sub_custom();", transformed)

    def test_l2_cache_invalidate_address(self):
        """Verifies selective invalidation of decompile entries by virtual address."""
        # Add 3 separate decompile entries in L2 cache
        payload_1 = {"status": "ok", "results": [{"va": "0x00101000", "code": "void f1() {}"}]}
        payload_2 = {"status": "ok", "results": [{"va": "0x00102000", "code": "void f2() {}"}]}
        payload_3 = {"status": "ok", "results": [{"va": "0x00103000", "code": "void f3() {}"}]}

        # Test both direct key format and JSON targets format
        self.cache.put("decompile", "0x00101000", payload_1)
        self.cache.put("decompile", '{"targets": ["0x00102000"]}', payload_2)
        self.cache.put("decompile", "0x00103000", payload_3)

        self.assertIsNotNone(self.cache.get("decompile", "0x00101000"))
        self.assertIsNotNone(self.cache.get("decompile", '{"targets": ["0x00102000"]}'))
        self.assertIsNotNone(self.cache.get("decompile", "0x00103000"))

        # Invalidate 0x00102000
        evicted = self.cache.invalidate_address(0x00102000)
        self.assertGreaterEqual(evicted, 1)

        # 0x00102000 is gone, 0x00101000 and 0x00103000 remain
        self.assertIsNone(self.cache.get("decompile", '{"targets": ["0x00102000"]}'))
        self.assertIsNotNone(self.cache.get("decompile", "0x00101000"))
        self.assertIsNotNone(self.cache.get("decompile", "0x00103000"))

        # Invalidate 0x00101000 by hex string
        evicted_direct = self.cache.invalidate_address("0x00101000")
        self.assertGreaterEqual(evicted_direct, 1)
        self.assertIsNone(self.cache.get("decompile", "0x00101000"))
        self.assertIsNotNone(self.cache.get("decompile", "0x00103000"))

    def test_1hop_dag_invalidation_on_rename(self):
        """Verifies 1-hop selective cache invalidation on rename (callees & unrelated remain cached)."""
        # Graph:
        # func_caller (0x00101000) -> func_target (0x00102000) -> func_callee (0x00103000)
        # func_unrelated (0x00104000)
        fid_caller = "0x00101000"
        fid_target = "0x00102000"
        fid_callee = "0x00103000"
        fid_unrelated = "0x00104000"

        self.session.dep_dag.add_function(fid_caller, address=0x00101000, name="caller")
        self.session.dep_dag.add_function(fid_target, address=0x00102000, name="target")
        self.session.dep_dag.add_function(fid_callee, address=0x00103000, name="callee")
        self.session.dep_dag.add_function(fid_unrelated, address=0x00104000, name="unrelated")

        self.session.dep_dag.add_call_edge(fid_caller, fid_target)
        self.session.dep_dag.add_call_edge(fid_target, fid_callee)

        # Pre-populate L1 decompile cache
        self.session.decompile_cache.put(0x00101000, {"code": "caller() { target(); }"})
        self.session.decompile_cache.put(0x00102000, {"code": "target() { callee(); }"})
        self.session.decompile_cache.put(0x00103000, {"code": "callee() {}"})
        self.session.decompile_cache.put(0x00104000, {"code": "unrelated() {}"})

        # Pre-populate L2 SQLite cache
        for addr_int in [0x00101000, 0x00102000, 0x00103000, 0x00104000]:
            self.session.l2_cache.put("decompile", f"0x{addr_int:08x}", {"status": "ok", "addr": addr_int})

        # Rename func_target
        res = self.session.set_rename(0x00102000, "target_renamed")
        self.assertEqual(res["status"], "ok")

        # Selective 1-hop:
        # func_target (0x00102000) and caller (0x00101000) must be evicted!
        self.assertIsNone(self.session.decompile_cache.get(0x00102000))
        self.assertIsNone(self.session.decompile_cache.get(0x00101000))
        self.assertIsNone(self.session.l2_cache.get("decompile", "0x00102000"))
        self.assertIsNone(self.session.l2_cache.get("decompile", "0x00101000"))

        # Callee (0x00103000) and unrelated (0x00104000) must REMAIN CACHED!
        self.assertIsNotNone(self.session.decompile_cache.get(0x00103000))
        self.assertIsNotNone(self.session.decompile_cache.get(0x00104000))
        self.assertIsNotNone(self.session.l2_cache.get("decompile", "0x00103000"))
        self.assertIsNotNone(self.session.l2_cache.get("decompile", "0x00104000"))

    def test_semantic_delta_log_integration(self):
        """Verifies mutations are recorded in SemanticDeltaLog with cryptographic proof hashes."""
        res_rename = self.session.set_rename(0x00102000, "Hero_Attack")
        self.assertEqual(res_rename["status"], "ok")

        res_comment = self.session.set_comment(0x00102000, "Critical attack logic")
        self.assertEqual(res_comment["status"], "ok")

        # Verify events recorded in delta log
        self.assertEqual(len(self.session.delta_log.events), 2)
        evt0 = self.session.delta_log.events[0]
        evt1 = self.session.delta_log.events[1]

        self.assertEqual(evt0.event_type, DeltaEventType.RENAME_SYMBOL)
        self.assertEqual(evt0.payload["new_name"], "Hero_Attack")
        self.assertEqual(evt0.target_address, 0x00102000)

        self.assertEqual(evt1.event_type, DeltaEventType.SET_COMMENT)
        self.assertEqual(evt1.payload["comment_text"], "Critical attack logic")
        self.assertEqual(evt1.target_address, 0x00102000)

        # Audit cryptographic proof hashes
        valid, violations = self.session.delta_log.verify_integrity()
        self.assertTrue(valid, f"Delta log proof violations: {violations}")

    def test_off_heap_type_store_integration(self):
        """Verifies registering deduplicated structs and querying layout & C decl off-heap."""
        # 1. Direct session call: register_struct
        members = [
            {"name": "m_health", "type_id": "int32_t", "offset": 0, "size": 4},
            {"name": "m_mana", "type_id": "int32_t", "offset": 4, "size": 4},
            {"name": "m_speed", "type_id": "float", "offset": 8, "size": 4},
        ]
        reg_res = self.session.register_struct("PlayerEntity", 0x20, members)
        self.assertEqual(reg_res["status"], "ok")
        self.assertEqual(reg_res["name"], "PlayerEntity")
        self.assertEqual(reg_res["byte_size"], 0x20)
        self.assertEqual(reg_res["members_count"], 3)
        self.assertIn("struct PlayerEntity", reg_res["c_decl"])
        self.assertEqual(len(reg_res["layout"]), 3)
        self.assertEqual(reg_res["layout"][0]["name"], "m_health")
        self.assertEqual(reg_res["layout"][0]["offset"], 0)

        # 2. Query type by name
        query_res = self.session.query_type("PlayerEntity")
        self.assertEqual(query_res["status"], "ok")
        self.assertEqual(query_res["type"]["name"], "PlayerEntity")
        self.assertEqual(len(query_res["layout"]), 3)
        self.assertIn("struct PlayerEntity", query_res["c_decl"])

        # 3. Query non-existent type
        missing_res = self.session.query_type("NonExistentType_123")
        self.assertEqual(missing_res["status"], "not_found")

        # 4. Daemon Server _dispatch_command verification
        server = GhidraDaemonServer(self.session)
        dispatch_reg = server._dispatch_command(
            json.dumps({
                "cmd": "register_struct",
                "args": {
                    "name": "EnemyEntity",
                    "byte_size": 16,
                    "members": [{"name": "dmg", "type_id": "int", "offset": 0, "size": 4}],
                },
            })
        )
        self.assertEqual(dispatch_reg["status"], "ok")
        self.assertEqual(dispatch_reg["name"], "EnemyEntity")

        dispatch_query = server._dispatch_command(
            json.dumps({"cmd": "type", "args": {"name": "EnemyEntity"}})
        )
        self.assertEqual(dispatch_query["status"], "ok")
        self.assertEqual(dispatch_query["type"]["name"], "EnemyEntity")
        self.assertEqual(dispatch_query["layout"][0]["name"], "dmg")

    def test_client_send_request_l2_cache_overlay_rewriting(self):
        """Verifies WriteOverlay renames and comments are applied to decompile results from L2 cache."""
        temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(temp_dir.name, "test_l2.db")
        overlay_path = os.path.join(temp_dir.name, "test_overlay.json")
        try:
            l2 = L2SQLiteCache(db_path=db_path)
            overlay = WriteOverlay(filepath=overlay_path)
            overlay.set_rename(0x00101000, "Logic_Process")
            overlay.set_comment(0x00101000, "Core game loop")

            decompile_data = {
                "status": "ok",
                "results": [
                    {
                        "target": "0x00101000",
                        "va": "0x00101000",
                        "rva": "0x00001000",
                        "name": "FUN_00101000",
                        "code": "void FUN_00101000(void) { FUN_00101000(); }",
                        "comment": None,
                        "style": "normalize",
                    }
                ]
            }
            l2.put("decompile", "0x00101000", decompile_data)

            with patch("ghidra_oracle.WriteOverlay", lambda *args, **kwargs: overlay):
                resp = client_send_request(
                    "decompile",
                    {"targets": ["0x00101000"]},
                    auto_spawn=False,
                    l2_cache=l2,
                )

            self.assertTrue(resp.get("l2_cached"))
            res_item = resp["results"][0]
            self.assertEqual(res_item["name"], "Logic_Process")
            self.assertEqual(res_item["comment"], "Core game loop")
            self.assertIn("Logic_Process();", res_item["code"])
        finally:
            l2.close()
            temp_dir.cleanup()

    def test_multi_segment_fast_index_scan(self):
        """Verifies _build_fast_indexes accumulates opcode gates across multiple executable/large segments."""
        session = GhidraOracleSession()
        mock_prog = MagicMock()
        mock_mem = MagicMock()
        session.program = mock_prog
        session.flat_api = MagicMock()
        mock_prog.getMemory.return_value = mock_mem

        # Segment 1: executable, contains mov w0, #10; ret -> imm=10
        # ARM64: [0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]
        gate_10 = bytes([0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6])
        blk1 = MagicMock()
        blk1.isExecute.return_value = True
        blk1.getSize.return_value = 8
        blk1.getStart().getOffset.return_value = 0x100000

        # Segment 2: large block > 4096, contains mov w0, #20; ret -> imm=20
        # ARM64: [0x80, 0x02, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]
        gate_20 = bytes([0x80, 0x02, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]) + b"\x00" * 4096
        blk2 = MagicMock()
        blk2.isExecute.return_value = False
        blk2.getSize.return_value = len(gate_20)
        blk2.getStart().getOffset.return_value = 0x200000

        mock_mem.getBlocks.return_value = [blk1, blk2]

        import sys
        mock_java = MagicMock()
        mock_array = MagicMock()
        mock_array.newInstance.side_effect = lambda t, sz: bytearray(sz)
        mock_java.lang.reflect.Array = mock_array
        mock_java.lang.Byte.TYPE = "byte"

        def mock_getBytes(start, jb):
            if len(jb) == 8:
                jb[:] = gate_10
            elif len(jb) == len(gate_20):
                jb[:] = gate_20
        mock_mem.getBytes.side_effect = mock_getBytes

        with patch.dict(sys.modules, {"java.lang.reflect": mock_java.lang.reflect, "java.lang": mock_java.lang}):
            session._build_fast_indexes()

        self.assertGreaterEqual(len(session._opcode_gates), 2)
        imms = [g[0] for g in session._opcode_gates]
        self.assertIn(10, imms)
        self.assertIn(20, imms)

    def test_query_decompile_complexity_downshifting(self):
        """Verifies query_decompile dynamically downshifts simplification style for megafunctions (>16KB)."""
        session = GhidraOracleSession(resource_mode="balanced")
        mock_prog = MagicMock()
        mock_decompiler = MagicMock()
        mock_flat = MagicMock()
        session.program = mock_prog
        session.decompiler = mock_decompiler
        session.flat_api = mock_flat
        session.monitor = MagicMock()

        # Mock function with body size 20000 (> 16384 bytes, Tier 3 Megafunction)
        mock_func = MagicMock()
        mock_func.getBody().getNumAddresses.return_value = 20000
        mock_func.getEntryPoint().getOffset.return_value = 0x00101000
        mock_func.getName.return_value = "MegaDispatcher"

        fm = mock_prog.getFunctionManager()
        fm.getFunctionAt.return_value = mock_func
        fm.getFunctionContaining.return_value = mock_func

        mock_res = MagicMock()
        mock_res.decompileCompleted.return_value = True
        mock_res.getDecompiledFunction().getC.return_value = "void MegaDispatcher(void) {}"
        mock_decompiler.decompileFunction.return_value = mock_res

        res = session.query_decompile(targets=["0x00101000"], style=None)

        self.assertEqual(res["status"], "ok")
        item = res["results"][0]
        # In balanced mode, Tier 3 downshifts to 'jumptable'
        self.assertEqual(item["style"], "jumptable")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

