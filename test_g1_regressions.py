"""Focused regression tests for G1/G1b fixes in SuperGhidra.

Verifies:
1. openProgram called with readOnly=True
2. clean_locks deletes nothing by default and deletes only an old lock when opted in
3. A fresh lock is never deleted even when opted in
4. L2 cache with program_id A does not return program B's (or legacy '') row
5. Invalidate on rename removes vtable/refs/decompile rows for that program
6. L1 decompile cache distinguishes styles
7. Socket server closes on an HTTP 'POST ' first line
8. Multibyte UTF-8 split across recv chunks decodes correctly
9. Headless no-return list does not match 'atexit'/'__cxa_atexit'
10. Recommended headless command never combines -readOnly with -import
11. Semantic delta log keeps A->B->A edits (replay ends at A)
12. DAG invalidates callers of a named function
13. Governor launch.properties has one VMARGS per line and no MAXMEM key
"""

import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from dependency_cache_dag import DependencyCacheDAG
from ghidra_oracle import GhidraDaemonServer, GhidraOracleSession, L2SQLiteCache
from headless_analyzer_tuner import HeadlessCommandBuilder, ScriptGenerator
from resource_governor import JVMResourceConfigurator, ResourceMode, get_default_mode_policy
from semantic_delta_log import DeltaEventType, SemanticDeltaLog, SemanticEvent


class TestG1Regressions(unittest.TestCase):
    """Suite of regression tests for all G1 and G1b storage/oracle fixes."""

    def test_open_program_called_with_read_only_true(self):
        """Verifies GhidraOracleSession.initialize opens programs with readOnly=True."""
        session = GhidraOracleSession(
            project_dir="/tmp/test_proj",
            project_name="TestProj",
            program_name="TestProg",
        )

        mock_pyghidra = MagicMock()
        mock_proj = MagicMock()
        mock_prog = MagicMock()
        mock_prog.getName.return_value = "TestProg"
        mock_prog.getImageBase.return_value.getOffset.return_value = 0x100000
        mock_proj.openProgram.return_value = mock_prog

        mock_ghidra_project_cls = MagicMock()
        mock_ghidra_project_cls.openProject.return_value = mock_proj

        with patch.dict(sys.modules, {
            "pyghidra": mock_pyghidra,
            "ghidra.base.project": MagicMock(GhidraProject=mock_ghidra_project_cls),
            "ghidra.program.flatapi": MagicMock(),
            "ghidra.app.decompiler": MagicMock(),
            "ghidra.util.task": MagicMock(),
        }), patch("os.path.exists", return_value=True), \
           patch.object(session, "clean_locks"), \
           patch.object(session, "_build_fast_indexes"):

            session.initialize()

            # Ensure openProgram was called with readOnly=True (3rd argument)
            mock_proj.openProgram.assert_called_with("/", "TestProg", True)
            self.assertEqual(session.program_name, "TestProg")

    def test_clean_locks_deletes_nothing_by_default(self):
        """Verifies clean_locks does not delete lock files without explicit opt-in."""
        with tempfile.TemporaryDirectory() as tmpdir:
            lock1 = os.path.join(tmpdir, "proj.lock")
            lock2 = os.path.join(tmpdir, "proj.lock~")
            with open(lock1, "w") as f:
                f.write("lock")
            with open(lock2, "w") as f:
                f.write("lock")

            # Set mtime to 1 hour ago
            old_time = time.time() - 3600
            os.utime(lock1, (old_time, old_time))
            os.utime(lock2, (old_time, old_time))

            session = GhidraOracleSession(clean_stale_locks=False)
            deleted = session.clean_locks(tmpdir, "proj")

            self.assertEqual(deleted, [])
            self.assertTrue(os.path.exists(lock1), "Lock file should NOT be deleted by default")
            self.assertTrue(os.path.exists(lock2), "Lock~ file should NOT be deleted by default")

    def test_clean_locks_deletes_only_old_lock_when_opted_in(self):
        """Verifies clean_locks deletes locks only when opted in and age > threshold."""
        with tempfile.TemporaryDirectory() as tmpdir:
            lock1 = os.path.join(tmpdir, "proj.lock")
            with open(lock1, "w") as f:
                f.write("lock")

            # Set mtime to 15 minutes ago (> 10 minute threshold)
            old_time = time.time() - 900
            os.utime(lock1, (old_time, old_time))

            session = GhidraOracleSession(clean_stale_locks=True, lock_stale_threshold_sec=600.0)
            deleted = session.clean_locks(tmpdir, "proj")

            self.assertIn(lock1, deleted)
            self.assertFalse(os.path.exists(lock1), "Stale lock file should be deleted when opted in")

    def test_fresh_lock_never_deleted_even_when_opted_in(self):
        """Verifies a recently touched lock is never deleted even when opted in."""
        with tempfile.TemporaryDirectory() as tmpdir:
            lock1 = os.path.join(tmpdir, "proj.lock")
            with open(lock1, "w") as f:
                f.write("live lock")

            # Mtime is fresh (now)
            now = time.time()
            os.utime(lock1, (now, now))

            session = GhidraOracleSession(clean_stale_locks=True, lock_stale_threshold_sec=600.0)
            deleted = session.clean_locks(tmpdir, "proj")

            self.assertEqual(deleted, [])
            self.assertTrue(os.path.exists(lock1), "Fresh lock must never be deleted")

    def test_l2_cache_program_id_scoping_no_cross_leak(self):
        """Verifies L2 cache does not leak across programs or return legacy empty rows."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_l2.db")
            cache = L2SQLiteCache(db_path=db_path)

            # Insert row for Program B
            cache.put("decompile", "0x1000", {"code": "int progB_func() {}"}, program_id="ProgB:0x100000")

            # Query with Program A
            res_a = cache.get("decompile", "0x1000", program_id="ProgA:0x100000")
            self.assertIsNone(res_a, "Query for ProgA must not return ProgB's cached row")

            # Query with Program B
            res_b = cache.get("decompile", "0x1000", program_id="ProgB:0x100000")
            self.assertIsNotNone(res_b)
            self.assertEqual(res_b.get("code"), "int progB_func() {}")

            # Insert legacy row without program_id
            with cache._conn_ctx() as conn:
                conn.execute(
                    "INSERT INTO oracle_cache (query_type, query_key, program_id, data_json, timestamp) VALUES (?, ?, ?, ?, ?)",
                    ("decompile", "0x2000", "", json.dumps({"code": "legacy_code"}), time.time())
                )
                conn.commit()

            # Query with explicit program_id should NOT match legacy empty program_id
            res_legacy_leak = cache.get("decompile", "0x2000", program_id="ProgA:0x100000")
            self.assertIsNone(res_legacy_leak, "Scoped query must not match legacy unscoped row")

    def test_invalidate_on_rename_removes_vtable_refs_decompile_for_program(self):
        """Verifies invalidating on rename evicts vtable, refs, and decompile entries for that program."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_l2_inval.db")
            l2 = L2SQLiteCache(db_path=db_path)

            # Insert entries for ProgA and ProgB
            for qtype in ("decompile", "vtable", "refs", "disassemble"):
                l2.put(qtype, "0x1000", {"data": f"{qtype}_A"}, program_id="ProgA:0x100000")
                l2.put(qtype, "0x1000", {"data": f"{qtype}_B"}, program_id="ProgB:0x100000")

            # Invalidate address 0x1000 for ProgA
            deleted = l2.invalidate_address(0x1000, program_id="ProgA:0x100000")
            self.assertGreaterEqual(deleted, 4)

            # Verify ProgA entries are gone
            for qtype in ("decompile", "vtable", "refs", "disassemble"):
                self.assertIsNone(l2.get(qtype, "0x1000", program_id="ProgA:0x100000"))
                # Verify ProgB entries are preserved
                self.assertIsNotNone(l2.get(qtype, "0x1000", program_id="ProgB:0x100000"))

    def test_l1_decompile_cache_distinguishes_styles(self):
        """Verifies L1 decompile cache separates entries by simplification style."""
        session = GhidraOracleSession()
        session.program = MagicMock()
        session.flat_api = MagicMock()
        session.decompiler = MagicMock()

        mock_func = MagicMock()
        mock_func.getEntryPoint().getOffset.return_value = 0x1000
        mock_func.getName.return_value = "target_func"
        mock_func.getCalledFunctions.return_value = []
        session.program.getFunctionManager().getFunctionAt.return_value = mock_func

        # Setup mock decompilation results for styles
        decomp_res_fp = MagicMock()
        decomp_res_fp.decompileCompleted.return_value = True
        decomp_res_fp.getDecompiledFunction().getC.return_value = "int target_func() { /* firstpass */ }"

        decomp_res_full = MagicMock()
        decomp_res_full.decompileCompleted.return_value = True
        decomp_res_full.getDecompiledFunction().getC.return_value = "int target_func() { /* full decompile */ }"

        def mock_decompile_func(func, timeout, monitor):
            style = session.decompiler.setSimplificationStyle.call_args[0][0]
            if style == "firstpass":
                return decomp_res_fp
            return decomp_res_full

        session.decompiler.decompileFunction.side_effect = mock_decompile_func

        res1 = session.query_decompile(["0x1000"], style="firstpass")
        res2 = session.query_decompile(["0x1000"], style="decompile")

        self.assertIn("firstpass", res1["results"][0]["code"])
        self.assertIn("full decompile", res2["results"][0]["code"])

        # Directly check L1 cache tuple keys using normalized VA
        va_int = int(res1["results"][0]["va"], 16)
        cached_fp = session.decompile_cache.get((va_int, "firstpass"))
        cached_dec = session.decompile_cache.get((va_int, "decompile"))
        self.assertIsNotNone(cached_fp)
        self.assertIsNotNone(cached_dec)
        self.assertNotEqual(cached_fp["code"], cached_dec["code"])

    def test_socket_server_closes_on_http_post_first_line(self):
        """Verifies TCP daemon closes socket when detecting HTTP method attack prefix."""
        session = GhidraOracleSession()
        server = GhidraDaemonServer(session, host="127.0.0.1", port=0)

        mock_socket = MagicMock()
        # Feed HTTP POST followed by bytes
        mock_socket.recv.side_effect = [b"POST /api HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b""]

        # Run _handle_client on mock socket
        server._handle_client(mock_socket, ("127.0.0.1", 12345))

        # Ensure no RPC response was returned and connection closed
        mock_socket.sendall.assert_not_called()

    def test_multibyte_utf8_split_across_recv_chunks_decodes_correctly(self):
        """Verifies server buffers chunks so multibyte UTF-8 across chunks decodes properly."""
        session = GhidraOracleSession()
        session.query_rva = MagicMock(return_value={"status": "ok", "va": "0x1000"})
        server = GhidraDaemonServer(session, host="127.0.0.1", port=0)
        server.running = True

        # UTF-8 multibyte character '🚀' is 4 bytes: F0 9F 99 80
        rocket_str = "🚀"
        payload = json.dumps({"cmd": "rva", "addr": f"0x1000_{rocket_str}"}, ensure_ascii=False).encode("utf-8") + b"\n"

        # Split directly in the middle of the rocket bytes
        split_idx = payload.index(rocket_str.encode("utf-8")) + 2
        chunk1 = payload[:split_idx]
        chunk2 = payload[split_idx:]

        sent_responses = []
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [chunk1, chunk2, b""]
        mock_socket.sendall.side_effect = lambda data: sent_responses.append(data)

        server._handle_client(mock_socket, ("127.0.0.1", 54321))

        self.assertEqual(len(sent_responses), 1)
        resp_obj = json.loads(sent_responses[0].decode("utf-8"))
        self.assertEqual(resp_obj.get("status"), "ok")

    def test_headless_no_return_list_does_not_match_atexit(self):
        """Verifies lazy noreturn terminal list excludes atexit and __cxa_atexit."""
        java_script = ScriptGenerator.generate_lazy_noreturn_postscript_java()
        py_script = ScriptGenerator.generate_lazy_noreturn_postscript_python()

        # Both postscripts must NOT mark atexit or __cxa_atexit as terminal non-returning
        self.assertNotIn('"atexit"', java_script)
        self.assertNotIn('"__cxa_atexit"', java_script)
        self.assertNotIn('"atexit"', py_script)
        self.assertNotIn('"__cxa_atexit"', py_script)

    def test_recommended_headless_command_never_combines_readonly_with_import(self):
        """Verifies analyzeHeadless invocation never combines -readOnly with -import."""
        config = HeadlessCommandBuilder(
            project_location="/tmp/proj",
            project_name="MyProj",
            import_target="/tmp/sample.bin",
        )
        args = config.build_command_args()
        self.assertIn("-import", args)
        self.assertNotIn("-readOnly", args, "Must not combine -readOnly with -import")

    def test_semantic_delta_log_keeps_a_b_a_edits(self):
        """Verifies semantic delta log retains A->B->A sequence and sequential replay ends at A."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "delta.jsonl")
            log = SemanticDeltaLog(file_path=log_path)
            log.record_function_rename(0x100020, "FuncA", old_name="Func0")
            log.record_function_rename(0x100020, "FuncB", old_name="FuncA")
            log.record_function_rename(0x100020, "FuncA", old_name="FuncB")

            self.assertEqual(len(log.events), 3, "Delta log must record all 3 mutations in history")
            state = log.project_cumulative_state()
            self.assertEqual(state["symbols_by_address"].get(hex(0x100020)), "FuncA")

    def test_dag_invalidates_callers_of_named_function(self):
        """Verifies dependency DAG invalidates callers when target is referenced by name."""
        dag = DependencyCacheDAG()
        dag.add_function("0x1000", address=0x1000, name="caller_one")
        dag.add_function("0x2000", address=0x2000, name="target_callee")
        dag.add_call_edge("0x1000", "0x2000")

        # Invalidate using the name string
        report = dag.invalidate_function("target_callee")
        self.assertIn("0x1000", report.affected_functions, "Caller must be invalidated when callee name is used")
        self.assertIn("0x2000", report.affected_functions)

    def test_governor_launch_properties_has_one_vmargs_per_line_and_no_maxmem(self):
        """Verifies generated launch.properties uses one VMARGS= line per flag and has no MAXMEM key."""
        policy = get_default_mode_policy(ResourceMode.BALANCED, logical_cores=8)
        content = JVMResourceConfigurator.generate_launch_properties(policy)

        self.assertNotIn("MAXMEM", content, "launch.properties must not contain deprecated MAXMEM key")
        lines = [line.strip() for line in content.strip().splitlines() if line.strip() and not line.startswith("#")]
        self.assertGreater(len(lines), 0)

        for line in lines:
            self.assertTrue(line.startswith("VMARGS="), f"Line does not start with VMARGS=: {line}")
            val = line[len("VMARGS="):]
            # Ensure no space-separated multiple flags per line
            self.assertFalse(" " in val and not val.startswith('"'), f"Multiple arguments on single VMARGS line: {line}")


if __name__ == "__main__":
    unittest.main()
