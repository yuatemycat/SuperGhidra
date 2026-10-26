"""
SuperGhidra Test Suite: Dependency Cache DAG & Semantic Delta Log.

Validates:
1. Dependency Cache DAG:
   - Call graph bidirectional caller <-> callee indexing.
   - Struct and struct-field level type dependency tracking.
   - Decompilation LRU cache hit/miss semantics and capacity bounds.
   - Selective 1-hop invalidation for function signatures, struct fields, and structs.
   - Retention Invariant: > 98% unaffected cached functions retained under 1000-node graph.
2. Semantic Delta Log:
   - All 5 deterministic event types: RenameSymbol, DefineStructField, BindVTableSlot,
     SetFunctionSignature, SetComment.
   - Deterministic SHA-256 proof hashes with tamper detection.
   - Integration with EvidenceLedger verifiers (VTableSlotVerifier, FieldDisplacementVerifier).
   - Git-mergeable append-only .ghidra-delta.jsonl loading, appending, and deduplication.
   - Cumulative state projection.
3. Cross-Binary Auto-Replay & Migration Engine:
   - Function pairing via BatchedBinaryMatcher across synthetic stripped binaries.
   - Event translation (addresses, symbols) from Binary A -> Binary B.
   - Re-verification of structural invariants on target binary.
   - Migration report generation and target delta log emission.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest

# Ensure current directory is on sys.path
CURRENT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from superghidra.core.dependency_cache_dag import (
    DecompilationLRUCache,
    DependencyCacheDAG,
    generate_synthetic_dependency_dag,
)
from superghidra.diff.binary_diff_engine import (
    generate_paired_synthetic_binaries,
)
from superghidra.diff.semantic_delta_log import (
    CommentType,
    DeltaEventType,
    DeltaMigrationEngine,
    SemanticDeltaLog,
    SemanticEvent,
)


class TestDependencyCacheDAG(unittest.TestCase):
    """Unit and retention tests for the Dependency Cache DAG & Selective Invalidation Engine."""

    def setUp(self):
        self.dag = DependencyCacheDAG(cache_capacity=100)

    def test_basic_dag_indexing(self):
        """Verifies caller <-> callee bidirectional indexing and type usage."""
        self.dag.add_function("func_main", address=0x1000, name="main")
        self.dag.add_function("func_helper", address=0x1100, name="helper")
        self.dag.add_function("func_leaf", address=0x1200, name="leaf")

        # main -> helper -> leaf
        self.dag.add_call_edge("func_main", "func_helper")
        self.dag.add_call_edge("func_helper", "func_leaf")

        # Caller/Callee checks
        self.assertEqual(self.dag.get_callees("func_main"), {"func_helper"})
        self.assertEqual(self.dag.get_callers("func_helper"), {"func_main"})
        self.assertEqual(self.dag.get_callees("func_helper"), {"func_leaf"})
        self.assertEqual(self.dag.get_callers("func_leaf"), {"func_helper"})

        # Struct and field usage
        self.dag.add_struct("Player", size=0x40)
        self.dag.add_struct_field("Player", "m_health", offset=0x10, size=4, type_name="int32_t")
        self.dag.add_struct_field("Player", "m_mana", offset=0x14, size=4, type_name="int32_t")

        self.dag.add_type_usage("func_helper", "Player", "m_health")
        self.dag.add_type_usage("func_leaf", "Player", "m_mana")

        self.assertIn("func_helper", self.dag.get_field_users("Player", "m_health"))
        self.assertNotIn("func_leaf", self.dag.get_field_users("Player", "m_health"))
        self.assertIn("func_leaf", self.dag.get_field_users("Player", "m_mana"))
        self.assertEqual(self.dag.get_type_users("Player"), {"func_helper", "func_leaf"})

    def test_lru_cache_operations(self):
        """Verifies LRU cache capacity bounds, hit/miss tracking, and eviction."""
        cache = DecompilationLRUCache(capacity=3)
        cache.put("f1", "code_f1")
        cache.put("f2", "code_f2")
        cache.put("f3", "code_f3")

        self.assertEqual(cache.size(), 3)
        self.assertEqual(cache.get("f1"), "code_f1")  # f1 now most recently used
        self.assertEqual(cache.hits, 1)

        # Inserting f4 should evict f2 (least recently used)
        cache.put("f4", "code_f4")
        self.assertEqual(cache.size(), 3)
        self.assertIsNone(cache.get("f2"))
        self.assertEqual(cache.misses, 1)
        self.assertEqual(cache.get("f1"), "code_f1")
        self.assertEqual(cache.get("f3"), "code_f3")
        self.assertEqual(cache.get("f4"), "code_f4")

    def test_selective_1hop_signature_invalidation(self):
        """
        Verifies that modifying a function signature invalidates ONLY the target
        and its direct 1-hop callers, retaining all other cached functions.
        """
        # Graph: A -> B -> C, and X -> Y
        for f in ["A", "B", "C", "X", "Y"]:
            self.dag.add_function(f)
            self.dag.cache.put(f, f"decompiled_{f}")

        self.dag.add_call_edge("A", "B")
        self.dag.add_call_edge("B", "C")
        self.dag.add_call_edge("X", "Y")

        self.assertEqual(self.dag.cache.size(), 5)

        # Invalidate C's signature
        # Affected set should be {C} + 1-hop callers {B} = {B, C}
        # A (2 hops away), X, Y must remain in cache!
        rep = self.dag.invalidate_function_signature("C", "void C(int x)")

        self.assertEqual(rep.affected_functions, {"B", "C"})
        self.assertEqual(set(rep.evicted_from_cache), {"B", "C"})
        self.assertEqual(self.dag.cache.size(), 3)
        self.assertFalse(self.dag.cache.contains("C"))
        self.assertFalse(self.dag.cache.contains("B"))
        self.assertTrue(self.dag.cache.contains("A"))
        self.assertTrue(self.dag.cache.contains("X"))
        self.assertTrue(self.dag.cache.contains("Y"))

    def test_selective_1hop_struct_field_invalidation(self):
        """
        Verifies that modifying a struct field invalidates only functions
        specifically accessing that field, keeping disjoint field users cached.
        """
        self.dag.add_struct("CombatStats", size=0x20)
        self.dag.add_struct_field("CombatStats", "damage", offset=0x0, size=4)
        self.dag.add_struct_field("CombatStats", "armor", offset=0x4, size=4)

        for fid in ["func_calc_damage", "func_apply_armor", "func_unrelated"]:
            self.dag.add_function(fid)
            self.dag.cache.put(fid, f"code_{fid}")

        self.dag.add_type_usage("func_calc_damage", "CombatStats", "damage")
        self.dag.add_type_usage("func_apply_armor", "CombatStats", "armor")

        self.assertEqual(self.dag.cache.size(), 3)

        # Invalidate field 'damage'
        rep = self.dag.invalidate_struct_field("CombatStats", "damage")

        self.assertEqual(rep.affected_functions, {"func_calc_damage"})
        self.assertFalse(self.dag.cache.contains("func_calc_damage"))
        self.assertTrue(self.dag.cache.contains("func_apply_armor"))
        self.assertTrue(self.dag.cache.contains("func_unrelated"))
        self.assertEqual(self.dag.cache.size(), 2)

    def test_large_scale_cache_retention_invariant(self):
        """
        CRITICAL RETENTION INVARIANT TEST:
        Under a realistic 1,000 function binary DAG with 2,000+ call edges and 50 structs:
        Selective 1-hop invalidations MUST retain > 98% of unaffected cached functions.
        """
        num_funcs = 1000
        dag = generate_synthetic_dependency_dag(num_functions=num_funcs, seed=123)

        self.assertEqual(dag.cache.size(), num_funcs)
        stats = dag.get_dag_stats()
        self.assertEqual(stats["num_functions"], num_funcs)
        self.assertGreater(stats["num_call_edges"], 1500)

        # 1. Test function signature invalidation
        # Pick function with ~3 callers
        target_func = "func_0100"
        rep_sig = dag.invalidate_function_signature(target_func, "int func_0100(float x)")

        # Verify retention rate > 98%
        self.assertGreaterEqual(
            rep_sig.retention_rate_pct,
            98.0,
            f"Signature invalidation retention rate was {rep_sig.retention_rate_pct:.2f}%, expected > 98%",
        )
        self.assertLessEqual(len(rep_sig.evicted_from_cache), 20)  # Evicted only target + callers
        self.assertFalse(dag.cache.contains(target_func))

        # 2. Test struct field invalidation
        rep_field = dag.invalidate_struct_field("StructType_005", "m_field_02")
        self.assertGreaterEqual(
            rep_field.retention_rate_pct,
            98.0,
            f"Field invalidation retention rate was {rep_field.retention_rate_pct:.2f}%, expected > 98%",
        )

        # 3. Test cumulative retention across 20 successive targeted invalidations
        pre_loop_size = dag.cache.size()
        for i in range(20):
            fid = f"func_{200 + i * 15:04d}"
            rep = dag.invalidate_function_signature(fid)
            self.assertGreaterEqual(rep.retention_rate_pct, 98.0)

        cum = dag.get_cumulative_metrics()
        self.assertGreaterEqual(cum["avg_retention_rate_pct"], 98.0)
        self.assertLess(cum["avg_latency_us"], 500.0)  # Sub-millisecond invalidation speed


class TestSemanticDeltaLog(unittest.TestCase):
    """Unit and integrity tests for the Git-Mergeable Semantic Delta Log."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, ".ghidra-delta.jsonl")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_event_types_and_proof_hashes(self):
        """Verifies deterministic event creation, proof hashes, and verification."""
        # 1. RenameSymbol
        evt_rename = SemanticEvent.create_rename_symbol(
            old_name="sub_10045A820",
            new_name="Player::TakeDamage",
            target_address=0x10045A820,
        )
        self.assertTrue(evt_rename.verify_proof_hash())
        self.assertEqual(evt_rename.event_type, DeltaEventType.RENAME_SYMBOL)
        self.assertEqual(evt_rename.payload["new_name"], "Player::TakeDamage")

        # 2. DefineStructField with valid displacement alignment (0x24 % 4 == 0)
        evt_field = SemanticEvent.create_define_struct_field(
            struct_name="Player",
            field_name="m_health",
            offset=0x24,
            size=4,
            type_name="uint32_t",
            instruction="ldr w1, [x22, #0x24]",
        )
        self.assertTrue(evt_field.verify_proof_hash())
        self.assertTrue(evt_field.verified)

        # 3. BindVTableSlot with valid 8-byte alignment (offset 0x38 = 7 * 8)
        evt_vtable = SemanticEvent.create_bind_vtable_slot(
            struct_name="Player",
            slot_index=7,
            function_name="Player::TakeDamage",
            slot_offset=0x38,
            function_address=0x10045A820,
            pointer_size=8,
        )
        self.assertTrue(evt_vtable.verify_proof_hash())
        self.assertTrue(evt_vtable.verified)

        # 4. SetFunctionSignature
        evt_sig = SemanticEvent.create_set_function_signature(
            function_name="Player::TakeDamage",
            return_type="int",
            parameters=[("Player*", "this"), ("int", "damage"), ("int", "source")],
            function_address=0x10045A820,
        )
        self.assertTrue(evt_sig.verify_proof_hash())
        self.assertIn("canonical_signature", evt_sig.payload)
        self.assertEqual(evt_sig.payload["canonical_signature"], "int Player::TakeDamage(Player* this, int damage, int source)")

        # 5. SetComment
        evt_comment = SemanticEvent.create_set_comment(
            comment_text="Virtual hook gate for damage processing",
            target_address=0x10045A820,
            comment_type=CommentType.PLATE,
        )
        self.assertTrue(evt_comment.verify_proof_hash())
        self.assertEqual(evt_comment.payload["comment_type"], "PLATE")

    def test_tamper_detection(self):
        """Verifies that altering event contents breaks cryptographic proof hash verification."""
        evt = SemanticEvent.create_rename_symbol(
            old_name="sub_1000",
            new_name="ValidFunction",
            target_address=0x1000,
        )
        self.assertTrue(evt.verify_proof_hash())

        # Tamper payload
        evt.payload["new_name"] = "MaliciousRename"
        self.assertFalse(evt.verify_proof_hash())

    def test_evidence_ledger_invariant_enforcement(self):
        """Verifies that invalid evidence (unaligned displacements/vtables) is detected."""
        # Unaligned vtable offset 0x37 for pointer_size 8
        evt_bad_vt = SemanticEvent.create_bind_vtable_slot(
            struct_name="Player",
            slot_index=7,
            function_name="Player::TakeDamage",
            slot_offset=0x37,  # Unaligned
            pointer_size=8,
        )
        self.assertFalse(evt_bad_vt.verified)

        # Unaligned displacement 0x25 for 4-byte load
        evt_bad_disp = SemanticEvent.create_define_struct_field(
            struct_name="Player",
            field_name="m_badField",
            offset=0x25,  # Unaligned (0x25 % 4 != 0)
            size=4,
            instruction="ldr w1, [x22, #0x25]",
        )
        self.assertFalse(evt_bad_disp.verified)

    def test_append_load_and_git_merge_simulation(self):
        """
        Tests appending to .ghidra-delta.jsonl, reloading, audit integrity,
        and git three-way branch merge deduplication.
        """
        log = SemanticDeltaLog(self.log_path)

        events_branch_a = [
            SemanticEvent.create_rename_symbol("sub_100", "FuncA", 0x100),
            SemanticEvent.create_set_comment("Comment on 100", 0x100),
        ]
        events_branch_b = [
            SemanticEvent.create_define_struct_field("Vector3", "x", 0x0, 4, "float"),
            SemanticEvent.create_define_struct_field("Vector3", "y", 0x4, 4, "float"),
        ]

        # Simulate branch A commit
        log.append_many(events_branch_a)
        self.assertEqual(len(log.events), 2)

        # Simulate branch B commit appended to the same delta log (git merge outcome)
        log.append_many(events_branch_b)
        self.assertEqual(len(log.events), 4)

        # Re-append an existing event (should be cleanly deduplicated)
        appended = log.append(events_branch_a[0])
        self.assertFalse(appended)
        self.assertEqual(len(log.events), 4)

        # Reload fresh from disk
        reloaded_log = SemanticDeltaLog(self.log_path)
        self.assertEqual(len(reloaded_log.events), 4)

        # Verify integrity
        is_intact, violations = reloaded_log.verify_integrity()
        self.assertTrue(is_intact, f"Integrity violations: {violations}")

        # Check cumulative projected state
        state = reloaded_log.project_cumulative_state()
        self.assertEqual(state["symbols_by_address"]["0x100"], "FuncA")
        self.assertIn("Vector3", state["structs"])
        self.assertIn("x", state["structs"]["Vector3"]["fields"])
        self.assertIn("y", state["structs"]["Vector3"]["fields"])


class TestCrossBinaryDeltaMigration(unittest.TestCase):
    """Verifies automated cross-binary delta migration using BinaryDiffEngine and EvidenceLedger."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.target_log_path = os.path.join(self.test_dir, ".ghidra-delta-v2.jsonl")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_cross_binary_migration_pipeline(self):
        """
        Simulates migrating annotations/renames from Binary A to stripped Binary B:
        1. Generates paired synthetic binaries (A and stripped/mutated B).
        2. Creates baseline delta log for Binary A.
        3. Runs BatchedBinaryMatcher to pair functions.
        4. Replays and migrates events to stripped Binary B.
        5. Confirms high migration success rate and valid target proof hashes.
        """
        num_funcs = 60
        bin_a, bin_b = generate_paired_synthetic_binaries(
            num_funcs=num_funcs,
            mutation_rate=0.10,
            seed=42,
        )

        # Create baseline delta events on Binary A
        baseline_events = []
        for i in range(15):
            fa = bin_a[i]
            # 1. Rename event
            baseline_events.append(
                SemanticEvent.create_rename_symbol(
                    old_name=fa.name,
                    new_name=f"Renamed_{fa.func_id}",
                    target_address=fa.address,
                )
            )
            # 2. Signature event
            baseline_events.append(
                SemanticEvent.create_set_function_signature(
                    function_name=fa.name,
                    return_type="int",
                    parameters=[("void*", "ctx"), ("uint32_t", "flags")],
                    function_address=fa.address,
                )
            )
            # 3. Comment event
            baseline_events.append(
                SemanticEvent.create_set_comment(
                    comment_text=f"Crucial logic hook for {fa.func_id}",
                    target_address=fa.address,
                    comment_type=CommentType.PRE,
                )
            )

        # Add global struct field events (platform layout)
        baseline_events.append(
            SemanticEvent.create_define_struct_field(
                struct_name="GlobalConfig",
                field_name="magic",
                offset=0x0,
                size=4,
                type_name="uint32_t",
                instruction="ldr w0, [x1]",
            )
        )
        baseline_events.append(
            SemanticEvent.create_define_struct_field(
                struct_name="GlobalConfig",
                field_name="version",
                offset=0x4,
                size=4,
                type_name="uint32_t",
                instruction="ldr w1, [x1, #0x4]",
            )
        )

        # Initialize Migration Engine and run binary diff pairing
        engine = DeltaMigrationEngine(similarity_threshold=0.75)
        diff_res = engine.run_diff_pairing(bin_a, bin_b)
        self.assertGreater(len(diff_res.matches), 0)

        # Execute migration to Binary B
        report, migrated_events = engine.migrate_events(
            baseline_events=baseline_events,
            target_log_path=self.target_log_path,
        )

        # Assertions
        self.assertGreaterEqual(
            report.migration_rate_pct,
            80.0,
            f"Expected >= 80% migration rate, got {report.migration_rate_pct:.1f}%",
        )
        self.assertGreater(report.migrated_verified_count, 0)
        self.assertEqual(report.evidence_rejected_count, 0)

        # Verify target log file was written and is valid
        self.assertTrue(os.path.exists(self.target_log_path))
        target_log = SemanticDeltaLog(self.target_log_path)
        self.assertEqual(len(target_log.events), len(migrated_events))

        # Check target log integrity
        is_intact, violations = target_log.verify_integrity()
        self.assertTrue(is_intact, f"Migrated delta log has integrity violations: {violations}")

        # Verify that migrated events target Binary B addresses (0x20000000 range)
        func_events = [e for e in migrated_events if e.target_address is not None]
        for fe in func_events:
            self.assertGreaterEqual(fe.target_address, 0x20000000)
            self.assertLess(fe.target_address, 0x30000000)


# =============================================================================
# High-Speed Benchmarking Runner
# =============================================================================

def run_performance_benchmarks():
    """Executes high-throughput stress benchmarks for DAG invalidation and delta operations."""
    print("\n" + "=" * 70)
    print(" SuperGhidra Cache DAG & Semantic Delta High-Throughput Benchmarks")
    print("=" * 70)

    # 1. DAG Invalidation Benchmark (1,000 functions)
    print("\n[*] Initializing 1,000-node Synthetic Dependency DAG...")
    t0 = time.perf_counter()
    dag = generate_synthetic_dependency_dag(num_functions=1000, seed=42)
    init_time_ms = (time.perf_counter() - t0) * 1000.0
    print(f"    Graph generated in {init_time_ms:.2f} ms")

    print("[*] Running 500 consecutive selective 1-hop invalidations...")
    t0 = time.perf_counter()
    retentions = []
    for i in range(500):
        fid = f"func_{i:04d}"
        rep = dag.invalidate_function_signature(fid, f"int {fid}(int arg)")
        retentions.append(rep.retention_rate_pct)
        # Re-insert into cache to simulate continuous decompiler workload
        dag.cache.put(fid, f"code_{fid}")

    inval_elapsed_ms = (time.perf_counter() - t0) * 1000.0
    inval_ops_sec = 500.0 / (inval_elapsed_ms / 1000.0)
    avg_retention = sum(retentions) / len(retentions)
    print(f"    Total invalidation time: {inval_elapsed_ms:.2f} ms")
    print(f"    Throughput:             {inval_ops_sec:,.0f} invalidations/sec")
    print(f"    Average retention rate: {avg_retention:.2f}% (Target: > 98.0%)")

    # 2. Semantic Delta Log Serialization & Throughput Benchmark
    print("\n[*] Benchmarking Semantic Delta Log append & read throughput (10,000 events)...")
    temp_dir = tempfile.mkdtemp()
    temp_log_file = os.path.join(temp_dir, "bench.jsonl")
    try:
        log = SemanticDeltaLog(temp_log_file)
        events = [
            SemanticEvent.create_rename_symbol(f"sub_{i:06x}", f"Func_{i:06x}", 0x100000 + i * 4)
            for i in range(10000)
        ]

        t0 = time.perf_counter()
        log.append_many(events)
        write_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        write_throughput = 10000.0 / (write_elapsed_ms / 1000.0)
        print(f"    Write 10,000 events:    {write_elapsed_ms:.2f} ms ({write_throughput:,.0f} events/sec)")

        t0 = time.perf_counter()
        read_log = SemanticDeltaLog(temp_log_file)
        read_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        read_throughput = len(read_log.events) / (read_elapsed_ms / 1000.0)
        print(f"    Read & parse 10k:       {read_elapsed_ms:.2f} ms ({read_throughput:,.0f} events/sec)")

        # Integrity verification benchmark
        t0 = time.perf_counter()
        valid, _ = read_log.verify_integrity()
        audit_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        audit_throughput = len(read_log.events) / (audit_elapsed_ms / 1000.0)
        print(f"    Cryptographic Audit:    {audit_elapsed_ms:.2f} ms ({audit_throughput:,.0f} SHA-256 proofs/sec)")
        assert valid
    finally:
        shutil.rmtree(temp_dir)

    print("\n" + "=" * 70)
    print(" Benchmarks Completed Successfully! All Invariants Verified.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    # Run Unit Tests
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestDependencyCacheDAG))
    suite.addTest(loader.loadTestsFromTestCase(TestSemanticDeltaLog))
    suite.addTest(loader.loadTestsFromTestCase(TestCrossBinaryDeltaMigration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if result.wasSuccessful():
        run_performance_benchmarks()
    else:
        sys.exit(1)
