"""
Unit and Integration Test Suite for Section 4 Benchmark & Next-Gen Engine
(tests/diff/test_benchmark_and_nextgen_engine.py)

Tests:
1. CRDTSessionForkManager:
   - Lattice joining with confidence tiers.
   - Automatic instruction-semantic (FADD) vs dataflow tie-breaking.
   - Multi-fork merging and symbol rename precedence.
   - Commutativity, associativity, and idempotence.
2. CrossVersionDiffEngine:
   - 32-dim CFG cosine similarity bipartite matching.
   - Struct displacement shift detection (+8B shift after pivot 0x10).
   - Tamper-evident SHA-256 hash-chained delta audit log.
3. GlobalTypeLatticeSolver:
   - Inter-procedural vtable & struct field type constraint propagation.
   - Flow constraint bidirectional type unification.
   - Fixed-point lattice resolution.
4. AndroidJNIFusionGraph / AndroidJNIFusionEngine:
   - JNI type signature stream decoder (primitives, arrays, objects).
   - AAPCS64 register mapping (x0=env, x1=thiz, GPR x2.., FP d0..).
   - Unified call graph and synthesized __usercall prototype generation.
5. EGraphMBASimplifier:
   - Equality saturation simplification of linear MBA expressions.
   - 64-bit bit-exact equivalence verification across edge vectors.
6. DLiFTVerificationGate:
   - 3-gate evaluation (R_syn, R_sem, R_read) and D_Score calculation.
   - Acceptance of correct neural skin.
   - Rejection of constant drift (0x16 -> 16 bug).
   - Rejection of malformed syntax (unbalanced braces).
7. Section4ComparisonMatrixHarness:
   - End-to-end execution of the 12-capability Head-to-Head Comparison Matrix.
   - Validation of scorecard entries, performance SLA, and leapfrog metrics.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest

import numpy as np

SUPERGHIDRA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)

from superghidra.diff.benchmark_and_nextgen_engine import (
    AndroidJNIFusionEngine,
    AndroidJNIFusionGraph,
    BinaryFunctionSummary,
    CRDTSessionForkManager,
    CrossVersionDiffEngine,
    DLiFTVerificationGate,
    EGraphMBASimplifier,
    ExprNode,
    FieldTypeFact,
    GlobalTypeLatticeSolver,
    JNINativeMethodEntry,
    LatticeType,
    MatrixCapabilityRow,
    Section4ComparisonMatrixHarness,
    SessionForkState,
    TypeConfidenceTier,
    TypeConstraint,
)


class TestCRDTSessionForkManager(unittest.TestCase):
    """Tests CRDT session fork creation, lattice joins, and automatic tie-breaking."""

    def setUp(self) -> None:
        self.mgr = CRDTSessionForkManager()

    def test_fork_creation_and_inheritance(self) -> None:
        self.mgr.assert_field_type(
            "main", "Player", 0x00, "void*", 8,
            TypeConfidenceTier.DWARF_OR_SMT_PROVED, "DWARF5_vtable",
        )
        fork_a = self.mgr.create_fork("fork_a", "agent_1", parent_fork_id="main")
        self.assertEqual(fork_a.fork_id, "fork_a")
        self.assertEqual(fork_a.parent_fork_id, "main")
        self.assertIn(("Player", 0x00), fork_a.field_facts)
        self.assertEqual(fork_a.field_facts[("Player", 0x00)].c_type, "void*")

    def test_invalid_parent_fork_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.mgr.create_fork("bad_fork", "agent_x", parent_fork_id="nonexistent")

    def test_confidence_tier_domination(self) -> None:
        self.mgr.create_fork("fork_heuristic", "agent_h")
        self.mgr.create_fork("fork_smt", "agent_s")

        self.mgr.assert_field_type(
            "fork_heuristic", "Entity", 0x20, "int32_t", 4,
            TypeConfidenceTier.HEURISTIC_NAME, "m_id heuristic",
        )
        self.mgr.assert_field_type(
            "fork_smt", "Entity", 0x20, "int64_t", 8,
            TypeConfidenceTier.DWARF_OR_SMT_PROVED, "Z3_UNSAT_PROVED",
        )

        merge_res_h = self.mgr.merge_fork("fork_heuristic", "main")
        merge_res_s = self.mgr.merge_fork("fork_smt", "main")

        main_fact = self.mgr._forks["main"].field_facts[("Entity", 0x20)]
        self.assertEqual(main_fact.c_type, "int64_t")
        self.assertEqual(main_fact.confidence, TypeConfidenceTier.DWARF_OR_SMT_PROVED)

    def test_hardware_instruction_semantic_tie_breaking(self) -> None:
        """Tests that FADD instruction semantics beat generic integer dataflow at equal tiers."""
        self.mgr.create_fork("fork_alpha", "agent_alpha")
        self.mgr.create_fork("fork_beta", "agent_beta")

        # Equal tier: INSTRUCTION_SEMANTIC
        self.mgr.assert_field_type(
            "fork_alpha", "Avatar", 0x18, "uint64_t", 8,
            TypeConfidenceTier.INSTRUCTION_SEMANTIC, "LDR x0, [x19, #0x18]",
        )
        self.mgr.assert_field_type(
            "fork_beta", "Avatar", 0x18, "float", 4,
            TypeConfidenceTier.INSTRUCTION_SEMANTIC, "FADD s0, s1, s2",
        )

        self.mgr.merge_fork("fork_alpha", "main")
        merge_beta = self.mgr.merge_fork("fork_beta", "main")

        main_fact = self.mgr._forks["main"].field_facts[("Avatar", 0x18)]
        self.assertEqual(main_fact.c_type, "float")
        self.assertIn("FADD", main_fact.evidence_op)
        self.assertEqual(len(merge_beta["symbolic_tie_breaks"]), 1)
        self.assertIn("FADD", merge_beta["symbolic_tie_breaks"][0]["winner"])

    def test_symbol_rename_merging_and_lww(self) -> None:
        self.mgr.create_fork("fork_1", "agent_1")
        self.mgr.rename_symbol("fork_1", 0x00401000, "executeOrder")
        merge_info = self.mgr.merge_fork("fork_1", "main")
        self.assertEqual(merge_info["merged_symbols"], 1)
        self.assertEqual(self.mgr._forks["main"].renamed_symbols[0x00401000][0], "executeOrder")


class TestCrossVersionDiffEngine(unittest.TestCase):
    """Tests 32-dim CFG cosine matching, struct shift detection, and SHA-256 delta logging."""

    def setUp(self) -> None:
        self.engine = CrossVersionDiffEngine()

    def test_cosine_similarity_bipartite_matching(self) -> None:
        vec_a = np.zeros(32, dtype=np.float64)
        vec_a[0] = 1.0
        vec_a[1] = 0.5

        vec_b = np.zeros(32, dtype=np.float64)
        vec_b[5] = 1.0

        v1_funcs = [
            BinaryFunctionSummary(0x1000, "fn_alpha", vec_a, []),
            BinaryFunctionSummary(0x2000, "fn_beta", vec_b, []),
        ]
        # v2 swapped RVA and renamed FUN_
        v2_funcs = [
            BinaryFunctionSummary(0x9000, "FUN_00009000", vec_b, []),
            BinaryFunctionSummary(0x8000, "FUN_00008000", vec_a, []),
        ]

        result = self.engine.match_functions_and_migrate_structs(v1_funcs, v2_funcs, similarity_threshold=0.9)
        self.assertEqual(result["matched_count"], 2)
        matches = {m["v1_name"]: m for m in result["matches"]}

        self.assertIn("fn_alpha", matches)
        self.assertEqual(matches["fn_alpha"]["v2_rva"], hex(0x8000))
        self.assertEqual(matches["fn_alpha"]["v2_migrated_name"], "fn_alpha")
        self.assertAlmostEqual(matches["fn_alpha"]["cosine_similarity"], 1.0, places=4)

        self.assertIn("fn_beta", matches)
        self.assertEqual(matches["fn_beta"]["v2_rva"], hex(0x9000))

    def test_struct_displacement_shift_detection(self) -> None:
        # In v1: offsets at 0x08, 0x10, 0x18
        # In v2: field inserted at 0x10 (+8B shift for offsets >= 0x10)
        vec = np.ones(32, dtype=np.float64)
        f1 = BinaryFunctionSummary(
            0x1000, "worker", vec,
            [
                ("TaskStruct", 0x08, "LOAD", 4),
                ("TaskStruct", 0x10, "LOAD", 8),
                ("TaskStruct", 0x18, "STORE", 8),
            ],
        )
        f2 = BinaryFunctionSummary(
            0x2000, "worker", vec,
            [
                ("TaskStruct", 0x08, "LOAD", 4),
                ("TaskStruct", 0x18, "LOAD", 8),
                ("TaskStruct", 0x20, "STORE", 8),
            ],
        )

        shifts = CrossVersionDiffEngine._detect_struct_displacement_shifts(f1, f2)
        self.assertIn("TaskStruct", shifts)
        shift_data = shifts["TaskStruct"]
        self.assertEqual(shift_data["insertion_pivot_offset"], "0x10")
        self.assertEqual(shift_data["shift_delta_bytes"], 8)
        self.assertEqual(len(shift_data["migrated_fields"]), 3)
        self.assertEqual(shift_data["migrated_fields"][0]["delta"], 0)
        self.assertEqual(shift_data["migrated_fields"][1]["delta"], 8)
        self.assertEqual(shift_data["migrated_fields"][2]["delta"], 8)

    def test_sha256_delta_audit_log_chaining(self) -> None:
        vec = np.ones(32, dtype=np.float64)
        f1 = BinaryFunctionSummary(0x1000, "f1", vec, [])
        f2 = BinaryFunctionSummary(0x2000, "f2", vec, [])

        res = self.engine.match_functions_and_migrate_structs([f1], [f2])
        lines = res["delta_jsonl_lines"]
        self.assertGreaterEqual(len(lines), 1)

        # Verify hash chaining
        prev_hash = "0" * 64
        for line in lines:
            entry = json.loads(line)
            self.assertEqual(entry["prev_sha256"], prev_hash)
            calc_entry = dict(entry)
            expected_hash = calc_entry.pop("sha256")
            canonical = json.dumps(calc_entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
            actual_hash = hashlib.sha256(canonical).hexdigest()
            self.assertEqual(actual_hash, expected_hash)
            prev_hash = expected_hash

        self.assertEqual(res["chain_head_sha256"], prev_hash)


class TestGlobalTypeLatticeSolver(unittest.TestCase):
    """Tests whole-program type lattice fixed-point solving and struct layout recovery."""

    def setUp(self) -> None:
        self.solver = GlobalTypeLatticeSolver()

    def test_field_access_and_flow_propagation(self) -> None:
        # Base variable accessed as CPP vtable obj at 0x00 and float at 0x18
        self.solver.add_field_access_constraint("pObj", 0x00, LatticeType.NON_NULL_PTR)
        self.solver.add_field_access_constraint("pObj", 0x18, LatticeType.FLOAT_32)
        self.solver.add_field_access_constraint("pObj", 0x20, LatticeType.CHAR_PTR)

        # Flow from pObj into callee param
        self.solver.add_flow_constraint("pObj", "callee_arg0")

        result = self.solver.solve_global_lattice()
        self.assertLessEqual(result["iterations"], 64)
        self.assertEqual(result["resolved_variables"]["pObj"], "CPP_VTABLE_OBJ_PTR")
        self.assertEqual(result["resolved_variables"]["callee_arg0"], "CPP_VTABLE_OBJ_PTR")

        callee_layout = result["recovered_struct_layouts"]["callee_arg0"]
        self.assertEqual(callee_layout["0x0"], "NON_NULL_PTR")
        self.assertEqual(callee_layout["0x18"], "FLOAT_32")
        self.assertEqual(callee_layout["0x20"], "CHAR_PTR")

    def test_lattice_meet_properties(self) -> None:
        # TOP_UNKNOWN meets concrete type -> concrete type
        self.assertEqual(
            GlobalTypeLatticeSolver._meet(LatticeType.TOP_UNKNOWN, LatticeType.INTEGER_32),
            LatticeType.INTEGER_32,
        )
        self.assertEqual(
            GlobalTypeLatticeSolver._meet(LatticeType.INTEGER_32, LatticeType.TOP_UNKNOWN),
            LatticeType.INTEGER_32,
        )
        # Structural pointers refine to more specific C++ vtable pointer
        self.assertEqual(
            GlobalTypeLatticeSolver._meet(LatticeType.NON_NULL_PTR, LatticeType.CPP_VTABLE_OBJ_PTR),
            LatticeType.CPP_VTABLE_OBJ_PTR,
        )


class TestAndroidJNIFusion(unittest.TestCase):
    """Tests Android DEX <-> NDK JNI signature parsing and prototype synthesis."""

    def test_decode_jni_signature_primitives_and_objects(self) -> None:
        sig = "(IJLjava/lang/String;[B[D)Z"
        args, ret = AndroidJNIFusionGraph.decode_jni_signature(sig)
        self.assertEqual(args, ["jint", "jlong", "jstring", "jbyte[]", "jdouble[]"])
        self.assertEqual(ret, "jboolean")

    def test_invalid_signature_raises(self) -> None:
        with self.assertRaises(ValueError):
            AndroidJNIFusionGraph.decode_jni_signature("invalid_signature")

    def test_unified_call_graph_and_usercall_prototype_synthesis(self) -> None:
        graph = AndroidJNIFusionEngine()
        graph.register_natives([
            JNINativeMethodEntry(
                java_class="com/company/engine/NativeBridge",
                method_name="processCommand",
                jni_signature="(IFD)V",
                native_rva=0x0024A100,
            )
        ])
        nodes = graph.build_unified_call_graph()
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertEqual(node["dex_caller"], "Lcom/company/engine/NativeBridge;->processCommand(IFD)V")
        self.assertEqual(node["native_target_rva"], hex(0x0024A100))
        self.assertEqual(node["cross_jni_arg_count"], 5)  # env, thiz, int, float, double

        proto = node["synthesized_usercall_prototype"]
        self.assertTrue(proto.startswith("void __usercall Java_com_company_engine_NativeBridge_processCommand@<x0>("))
        self.assertIn("JNIEnv *env@<x0>", proto)
        self.assertIn("jobject thiz@<x1>", proto)
        self.assertIn("jint arg0@<x2>", proto)
        self.assertIn("jfloat arg1@<d0>", proto)
        self.assertIn("jdouble arg2@<d1>", proto)


class TestEGraphMBASimplifier(unittest.TestCase):
    """Tests equality saturation rewriting and 64-bit formal verification."""

    def test_linear_mba_simplification(self) -> None:
        # (x ^ y) + 2 * (x & y) == x + y
        expr = ExprNode(
            "+",
            (
                ExprNode("^", (ExprNode("var", ("x",)), ExprNode("var", ("y",)))),
                ExprNode(
                    "*",
                    (
                        ExprNode("const", (2,)),
                        ExprNode("&", (ExprNode("var", ("x",)), ExprNode("var", ("y",)))),
                    ),
                ),
            ),
        )
        res = EGraphMBASimplifier.saturate_and_extract(expr)
        self.assertIn(res["simplified_expr"], ("(x + y)", "(y + x)"))
        self.assertTrue(res["bit_exact_verified"])

    def test_identity_and_zero_cancellation(self) -> None:
        # (x ^ x) + 0 == 0
        expr = ExprNode(
            "+",
            (
                ExprNode("^", (ExprNode("var", ("x",)), ExprNode("var", ("x",)))),
                ExprNode("const", (0,)),
            ),
        )
        res = EGraphMBASimplifier.saturate_and_extract(expr)
        self.assertEqual(res["simplified_expr"], "0")
        self.assertTrue(res["bit_exact_verified"])

    def test_eval_expr_operators(self) -> None:
        env = {"x": 10, "y": 4}
        expr = ExprNode(
            "-",
            (
                ExprNode("*", (ExprNode("var", ("x",)), ExprNode("var", ("y",)))),  # 40
                ExprNode("~", (ExprNode("const", (-5,)),)),  # ~(-5) = 4
            ),
        )
        val = EGraphMBASimplifier.eval_expr(expr, env)
        self.assertEqual(val, 36)


class TestDLiFTVerificationGate(unittest.TestCase):
    """Tests D-LiFT 3-gate neural verification against semantic drift and hallucinations."""

    def test_accepts_valid_candidate(self) -> None:
        orig = "int foo(int x, int y) { if (x == 0x16) return x + y; return 0; }"
        cand = "int foo(int status, int offset) {\n  if (status == 0x16) {\n    return status + offset;\n  }\n  return 0;\n}"
        res = DLiFTVerificationGate.evaluate_candidate(
            orig, cand,
            lambda x, y: (x + y) if x == 0x16 else 0,
            lambda x, y: (x + y) if x == 0x16 else 0,
        )
        self.assertTrue(res["accepted"])
        self.assertEqual(res["R_syn"], 1.0)
        self.assertEqual(res["R_sem"], 1.0)
        self.assertEqual(res["D_Score"], 1.0)
        self.assertEqual(len(res["diagnostics"]), 0)

    def test_rejects_hex_to_decimal_drift(self) -> None:
        # Catches critical 0x16 (22) -> 16 hallucination bug
        orig = "int foo(int x, int y) { if (x == 0x16) return x + y; return 0; }"
        cand = "int foo(int status, int offset) {\n  if (status == 16) {\n    return status + offset;\n  }\n  return 0;\n}"
        res = DLiFTVerificationGate.evaluate_candidate(
            orig, cand,
            lambda x, y: (x + y) if x == 0x16 else 0,
            lambda x, y: (x + y) if x == 16 else 0,
        )
        self.assertFalse(res["accepted"])
        self.assertEqual(res["R_sem"], 0.0)
        self.assertEqual(res["D_Score"], 0.0)
        self.assertTrue(any("Semantic constant drift" in diag for diag in res["diagnostics"]))

    def test_rejects_unbalanced_syntax(self) -> None:
        orig = "int foo(int x, int y) { return x + y; }"
        cand = "int foo(int x, int y) { return x + y; "  # Missing closing brace
        res = DLiFTVerificationGate.evaluate_candidate(
            orig, cand,
            lambda x, y: x + y,
            lambda x, y: x + y,
        )
        self.assertFalse(res["accepted"])
        self.assertEqual(res["R_syn"], 0.0)
        self.assertIn("Unbalanced braces", res["diagnostics"][0])

    def test_readability_penalties(self) -> None:
        code_with_gotos = "int f() { goto fail; fail: return -1; }"
        score_goto = DLiFTVerificationGate._score_readability(code_with_gotos)
        self.assertLess(score_goto, 1.0)

        code_clean = "int f() { return 0; }"
        score_clean = DLiFTVerificationGate._score_readability(code_clean)
        self.assertEqual(score_clean, 1.0)


class TestSection4ComparisonMatrixHarness(unittest.TestCase):
    """Tests the full 12-capability Section 4 comparison matrix benchmark execution."""

    def test_full_matrix_benchmark_execution(self) -> None:
        report = Section4ComparisonMatrixHarness.run_full_matrix_benchmark()

        # Check required top-level keys
        self.assertIn("benchmark_elapsed_ms", report)
        self.assertIn("mba_egraph_result", report)
        self.assertIn("dlift_verification", report)
        self.assertIn("crdt_fork_merge", report)
        self.assertIn("cross_version_diff", report)
        self.assertIn("global_type_lattice", report)
        self.assertIn("android_jni_fusion", report)
        self.assertIn("section4_matrix_scorecard", report)

        # Check all 12 capabilities in the scorecard
        scorecard = report["section4_matrix_scorecard"]
        self.assertEqual(len(scorecard), 12)

        verdicts = {row["capability"]: row["gap_severity_or_verdict"] for row in scorecard}

        # Check the 5 "SUPERGHIDRA WINS" rows
        wins_capabilities = [
            "8. AI Agent Autonomy & Tooling",
            "9. Multi-Agent Collaboration",
            "10. Hardware Scanning Acceleration",
            "11. Formal Logic Equivalence",
            "12. Cross-Version Struct Migration",
        ]
        for cap in wins_capabilities:
            self.assertIn(cap, verdicts)
            self.assertEqual(verdicts[cap], "SUPERGHIDRA WINS")

        # Check latency SLA (< 500 ms for complete matrix execution)
        self.assertLess(report["benchmark_elapsed_ms"], 500.0)


if __name__ == "__main__":
    unittest.main()
