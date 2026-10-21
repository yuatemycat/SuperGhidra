"""
Unit and Integration Test Suite for Sections 6 & 7: Phase 1 Parity & Phase 2 Next-Gen Kill-Shots Engine
(tests/diff/test_phase1_phase2_roadmap_engine.py)

Comprehensive test coverage for:
1. Backward-compatibility shims and package exports (superghidra.diff.__init__).
2. Kill-Shot 1: MLIR dialect tiered lowering and Rellic region-based restructuring (provably goto-free).
3. Kill-Shot 2: D-LiFT GRPO advantage computation and multi-candidate selection gate.
4. Kill-Shot 3: CSR sparse-matrix whole-binary VSA and indirect BLR x8 resolution.
5. Kill-Shot 4: Zero-heuristic C++ STL & Rust monomorphized template recognition & collapsing.
6. Kill-Shot 5: Concolic path exploration and trace-merged dynamic decompilation.
7. End-to-end demonstration verification suite.
"""

from __future__ import annotations

import math
import os
import sys
import unittest

import numpy as np

SUPERGHIDRA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)

from superghidra.diff import (
    BranchConstraint,
    CFGNodeSpec,
    ConcolicAndTraceMergeEngine,
    CSRSparseMatrixVSAEngine,
    DLiFTCandidateCompletion,
    DLiFTGRPOEngine,
    InlinedTemplateSubgraph,
    MonomorphizedTemplateCollapser,
    PatchestryMLIRPipeline,
    RellicGotoFreeRestructurer,
    run_phase1_phase2_demonstration,
    run_section6_7_verification,
)


class TestShimsAndExports(unittest.TestCase):
    """Verifies module loading, root shims, and package exports."""

    def test_direct_import_from_diff_package(self) -> None:
        import superghidra.diff as diff_pkg
        self.assertTrue(hasattr(diff_pkg, "RellicGotoFreeRestructurer"))
        self.assertTrue(hasattr(diff_pkg, "PatchestryMLIRPipeline"))
        self.assertTrue(hasattr(diff_pkg, "DLiFTGRPOEngine"))
        self.assertTrue(hasattr(diff_pkg, "CSRSparseMatrixVSAEngine"))
        self.assertTrue(hasattr(diff_pkg, "MonomorphizedTemplateCollapser"))
        self.assertTrue(hasattr(diff_pkg, "ConcolicAndTraceMergeEngine"))
        self.assertTrue(hasattr(diff_pkg, "run_phase1_phase2_demonstration"))

    def test_root_shims_import(self) -> None:
        import phase1_phase2_roadmap_engine as root_shim1

        self.assertIs(root_shim1.RellicGotoFreeRestructurer, RellicGotoFreeRestructurer)
        self.assertIs(root_shim1.CSRSparseMatrixVSAEngine, CSRSparseMatrixVSAEngine)


class TestKillShot1MLIRAndRellic(unittest.TestCase):
    """Tests Kill-Shot 1: MLIR dialect lowering & Rellic goto-free restructuring."""

    def test_simple_diamond_goto_free_restructuring(self) -> None:
        cfg_nodes = [
            CFGNodeSpec(0, ["int status = validate_header(pkt);"], "status == 0", 1, 2),
            CFGNodeSpec(1, ["dispatch_truck_order(pkt);"], None, 3, None),
            CFGNodeSpec(2, ["log_invalid_packet(pkt);"], None, 3, None),
            CFGNodeSpec(3, ["finalize_tick();"], None, None, None),
        ]
        res = RellicGotoFreeRestructurer.lower_and_restructure("handle_packet", 0, cfg_nodes)

        self.assertTrue(res["provably_goto_free"])
        self.assertEqual(res["goto_count"], 0)
        self.assertIn("module @handle_packet {", res["mlir_ssa_dialect"])
        self.assertIn("patchestry.ssa.cond_br \"status == 0\", ^bb1, ^bb2", res["mlir_ssa_dialect"])
        self.assertIn("void handle_packet(void) {", res["structured_c_code"])
        self.assertIn("dispatch_truck_order(pkt);", res["structured_c_code"])
        self.assertIn("log_invalid_packet(pkt);", res["structured_c_code"])
        self.assertIn("finalize_tick();", res["structured_c_code"])

    def test_patchestry_mlir_pipeline_alias(self) -> None:
        cfg_nodes = [
            CFGNodeSpec(0, ["uint32_t x = read_reg();"], "x != 0", 1, 2),
            CFGNodeSpec(1, ["handle_active();"], None, None, None),
            CFGNodeSpec(2, ["handle_idle();"], None, None, None),
        ]
        res = PatchestryMLIRPipeline.lower_and_restructure("dispatch_state", 0, cfg_nodes)
        self.assertTrue(res["provably_goto_free"])
        self.assertEqual(res["goto_count"], 0)

    def test_or_join_logic(self) -> None:
        join = RellicGotoFreeRestructurer._or_join
        self.assertEqual(join(None, "cond1"), "cond1")
        self.assertEqual(join("true", "cond1"), "true")
        self.assertEqual(join("cond1", "true"), "true")
        self.assertEqual(join("!(x == 0)", "x == 0"), "true")
        self.assertEqual(join("x == 0", "!(x == 0)"), "true")
        self.assertEqual(join("condA", "condB"), "(condA) || (condB)")

    def test_topological_sort(self) -> None:
        node_map = {
            0: CFGNodeSpec(0, [], "c", 1, 2),
            1: CFGNodeSpec(1, [], None, 3, None),
            2: CFGNodeSpec(2, [], None, 3, None),
            3: CFGNodeSpec(3, [], None, None, None),
        }
        order = RellicGotoFreeRestructurer._topological_sort(0, node_map)
        self.assertEqual(order[0], 0)
        self.assertEqual(order[-1], 3)
        self.assertEqual(set(order), {0, 1, 2, 3})


class TestKillShot2DLiFTGRPO(unittest.TestCase):
    """Tests Kill-Shot 2: D-LiFT GRPO advantage computation and gated selection."""

    def test_d_score_computation(self) -> None:
        cand = DLiFTCandidateCompletion("test_cand", "code", r_syn=1.0, r_sem=0.8, r_read=0.9)
        expected = round(1.0 * 0.8 * 0.9, 6)
        self.assertAlmostEqual(cand.d_score, expected, places=5)

    def test_grpo_advantage_and_selection(self) -> None:
        rollouts = [
            DLiFTCandidateCompletion("cand_hallucinated", "int x = 1;", 0.5, 0.0, 0.95),
            DLiFTCandidateCompletion("cand_verbose", "int x = 2;", 1.0, 1.0, 0.70),
            DLiFTCandidateCompletion("cand_clean", "int x = 3;", 1.0, 1.0, 0.98),
        ]
        res = DLiFTGRPOEngine.score_and_select_group(rollouts)

        self.assertEqual(res["group_size"], 3)
        self.assertEqual(res["selected_candidate_id"], "cand_clean")
        self.assertAlmostEqual(res["selected_d_score"], 0.98, places=4)
        advs = res["grpo_advantages"]
        # Top candidate must have positive advantage and exceed verbose
        self.assertGreater(advs["cand_clean"], advs["cand_verbose"])
        self.assertGreater(advs["cand_clean"], 0.0)
        self.assertLess(advs["cand_hallucinated"], 0.0)

    def test_grpo_selection_no_verified(self) -> None:
        rollouts = [
            DLiFTCandidateCompletion("fail1", "bad code 1", 0.0, 0.0, 0.9),
            DLiFTCandidateCompletion("fail2", "bad code 2", 1.0, 0.0, 0.8),
        ]
        res = DLiFTGRPOEngine.score_and_select_group(rollouts)
        self.assertIsNone(res["selected_candidate_id"])
        self.assertEqual(res["selected_d_score"], 0.0)


class TestKillShot3CSRSparseMatrixVSA(unittest.TestCase):
    """Tests Kill-Shot 3: Compressed Sparse Row (CSR) VSA & indirect BLR x8 resolution."""

    def test_csr_array_construction(self) -> None:
        vsa = CSRSparseMatrixVSAEngine(num_nodes=4)
        vsa.add_edge(0, 1)
        vsa.add_edge(0, 2)
        vsa.add_edge(1, 3)
        vsa.add_edge(2, 3)

        indptr, indices, data = vsa.build_csr_arrays()
        self.assertEqual(len(indptr), 5)
        self.assertEqual(indptr[0], 0)
        self.assertEqual(indptr[1], 2)  # row 0 has 2 neighbors
        self.assertEqual(indptr[4], 4)  # total 4 edges
        self.assertEqual(len(indices), 4)
        self.assertEqual(len(data), 4)
        self.assertTrue(np.all(data == 1.0))

    def test_indirect_blr_resolution(self) -> None:
        vsa = CSRSparseMatrixVSAEngine(num_nodes=6)
        vtable_a = 0x00E01000
        vtable_b = 0x00E02000
        vtable_c = 0x00E03000

        vsa.register_vtable_slot(vtable_a, 0x18, "CmdDeliver::execute")
        vsa.register_vtable_slot(vtable_b, 0x18, "CmdTrainUnit::execute")
        vsa.register_vtable_slot(vtable_c, 0x20, "CmdBuildStructure::render")

        # Query offset 0x18 across vtable A and B
        res_0x18 = vsa.resolve_indirect_blr([vtable_a, vtable_b], 0x18)
        self.assertEqual(res_0x18, ["CmdDeliver::execute", "CmdTrainUnit::execute"])

        # Query offset 0x20 across vtable A, B, and C
        res_0x20 = vsa.resolve_indirect_blr([vtable_a, vtable_b, vtable_c], 0x20)
        self.assertEqual(res_0x20, ["CmdBuildStructure::render"])

        # Query non-existent offset
        res_empty = vsa.resolve_indirect_blr([vtable_a], 0x90)
        self.assertEqual(res_empty, [])


class TestKillShot4MonomorphizedTemplates(unittest.TestCase):
    """Tests Kill-Shot 4: Monomorphized C++ STL & Rust template collapse."""

    def test_std_map_red_black_tree_collapse(self) -> None:
        sub = InlinedTemplateSubgraph(
            rva=0x00712000,
            pointer_strides=[0, 8, 16, 24],
            loop_back_edges=2,
            comparison_opcodes=3,
            pointer_swaps=4,
            base_var="this->orders",
            key_var="id",
            val_var="quantity",
        )
        res = MonomorphizedTemplateCollapser.collapse_subgraph(sub)
        self.assertEqual(res["rva"], "0x712000")
        self.assertIn("std::map", res["recognized_template"])
        self.assertEqual(res["collapsed_c_statement"], "this->orders[id] = quantity;")

    def test_std_vector_push_back_collapse(self) -> None:
        sub = InlinedTemplateSubgraph(
            rva=0x00713000,
            pointer_strides=[0, 8, 16],
            loop_back_edges=0,
            comparison_opcodes=2,
            pointer_swaps=0,
            base_var="this->items",
            key_var="",
            val_var="new_item",
        )
        res = MonomorphizedTemplateCollapser.collapse_subgraph(sub)
        self.assertEqual(res["rva"], "0x713000")
        self.assertIn("std::vector", res["recognized_template"])
        self.assertEqual(res["collapsed_c_statement"], "this->items.push_back(new_item);")

    def test_generic_fallback_template(self) -> None:
        sub = InlinedTemplateSubgraph(
            rva=0x00714000,
            pointer_strides=[0, 4],
            loop_back_edges=0,
            comparison_opcodes=0,
            pointer_swaps=0,
            base_var="custom",
            key_var="",
            val_var="",
        )
        res = MonomorphizedTemplateCollapser.collapse_subgraph(sub)
        self.assertEqual(res["recognized_template"], "generic_monomorphized_region")
        self.assertTrue(res["collapsed_c_statement"].startswith("/* template_region_"))


class TestKillShot5ConcolicAndTraceMerge(unittest.TestCase):
    """Tests Kill-Shot 5: Concolic exploration & trace-merged decompilation."""

    def test_concolic_exploration_constraint_solving(self) -> None:
        constraints = [
            BranchConstraint(0x00412040, "magic", "==", 0x53474442),
            BranchConstraint(0x004120B0, "op_code", "==", 7),
            BranchConstraint(0x00412100, "count", ">", 10),
            BranchConstraint(0x00412120, "max_limit", "<", 100),
            BranchConstraint(0x00412140, "forbidden", "!=", 0),
        ]
        seed = {"magic": 0, "op_code": 1, "count": 5, "max_limit": 200, "forbidden": 0}
        res = ConcolicAndTraceMergeEngine.concolic_explore(
            entry_rva=0x00412000,
            target_branch_rva=0x00412150,
            concrete_seed_struct=seed,
            path_constraints=constraints,
        )
        solved = res["synthesized_input_struct"]
        self.assertEqual(solved["magic"], 0x53474442)
        self.assertEqual(solved["op_code"], 7)
        self.assertGreater(solved["count"], 10)
        self.assertLess(solved["max_limit"], 100)
        self.assertNotEqual(solved["forbidden"], 0)
        self.assertEqual(len(res["solved_path_constraints"]), 5)

    def test_merge_dynamic_trace_into_c(self) -> None:
        raw_c = (
            "void worker(Task *t) {\n"
            "  if (opaque_always_zero_guard) { trap(); }\n"
            "  (*(code *)(t->vtable + 0x10))(t);\n"
            "  if (bogus_branch_check) { abort(); }\n"
            "}"
        )
        resolved_calls = {"(*(code *)(t->vtable + 0x10))(t)": "TaskProcess::execute(t)"}
        dead_guards = ["opaque_always_zero_guard", "bogus_branch_check"]

        clean_c = ConcolicAndTraceMergeEngine.merge_dynamic_trace_into_c(raw_c, resolved_calls, dead_guards)
        self.assertIn("TaskProcess::execute(t);", clean_c)
        self.assertNotIn("opaque_always_zero_guard", clean_c)
        self.assertNotIn("bogus_branch_check", clean_c)


class TestFullEndToEndDemonstration(unittest.TestCase):
    """Tests full end-to-end demonstration verification run."""

    def test_run_phase1_phase2_demonstration(self) -> None:
        summary = run_phase1_phase2_demonstration()
        self.assertIn("killshot1_mlir_rellic_goto_free", summary)
        self.assertIn("killshot2_dlift_grpo", summary)
        self.assertIn("killshot3_csr_vsa", summary)
        self.assertIn("killshot4_stl_monomorphization", summary)
        self.assertIn("killshot5_concolic_and_trace_merge", summary)

        self.assertTrue(summary["killshot1_mlir_rellic_goto_free"]["provably_goto_free"])
        self.assertEqual(summary["killshot1_mlir_rellic_goto_free"]["goto_count"], 0)
        self.assertEqual(summary["killshot2_dlift_grpo"]["selected_candidate_id"], "cand_clean_struct")
        self.assertEqual(len(summary["killshot3_csr_vsa"]["resolved_blr_x8_targets"]), 2)
        self.assertIn("std::map", summary["killshot4_stl_monomorphization"]["recognized_template"])
        self.assertEqual(
            summary["killshot5_concolic_and_trace_merge"]["concolic_solution"]["protocol_magic"],
            0x53474442,
        )

    def test_run_section6_7_verification_alias(self) -> None:
        summary = run_section6_7_verification()
        self.assertEqual(summary["killshot2_dlift_grpo"]["selected_candidate_id"], "cand_clean_struct")


if __name__ == "__main__":
    unittest.main()
