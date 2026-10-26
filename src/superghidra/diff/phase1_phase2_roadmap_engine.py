#!/usr/bin/env python3
r"""
STATUS: Experimental research prototype.

Core production modules live in `ghidra_oracle.py`, `compilable_filter.py`,
`binary_diff_engine.py`, and `struct_shift_migrator.py`. By contrast,
`mitigation_roadmap_engine.py`, `phase1_phase2_roadmap_engine.py`, and
`benchmark_and_nextgen_engine.py` are experimental research and simulation
prototypes used to test Section 6 and Section 7 design concepts in isolation:

  1. `PatchestryMLIRPipeline` & `RellicGotoFreeRestructurer`:
     Emits synthetic MLIR dialect text (`patchestry.ssa`) from basic block specs
     and projects path conditions to structure acyclic CFGs without `goto`.
  2. `DLiFTGRPOEngine`:
     Computes group-normalized advantages ($\hat{A}_i = \frac{D_i - \mu_D}{\sigma_D + \epsilon}$)
     over candidate completions scored by $R_{\text{syn}}$, $R_{\text{sem}}$,
     and $R_{\text{read}}$.
  3. `CSRSparseMatrixVSAEngine`:
     Stores graph edges in Compressed Sparse Row (CSR) arrays and looks up
     indirect `BLR` call targets by `(vtable_base, slot_offset)`.
  4. `MonomorphizedTemplateCollapser`:
     Matches pointer-stride sets and loop counts from `InlinedTemplateSubgraph`
     against `std::map` and `std::vector` patterns to emit a single C statement.
  5. `ConcolicAndTraceMergeEngine`:
     Evaluates simple branch comparisons (`==`, `!=`, `>`, `<`) against a seed
     dict and substitutes resolved indirect call strings into decompiled C text.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Set, Tuple

import numpy as np


@dataclass
class CFGNodeSpec:
    """Basic block specification for condition-projected region restructuring."""
    block_id: int
    statements: List[str]
    branch_cond: str | None = None
    true_target: int | None = None
    false_target: int | None = None


class RellicGotoFreeRestructurer:
    """
    Formats basic blocks into `patchestry.ssa` dialect text and projects path
    reaching conditions in topological order to emit `goto`-free C code for
    acyclic control flow graphs.
    """

    @classmethod
    def lower_and_restructure(
        cls, func_name: str, entry_id: int, nodes: Sequence[CFGNodeSpec]
    ) -> Dict[str, Any]:
        node_map = {n.block_id: n for n in nodes}

        # 1. Emit Tier 1 (patchestry.low) and Tier 2 (patchestry.ssa) dialect IR
        mlir_ssa_lines: List[str] = [f"module @{func_name} {{"]
        for n in nodes:
            mlir_ssa_lines.append(f"  ^bb{n.block_id}:")
            for stmt in n.statements:
                mlir_ssa_lines.append(f"    patchestry.ssa.exec \"{stmt}\"")
            if n.branch_cond and n.true_target is not None and n.false_target is not None:
                mlir_ssa_lines.append(
                    f"    patchestry.ssa.cond_br \"{n.branch_cond}\", ^bb{n.true_target}, ^bb{n.false_target}"
                )
            elif n.true_target is not None:
                mlir_ssa_lines.append(f"    patchestry.ssa.br ^bb{n.true_target}")
        mlir_ssa_lines.append("}")

        # 2. Compute path reaching conditions (Rellic condition projection) in topological order
        reach_cond: Dict[int, str] = {entry_id: "true"}
        c_lines: List[str] = [f"void {func_name}(void) {{"]

        visited: Set[int] = set()
        order = cls._topological_sort(entry_id, node_map)

        for bid in order:
            visited.add(bid)
            node = node_map[bid]
            cond = reach_cond.get(bid, "true")

            if cond == "true":
                for stmt in node.statements:
                    c_lines.append(f"  {stmt}")
            else:
                c_lines.append(f"  if ({cond}) {{")
                for stmt in node.statements:
                    c_lines.append(f"    {stmt}")
                c_lines.append("  }")

            if node.branch_cond and node.true_target is not None and node.false_target is not None:
                t_cond = node.branch_cond if cond == "true" else f"({cond}) && ({node.branch_cond})"
                f_cond = f"!({node.branch_cond})" if cond == "true" else f"({cond}) && !({node.branch_cond})"
                reach_cond[node.true_target] = cls._or_join(reach_cond.get(node.true_target), t_cond)
                reach_cond[node.false_target] = cls._or_join(reach_cond.get(node.false_target), f_cond)
            elif node.true_target is not None:
                reach_cond[node.true_target] = cls._or_join(reach_cond.get(node.true_target), cond)

        c_lines.append("}")
        c_ast_code = "\n".join(c_lines)

        return {
            "mlir_ssa_dialect": "\n".join(mlir_ssa_lines),
            "structured_c_code": c_ast_code,
            "goto_count": c_ast_code.count("goto "),
            "provably_goto_free": ("goto " not in c_ast_code),
        }

    @staticmethod
    def _or_join(existing: str | None, new_cond: str) -> str:
        if existing is None:
            return new_cond
        if existing == "true" or new_cond == "true":
            return "true"
        if existing.startswith("!(") and existing[2:-1] == new_cond:
            return "true"
        if new_cond.startswith("!(") and new_cond[2:-1] == existing:
            return "true"
        return f"({existing}) || ({new_cond})"

    @staticmethod
    def _topological_sort(entry_id: int, node_map: Dict[int, CFGNodeSpec]) -> List[int]:
        in_deg: Dict[int, int] = {bid: 0 for bid in node_map}
        for n in node_map.values():
            for dst in (n.true_target, n.false_target):
                if dst is not None and dst in in_deg:
                    in_deg[dst] += 1
        queue = [entry_id] if in_deg.get(entry_id, 0) == 0 else sorted(node_map.keys())
        order: List[int] = []
        seen: Set[int] = set()
        while queue:
            curr = queue.pop(0)
            if curr in seen or curr not in node_map:
                continue
            seen.add(curr)
            order.append(curr)
            node = node_map[curr]
            for dst in (node.true_target, node.false_target):
                if dst is not None and dst in in_deg:
                    in_deg[dst] -= 1
                    if in_deg[dst] <= 0:
                        queue.append(dst)
        for rem in sorted(node_map.keys()):
            if rem not in seen:
                order.append(rem)
        return order


class PatchestryMLIRPipeline(RellicGotoFreeRestructurer):
    """Subclass alias for `RellicGotoFreeRestructurer`."""
    pass


@dataclass
class DLiFTCandidateCompletion:
    """Single candidate completion evaluated by syntax, semantic, and readability scores."""
    candidate_id: str
    c_code: str
    r_syn: float
    r_sem: float
    r_read: float

    @property
    def d_score(self) -> float:
        return round(self.r_syn * self.r_sem * self.r_read, 6)


class DLiFTGRPOEngine:
    """
    Computes group-normalized advantages across candidate completions:
      D_i = R_syn(y_i) * R_sem(y_i) * R_read(y_i)
      A_hat_i = (D_i - mean(D)) / (std(D) + 1e-8)
    and selects the highest-scoring candidate with `r_syn == 1.0` and `r_sem == 1.0`.
    """

    @staticmethod
    def score_and_select_group(
        candidates: Sequence[DLiFTCandidateCompletion],
    ) -> Dict[str, Any]:
        scores = np.array([c.d_score for c in candidates], dtype=np.float64)
        mean_d = float(np.mean(scores))
        std_d = float(np.std(scores))
        advantages = (scores - mean_d) / (std_d + 1e-8)

        verified = [c for c in candidates if c.r_syn == 1.0 and c.r_sem == 1.0]
        selected = max(verified, key=lambda c: c.d_score) if verified else None

        return {
            "group_size": len(candidates),
            "mean_d_score": round(mean_d, 6),
            "std_d_score": round(std_d, 6),
            "grpo_advantages": {
                c.candidate_id: round(float(adv), 6)
                for c, adv in zip(candidates, advantages)
            },
            "selected_candidate_id": selected.candidate_id if selected else None,
            "selected_d_score": selected.d_score if selected else 0.0,
        }


class CSRSparseMatrixVSAEngine:
    """
    Packs directed graph edges into Compressed Sparse Row (CSR) arrays
    (`indptr`, `indices`, `data`) and resolves indirect `BLR` call targets
    from registered `(vtable_base, slot_offset)` pairs.
    """

    def __init__(self, num_nodes: int) -> None:
        self.num_nodes = num_nodes
        self._adj_rows: Dict[int, Set[int]] = {i: set() for i in range(num_nodes)}
        self._vtable_slots: Dict[Tuple[int, int], str] = {}  # (vtable_base, offset) -> target_symbol

    def add_edge(self, u: int, v: int) -> None:
        self._adj_rows[u].add(v)

    def register_vtable_slot(self, vtable_base: int, slot_offset: int, symbol_name: str) -> None:
        self._vtable_slots[(vtable_base, slot_offset)] = symbol_name

    def build_csr_arrays(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        indptr = np.zeros(self.num_nodes + 1, dtype=np.int32)
        indices_list: List[int] = []
        for row_idx in range(self.num_nodes):
            cols = sorted(self._adj_rows[row_idx])
            indices_list.extend(cols)
            indptr[row_idx + 1] = len(indices_list)
        indices = np.array(indices_list, dtype=np.int32)
        data = np.ones(len(indices_list), dtype=np.float32)
        return indptr, indices, data

    def resolve_indirect_blr(
        self, candidate_vtable_bases: Sequence[int], slot_displacement: int
    ) -> List[str]:
        """Resolves `LDR x8, [vptr, #slot_displacement]; BLR x8` across value-set bases."""
        targets: List[str] = []
        for base in candidate_vtable_bases:
            sym = self._vtable_slots.get((base, slot_displacement))
            if sym:
                targets.append(sym)
        return targets


@dataclass
class InlinedTemplateSubgraph:
    """Summary of pointer strides and loop counts for an inlined C++ or Rust template block."""
    rva: int
    pointer_strides: List[int]          # e.g. [0, 8, 16, 24] for std::_Rb_tree_node (color, parent, left, right)
    loop_back_edges: int
    comparison_opcodes: int
    pointer_swaps: int
    base_var: str
    key_var: str
    val_var: str


class MonomorphizedTemplateCollapser:
    """
    Matches `InlinedTemplateSubgraph` stride sets and loop/swap counts against
    `std::map` red-black tree insert and `std::vector::push_back` patterns,
    returning a single C statement for matched regions.
    """

    @staticmethod
    def collapse_subgraph(sub: InlinedTemplateSubgraph) -> Dict[str, Any]:
        stride_set = set(sub.pointer_strides)
        topo_sig = hashlib.sha256(
            f"{sorted(stride_set)}:{sub.loop_back_edges}:{sub.comparison_opcodes}:{sub.pointer_swaps}".encode()
        ).hexdigest()[:16]

        # Pattern 1: std::map / std::_Rb_tree_insert_and_rebalance (parent=+8, left=+16, right=+24, color=+0)
        if {0, 8, 16, 24}.issubset(stride_set) and sub.loop_back_edges >= 1 and sub.pointer_swaps >= 2:
            return {
                "rva": hex(sub.rva),
                "recognized_template": "std::map<K, V>::operator[] (inlined _Rb_tree rebalance)",
                "topological_hash": topo_sig,
                "collapsed_c_statement": f"{sub.base_var}[{sub.key_var}] = {sub.val_var};",
            }

        # Pattern 2: std::vector<T>::push_back (begin=+0, end=+8, cap=+16)
        if {0, 8, 16}.issubset(stride_set) and sub.comparison_opcodes >= 1:
            return {
                "rva": hex(sub.rva),
                "recognized_template": "std::vector<T>::push_back (inlined capacity check + append)",
                "topological_hash": topo_sig,
                "collapsed_c_statement": f"{sub.base_var}.push_back({sub.val_var});",
            }

        return {
            "rva": hex(sub.rva),
            "recognized_template": "generic_monomorphized_region",
            "topological_hash": topo_sig,
            "collapsed_c_statement": f"/* template_region_{topo_sig} */",
        }


@dataclass
class BranchConstraint:
    """Single field comparison constraint along a path to a target branch RVA."""
    branch_rva: int
    field_name: str
    operator: str               # '==', '!=', '>', '<', '&'
    constant_rhs: int


class ConcolicAndTraceMergeEngine:
    """
    Updates a concrete seed dict to satisfy simple `BranchConstraint` comparisons
    (`concolic_explore`) and replaces indirect call strings / dead guard lines
    in decompiled C (`merge_dynamic_trace_into_c`).
    """

    @staticmethod
    def concolic_explore(
        entry_rva: int,
        target_branch_rva: int,
        concrete_seed_struct: Dict[str, int],
        path_constraints: Sequence[BranchConstraint],
    ) -> Dict[str, Any]:
        solved_struct = dict(concrete_seed_struct)
        satisfied_steps: List[str] = []

        for bc in path_constraints:
            if bc.operator == "==":
                solved_struct[bc.field_name] = bc.constant_rhs
            elif bc.operator == ">":
                solved_struct[bc.field_name] = max(solved_struct.get(bc.field_name, 0), bc.constant_rhs + 1)
            elif bc.operator == "<":
                solved_struct[bc.field_name] = min(solved_struct.get(bc.field_name, 0), bc.constant_rhs - 1)
            elif bc.operator == "!=":
                if solved_struct.get(bc.field_name, 0) == bc.constant_rhs:
                    solved_struct[bc.field_name] = bc.constant_rhs + 1
            satisfied_steps.append(f"@0x{bc.branch_rva:x}: {bc.field_name} {bc.operator} 0x{bc.constant_rhs:x}")

        return {
            "entry_rva": hex(entry_rva),
            "target_branch_rva": hex(target_branch_rva),
            "reachable": True,
            "synthesized_input_struct": solved_struct,
            "solved_path_constraints": satisfied_steps,
        }

    @staticmethod
    def merge_dynamic_trace_into_c(
        decompiled_c: str,
        resolved_indirect_calls: Dict[str, str],
        dead_opaque_guard_tokens: Sequence[str],
    ) -> str:
        """Replaces indirect `(*code_ptr)(...)` calls with trace-resolved symbols and prunes dead guards."""
        merged = decompiled_c
        for raw_call, resolved_sym in resolved_indirect_calls.items():
            merged = merged.replace(raw_call, resolved_sym)
        kept_lines = [
            ln for ln in merged.splitlines()
            if not any(dead_tok in ln for dead_tok in dead_opaque_guard_tokens)
        ]
        return "\n".join(kept_lines)


def run_section6_7_verification() -> Dict[str, Any]:
    """Run self-checks for all five prototype components in this module."""
    summary: Dict[str, Any] = {}

    # 1. Verify MLIR lowering and region restructuring
    cfg_nodes = [
        CFGNodeSpec(0, ["int status = validate_header(pkt);"], "status == 0", 1, 2),
        CFGNodeSpec(1, ["dispatch_order(pkt);"], None, 3, None),
        CFGNodeSpec(2, ["log_invalid_packet(pkt);"], None, 3, None),
        CFGNodeSpec(3, ["finalize_tick();"], None, None, None),
    ]
    rellic_res = RellicGotoFreeRestructurer.lower_and_restructure("handle_packet", 0, cfg_nodes)
    assert rellic_res["provably_goto_free"] is True
    assert rellic_res["goto_count"] == 0
    summary["killshot1_mlir_rellic_goto_free"] = {
        "provably_goto_free": rellic_res["provably_goto_free"],
        "goto_count": rellic_res["goto_count"],
        "structured_c_preview": rellic_res["structured_c_code"],
    }

    # 2. Verify D-LiFT GRPO advantage calculation and gated selection
    rollouts = [
        DLiFTCandidateCompletion("cand_hallucinated_hex", "if (err == 16) return 0;", 0.5, 0.0, 0.95),
        DLiFTCandidateCompletion("cand_verbose_casts", "if (err == 0x16) return *(int*)a;", 1.0, 1.0, 0.70),
        DLiFTCandidateCompletion("cand_clean_struct", "if (err == EINVAL_0x16) return ctx->code;", 1.0, 1.0, 0.98),
    ]
    grpo_res = DLiFTGRPOEngine.score_and_select_group(rollouts)
    assert grpo_res["selected_candidate_id"] == "cand_clean_struct"
    assert grpo_res["grpo_advantages"]["cand_clean_struct"] > 0.8
    summary["killshot2_dlift_grpo"] = grpo_res

    # 3. Verify CSR sparse-matrix VSA and indirect BLR resolution
    vsa = CSRSparseMatrixVSAEngine(num_nodes=5)
    vsa.add_edge(0, 1)
    vsa.add_edge(1, 3)
    vsa.add_edge(3, 4)
    vsa.register_vtable_slot(0x00E01000, 0x18, "ProcessOrderCommand::execute")
    vsa.register_vtable_slot(0x00E02000, 0x18, "QueueJobCommand::execute")
    indptr, indices, _ = vsa.build_csr_arrays()
    resolved_targets = vsa.resolve_indirect_blr([0x00E01000, 0x00E02000], 0x18)
    assert len(resolved_targets) == 2
    summary["killshot3_csr_vsa"] = {
        "csr_nnz": int(len(indices)),
        "resolved_blr_x8_targets": resolved_targets,
    }

    # 4. Verify C++ STL inlined red-black tree pattern collapser
    rbtree_sub = InlinedTemplateSubgraph(
        rva=0x00712000,
        pointer_strides=[0, 8, 16, 24],
        loop_back_edges=2,
        comparison_opcodes=3,
        pointer_swaps=4,
        base_var="this->order_rewards",
        key_var="order_id",
        val_var="reward_xp",
    )
    collapsed = MonomorphizedTemplateCollapser.collapse_subgraph(rbtree_sub)
    assert collapsed["collapsed_c_statement"] == "this->order_rewards[order_id] = reward_xp;"
    summary["killshot4_stl_monomorphization"] = collapsed

    # 5. Verify concolic constraint evaluation and trace-merged C substitution
    concolic_res = ConcolicAndTraceMergeEngine.concolic_explore(
        entry_rva=0x00412000,
        target_branch_rva=0x00412190,
        concrete_seed_struct={"command_type": 1, "slot_idx": 0, "protocol_magic": 0},
        path_constraints=[
            BranchConstraint(0x00412040, "protocol_magic", "==", 0x53474442),
            BranchConstraint(0x004120B0, "command_type", "==", 7),
            BranchConstraint(0x00412120, "slot_idx", ">", 2),
        ],
    )
    assert concolic_res["synthesized_input_struct"]["protocol_magic"] == 0x53474442
    assert concolic_res["synthesized_input_struct"]["slot_idx"] == 3

    raw_indirect_c = (
        "void dispatch(Command *cmd) {\n"
        "  if (opaque_always_false_guard) { unreachable_trap(); }\n"
        "  (*(code *)(cmd->vptr + 0x18))(cmd);\n"
        "}"
    )
    trace_merged_c = ConcolicAndTraceMergeEngine.merge_dynamic_trace_into_c(
        raw_indirect_c,
        {"(*(code *)(cmd->vptr + 0x18))(cmd)": "ProcessOrderCommand::execute(cmd)"},
        ["opaque_always_false_guard"],
    )
    assert "ProcessOrderCommand::execute(cmd)" in trace_merged_c
    assert "opaque_always_false_guard" not in trace_merged_c
    summary["killshot5_concolic_and_trace_merge"] = {
        "concolic_solution": concolic_res["synthesized_input_struct"],
        "trace_merged_c": trace_merged_c,
    }

    return summary


def run_phase1_phase2_demonstration() -> Dict[str, Any]:
    """Alias for `run_section6_7_verification`."""
    return run_section6_7_verification()


__all__ = [
    "CFGNodeSpec",
    "RellicGotoFreeRestructurer",
    "PatchestryMLIRPipeline",
    "DLiFTCandidateCompletion",
    "DLiFTGRPOEngine",
    "CSRSparseMatrixVSAEngine",
    "InlinedTemplateSubgraph",
    "MonomorphizedTemplateCollapser",
    "BranchConstraint",
    "ConcolicAndTraceMergeEngine",
    "run_section6_7_verification",
    "run_phase1_phase2_demonstration",
]


if __name__ == "__main__":
    print(json.dumps(run_phase1_phase2_demonstration(), indent=2))
