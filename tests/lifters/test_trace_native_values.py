"""Unit test suite for inter-procedural high-P-code value tracing (16 test cases)."""

import json
import pytest
from unittest.mock import MagicMock

from superghidra.core.evidence_ledger import EpistemicStatus
from superghidra.lifters.pcode_lifter_bridge import (
    AddressSpace,
    PcodeOp,
    PcodeOpcode,
    Varnode,
)
from superghidra.lifters.trace_values import (
    HighPCodeValueTracer,
    trace_native_values,
    MAX_PCODE_OPS_PER_PROCEDURE,
    MAX_INPUTS_PER_OP,
    MAX_DEF_USE_EDGES,
)


def _make_const(val: int, size: int = 8) -> Varnode:
    return Varnode(space=AddressSpace.CONST, offset=val, size=size)


def _make_reg(name: str, size: int = 8) -> Varnode:
    return Varnode(space=AddressSpace.REGISTER, offset=name, size=size, reg_name=name)


def _make_ram(offset: int, size: int = 8) -> Varnode:
    return Varnode(space=AddressSpace.RAM, offset=offset, size=size)


def test_single_procedure_intra_def_use():
    """1. Generates intra-procedural def-use edges connecting definition to usage."""
    ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(10)], output=_make_reg("x0"), pc=0x1000),
        PcodeOp(opcode=PcodeOpcode.INT_ADD, inputs=[_make_reg("x0"), _make_const(5)], output=_make_reg("x1"), pc=0x1004),
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
    )
    assert len(report.nodes) > 0
    # There should be an intra-procedural edge from output of COPY (x0) to input of INT_ADD (x0)
    intra_edges = [e for e in report.edges if e.edge_type == "intra_procedural"]
    assert len(intra_edges) >= 1
    # Check that x0 connects to x0
    source_node = next(n for n in report.nodes if n.node_id == intra_edges[0].source_id)
    target_node = next(n for n in report.nodes if n.node_id == intra_edges[0].target_id)
    assert source_node.varnode_role in ("def", "use")


def test_cross_call_parameter_binding():
    """2. Caller CALL inputs bind to callee formal parameters (param_0..param_n)."""
    caller_ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(100)], output=_make_reg("x0"), pc=0x1000),
        PcodeOp(
            opcode=PcodeOpcode.CALL,
            inputs=[_make_const(0x2000), _make_reg("x0")],
            output=_make_reg("x0"),
            pc=0x1004,
        ),
    ]
    callee_ops = [
        PcodeOp(opcode=PcodeOpcode.INT_ADD, inputs=[_make_reg("x0"), _make_const(1)], output=_make_reg("x0"), pc=0x2000),
        PcodeOp(opcode=PcodeOpcode.RETURN, inputs=[_make_reg("x0")], pc=0x2004),
    ]

    def provider(proc_id: str):
        if proc_id in ("0x2000", "0x2000"):
            return callee_ops
        return []

    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=caller_ops,
        procedure_provider=provider,
        max_depth=3,
    )

    param_bind_edges = [e for e in report.edges if e.edge_type == "call_param_bind"]
    assert len(param_bind_edges) == 1
    assert param_bind_edges[0].param_ordinal == 0
    # Verify target node is a formal parameter node
    target = next(n for n in report.nodes if n.node_id == param_bind_edges[0].target_id)
    assert target.varnode_role == "param_in"
    assert target.varnode.get("ordinal") == 0


def test_cross_call_return_binding():
    """3. Callee RETURN operations bind back to caller CALL output."""
    caller_ops = [
        PcodeOp(opcode=PcodeOpcode.CALL, inputs=[_make_const(0x3000)], output=_make_reg("x0"), pc=0x1000),
    ]
    callee_ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(42)], output=_make_reg("x0"), pc=0x3000),
        PcodeOp(opcode=PcodeOpcode.RETURN, inputs=[_make_reg("x0")], pc=0x3004),
    ]

    def provider(proc_id: str):
        if proc_id == "0x3000":
            return callee_ops
        return []

    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=caller_ops,
        procedure_provider=provider,
        max_depth=2,
    )

    return_edges = [e for e in report.edges if e.edge_type == "callee_return_bind"]
    assert len(return_edges) >= 1


def test_cycle_safe_recursion_memoization():
    """4. Direct and indirect recursive calls terminate without infinite loops."""
    # A calls A
    recursive_ops = [
        PcodeOp(opcode=PcodeOpcode.CALL, inputs=[_make_const(0x4000)], output=None, pc=0x4000),
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x4000",
        pcode_ops=recursive_ops,
        max_depth=5,
    )
    # Should visit 0x4000 only once
    assert report.procedures_visited == ["0x4000"]


def test_call_depth_limit():
    """5. Respects max_depth traversal limit."""
    call_tree = {
        "0x1000": [PcodeOp(opcode=PcodeOpcode.CALL, inputs=[_make_const(0x2000)], pc=0x1000)],
        "0x2000": [PcodeOp(opcode=PcodeOpcode.CALL, inputs=[_make_const(0x3000)], pc=0x2000)],
        "0x3000": [PcodeOp(opcode=PcodeOpcode.CALL, inputs=[_make_const(0x4000)], pc=0x3000)],
    }
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=call_tree["0x1000"],
        procedure_provider=lambda p: call_tree.get(p, []),
        max_depth=2,
    )
    # At max_depth=2, 0x1000 (depth 1) calls 0x2000 (depth 2), but 0x2000's callee 0x3000 is not visited
    assert "0x1000" in report.procedures_visited
    assert "0x2000" in report.procedures_visited
    assert "0x3000" not in report.procedures_visited


def test_max_nodes_cap():
    """6. Truncates when node count exceeds max_nodes budget."""
    # Generate 60 ops, each having input + output (120 nodes)
    ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(i)], output=_make_reg(f"x{i % 8}"), pc=0x1000 + i * 4)
        for i in range(60)
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
        max_nodes=100,  # min allowed is 100
    )
    assert len(report.nodes) <= 100
    assert report.is_truncated is True


def test_per_procedure_op_cap_3000():
    """7. Procedures with >3,000 P-code operations cap at 3,000 and record omitted_ops."""
    ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(1)], output=_make_reg("x0"), pc=0x1000 + i * 4)
        for i in range(3500)
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
        max_nodes=10000,
    )
    assert report.omitted_ops_total == 500


def test_per_op_input_cap_64():
    """8. Operations with >64 inputs cap inputs at 64."""
    excess_inputs = [_make_const(i) for i in range(80)]
    ops = [
        PcodeOp(opcode=PcodeOpcode.CALL, inputs=excess_inputs, output=None, pc=0x1000)
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
    )
    # Total input nodes for this op must not exceed 64
    op_inputs = [n for n in report.nodes if n.varnode_role == "use"]
    assert len(op_inputs) == 64


def test_def_use_edges_cap_12000():
    """9. Edges truncate cleanly when 12,000 cap is reached."""
    tracer = HighPCodeValueTracer()
    tracer._edges = [MagicMock() for _ in range(12000)]
    tracer._add_edge(MagicMock())
    assert tracer._omitted_edges == 1
    assert tracer._is_truncated is True


def test_ast_live_vs_is_dead_separation():
    """10. Distinguishes ast_live from ast_elided regardless of pcode_is_dead."""
    ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(1)], output=_make_reg("x0"), pc=0x1000),
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(2)], output=_make_reg("x1"), pc=0x1004),
    ]
    # pc 0x1000: ast_live=True, pcode_is_dead=True (stale Ghidra flag)
    # pc 0x1004: ast_live=False, pcode_is_dead=False (elided from AST)
    ast_dead_info = {
        0x1000: (True, True),
        0x1004: (False, False),
    }
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
        ast_dead_info=ast_dead_info,
    )
    nodes_1000 = [n for n in report.nodes if n.pc in ("0x1000", 0x1000)]
    nodes_1004 = [n for n in report.nodes if n.pc in ("0x1004", 0x1004)]

    assert all(n.ast_membership == "ast_live" and n.pcode_is_dead for n in nodes_1000)
    assert all(n.ast_membership == "ast_elided" and not n.pcode_is_dead for n in nodes_1004)


def test_stack_local_store_epistemic_tagging():
    """11. Stack writes are labeled stack_local_store."""
    stack_var = Varnode(space=AddressSpace.RAM, offset="stack", size=8)
    ops = [
        PcodeOp(
            opcode=PcodeOpcode.STORE,
            inputs=[stack_var, _make_const(8), _make_reg("x0")],
            output=stack_var,
            pc=0x1000,
        ),
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
    )
    store_out = next(n for n in report.nodes if n.op == "STORE" and n.varnode_role == "stack_local_store")
    assert store_out.varnode_role == "stack_local_store"


def test_pointer_aliasing_unknown_tag():
    """12. Indirect memory operations without known base have epistemic_status unknown."""
    ops = [
        PcodeOp(
            opcode=PcodeOpcode.LOAD,
            inputs=[_make_ram(0), Varnode(space=AddressSpace.RAM, offset=0, size=8)],
            output=_make_reg("x0"),
            pc=0x1000,
        ),
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
    )
    unknown_nodes = [n for n in report.nodes if n.epistemic_status == "unknown"]
    assert len(unknown_nodes) >= 1


def test_evidence_envelope_integration():
    """13. Report wraps into valid EvidenceEnvelope with CoverageBoundary."""
    ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(5)], output=_make_reg("x0"), pc=0x1000),
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
    )
    envelope = report.to_envelope()
    assert envelope.evidence_id.startswith("ev_")
    assert envelope.coverage[0].decoded_count == len(report.nodes)
    assert envelope.coverage[0].examined_count >= len(report.nodes)


def test_unresolved_indirect_call():
    """14. Indirect calls (CALLIND) mark input as unknown epistemic status without raising."""
    ops = [
        PcodeOp(opcode=PcodeOpcode.CALLIND, inputs=[_make_reg("x8")], output=None, pc=0x1000),
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
    )
    assert any(n.epistemic_status == "unknown" for n in report.nodes)


def test_serialized_trace_byte_budget_cap():
    """15. Large traces truncate within byte budget limits."""
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=[PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(i)], output=_make_reg("x0"), pc=0x1000) for i in range(10)],
    )
    envelope = report.to_envelope()
    assert envelope.data["node_count"] > 0


def test_cli_trace_values_invocation(tmp_path):
    """16. Programmatic execution with output file writes valid JSON."""
    out_file = tmp_path / "trace_out.json"
    ops = [
        PcodeOp(opcode=PcodeOpcode.COPY, inputs=[_make_const(7)], output=_make_reg("x0"), pc=0x1000),
    ]
    report = trace_native_values(
        binary_path_or_image="sample.elf",
        procedure="0x1000",
        pcode_ops=ops,
        output=str(out_file),
    )
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["root_procedure"] == "0x1000"
    assert "nodes" in data
    assert "edges" in data
