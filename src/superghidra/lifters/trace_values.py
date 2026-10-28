"""High-P-Code Inter-Procedural Def-Use Graph and Value Tracing Engine.

Composes high-P-code def-use graphs across statically resolved calls,
distinguishing AST block membership from stale decompiler is_dead flags,
binding formal parameter ordinals and return varnodes across procedures,
and enforcing strict resource and pagination bounds.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from superghidra.core.evidence_ledger import (
    CoverageBoundary,
    EpistemicStatus,
    EvidenceEnvelope,
    ReferenceProvenance,
)
from superghidra.lifters.pcode_lifter_bridge import (
    AddressSpace,
    PcodeOp,
    PcodeOpcode,
    Varnode,
)

logger = logging.getLogger(__name__)

# Strict resource bounds per specification
MAX_PCODE_OPS_PER_PROCEDURE: int = 3000
MAX_INPUTS_PER_OP: int = 64
MAX_DEF_USE_EDGES: int = 12000
MAX_NODES_DEFAULT: int = 2500
MAX_DEPTH_DEFAULT: int = 3
MAX_NODE_BYTES: int = 8 * 1024 * 1024       # 8 MiB
MAX_TRACE_BYTES: int = 32 * 1024 * 1024     # 32 MiB


@dataclasses.dataclass
class DefUseNode:
    """Represents a node in the high-P-code def-use graph."""
    node_id: str
    procedure: str
    pc: int
    op: str
    varnode_role: str  # "def", "use", "param_in", "return_out", "stack_local_store", "input"
    varnode: Dict[str, Any]
    ast_membership: str = "ast_live"  # "ast_live" | "ast_elided"
    pcode_is_dead: bool = False
    epistemic_status: str = "observed"  # "observed" | "inferred" | "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "procedure": self.procedure,
            "pc": hex(self.pc) if isinstance(self.pc, int) else str(self.pc),
            "op": self.op,
            "varnode_role": self.varnode_role,
            "varnode": self.varnode,
            "ast_membership": self.ast_membership,
            "pcode_is_dead": self.pcode_is_dead,
            "epistemic_status": self.epistemic_status,
        }


@dataclasses.dataclass
class DefUseEdge:
    """Represents a directed def-use or inter-procedural edge."""
    source_id: str
    target_id: str
    edge_type: str  # "intra_procedural", "call_param_bind", "callee_return_bind", "memory_alias"
    param_ordinal: Optional[int] = None
    epistemic_status: str = "observed"

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "epistemic_status": self.epistemic_status,
        }
        if self.param_ordinal is not None:
            res["param_ordinal"] = self.param_ordinal
        return res


@dataclasses.dataclass
class ProcedureDossier:
    """Analysis results for a single procedure."""
    procedure: str
    canonical_address: int
    ops_processed: int
    omitted_ops: int = 0
    omitted_edges: int = 0
    nodes: List[DefUseNode] = dataclasses.field(default_factory=list)
    edges: List[DefUseEdge] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ValueTraceReport:
    """Complete cross-call value tracing report."""
    binary_path: str
    root_procedure: str
    max_depth: int
    max_nodes: int
    nodes: List[DefUseNode] = dataclasses.field(default_factory=list)
    edges: List[DefUseEdge] = dataclasses.field(default_factory=list)
    procedures_visited: List[str] = dataclasses.field(default_factory=list)
    omitted_ops_total: int = 0
    omitted_edges_total: int = 0
    is_truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "binary_path": self.binary_path,
            "root_procedure": self.root_procedure,
            "max_depth": self.max_depth,
            "max_nodes": self.max_nodes,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "procedures_visited": self.procedures_visited,
            "omitted_ops_total": self.omitted_ops_total,
            "omitted_edges_total": self.omitted_edges_total,
            "is_truncated": self.is_truncated,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }
        return data

    def to_envelope(self) -> EvidenceEnvelope:
        """Wraps the trace report into a canonical EvidenceEnvelope."""
        payload = self.to_dict()
        serialized = json.dumps(payload, sort_keys=True)
        if len(serialized.encode("utf-8")) > MAX_TRACE_BYTES:
            # Enforce 32 MiB budget
            payload["nodes"] = payload["nodes"][:1000]
            payload["edges"] = payload["edges"][:2000]
            payload["is_truncated"] = True

        status = EpistemicStatus.OBSERVED
        if any(n.epistemic_status == "unknown" for n in self.nodes):
            status = EpistemicStatus.INFERRED

        import hashlib
        target_hash = hashlib.sha256(self.binary_path.encode("utf-8")).hexdigest()
        ev_id = f"ev_{hashlib.sha256((target_hash + self.root_procedure).encode('utf-8')).hexdigest()[:12]}"
        return EvidenceEnvelope(
            evidence_id=ev_id,
            target_sha256=target_hash,
            overlay_revision=0,
            epistemic_status=status,
            provenance=ReferenceProvenance.ANALYSIS,
            data=payload,
            coverage=[
                CoverageBoundary(
                    facet="def_use_edges",
                    examined_count=len(self.nodes) + self.omitted_ops_total,
                    decoded_count=len(self.nodes),
                    omitted_count=self.omitted_ops_total,
                    truncated=self.is_truncated or self.omitted_ops_total > 0,
                    reason="budget_limit" if (self.is_truncated or self.omitted_ops_total > 0) else None,
                )
            ],
            limitations=["omitted_ops_budget"] if self.omitted_ops_total > 0 else [],
        )


class HighPCodeValueTracer:
    """Builds inter-procedural def-use graphs across procedures."""

    def __init__(
        self,
        procedure_provider: Optional[Callable[[str], Any]] = None,
        max_depth: int = MAX_DEPTH_DEFAULT,
        max_nodes: int = MAX_NODES_DEFAULT,
    ) -> None:
        self.procedure_provider = procedure_provider
        self.max_depth = max(1, min(max_depth, 8))
        self.max_nodes = max(100, min(max_nodes, 12000))
        self._visited_procs: Set[str] = set()
        self._node_registry: Dict[str, DefUseNode] = {}
        self._edges: List[DefUseEdge] = []
        self._omitted_ops: int = 0
        self._omitted_edges: int = 0
        self._is_truncated: bool = False

    def trace(
        self,
        binary_path: str,
        root_procedure: str,
        initial_ops: Optional[List[PcodeOp]] = None,
        ast_dead_info: Optional[Dict[int, Tuple[bool, bool]]] = None,
    ) -> ValueTraceReport:
        """Executes inter-procedural value tracing starting from root_procedure."""
        self._visited_procs.clear()
        self._node_registry.clear()
        self._edges.clear()
        self._omitted_ops = 0
        self._omitted_edges = 0
        self._is_truncated = False

        self._trace_procedure(
            proc_id=root_procedure,
            depth=1,
            pcode_ops=initial_ops,
            ast_dead_info=ast_dead_info,
        )

        node_list = list(self._node_registry.values())
        if len(node_list) > self.max_nodes:
            node_list = node_list[:self.max_nodes]
            self._is_truncated = True

        return ValueTraceReport(
            binary_path=binary_path,
            root_procedure=root_procedure,
            max_depth=self.max_depth,
            max_nodes=self.max_nodes,
            nodes=node_list,
            edges=self._edges,
            procedures_visited=sorted(list(self._visited_procs)),
            omitted_ops_total=self._omitted_ops,
            omitted_edges_total=self._omitted_edges,
            is_truncated=self._is_truncated,
        )

    def _trace_procedure(
        self,
        proc_id: str,
        depth: int,
        pcode_ops: Optional[List[PcodeOp]] = None,
        ast_dead_info: Optional[Dict[int, Tuple[bool, bool]]] = None,
    ) -> Optional[ProcedureDossier]:
        """Traces a single procedure and recurses into statically resolved callees."""
        if proc_id in self._visited_procs:
            return None  # Cycle-safe single-attempt memoization
        self._visited_procs.add(proc_id)

        # Retrieve P-code operations if not provided
        ops: List[PcodeOp] = []
        if pcode_ops is not None:
            ops = pcode_ops
        elif self.procedure_provider:
            provider_result = self.procedure_provider(proc_id)
            if isinstance(provider_result, list):
                ops = provider_result
            elif isinstance(provider_result, dict):
                ops = provider_result.get("ops", [])
                if not ast_dead_info and "ast_dead_info" in provider_result:
                    ast_dead_info = provider_result["ast_dead_info"]

        # Parse canonical address
        canonical_addr = 0
        if proc_id.startswith("0x") or proc_id.startswith("0X"):
            try:
                canonical_addr = int(proc_id, 16)
            except ValueError:
                canonical_addr = 0

        # Enforce max 3,000 ops cap per procedure
        omitted_in_proc = 0
        if len(ops) > MAX_PCODE_OPS_PER_PROCEDURE:
            omitted_in_proc = len(ops) - MAX_PCODE_OPS_PER_PROCEDURE
            self._omitted_ops += omitted_in_proc
            ops = ops[:MAX_PCODE_OPS_PER_PROCEDURE]

        dossier = ProcedureDossier(
            procedure=proc_id,
            canonical_address=canonical_addr,
            ops_processed=len(ops),
            omitted_ops=omitted_in_proc,
        )

        # Track latest definitions of varnodes in this procedure for intra-procedural def-use
        var_defs: Dict[str, str] = {}  # key -> node_id
        callee_call_sites: List[Tuple[PcodeOp, str, List[str]]] = []  # op, callee_id, arg_node_ids
        return_nodes: List[str] = []

        for op_idx, op in enumerate(ops):
            if len(self._node_registry) >= self.max_nodes:
                self._is_truncated = True
                break

            # Inputs cap: 64 inputs per op
            inputs = op.inputs
            if len(inputs) > MAX_INPUTS_PER_OP:
                inputs = inputs[:MAX_INPUTS_PER_OP]

            # AST membership and dead flag check
            # ast_dead_info mapping: pc -> (is_ast_live, is_dead)
            ast_live = True
            is_dead = False
            if ast_dead_info and op.pc in ast_dead_info:
                ast_live, is_dead = ast_dead_info[op.pc]

            ast_membership = "ast_live" if ast_live else "ast_elided"

            # Check for stack local store
            is_stack_store = False
            if op.opcode == PcodeOpcode.STORE:
                # In STORE, input[0] is space/dest. If stack space, it's local store.
                if len(inputs) > 0 and (
                    inputs[0].space == AddressSpace.RAM or
                    str(inputs[0].offset).lower() in ("stack", "sp", "0x0") or
                    getattr(inputs[0].space, "name", "").lower() == "stack"
                ):
                    is_stack_store = True

            # Register input nodes and intra-procedural def-use edges
            input_node_ids: List[str] = []
            for inp_idx, inp in enumerate(inputs):
                inp_id = f"{proc_id}_{op_idx}_in_{inp_idx}"
                role = "use"
                epistemic = "observed"

                # Check pointer aliasing / unresolved indirect targets
                if op.opcode in (PcodeOpcode.LOAD, PcodeOpcode.STORE) and inp_idx == 1:
                    if inp.space != AddressSpace.CONST and not inp.name:
                        epistemic = "unknown"
                elif op.opcode in (PcodeOpcode.CALLIND, PcodeOpcode.BRANCHIND):
                    epistemic = "unknown"

                inp_node = DefUseNode(
                    node_id=inp_id,
                    procedure=proc_id,
                    pc=op.pc,
                    op=op.opcode.name if hasattr(op.opcode, "name") else str(op.opcode),
                    varnode_role=role,
                    varnode=inp.to_dict() if hasattr(inp, "to_dict") else {"raw": str(inp)},
                    ast_membership=ast_membership,
                    pcode_is_dead=is_dead,
                    epistemic_status=epistemic,
                )
                self._node_registry[inp_id] = inp_node
                input_node_ids.append(inp_id)

                # Connect from prior def if available
                v_key = self._varnode_key(inp)
                if v_key in var_defs:
                    self._add_edge(DefUseEdge(
                        source_id=var_defs[v_key],
                        target_id=inp_id,
                        edge_type="intra_procedural",
                    ))

            # Register output node
            out_node_id: Optional[str] = None
            if op.output:
                out_id = f"{proc_id}_{op_idx}_out"
                out_role = "stack_local_store" if is_stack_store else "def"
                out_epistemic = "observed"

                out_node = DefUseNode(
                    node_id=out_id,
                    procedure=proc_id,
                    pc=op.pc,
                    op=op.opcode.name if hasattr(op.opcode, "name") else str(op.opcode),
                    varnode_role=out_role,
                    varnode=op.output.to_dict() if hasattr(op.output, "to_dict") else {"raw": str(op.output)},
                    ast_membership=ast_membership,
                    pcode_is_dead=is_dead,
                    epistemic_status=out_epistemic,
                )
                self._node_registry[out_id] = out_node
                out_node_id = out_id
                v_key = self._varnode_key(op.output)
                var_defs[v_key] = out_id

                # Dataflow within instruction: inputs -> output
                for inp_id in input_node_ids:
                    self._add_edge(DefUseEdge(
                        source_id=inp_id,
                        target_id=out_id,
                        edge_type="intra_procedural",
                    ))

            # Inter-procedural call detection
            if op.opcode == PcodeOpcode.CALL:
                # First input is target address/symbol
                target_proc: Optional[str] = None
                call_args: List[str] = []
                if len(inputs) > 0:
                    tgt_inp = inputs[0]
                    if tgt_inp.space == AddressSpace.CONST and isinstance(tgt_inp.offset, int):
                        target_proc = hex(tgt_inp.offset)
                    elif tgt_inp.name:
                        target_proc = tgt_inp.name
                    elif isinstance(tgt_inp.offset, str):
                        target_proc = tgt_inp.offset
                    # Additional inputs represent call parameters
                    call_args = input_node_ids[1:] if len(input_node_ids) > 1 else []

                if target_proc:
                    callee_call_sites.append((op, target_proc, call_args))
            elif op.opcode == PcodeOpcode.CALLIND:
                # Indirect call target unknown
                pass
            elif op.opcode == PcodeOpcode.RETURN:
                if input_node_ids:
                    return_nodes.extend(input_node_ids)

        # Cross-call recursion if within max_depth
        if depth < self.max_depth:
            for call_op, target_proc, call_args in callee_call_sites:
                callee_dossier = self._trace_procedure(
                    proc_id=target_proc,
                    depth=depth + 1,
                    ast_dead_info=ast_dead_info,
                )
                if callee_dossier:
                    # Bind call site args to callee parameter ordinals (param_0..param_n)
                    for ordinal, arg_node_id in enumerate(call_args):
                        # Locate or synthesize formal parameter node in callee
                        param_node_id = f"{target_proc}_formal_param_{ordinal}"
                        if param_node_id not in self._node_registry:
                            param_node = DefUseNode(
                                node_id=param_node_id,
                                procedure=target_proc,
                                pc=callee_dossier.canonical_address,
                                op="PARAM",
                                varnode_role="param_in",
                                varnode={"name": f"param_{ordinal}", "ordinal": ordinal},
                                ast_membership="ast_live",
                                pcode_is_dead=False,
                                epistemic_status="observed",
                            )
                            self._node_registry[param_node_id] = param_node
                        self._add_edge(DefUseEdge(
                            source_id=arg_node_id,
                            target_id=param_node_id,
                            edge_type="call_param_bind",
                            param_ordinal=ordinal,
                        ))

                    # Bind callee return nodes to caller's call output
                    caller_out_key = self._varnode_key(call_op.output) if call_op.output else None
                    if caller_out_key and caller_out_key in var_defs:
                        caller_out_id = var_defs[caller_out_key]
                        for ret_node_id in callee_dossier.nodes:
                            if ret_node_id.op == "RETURN" or ret_node_id.varnode_role == "return_out":
                                self._add_edge(DefUseEdge(
                                    source_id=ret_node_id.node_id,
                                    target_id=caller_out_id,
                                    edge_type="callee_return_bind",
                                ))

        dossier.nodes = [n for n in self._node_registry.values() if n.procedure == proc_id]
        return dossier

    def _varnode_key(self, vn: Optional[Varnode]) -> str:
        if vn is None:
            return ""
        if vn.name:
            return f"reg_{vn.name}"
        space_name = vn.space.name if hasattr(vn.space, "name") else str(vn.space)
        return f"{space_name}_{vn.offset}_{vn.size}"

    def _add_edge(self, edge: DefUseEdge) -> None:
        if len(self._edges) >= MAX_DEF_USE_EDGES:
            self._omitted_edges += 1
            self._is_truncated = True
            return
        self._edges.append(edge)


def trace_native_values(
    binary_path_or_image: str,
    procedure: str,
    max_depth: int = MAX_DEPTH_DEFAULT,
    max_nodes: int = MAX_NODES_DEFAULT,
    output: Optional[str] = None,
    procedure_provider: Optional[Callable[[str], Any]] = None,
    pcode_ops: Optional[List[PcodeOp]] = None,
    ast_dead_info: Optional[Dict[int, Tuple[bool, bool]]] = None,
) -> ValueTraceReport:
    """Main programmatic entry point for high-P-code cross-call value tracing."""
    tracer = HighPCodeValueTracer(
        procedure_provider=procedure_provider,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    report = tracer.trace(
        binary_path=str(binary_path_or_image),
        root_procedure=procedure,
        initial_ops=pcode_ops,
        ast_dead_info=ast_dead_info,
    )
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
    return report
