"""
smt_pcode_verifier.py
=====================
SuperGhidra SMT-Backed Decompilation Equivalence Verifier.

Frontier 2 of SuperGhidra Reformation:
- Translates P-Code basic blocks into symbolic Z3 bitvector expressions (BitVec 32/64)
  and byte-level memory arrays (Array('mem', BitVecSort(64), BitVecSort(8))).
- Translates core P-code opcodes:
    COPY, INT_ADD, INT_SUB, INT_AND, INT_OR, INT_XOR, INT_LEFT, INT_RIGHT,
    INT_SRIGHT, INT_MULT, INT_DIV, INT_SDIV, INT_REM, INT_SREM, INT_NEGATE,
    INT_2COMP, INT_ZEXT, INT_SEXT, INT_EQUAL, INT_NOTEQUAL, INT_LESS,
    INT_LESSEQUAL, INT_SLESS, INT_SLESSEQUAL, LOAD, STORE.
- Parses decompiled C-like statements and ASTs (arithmetic, bitwise, field dereferences,
  pointer arithmetic, assignments, and returns).
- Formulates formal equivalence queries in Z3:
    Not(symbolic_pcode_state == symbolic_c_state)
- Returns structured VerificationResult (UNSAT = proven equivalent, SAT = counterexample).
- Integrates with ReconstructionObligationLedger (FUNCTION_HOOK and
  STRUCT_FIELD_RENAME obligations).
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import z3
except ImportError:
    z3 = None


def _require_z3():
    if z3 is None:
        raise ImportError("install superghidra[smt] to use SMT verification features")

# Import P-Code lifter and ledger models
try:
    from superghidra.lifters.pcode_lifter_bridge import (
        ARM64PcodeLifter,
        AddressSpace,
        CANONICAL_REG_OFFSETS,
        DaemonPcodeBackend,
        PcodeOp,
        PcodeOpcode,
        PypcodeSleighBackend,
        UnifiedPcodeLifter,
        Varnode,
        X86_64PcodeLifter,
    )
    from superghidra.diff.evidence_ledger import (
        CheckResult,
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
    )
except ImportError:
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from superghidra.lifters.pcode_lifter_bridge import (  # type: ignore
        ARM64PcodeLifter,
        AddressSpace,
        CANONICAL_REG_OFFSETS,
        DaemonPcodeBackend,
        PcodeOp,
        PcodeOpcode,
        PypcodeSleighBackend,
        UnifiedPcodeLifter,
        Varnode,
        X86_64PcodeLifter,
    )
    from superghidra.diff.evidence_ledger import (  # type: ignore
        CheckResult,
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
    )


# ==============================================================================
# Verification Result Data Model
# ==============================================================================

@dataclasses.dataclass
class VerificationResult:
    """Outcome of SMT formal equivalence verification."""
    obligation_id: Optional[str]
    equivalent: bool
    status: str  # "UNSAT" (proven equivalent), "SAT" (counterexample found), "UNKNOWN", "ERROR"
    details: str
    counterexample: Optional[Dict[str, Any]] = None
    model_inputs: Optional[Dict[str, Any]] = None
    pcode_out: Optional[str] = None
    c_out: Optional[str] = None
    backend_used: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "equivalent": self.equivalent,
            "status": self.status,
            "details": self.details,
            "counterexample": self.counterexample,
            "model_inputs": self.model_inputs,
            "pcode_out": self.pcode_out,
            "c_out": self.c_out,
            "backend_used": self.backend_used,
        }


EquivalenceResult = VerificationResult


# ==============================================================================
# Symbolic Memory & State
# ==============================================================================

def read_symbolic_memory(mem: z3.ArrayRef, addr: z3.BitVecRef, size: int) -> z3.BitVecRef:
    """Reads a little-endian bitvector of `size` bytes from symbolic byte array."""
    _require_z3()
    if addr.size() != 64:
        addr = z3.ZeroExt(64 - addr.size(), addr) if addr.size() < 64 else z3.Extract(63, 0, addr)

    if size == 1:
        return mem[addr]
    elif size == 2:
        return z3.Concat(mem[addr + 1], mem[addr])
    elif size == 4:
        return z3.Concat(mem[addr + 3], mem[addr + 2], mem[addr + 1], mem[addr])
    elif size == 8:
        return z3.Concat(
            mem[addr + 7], mem[addr + 6], mem[addr + 5], mem[addr + 4],
            mem[addr + 3], mem[addr + 2], mem[addr + 1], mem[addr]
        )
    else:
        # Generic variable size reader
        chunks = [mem[addr + i] for i in reversed(range(size))]
        res = chunks[0]
        for c in chunks[1:]:
            res = z3.Concat(res, c)
        return res


def write_symbolic_memory(mem: z3.ArrayRef, addr: z3.BitVecRef, val: z3.BitVecRef, size: int) -> z3.ArrayRef:
    """Writes a little-endian bitvector of `size` bytes into symbolic byte array."""
    _require_z3()
    if addr.size() != 64:
        addr = z3.ZeroExt(64 - addr.size(), addr) if addr.size() < 64 else z3.Extract(63, 0, addr)

    target_bits = size * 8
    if val.size() < target_bits:
        val = z3.ZeroExt(target_bits - val.size(), val)
    elif val.size() > target_bits:
        val = z3.Extract(target_bits - 1, 0, val)

    for i in range(size):
        byte_i = z3.Extract((i + 1) * 8 - 1, i * 8, val)
        mem = z3.Store(mem, addr + i, byte_i)
    return mem


class SymbolicState:
    """
    Tracks registers, unique scratchpad Varnodes, named variables, and byte-addressed RAM.
    """

    def __init__(self, name_prefix: str = "", initial_mem: Optional[z3.ArrayRef] = None):
        _require_z3()
        self.prefix = name_prefix
        # Register mapping: offset (e.g. reg_idx * 8) -> 64-bit BitVecRef
        self.regs: Dict[int, z3.BitVecRef] = {}
        # Unique scratchpad mapping: offset -> BitVecRef
        self.uniques: Dict[int, z3.BitVecRef] = {}
        # Named C variables: name -> BitVecRef
        self.vars: Dict[str, z3.BitVecRef] = {}
        # Byte memory array: Array('mem', BitVecSort(64), BitVecSort(8))
        self.mem = (
            initial_mem
            if initial_mem is not None
            else z3.Array(f"{name_prefix}mem", z3.BitVecSort(64), z3.BitVecSort(8))
        )
        # Parameter bindings: {"player": "x0", "damage": "w2"}
        self.param_map: Dict[str, str] = {}
        # Return value expression
        self.return_val: Optional[z3.BitVecRef] = None
        # Branch conditions and path constraints
        self.path_constraints: List[z3.BoolRef] = []
        self.branches: List[Tuple[Any, Any]] = []
        # Soundness: track when state contains unsupported/undecidable approximations
        self.is_unknown: bool = False
        self.unknown_reason: Optional[str] = None

    def mark_unknown(self, reason: str) -> None:
        """Marks this state as undecidable/unsupported for formal equivalence."""
        self.is_unknown = True
        if not self.unknown_reason:
            self.unknown_reason = reason

    def clone(self, new_prefix: Optional[str] = None) -> SymbolicState:
        """Creates a copy of the symbolic state sharing base memory and registers."""
        st = SymbolicState(new_prefix or self.prefix, initial_mem=self.mem)
        st.regs = dict(self.regs)
        st.uniques = dict(self.uniques)
        st.vars = dict(self.vars)
        st.param_map = dict(self.param_map)
        st.return_val = self.return_val
        st.path_constraints = list(self.path_constraints)
        st.branches = list(self.branches)
        st.is_unknown = self.is_unknown
        st.unknown_reason = self.unknown_reason
        return st

    def get_register(self, reg_offset: Union[int, str], size: int = 8) -> z3.BitVecRef:
        """Gets or lazily creates a symbolic register."""
        if isinstance(reg_offset, str):
            reg_offset = CANONICAL_REG_OFFSETS.get(reg_offset.lower(), 0x800)
        if reg_offset not in self.regs:
            if reg_offset >= 0x700:
                flag_names = {0x700: "flag_n", 0x701: "flag_z", 0x702: "flag_c", 0x703: "flag_v"}
                base_name = flag_names.get(reg_offset, f"flag_{reg_offset:x}")
                reg_name = f"{self.prefix}{base_name}" if self.prefix else base_name
            elif reg_offset >= 0x400:
                fp_idx = (reg_offset - 0x400) // 16
                reg_name = f"{self.prefix}d{fp_idx}" if self.prefix else f"d{fp_idx}"
            else:
                reg_idx = reg_offset // 8
                reg_name = f"{self.prefix}x{reg_idx}" if self.prefix else f"x{reg_idx}"
            self.regs[reg_offset] = z3.BitVec(reg_name, max(64, size * 8))

        val_reg = self.regs[reg_offset]
        target_bits = size * 8
        if val_reg.size() == target_bits:
            return val_reg
        elif val_reg.size() > target_bits:
            return z3.Extract(target_bits - 1, 0, val_reg)
        else:
            return z3.ZeroExt(target_bits - val_reg.size(), val_reg)

    def set_register(self, reg_offset: Union[int, str], val: z3.BitVecRef, size: int = 8) -> None:
        """Sets a register, with 32-bit writes automatically zero-extended to 64-bit."""
        if isinstance(reg_offset, str):
            reg_offset = CANONICAL_REG_OFFSETS.get(reg_offset.lower(), 0x800)
        if val.size() < size * 8:
            val = z3.ZeroExt(size * 8 - val.size(), val)
        elif val.size() > size * 8:
            val = z3.Extract(size * 8 - 1, 0, val)

        if size >= 8:
            self.regs[reg_offset] = val
        elif size == 4 or reg_offset >= 0x400:
            # In 64-bit architectures (ARM64/x86_64) and FP/flag regs, clear upper bits
            self.regs[reg_offset] = z3.ZeroExt(64 - size * 8, val)
        else:
            # Partial byte/half-word update on GPR
            curr = self.get_register(reg_offset, 8)
            upper = z3.Extract(63, size * 8, curr)
            self.regs[reg_offset] = z3.Concat(upper, val)


    def get_varnode_value(self, vn: Varnode) -> z3.BitVecRef:
        """Retrieves symbolic expression for a Varnode."""
        if vn.space == AddressSpace.CONST:
            return z3.BitVecVal(vn.offset, vn.size * 8)
        elif vn.space == AddressSpace.REGISTER:
            return self.get_register(vn.offset, vn.size)
        elif vn.space == AddressSpace.UNIQUE:
            if vn.offset not in self.uniques:
                name = f"{self.prefix}u_{vn.offset:x}" if self.prefix else f"u_{vn.offset:x}"
                self.uniques[vn.offset] = z3.BitVec(name, vn.size * 8)
            val = self.uniques[vn.offset]
            if val.size() != vn.size * 8:
                if val.size() < vn.size * 8:
                    val = z3.ZeroExt(vn.size * 8 - val.size(), val)
                else:
                    val = z3.Extract(vn.size * 8 - 1, 0, val)
            return val
        elif vn.space == AddressSpace.RAM:
            addr = z3.BitVecVal(vn.offset, 64)
            return read_symbolic_memory(self.mem, addr, vn.size)
        else:
            name = f"{self.prefix}unk_{vn.space.value}_{vn.offset:x}"
            return z3.BitVec(name, vn.size * 8)

    def set_varnode_value(self, vn: Varnode, val: z3.BitVecRef) -> None:
        """Assigns symbolic expression to a Varnode."""
        target_bits = vn.size * 8
        if val.size() < target_bits:
            val = z3.ZeroExt(target_bits - val.size(), val)
        elif val.size() > target_bits:
            val = z3.Extract(target_bits - 1, 0, val)

        if vn.space == AddressSpace.REGISTER:
            self.set_register(vn.offset, val, vn.size)
        elif vn.space == AddressSpace.UNIQUE:
            self.uniques[vn.offset] = val
        elif vn.space == AddressSpace.RAM:
            addr = z3.BitVecVal(vn.offset, 64)
            self.mem = write_symbolic_memory(self.mem, addr, val, vn.size)


def merge_symbolic_states(cond: Any, state_then: SymbolicState, state_else: SymbolicState) -> SymbolicState:
    """Merges two symbolic execution states conditioned on a boolean Z3 expression."""
    z3_cond = (cond != 0) if isinstance(cond, z3.BitVecRef) else (cond if isinstance(cond, z3.BoolRef) else True)
    merged = state_then.clone()

    # Merge registers
    all_regs = set(state_then.regs.keys()).union(state_else.regs.keys())
    for r in all_regs:
        vt = state_then.get_register(r, 8)
        ve = state_else.get_register(r, 8)
        merged.regs[r] = z3.If(z3_cond, vt, ve)

    # Merge uniques
    all_uniques = set(state_then.uniques.keys()).union(state_else.uniques.keys())
    for u in all_uniques:
        if u in state_then.uniques and u in state_else.uniques:
            ut = state_then.uniques[u]
            ue = state_else.uniques[u]
            if ut.size() == ue.size():
                merged.uniques[u] = z3.If(z3_cond, ut, ue)
            else:
                merged.uniques[u] = ut
        elif u in state_then.uniques:
            merged.uniques[u] = state_then.uniques[u]
        else:
            merged.uniques[u] = state_else.uniques[u]

    # Merge vars
    all_vars = set(state_then.vars.keys()).union(state_else.vars.keys())
    for v in all_vars:
        if v in state_then.vars and v in state_else.vars:
            vt = state_then.vars[v]
            ve = state_else.vars[v]
            if vt.size() == ve.size():
                merged.vars[v] = z3.If(z3_cond, vt, ve)
            else:
                merged.vars[v] = vt
        elif v in state_then.vars:
            merged.vars[v] = state_then.vars[v]
        else:
            merged.vars[v] = state_else.vars[v]

    # Merge return_val
    if state_then.return_val is not None or state_else.return_val is not None:
        rt = state_then.return_val if state_then.return_val is not None else state_then.get_register(0, 8)
        re = state_else.return_val if state_else.return_val is not None else state_else.get_register(0, 8)
        if rt.size() < re.size():
            rt = z3.ZeroExt(re.size() - rt.size(), rt)
        elif rt.size() > re.size():
            re = z3.ZeroExt(rt.size() - re.size(), re)
        merged.return_val = z3.If(z3_cond, rt, re)

    # Merge memory array
    if str(state_then.mem) != str(state_else.mem):
        merged.mem = z3.If(z3_cond, state_then.mem, state_else.mem)
    else:
        merged.mem = state_then.mem

    merged.is_unknown = state_then.is_unknown or state_else.is_unknown
    if state_then.is_unknown:
        merged.unknown_reason = state_then.unknown_reason
    elif state_else.is_unknown:
        merged.unknown_reason = state_else.unknown_reason

    merged.path_constraints.append(z3_cond)
    return merged


# ==============================================================================
# P-Code Symbolic Simulator
# ==============================================================================

class PcodeSymbolicSimulator:
    """Executes P-Code IR operations symbolically using Z3 bitvectors and arrays."""

    def __init__(self, max_loop_unroll: int = 16):
        _require_z3()
        self.max_loop_unroll = max_loop_unroll

    @staticmethod
    def _match_widths(a: z3.BitVecRef, b: z3.BitVecRef) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        """Ensures two bitvectors have equal bit width by zero-extending the narrower."""
        if a.size() == b.size():
            return a, b
        elif a.size() < b.size():
            return z3.ZeroExt(b.size() - a.size(), a), b
        else:
            return a, z3.ZeroExt(a.size() - b.size(), b)

    def step(self, state: SymbolicState, op: PcodeOp) -> None:
        """Executes a single PcodeOp against symbolic state."""
        opcode = op.opcode
        inputs = op.inputs
        output = op.output

        # 1. Unary & Data Movement
        if opcode == PcodeOpcode.COPY:
            if output:
                val = state.get_varnode_value(inputs[0])
                state.set_varnode_value(output, val)

        elif opcode == PcodeOpcode.RETURN:
            if inputs:
                state.return_val = state.get_varnode_value(inputs[0])
            else:
                state.return_val = state.get_register(0, 8)  # default x0 / rax

        # 2. Arithmetic Operations
        elif opcode == PcodeOpcode.INT_ADD:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 + v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SUB:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 - v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_MULT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 * v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_DIV:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.UDiv(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SDIV:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 / v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_REM:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.URem(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SREM:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.SRem(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        # 3. Bitwise & Logic Operations
        elif opcode == PcodeOpcode.INT_AND:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 & v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_OR:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 | v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_XOR:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 ^ v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_LEFT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 << v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_RIGHT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.LShR(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SRIGHT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 >> v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_NEGATE:
            v0 = state.get_varnode_value(inputs[0])
            res = ~v0
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_2COMP:
            v0 = state.get_varnode_value(inputs[0])
            res = -v0
            if output:
                state.set_varnode_value(output, res)

        # 4. Extension Operations
        elif opcode == PcodeOpcode.INT_ZEXT:
            v0 = state.get_varnode_value(inputs[0])
            if output:
                out_bits = output.size * 8
                res = z3.ZeroExt(out_bits - v0.size(), v0) if out_bits > v0.size() else v0
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SEXT:
            v0 = state.get_varnode_value(inputs[0])
            if output:
                out_bits = output.size * 8
                res = z3.SignExt(out_bits - v0.size(), v0) if out_bits > v0.size() else v0
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.SUBPIECE:
            v0 = state.get_varnode_value(inputs[0])
            byte_offset = inputs[1].offset if len(inputs) > 1 and inputs[1].space == AddressSpace.CONST else 0
            low_bit = byte_offset * 8
            high_bit = low_bit + output.size * 8 - 1
            if high_bit >= v0.size():
                v0 = z3.ZeroExt(high_bit + 1 - v0.size(), v0)
            res = z3.Extract(high_bit, low_bit, v0)
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.PIECE:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            res = z3.Concat(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        # 5. Comparisons
        elif opcode == PcodeOpcode.INT_EQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 == v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_NOTEQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 != v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_LESS:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.ULT(v0, v1), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_LESSEQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.ULE(v0, v1), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SLESS:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 < v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SLESSEQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 <= v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_CARRY:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.ULT(v0 + v1, v0), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SCARRY:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            s = v0 + v1
            zero = z3.BitVecVal(0, v0.size())
            ovf = z3.Or(z3.And(v0 >= zero, v1 >= zero, s < zero), z3.And(v0 < zero, v1 < zero, s >= zero))
            res = z3.If(ovf, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SBORROW:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            d = v0 - v1
            zero = z3.BitVecVal(0, v0.size())
            ovf = z3.Or(z3.And(v0 >= zero, v1 < zero, d < zero), z3.And(v0 < zero, v1 >= zero, d >= zero))
            res = z3.If(ovf, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.BOOL_NEGATE:
            v0 = state.get_varnode_value(inputs[0])
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 == 0, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.BOOL_XOR:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.Xor(v0 != 0, v1 != 0), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.BOOL_AND:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.And(v0 != 0, v1 != 0), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.BOOL_OR:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.Or(v0 != 0, v1 != 0), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.POPCOUNT:
            v0 = state.get_varnode_value(inputs[0])
            out_sz = output.size * 8 if output else 8
            bits = [
                z3.ZeroExt(out_sz - 1, z3.Extract(i, i, v0)) if out_sz > 1 else z3.Extract(i, i, v0)
                for i in range(v0.size())
            ]
            res = sum(bits[1:], bits[0]) if bits else z3.BitVecVal(0, out_sz)
            if output:
                state.set_varnode_value(output, res)

        # 5b. Floating-Point Operations (Unsupported in Bitvector SMT domain -> UNKNOWN)
        elif opcode in (
            PcodeOpcode.FLOAT_ADD, PcodeOpcode.FLOAT_SUB, PcodeOpcode.FLOAT_MULT,
            PcodeOpcode.FLOAT_DIV, PcodeOpcode.FLOAT_NEG, PcodeOpcode.FLOAT_ABS,
            PcodeOpcode.FLOAT_SQRT, PcodeOpcode.FLOAT_INT2FLOAT, PcodeOpcode.FLOAT_FLOAT2FLOAT,
            PcodeOpcode.FLOAT_TRUNC, PcodeOpcode.FLOAT_EQUAL, PcodeOpcode.FLOAT_NOTEQUAL,
            PcodeOpcode.FLOAT_LESS, PcodeOpcode.FLOAT_LESSEQUAL
        ):
            state.mark_unknown(f"Floating-point opcode {opcode.name} unsupported in bitvector SMT domain")
            if output:
                out_sz = output.size * 8
                state.set_varnode_value(output, z3.BitVec(f"{state.prefix}fp_unk_{output.offset}", out_sz))

        # 6. Memory Load & Store
        elif opcode == PcodeOpcode.LOAD:
            addr_val = state.get_varnode_value(inputs[1])
            if output:
                val = read_symbolic_memory(state.mem, addr_val, output.size)
                state.set_varnode_value(output, val)

        elif opcode == PcodeOpcode.STORE:
            addr_val = state.get_varnode_value(inputs[1])
            data_val = state.get_varnode_value(inputs[2])
            state.mem = write_symbolic_memory(state.mem, addr_val, data_val, inputs[2].size)

        # 7. Control Flow & Branches
        elif opcode == PcodeOpcode.CBRANCH:
            target = inputs[0]
            cond_vn = inputs[1]
            cond_val = state.get_varnode_value(cond_vn)
            z3_cond = (cond_val != 0) if isinstance(cond_val, z3.BitVecRef) else (cond_val if isinstance(cond_val, z3.BoolRef) else True)
            target_pc = target.offset
            state.branches.append((z3_cond, target_pc))
            state.path_constraints.append(z3_cond)

        elif opcode == PcodeOpcode.BRANCHIND:
            if inputs:
                target_val = state.get_varnode_value(inputs[0])
                state.branches.append((True, target_val))

        elif opcode == PcodeOpcode.CALL:
            state.mark_unknown("Encountered CALL opcode in P-code; interprocedural side effects unmodeled")

        elif opcode == PcodeOpcode.CALLIND:
            state.mark_unknown("Encountered CALLIND opcode in P-code; indirect call side effects unmodeled")
            if inputs:
                target_val = state.get_varnode_value(inputs[0])
                state.branches.append((True, target_val))

        elif opcode == PcodeOpcode.CALLOTHER:
            state.mark_unknown("Encountered CALLOTHER intrinsic in P-code; usercall side effects unmodeled")

        elif opcode == PcodeOpcode.UNIMPLEMENTED:
            state.mark_unknown("Encountered UNIMPLEMENTED opcode in P-code")

        elif opcode == PcodeOpcode.BRANCH:
            pass  # intra-block handled in execute_block

        else:
            state.mark_unknown(f"Unhandled P-code opcode: {opcode.name if hasattr(opcode, 'name') else opcode}")

    def execute_block(self, state: SymbolicState, ops: List[PcodeOp]) -> None:
        """Executes a linear sequence or conditional diamond DAG of PcodeOps on state."""
        has_branch = any(op.opcode in (PcodeOpcode.CBRANCH, PcodeOpcode.BRANCH) for op in ops)
        if not has_branch:
            for op in ops:
                self.step(state, op)
            return

        pc_to_first_idx: Dict[int, int] = {}
        for i, op in enumerate(ops):
            if op.pc not in pc_to_first_idx:
                pc_to_first_idx[op.pc] = i

        loop_counts: Dict[int, int] = {}
        accumulated_exit_states: List[Tuple[Any, SymbolicState]] = []

        idx = 0
        n = len(ops)
        while idx < n:
            op = ops[idx]
            if op.opcode == PcodeOpcode.CBRANCH:
                self.step(state, op)
                target_pc = op.inputs[0].offset if op.inputs else None
                cond_vn = op.inputs[1] if len(op.inputs) > 1 else None
                cond_val = state.get_varnode_value(cond_vn) if cond_vn else None
                z3_cond = (cond_val != 0) if isinstance(cond_val, z3.BitVecRef) else (cond_val if isinstance(cond_val, z3.BoolRef) else True)

                if target_pc is not None and target_pc in pc_to_first_idx:
                    target_idx = pc_to_first_idx[target_pc]
                    if target_idx > idx:
                        branch_idx = None
                        for k in range(idx + 1, target_idx):
                            if ops[k].opcode == PcodeOpcode.BRANCH:
                                branch_idx = k
                                break

                        if branch_idx is not None:
                            merge_pc = ops[branch_idx].inputs[0].offset if ops[branch_idx].inputs else None
                            merge_idx = pc_to_first_idx.get(merge_pc, n) if merge_pc else n

                            # Taken path (starts at target_idx, runs until merge_idx)
                            state_taken = state.clone()
                            for k in range(target_idx, merge_idx):
                                if ops[k].opcode != PcodeOpcode.BRANCH:
                                    self.step(state_taken, ops[k])

                            # Fallthrough path (starts at idx + 1, runs until branch_idx)
                            state_fallthrough = state.clone()
                            for k in range(idx + 1, branch_idx):
                                self.step(state_fallthrough, ops[k])

                            merged = merge_symbolic_states(z3_cond, state_taken, state_fallthrough)
                            state.regs = merged.regs
                            state.uniques = merged.uniques
                            state.vars = merged.vars
                            state.mem = merged.mem
                            state.return_val = merged.return_val
                            idx = merge_idx
                            continue
                        else:
                            # Simple if-then diamond (skip over [idx+1 .. target_idx-1] if taken)
                            state_taken = state.clone()

                            state_fallthrough = state.clone()
                            for k in range(idx + 1, target_idx):
                                self.step(state_fallthrough, ops[k])

                            merged = merge_symbolic_states(z3_cond, state_taken, state_fallthrough)
                            state.regs = merged.regs
                            state.uniques = merged.uniques
                            state.vars = merged.vars
                            state.mem = merged.mem
                            state.return_val = merged.return_val
                            idx = target_idx
                            continue
                    else:
                        # Backward conditional branch (bounded loop unrolling)
                        simp_cond = z3.simplify(z3_cond)
                        if z3.is_false(simp_cond):
                            idx += 1
                            continue
                        elif z3.is_true(simp_cond):
                            cnt = loop_counts.get(idx, 0)
                            if cnt < self.max_loop_unroll:
                                loop_counts[idx] = cnt + 1
                                idx = target_idx
                                continue
                            else:
                                idx += 1
                                continue
                        else:
                            cnt = loop_counts.get(idx, 0)
                            if cnt < self.max_loop_unroll:
                                loop_counts[idx] = cnt + 1
                                exit_state = state.clone()
                                not_cond = z3.Not(z3_cond) if isinstance(z3_cond, z3.BoolRef) else (z3_cond == 0)
                                accumulated_exit_states.append((not_cond, exit_state))
                                state.path_constraints.append(z3_cond)
                                idx = target_idx
                                continue
                            else:
                                state.mark_unknown(f"Loop truncated at unroll limit ({self.max_loop_unroll}); bounded unroll is not a proof")
                                idx += 1
                                continue

            elif op.opcode == PcodeOpcode.BRANCH:
                target_pc = op.inputs[0].offset if op.inputs else None
                if target_pc is not None and target_pc in pc_to_first_idx:
                    target_idx = pc_to_first_idx[target_pc]
                    if target_idx > idx:
                        idx = target_idx
                        continue
                    else:
                        cnt = loop_counts.get(idx, 0)
                        if cnt < self.max_loop_unroll:
                            loop_counts[idx] = cnt + 1
                            idx = target_idx
                            continue
                        else:
                            state.mark_unknown(f"Loop truncated at unroll limit ({self.max_loop_unroll}); bounded unroll is not a proof")
                            idx += 1
                            continue

            self.step(state, op)
            idx += 1

        if accumulated_exit_states:
            cur_merged = state
            for exit_cond, exit_st in reversed(accumulated_exit_states):
                cur_merged = merge_symbolic_states(exit_cond, exit_st, cur_merged)
            state.regs = cur_merged.regs
            state.uniques = cur_merged.uniques
            state.vars = cur_merged.vars
            state.mem = cur_merged.mem
            state.return_val = cur_merged.return_val
            state.is_unknown = cur_merged.is_unknown
            state.unknown_reason = cur_merged.unknown_reason


# ==============================================================================
# Decompiled C Expression & AST Parser
# ==============================================================================

class CASTNode:
    """Base class for parsed C AST nodes."""
    pass


@dataclasses.dataclass
class CVar(CASTNode):
    name: str
    size: int = 8


@dataclasses.dataclass
class CConst(CASTNode):
    val: int
    size: int = 8


@dataclasses.dataclass
class CBinary(CASTNode):
    op: str  # '+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '==', '!=', '<', '<=', '>', '>='
    left: CASTNode
    right: CASTNode


@dataclasses.dataclass
class CUnary(CASTNode):
    op: str  # '~', '-', '!'
    operand: CASTNode


@dataclasses.dataclass
class CDeref(CASTNode):
    ptr_expr: CASTNode
    size: int = 4  # bytes


@dataclasses.dataclass
class CFieldAccess(CASTNode):
    base_expr: CASTNode
    field_name: str
    offset: Optional[int] = None
    size: int = 4


@dataclasses.dataclass
class CIntrinsic(CASTNode):
    name: str
    args: List[CASTNode]


@dataclasses.dataclass
class CCall(CASTNode):
    func: str
    args: List[CASTNode] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class CAssignment(CASTNode):
    target: CASTNode  # CVar, CDeref, or CFieldAccess
    value: CASTNode


@dataclasses.dataclass
class CReturn(CASTNode):
    value: CASTNode


@dataclasses.dataclass
class CTernary(CASTNode):
    condition: CASTNode
    then_expr: CASTNode
    else_expr: CASTNode


@dataclasses.dataclass
class CBlock(CASTNode):
    statements: List[CASTNode] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class CIfElse(CASTNode):
    condition: CASTNode
    then_block: CBlock
    else_block: Optional[CBlock] = None


@dataclasses.dataclass
class CWhile(CASTNode):
    condition: CASTNode
    body: CBlock
    max_unroll: int = 16



class CCodeParser:
    """
    Parses decompiled C function bodies, statements, or expressions into symbolic AST nodes.
    Supports pointer arithmetic (`*(int*)(p + 0x24)`), field dereferences (`p->m_health`),
    standard C operators, and structured if/else control flow.
    """

    def __init__(self, struct_schemas: Optional[Dict[str, Dict[str, Tuple[int, int]]]] = None):
        self.struct_schemas = struct_schemas or {}
        self.flat_fields: Dict[str, Tuple[int, int]] = {}
        for st_name, fields in self.struct_schemas.items():
            for f_name, f_info in fields.items():
                self.flat_fields[f_name] = f_info

    def register_field(self, field_name: str, offset: int, size: int = 4) -> None:
        """Registers a struct field offset and access size."""
        self.flat_fields[field_name] = (offset, size)

    def parse(self, text: str) -> CBlock:
        """Parses a multi-statement C code block, including structured if/else."""
        clean_text = re.sub(r"//.*", "", text)
        clean_text = re.sub(r"/\*.*?\*/", "", clean_text, flags=re.DOTALL).strip()
        return self._parse_block_text(clean_text)

    def _parse_block_text(self, text: str) -> CBlock:
        statements: List[CASTNode] = []
        i = 0
        n = len(text)

        while i < n:
            while i < n and text[i].isspace():
                i += 1
            if i >= n:
                break

            # 1. Parse 'if' statement
            if text[i:i+2] == "if" and (i + 2 == n or text[i+2].isspace() or text[i+2] == "("):
                i += 2
                while i < n and text[i].isspace():
                    i += 1
                if i < n and text[i] == "(":
                    cond_start = i + 1
                    depth = 1
                    i += 1
                    while i < n and depth > 0:
                        if text[i] == "(":
                            depth += 1
                        elif text[i] == ")":
                            depth -= 1
                        i += 1
                    cond_end = i - 1
                    cond_str = text[cond_start:cond_end].strip()
                    cond_node = self._parse_expr(cond_str)

                    while i < n and text[i].isspace():
                        i += 1

                    # Parse then-branch
                    if i < n and text[i] == "{":
                        then_start = i + 1
                        depth = 1
                        i += 1
                        while i < n and depth > 0:
                            if text[i] == "{":
                                depth += 1
                            elif text[i] == "}":
                                depth -= 1
                            i += 1
                        then_end = i - 1
                        then_block = self._parse_block_text(text[then_start:then_end])
                    else:
                        stmt_start = i
                        depth_paren = 0
                        while i < n:
                            if text[i] == "(":
                                depth_paren += 1
                            elif text[i] == ")":
                                depth_paren -= 1
                            elif text[i] == ";" and depth_paren == 0:
                                break
                            i += 1
                        stmt_text = text[stmt_start:i].strip()
                        if i < n and text[i] == ";":
                            i += 1
                        then_block = CBlock(statements=[self._parse_single_stmt(stmt_text)]) if stmt_text else CBlock()

                    # Check for optional else-branch
                    saved_i = i
                    while i < n and text[i].isspace():
                        i += 1
                    else_block = None
                    if i + 4 <= n and text[i:i+4] == "else" and (i + 4 == n or text[i+4].isspace() or text[i+4] in "({"):
                        i += 4
                        while i < n and text[i].isspace():
                            i += 1
                        if i < n and text[i] == "{":
                            else_start = i + 1
                            depth = 1
                            i += 1
                            while i < n and depth > 0:
                                if text[i] == "{":
                                    depth += 1
                                elif text[i] == "}":
                                    depth -= 1
                                i += 1
                            else_end = i - 1
                            else_block = self._parse_block_text(text[else_start:else_end])
                        elif i + 2 <= n and text[i:i+2] == "if" and (i + 2 == n or text[i+2].isspace() or text[i+2] == "("):
                            else_block = self._parse_block_text(text[i:])
                            i = n
                        else:
                            stmt_start = i
                            depth_paren = 0
                            while i < n:
                                if text[i] == "(":
                                    depth_paren += 1
                                elif text[i] == ")":
                                    depth_paren -= 1
                                elif text[i] == ";" and depth_paren == 0:
                                    break
                                i += 1
                            stmt_text = text[stmt_start:i].strip()
                            if i < n and text[i] == ";":
                                i += 1
                            else_block = CBlock(statements=[self._parse_single_stmt(stmt_text)]) if stmt_text else CBlock()
                    else:
                        i = saved_i

                    statements.append(CIfElse(condition=cond_node, then_block=then_block, else_block=else_block))
                    continue

            # 2. Parse 'while' statement
            if text[i:i+5] == "while" and (i + 5 == n or text[i+5].isspace() or text[i+5] == "("):
                i += 5
                while i < n and text[i].isspace(): i += 1
                if i < n and text[i] == "(":
                    cond_start = i + 1
                    depth = 1
                    i += 1
                    while i < n and depth > 0:
                        if text[i] == "(": depth += 1
                        elif text[i] == ")": depth -= 1
                        i += 1
                    cond_end = i - 1
                    cond_str = text[cond_start:cond_end].strip()
                    cond_node = self._parse_expr(cond_str)

                    while i < n and text[i].isspace(): i += 1
                    if i < n and text[i] == "{":
                        body_start = i + 1
                        depth = 1
                        i += 1
                        while i < n and depth > 0:
                            if text[i] == "{": depth += 1
                            elif text[i] == "}": depth -= 1
                            i += 1
                        body_end = i - 1
                        body_block = self._parse_block_text(text[body_start:body_end])
                    else:
                        stmt_start = i
                        depth_paren = 0
                        while i < n:
                            if text[i] == "(": depth_paren += 1
                            elif text[i] == ")": depth_paren -= 1
                            elif text[i] == ";" and depth_paren == 0: break
                            i += 1
                        stmt_text = text[stmt_start:i].strip()
                        if i < n and text[i] == ";": i += 1
                        body_block = CBlock(statements=[self._parse_single_stmt(stmt_text)]) if stmt_text else CBlock()

                    statements.append(CWhile(condition=cond_node, body=body_block))
                    continue

            # 3. Parse 'for' statement
            if text[i:i+3] == "for" and (i + 3 == n or text[i+3].isspace() or text[i+3] == "("):
                i += 3
                while i < n and text[i].isspace(): i += 1
                if i < n and text[i] == "(":
                    header_start = i + 1
                    depth = 1
                    i += 1
                    while i < n and depth > 0:
                        if text[i] == "(": depth += 1
                        elif text[i] == ")": depth -= 1
                        i += 1
                    header_end = i - 1
                    header_str = text[header_start:header_end].strip()
                    header_parts = header_str.split(";")
                    init_str = header_parts[0].strip() if len(header_parts) > 0 else ""
                    cond_str = header_parts[1].strip() if len(header_parts) > 1 else "1"
                    step_str = header_parts[2].strip() if len(header_parts) > 2 else ""

                    init_stmt = self._parse_single_stmt(init_str) if init_str else None
                    cond_node = self._parse_expr(cond_str) if cond_str else CConst(1)
                    step_stmt = self._parse_single_stmt(step_str) if step_str else None

                    while i < n and text[i].isspace(): i += 1
                    if i < n and text[i] == "{":
                        body_start = i + 1
                        depth = 1
                        i += 1
                        while i < n and depth > 0:
                            if text[i] == "{": depth += 1
                            elif text[i] == "}": depth -= 1
                            i += 1
                        body_end = i - 1
                        body_block = self._parse_block_text(text[body_start:body_end])
                    else:
                        stmt_start = i
                        depth_paren = 0
                        while i < n:
                            if text[i] == "(": depth_paren += 1
                            elif text[i] == ")": depth_paren -= 1
                            elif text[i] == ";" and depth_paren == 0: break
                            i += 1
                        stmt_text = text[stmt_start:i].strip()
                        if i < n and text[i] == ";": i += 1
                        body_block = CBlock(statements=[self._parse_single_stmt(stmt_text)]) if stmt_text else CBlock()

                    if init_stmt and not isinstance(init_stmt, CBlock):
                        statements.append(init_stmt)
                    loop_stmts = list(body_block.statements)
                    if step_stmt and not isinstance(step_stmt, CBlock):
                        loop_stmts.append(step_stmt)
                    statements.append(CWhile(condition=cond_node, body=CBlock(statements=loop_stmts)))
                    continue

            # 4. Parse 'switch' statement
            if text[i:i+6] == "switch" and (i + 6 == n or text[i+6].isspace() or text[i+6] == "("):
                i += 6
                while i < n and text[i].isspace(): i += 1
                if i < n and text[i] == "(":
                    expr_start = i + 1
                    depth = 1
                    i += 1
                    while i < n and depth > 0:
                        if text[i] == "(": depth += 1
                        elif text[i] == ")": depth -= 1
                        i += 1
                    expr_end = i - 1
                    expr_str = text[expr_start:expr_end].strip()
                    switch_expr = self._parse_expr(expr_str)

                    while i < n and text[i].isspace(): i += 1
                    if i < n and text[i] == "{":
                        body_start = i + 1
                        depth = 1
                        i += 1
                        while i < n and depth > 0:
                            if text[i] == "{": depth += 1
                            elif text[i] == "}": depth -= 1
                            i += 1
                        body_end = i - 1
                        switch_body_text = text[body_start:body_end]
                        switch_stmt = self._parse_switch_body(switch_expr, switch_body_text)
                        if switch_stmt:
                            statements.append(switch_stmt)
                        continue

            # 5. Nested block { ... }
            if text[i] == "{":
                block_start = i + 1
                depth = 1
                i += 1
                while i < n and depth > 0:
                    if text[i] == "{":
                        depth += 1
                    elif text[i] == "}":
                        depth -= 1
                    i += 1
                block_end = i - 1
                sub_block = self._parse_block_text(text[block_start:block_end])
                statements.extend(sub_block.statements)
                continue

            # 6. Regular statement ending with ';'
            stmt_start = i
            depth_paren = 0
            while i < n:
                if text[i] == "(":
                    depth_paren += 1
                elif text[i] == ")":
                    depth_paren -= 1
                elif text[i] == ";" and depth_paren == 0:
                    break
                i += 1
            stmt_text = text[stmt_start:i].strip()
            if i < n and text[i] == ";":
                i += 1
            if stmt_text:
                statements.append(self._parse_single_stmt(stmt_text))

        return CBlock(statements=statements)

    def _parse_switch_body(self, switch_expr: CASTNode, body_text: str) -> Optional[CASTNode]:
        """Lowers switch body with case/default into a chained CIfElse AST."""
        pattern = re.compile(r'\b(case\s+([^:]+)|default)\s*:', re.MULTILINE)
        matches = list(pattern.finditer(body_text))
        if not matches:
            return None

        cases: List[Tuple[Optional[CASTNode], CBlock]] = []
        for idx_m, m in enumerate(matches):
            label_kind = m.group(1).strip()
            code_start = m.end()
            code_end = matches[idx_m + 1].start() if idx_m + 1 < len(matches) else len(body_text)
            code_slice = body_text[code_start:code_end].strip()
            code_slice = re.sub(r'\bbreak\s*;', '', code_slice).strip()
            case_block = self._parse_block_text(code_slice)

            if label_kind.startswith("case"):
                case_val_str = m.group(2).strip()
                case_val_node = self._parse_expr(case_val_str)
                cases.append((case_val_node, case_block))
            else:
                cases.append((None, case_block))

        default_block: Optional[CBlock] = None
        case_list = []
        for val_node, blk in cases:
            if val_node is None:
                default_block = blk
            else:
                case_list.append((val_node, blk))

        cur_else: Optional[CBlock] = default_block
        for val_node, blk in reversed(case_list):
            cond = CBinary("==", switch_expr, val_node)
            cur_else = CBlock(statements=[CIfElse(condition=cond, then_block=blk, else_block=cur_else)])

        return cur_else.statements[0] if cur_else and cur_else.statements else None

    def _parse_single_stmt(self, s: str) -> CASTNode:
        """Parses a single semicolon-delimited statement, including compound assignments and ++/--."""
        s = s.strip()
        if not s:
            return CBlock()
        if s.startswith("return"):
            expr_str = s[len("return"):].strip()
            return CReturn(self._parse_expr(expr_str))

        # Check ++ and --
        if s.endswith("++"):
            var_str = s[:-2].strip()
            tgt = self._parse_target(var_str)
            return CAssignment(target=tgt, value=CBinary("+", tgt, CConst(1)))
        elif s.startswith("++"):
            var_str = s[2:].strip()
            tgt = self._parse_target(var_str)
            return CAssignment(target=tgt, value=CBinary("+", tgt, CConst(1)))
        elif s.endswith("--"):
            var_str = s[:-2].strip()
            tgt = self._parse_target(var_str)
            return CAssignment(target=tgt, value=CBinary("-", tgt, CConst(1)))
        elif s.startswith("--"):
            var_str = s[2:].strip()
            tgt = self._parse_target(var_str)
            return CAssignment(target=tgt, value=CBinary("-", tgt, CConst(1)))

        # Check compound assignment operators (+=, -=, *=, /=, %=, &=, |=, ^=, <<=, >>=)
        compound_ops = ["<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="]
        for cop in compound_ops:
            if cop in s:
                parts = s.split(cop, 1)
                lhs_str = parts[0].strip()
                rhs_str = parts[1].strip()
                lhs_tokens = lhs_str.split()
                if len(lhs_tokens) > 1 and not lhs_str.startswith("*") and "->" not in lhs_str and "." not in lhs_str:
                    lhs_str = lhs_tokens[-1]
                lhs_node = self._parse_target(lhs_str)
                rhs_node = self._parse_expr(rhs_str)
                bin_op = cop[:-1]
                return CAssignment(target=lhs_node, value=CBinary(bin_op, lhs_node, rhs_node))

        # Check simple assignment '=' (ensure it's not ==, <=, >=, !=)
        eq_match = re.search(r'(?<![!=<>])=(?!=)', s)
        if eq_match:
            eq_pos = eq_match.start()
            lhs_str = s[:eq_pos].strip()
            rhs_str = s[eq_pos + 1:].strip()
            lhs_tokens = lhs_str.split()
            if len(lhs_tokens) > 1 and not lhs_str.startswith("*") and "->" not in lhs_str and "." not in lhs_str:
                lhs_str = lhs_tokens[-1]
            lhs_node = self._parse_target(lhs_str)
            rhs_node = self._parse_expr(rhs_str)
            return CAssignment(target=lhs_node, value=rhs_node)
        else:
            return self._parse_expr(s)

    def _parse_target(self, target_str: str) -> CASTNode:
        """Parses assignment target (variable, dereference, or field access)."""
        node = self._parse_expr(target_str)
        if isinstance(node, (CVar, CDeref, CFieldAccess)):
            return node
        return CVar(name=target_str)

    def _normalize_c_syntax(self, s: str) -> str:
        """Normalizes C syntax (-> to ., *(cast*)(ptr) to __derefN(ptr), ternaries) for python AST parsing."""
        # 1. Normalize arrow operator -> to dot .
        s = s.replace("->", ".")

        # 2. Normalize *(type*)(expr) casts
        s = re.sub(r"\*\s*\(\s*(?:uint64_t|int64_t|uint64|int64|long\s+long|size_t)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref8(\1)", s)
        s = re.sub(r"\*\s*\(\s*(?:uint32_t|int32_t|uint32|int32|int|unsigned\s+int)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref4(\1)", s)
        s = re.sub(r"\*\s*\(\s*(?:uint16_t|int16_t|uint16|int16|short|unsigned\s+short)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref2(\1)", s)
        s = re.sub(r"\*\s*\(\s*(?:uint8_t|int8_t|uint8|int8|char|unsigned\s+char)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref1(\1)", s)

        # 3. Simple *(expr)
        s = re.sub(r"\*\s*\(([^)]+)\)", r"__deref4(\1)", s)

        # 4. Normalize signed arithmetic right shift: (int64_t)x >> n -> __ashr(x, n)
        s = re.sub(
            r"\(\s*(?:int64_t|int32_t|int16_t|int8_t|int|long\s+long|long)\s*\)\s*([a-zA-Z0-9_]+)\s*>>\s*([^;,\)]+)",
            r"__ashr(\1, \2)",
            s
        )

        # 4b. Normalize unsigned division: (uint64_t)x / y -> __udiv(x, y)
        s = re.sub(
            r"\(\s*(?:uint64_t|uint32_t|uint16_t|uint8_t|unsigned\s+int|unsigned\s+long|unsigned)\s*\)\s*([a-zA-Z0-9_]+)\s*/\s*([^;,\)]+)",
            r"__udiv(\1, \2)",
            s
        )

        # 5. Normalize C ternaries `cond ? expr1 : expr2` -> `((expr1) if (cond) else (expr2))`
        while '?' in s:
            q_pos = s.rfind('?')
            depth = 0
            colon_pos = -1
            for i in range(q_pos + 1, len(s)):
                ch = s[i]
                if ch in '([{': depth += 1
                elif ch in ')]}':
                    if depth > 0: depth -= 1
                    else: break
                elif ch == ':' and depth == 0:
                    colon_pos = i
                    break
            if colon_pos == -1: break
            depth = 0
            cond_start = 0
            for i in range(q_pos - 1, -1, -1):
                ch = s[i]
                if ch in ')]}': depth += 1
                elif ch in '([{':
                    if depth > 0: depth -= 1
                    else:
                        cond_start = i + 1
                        break
                elif depth == 0 and ch in ';,?:':
                    cond_start = i + 1
                    break
            depth = 0
            else_end = len(s)
            for i in range(colon_pos + 1, len(s)):
                ch = s[i]
                if ch in '([{': depth += 1
                elif ch in ')]}':
                    if depth > 0: depth -= 1
                    else:
                        else_end = i
                        break
                elif depth == 0 and ch in ';,?:':
                    else_end = i
                    break
            cond = s[cond_start:q_pos].strip()
            expr1 = s[q_pos + 1:colon_pos].strip()
            expr2 = s[colon_pos + 1:else_end].strip()
            repl = f'(({expr1}) if ({cond}) else ({expr2}))'
            s = s[:cond_start] + repl + s[else_end:]

        # 5. Normalize C logical operators
        s = re.sub(r"&&", " and ", s)
        s = re.sub(r"\|\|", " or ", s)
        s = re.sub(r"!(?!=)", " not ", s)

        return s.strip()

    def _parse_expr(self, expr_str: str) -> CASTNode:
        """Parses an algebraic/pointer expression into AST."""
        expr_str = expr_str.strip()
        norm_str = self._normalize_c_syntax(expr_str)

        try:
            tree = ast.parse(norm_str, mode="eval")
            return self._from_ast(tree.body)
        except Exception:
            # Fallback identifier or integer literal
            if expr_str.startswith("0x") or expr_str.startswith("0X"):
                return CConst(int(expr_str, 16))
            elif expr_str.isdigit():
                return CConst(int(expr_str))
            return CVar(name=expr_str)

    def _from_ast(self, node: ast.AST) -> CASTNode:
        """Transforms Python AST expression node to CASTNode."""
        if isinstance(node, ast.Constant):
            return CConst(val=int(node.value))
        elif isinstance(node, ast.Name):
            return CVar(name=node.id)
        elif isinstance(node, ast.Attribute):
            base = self._from_ast(node.value)
            f_name = node.attr
            offset, size = self.flat_fields.get(f_name, (None, 4))
            return CFieldAccess(base_expr=base, field_name=f_name, offset=offset, size=size)
        elif isinstance(node, ast.IfExp):
            return CTernary(
                condition=self._from_ast(node.test),
                then_expr=self._from_ast(node.body),
                else_expr=self._from_ast(node.orelse),
            )
        elif isinstance(node, ast.BoolOp):
            op_str = "&&" if isinstance(node.op, ast.And) else "||"
            res = self._from_ast(node.values[0])
            for v in node.values[1:]:
                res = CBinary(op=op_str, left=res, right=self._from_ast(v))
            return res
        elif isinstance(node, ast.Call):
            # Function call, synthetic __derefN/__ashr, or Ghidra decompiler macro intrinsic
            fn_name = node.func.id if isinstance(node.func, ast.Name) else ""
            if fn_name == "__ashr" and len(node.args) == 2:
                return CBinary(op=">>>", left=self._from_ast(node.args[0]), right=self._from_ast(node.args[1]))
            if fn_name == "__udiv" and len(node.args) == 2:
                return CBinary(op="udiv", left=self._from_ast(node.args[0]), right=self._from_ast(node.args[1]))
            if fn_name.startswith("__deref") and node.args:
                sz = 4
                if fn_name == "__deref8":
                    sz = 8
                elif fn_name == "__deref2":
                    sz = 2
                elif fn_name == "__deref1":
                    sz = 1
                inner_ptr = self._from_ast(node.args[0])
                return CDeref(ptr_expr=inner_ptr, size=sz)
            upper_fn = fn_name.upper()
            if re.match(r"^(CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|CARRY\d+|SCARRY\d+|SBORROW\d+|ABS|FABS)$", upper_fn):
                return CIntrinsic(name=upper_fn, args=[self._from_ast(a) for a in node.args])
            return CCall(func=fn_name or ast.unparse(node.func), args=[self._from_ast(a) for a in node.args])
        elif isinstance(node, ast.BinOp):
            op_map = {
                ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.FloorDiv: "/",
                ast.Div: "/", ast.Mod: "%", ast.BitAnd: "&", ast.BitOr: "|",
                ast.BitXor: "^", ast.LShift: "<<", ast.RShift: ">>"
            }
            if type(node.op) in op_map:
                op_str = op_map[type(node.op)]
            else:
                op_str = f"unsupported_{type(node.op).__name__}"
            return CBinary(op=op_str, left=self._from_ast(node.left), right=self._from_ast(node.right))
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            cmp_map = {
                ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=",
                ast.Gt: ">", ast.GtE: ">="
            }
            if type(node.ops[0]) in cmp_map:
                op_str = cmp_map[type(node.ops[0])]
            else:
                op_str = f"unsupported_{type(node.ops[0]).__name__}"
            return CBinary(op=op_str, left=self._from_ast(node.left), right=self._from_ast(node.comparators[0]))
        elif isinstance(node, ast.UnaryOp):
            op_map = {ast.Invert: "~", ast.USub: "-", ast.Not: "!"}
            op_str = op_map.get(type(node.op), "~")
            return CUnary(op=op_str, operand=self._from_ast(node.operand))
        return CVar(name=ast.unparse(node))


# ==============================================================================
# C Symbolic Evaluator
# ==============================================================================

class CSymbolicEvaluator:
    """Evaluates CASTNodes symbolically against SymbolicState."""

    _X86_64_REG_MAP: Dict[str, Tuple[int, int]] = {
        "rax": (0, 8), "eax": (0, 4), "ax": (0, 2), "al": (0, 1),
        "rcx": (8, 8), "ecx": (8, 4), "cx": (8, 2), "cl": (8, 1),
        "rdx": (16, 8), "edx": (16, 4), "dx": (16, 2), "dl": (16, 1),
        "rbx": (24, 8), "ebx": (24, 4), "bx": (24, 2), "bl": (24, 1),
        "rsp": (32, 8), "esp": (32, 4), "sp": (32, 8), "spl": (32, 1),
        "rbp": (40, 8), "ebp": (40, 4), "bp": (40, 2), "bpl": (40, 1),
        "rsi": (48, 8), "esi": (48, 4), "si": (48, 2), "sil": (48, 1),
        "rdi": (56, 8), "edi": (56, 4), "di": (56, 2), "dil": (56, 1),
        "r8": (64, 8), "r8d": (64, 4), "r8w": (64, 2), "r8b": (64, 1),
        "r9": (72, 8), "r9d": (72, 4), "r9w": (72, 2), "r9b": (72, 1),
        "r10": (80, 8), "r10d": (80, 4), "r10w": (80, 2), "r10b": (80, 1),
        "r11": (88, 8), "r11d": (88, 4), "r11w": (88, 2), "r11b": (88, 1),
        "r12": (96, 8), "r12d": (96, 4), "r12w": (96, 2), "r12b": (96, 1),
        "r13": (104, 8), "r13d": (104, 4), "r13w": (104, 2), "r13b": (104, 1),
        "r14": (112, 8), "r14d": (112, 4), "r14w": (112, 2), "r14b": (112, 1),
        "r15": (120, 8), "r15d": (120, 4), "r15w": (120, 2), "r15b": (120, 1),
    }

    def __init__(self):
        _require_z3()
        self._unk_counter: int = 0

    @staticmethod
    def _match_widths(a: z3.BitVecRef, b: z3.BitVecRef) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        if a.size() == b.size():
            return a, b
        elif a.size() < b.size():
            return z3.ZeroExt(b.size() - a.size(), a), b
        else:
            return a, z3.ZeroExt(a.size() - b.size(), b)

    def _resolve_var_target(self, state: SymbolicState, name: str) -> Optional[Tuple[int, int]]:
        """Resolves variable name to (reg_offset, size) if it is a register or mapped param."""
        # 1. Direct param_map lookup
        if name in state.param_map:
            name = state.param_map[name]

        low = name.lower()
        # 2. ARM64 general register name regex: x0..x30, w0..w30
        arm_m = re.match(r"^([xw])(\d+)$", low)
        if arm_m:
            kind, idx_str = arm_m.group(1), arm_m.group(2)
            reg_idx = int(idx_str)
            size = 8 if kind == "x" else 4
            return (reg_idx * 8, size)

        # 3. ARM64 FP/SIMD scalar registers: d0..d31, s0..s31, v0..v31
        fp_m = re.match(r"^([dsv])(\d+)$", low)
        if fp_m:
            kind, idx_str = fp_m.group(1), fp_m.group(2)
            reg_idx = int(idx_str)
            if 0 <= reg_idx <= 31:
                size = 16 if kind == "v" else (8 if kind == "d" else 4)
                return (0x400 + reg_idx * 16, size)

        # 4. x86_64 general registers: rax..r15, eax..r15d
        if low in self._X86_64_REG_MAP:
            return self._X86_64_REG_MAP[low]

        # 5. Architectural NZCV flags
        flag_map = {"flag_n": (0x700, 1), "flag_z": (0x701, 1), "flag_c": (0x702, 1), "flag_v": (0x703, 1)}
        if low in flag_map:
            return flag_map[low]

        return None

    def eval_expr(self, state: SymbolicState, node: CASTNode) -> z3.BitVecRef:
        """Evaluates an expression node to a Z3 bitvector."""
        if isinstance(node, CConst):
            return z3.BitVecVal(node.val, node.size * 8)

        elif isinstance(node, CVar):
            name = node.name
            reg_info = self._resolve_var_target(state, name)
            if reg_info is not None:
                reg_off, sz = reg_info
                return state.get_register(reg_off, sz)

            if name not in state.vars:
                prefix_name = f"{state.prefix}{name}" if state.prefix else name
                state.vars[name] = z3.BitVec(prefix_name, node.size * 8)
            return state.vars[name]

        elif isinstance(node, CBinary):
            l = self.eval_expr(state, node.left)
            r = self.eval_expr(state, node.right)
            l, r = self._match_widths(l, r)
            op = node.op
            if op == "+":
                return l + r
            elif op == "-":
                return l - r
            elif op == "*":
                return l * r
            elif op == "/":
                return l / r
            elif op == "udiv":
                return z3.UDiv(l, r)
            elif op == "%":
                return z3.SRem(l, r)
            elif op == "&":
                return l & r
            elif op == "|":
                return l | r
            elif op == "^":
                return l ^ r
            elif op == "<<":
                return l << r
            elif op == ">>":
                return z3.LShR(l, r)
            elif op == ">>>":
                return l >> r
            elif op == "==":
                return z3.If(l == r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "!=":
                return z3.If(l != r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "<":
                return z3.If(l < r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "<=":
                return z3.If(l <= r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == ">":
                return z3.If(l > r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == ">=":
                return z3.If(l >= r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "&&":
                l_bool = (l != 0) if isinstance(l, z3.BitVecRef) else l
                r_bool = (r != 0) if isinstance(r, z3.BitVecRef) else r
                return z3.If(z3.And(l_bool, r_bool), z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "||":
                l_bool = (l != 0) if isinstance(l, z3.BitVecRef) else l
                r_bool = (r != 0) if isinstance(r, z3.BitVecRef) else r
                return z3.If(z3.Or(l_bool, r_bool), z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            state.mark_unknown(f"Unsupported binary/compare operator: {node.op}")
            self._unk_counter += 1
            return z3.BitVec(f"{state.prefix}unk_binop_{self._unk_counter}", max(l.size(), r.size()))

        elif isinstance(node, CTernary):
            cond = self.eval_expr(state, node.condition)
            then_val = self.eval_expr(state, node.then_expr)
            else_val = self.eval_expr(state, node.else_expr)
            then_val, else_val = self._match_widths(then_val, else_val)
            z3_cond = (cond != 0) if isinstance(cond, z3.BitVecRef) else (cond if isinstance(cond, z3.BoolRef) else True)
            return z3.If(z3_cond, then_val, else_val)

        elif isinstance(node, CUnary):
            val = self.eval_expr(state, node.operand)
            if node.op == "~":
                return ~val
            elif node.op == "-":
                return -val
            elif node.op == "!":
                return z3.If(val == 0, z3.BitVecVal(1, val.size()), z3.BitVecVal(0, val.size()))
            state.mark_unknown(f"Unsupported unary operator: {node.op}")
            self._unk_counter += 1
            return z3.BitVec(f"{state.prefix}unk_unop_{self._unk_counter}", val.size())

        elif isinstance(node, CDeref):
            ptr_val = self.eval_expr(state, node.ptr_expr)
            return read_symbolic_memory(state.mem, ptr_val, node.size)

        elif isinstance(node, CFieldAccess):
            if node.offset is None:
                state.mark_unknown(f"Unknown struct field '{node.field_name}': displacement offset is unmapped")
                self._unk_counter += 1
                return z3.BitVec(f"{state.prefix}unk_field_{node.field_name}_{self._unk_counter}", node.size * 8)
            base_ptr = self.eval_expr(state, node.base_expr)
            offset = node.offset
            if base_ptr.size() != 64:
                base_ptr = z3.ZeroExt(64 - base_ptr.size(), base_ptr)
            addr = base_ptr + z3.BitVecVal(offset, 64)
            return read_symbolic_memory(state.mem, addr, node.size)

        elif isinstance(node, CIntrinsic):
            fn = node.name.upper()
            # 1. CONCAT<N><M>(hi, lo)
            concat_m = re.match(r"^CONCAT(\d)(\d)$", fn)
            if concat_m and len(node.args) == 2:
                hi_bits = int(concat_m.group(1)) * 8
                lo_bits = int(concat_m.group(2)) * 8
                hi_bv = self.eval_expr(state, node.args[0])
                lo_bv = self.eval_expr(state, node.args[1])
                if hi_bv.size() > hi_bits:
                    hi_bv = z3.Extract(hi_bits - 1, 0, hi_bv)
                elif hi_bv.size() < hi_bits:
                    hi_bv = z3.ZeroExt(hi_bits - hi_bv.size(), hi_bv)
                if lo_bv.size() > lo_bits:
                    lo_bv = z3.Extract(lo_bits - 1, 0, lo_bv)
                elif lo_bv.size() < lo_bits:
                    lo_bv = z3.ZeroExt(lo_bits - lo_bv.size(), lo_bv)
                return z3.Concat(hi_bv, lo_bv)

            # 2. SUB<N><M>(val, byte_offset)
            sub_m = re.match(r"^SUB(\d)(\d)$", fn)
            if sub_m and len(node.args) == 2:
                out_bits = int(sub_m.group(2)) * 8
                val_bv = self.eval_expr(state, node.args[0])
                byte_off = node.args[1].val if isinstance(node.args[1], CConst) else 0
                low_bit = byte_off * 8
                high_bit = low_bit + out_bits - 1
                if high_bit >= val_bv.size():
                    val_bv = z3.ZeroExt(high_bit + 1 - val_bv.size(), val_bv)
                return z3.Extract(high_bit, low_bit, val_bv)

            # 3. ZEXT<N><M>(val)
            zext_m = re.match(r"^ZEXT(\d)(\d)$", fn)
            if zext_m and len(node.args) == 1:
                in_bits = int(zext_m.group(1)) * 8
                out_bits = int(zext_m.group(2)) * 8
                val_bv = self.eval_expr(state, node.args[0])
                if val_bv.size() > in_bits:
                    val_bv = z3.Extract(in_bits - 1, 0, val_bv)
                elif val_bv.size() < in_bits:
                    val_bv = z3.ZeroExt(in_bits - val_bv.size(), val_bv)
                return z3.ZeroExt(out_bits - in_bits, val_bv) if out_bits > in_bits else val_bv

            # 4. SEXT<N><M>(val)
            sext_m = re.match(r"^SEXT(\d)(\d)$", fn)
            if sext_m and len(node.args) == 1:
                in_bits = int(sext_m.group(1)) * 8
                out_bits = int(sext_m.group(2)) * 8
                val_bv = self.eval_expr(state, node.args[0])
                if val_bv.size() > in_bits:
                    val_bv = z3.Extract(in_bits - 1, 0, val_bv)
                elif val_bv.size() < in_bits:
                    val_bv = z3.SignExt(in_bits - val_bv.size(), val_bv)
                return z3.SignExt(out_bits - in_bits, val_bv) if out_bits > in_bits else val_bv

            # 5. CARRY<N>(a, b), SCARRY<N>(a, b), SBORROW<N>(a, b)
            carry_m = re.match(r"^(CARRY|SCARRY|SBORROW)(\d+)$", fn)
            if carry_m and len(node.args) == 2:
                kind = carry_m.group(1)
                n_bits = int(carry_m.group(2)) * 8
                a_bv = self.eval_expr(state, node.args[0])
                b_bv = self.eval_expr(state, node.args[1])
                if a_bv.size() > n_bits:
                    a_bv = z3.Extract(n_bits - 1, 0, a_bv)
                elif a_bv.size() < n_bits:
                    a_bv = z3.ZeroExt(n_bits - a_bv.size(), a_bv)
                if b_bv.size() > n_bits:
                    b_bv = z3.Extract(n_bits - 1, 0, b_bv)
                elif b_bv.size() < n_bits:
                    b_bv = z3.ZeroExt(n_bits - b_bv.size(), b_bv)
                zero = z3.BitVecVal(0, n_bits)
                if kind == "CARRY":
                    cond = z3.ULT(a_bv + b_bv, a_bv)
                elif kind == "SCARRY":
                    s = a_bv + b_bv
                    cond = z3.Or(z3.And(a_bv >= zero, b_bv >= zero, s < zero), z3.And(a_bv < zero, b_bv < zero, s >= zero))
                else:
                    d = a_bv - b_bv
                    cond = z3.Or(z3.And(a_bv >= zero, b_bv < zero, d < zero), z3.And(a_bv < zero, b_bv >= zero, d >= zero))
                return z3.If(cond, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))

            # 6. ABS / FABS / SQRT / FSQRT
            if fn in ("ABS", "FABS") and len(node.args) == 1:
                v0 = self.eval_expr(state, node.args[0])
                zero = z3.BitVecVal(0, v0.size())
                return z3.If(v0 < zero, -v0, v0)
            if fn in ("SQRT", "FSQRT") and len(node.args) == 1:
                state.mark_unknown(f"Float intrinsic {fn} unsupported in SMT bitvector domain")
                self._unk_counter += 1
                return z3.BitVec(f"{state.prefix}unk_sqrt_{self._unk_counter}", 64)

        elif isinstance(node, CCall):
            state.mark_unknown(f"C function call unsupported: {node.func}()")
            self._unk_counter += 1
            return z3.BitVec(f"{state.prefix}call_{node.func}_{self._unk_counter}", 64)

        self._unk_counter += 1
        state.mark_unknown(f"Unsupported C expression: {type(node).__name__}")
        prefix_unk = f"{state.prefix}unk_{self._unk_counter}" if state.prefix else f"unk_{self._unk_counter}"
        return z3.BitVec(prefix_unk, 64)

    def execute_statement(self, state: SymbolicState, stmt: CASTNode) -> None:
        """Executes an assignment or return statement on state."""
        if isinstance(stmt, CAssignment):
            val = self.eval_expr(state, stmt.value)
            tgt = stmt.target
            if isinstance(tgt, CVar):
                reg_info = self._resolve_var_target(state, tgt.name)
                if reg_info is not None:
                    reg_off, sz = reg_info
                    state.set_register(reg_off, val, sz)
                else:
                    state.vars[tgt.name] = val

            elif isinstance(tgt, CDeref):
                ptr_val = self.eval_expr(state, tgt.ptr_expr)
                state.mem = write_symbolic_memory(state.mem, ptr_val, val, tgt.size)

            elif isinstance(tgt, CFieldAccess):
                if tgt.offset is None:
                    state.mark_unknown(f"Unknown struct field '{tgt.field_name}': displacement offset is unmapped")
                else:
                    base_ptr = self.eval_expr(state, tgt.base_expr)
                    offset = tgt.offset
                    if base_ptr.size() != 64:
                        base_ptr = z3.ZeroExt(64 - base_ptr.size(), base_ptr)
                    addr = base_ptr + z3.BitVecVal(offset, 64)
                    state.mem = write_symbolic_memory(state.mem, addr, val, tgt.size)

        elif isinstance(stmt, CReturn):
            state.return_val = self.eval_expr(state, stmt.value)

        elif isinstance(stmt, CIfElse):
            cond_val = self.eval_expr(state, stmt.condition)
            z3_cond = (cond_val != 0) if isinstance(cond_val, z3.BitVecRef) else (cond_val if isinstance(cond_val, z3.BoolRef) else True)

            state_then = state.clone()
            self.execute_block(state_then, stmt.then_block)

            if stmt.else_block:
                state_else = state.clone()
                self.execute_block(state_else, stmt.else_block)
            else:
                state_else = state.clone()

            merged = merge_symbolic_states(z3_cond, state_then, state_else)
            state.regs = merged.regs
            state.uniques = merged.uniques
            state.vars = merged.vars
            state.mem = merged.mem
            state.return_val = merged.return_val

        elif isinstance(stmt, CWhile):
            cur_state = state
            accumulated_exit_states: List[Tuple[Any, SymbolicState]] = []
            for _ in range(stmt.max_unroll):
                cond_val = self.eval_expr(cur_state, stmt.condition)
                z3_cond = (cond_val != 0) if isinstance(cond_val, z3.BitVecRef) else (cond_val if isinstance(cond_val, z3.BoolRef) else True)
                simp = z3.simplify(z3_cond)
                if z3.is_false(simp):
                    break
                elif z3.is_true(simp):
                    self.execute_block(cur_state, stmt.body)
                else:
                    exit_state = cur_state.clone()
                    not_cond = z3.Not(z3_cond) if isinstance(z3_cond, z3.BoolRef) else (z3_cond == 0)
                    accumulated_exit_states.append((not_cond, exit_state))
                    self.execute_block(cur_state, stmt.body)
                    cur_state.path_constraints.append(z3_cond)

            for exit_cond, exit_st in reversed(accumulated_exit_states):
                cur_state = merge_symbolic_states(exit_cond, exit_st, cur_state)

            state.regs = cur_state.regs
            state.uniques = cur_state.uniques
            state.vars = cur_state.vars
            state.mem = cur_state.mem
            state.return_val = cur_state.return_val

    def execute_block(self, state: SymbolicState, block: CBlock) -> None:
        """Executes a list of C statements."""
        for stmt in block.statements:
            self.execute_statement(state, stmt)


# ==============================================================================
# SMT P-Code Equivalence Verifier Engine
# ==============================================================================

class SMTPcodeVerifier:
    """
    Formal SMT Verifier for P-Code vs Decompiled C Equivalence.
    Queries Z3 for counterexamples: Not(symbolic_pcode == symbolic_c).
    UNSAT = Formally Proven Equivalent.
    SAT = Divergent (Counterexample extracted with model inputs).
    """

    def __init__(self, timeout_ms: int = 10000):
        _require_z3()
        self.timeout_ms = timeout_ms
        self.pcode_sim = PcodeSymbolicSimulator()
        self.c_eval = CSymbolicEvaluator()
        self.lifter = ARM64PcodeLifter()

    def verify_equivalence(
        self,
        pcode_ops: List[PcodeOp],
        c_code_or_ast: Union[str, CASTNode],
        struct_fields: Optional[Dict[str, Tuple[int, int]]] = None,
        param_map: Optional[Dict[str, str]] = None,
        obligation_id: Optional[str] = None,
        check_memory: bool = True,
        tracked_registers: Optional[List[int]] = None,
    ) -> VerificationResult:
        """
        Formally verifies equivalence between a sequence of P-Code ops and a decompiled C snippet.

        Args:
            pcode_ops: Sequence of PcodeOps to verify.
            c_code_or_ast: Decompiled C snippet string or CASTNode.
            struct_fields: Struct field offset mappings for C field resolution: {"m_health": (0x24, 4)}.
            param_map: Variable-to-register parameter mapping: {"player": "x0", "damage": "w2"}.
            obligation_id: Optional obligation ID being verified.
            check_memory: Whether to verify memory state equivalence.
            tracked_registers: Specific register offsets (e.g. [0 for x0]) to verify.
        """
        if tracked_registers is None:
            # Default to return register x0 (offset 0)
            tracked_registers = [0]

        # 1. Parse C code into AST
        parser = CCodeParser()
        if struct_fields:
            for fn, (foff, fsz) in struct_fields.items():
                parser.register_field(fn, foff, fsz)

        if isinstance(c_code_or_ast, str):
            c_ast = parser.parse(c_code_or_ast)
        elif isinstance(c_code_or_ast, CBlock):
            c_ast = c_code_or_ast
        else:
            c_ast = CBlock(statements=[c_code_or_ast])

        # 2. Initialize Shared Base Symbolic State
        base_state = SymbolicState(name_prefix="")
        # Pre-populate common ARM64 parameter registers x0..x7
        for i in range(8):
            base_state.get_register(i * 8, 8)

        # Apply parameter mappings
        if param_map:
            base_state.param_map = dict(param_map)

        # 3. Simulate P-Code on state clone
        pcode_state = base_state.clone()
        self.pcode_sim.execute_block(pcode_state, pcode_ops)

        # 4. Simulate C code on state clone
        c_state = base_state.clone()
        self.c_eval.execute_block(c_state, c_ast)

        # Check soundness: if simulation encountered unsupported/undecidable constructs
        if pcode_state.is_unknown or c_state.is_unknown:
            reason = pcode_state.unknown_reason or c_state.unknown_reason or "Unknown operation encountered"
            c_val_out = c_state.return_val if c_state.return_val is not None else c_state.get_register(0, 8)
            return VerificationResult(
                obligation_id=obligation_id,
                equivalent=False,
                status="UNKNOWN",
                details=f"SMT Equivalence Undecidable: {reason}",
                pcode_out=str(pcode_state.get_register(0, 8)),
                c_out=str(c_val_out),
            )

        # 5. Formulate Equivalence Conditions
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)

        equiv_conditions: List[z3.BoolRef] = []

        # Check return value / tracked registers
        for reg_off in tracked_registers:
            actual_off = reg_off
            if reg_off == 0x100 and 0x400 in pcode_state.regs and 0x100 not in pcode_state.regs:
                actual_off = 0x400
            p_val = pcode_state.get_register(actual_off, 8)
            # If C explicitly returned a value and actual_off is 0 (or single FP return reg 0x400/0x100), compare with C return_val
            if (actual_off == 0 or (len(tracked_registers) == 1 and actual_off in (0x100, 0x400))) and c_state.return_val is not None:
                c_val = c_state.return_val
                if c_val.size() != 64:
                    c_val = z3.ZeroExt(64 - c_val.size(), c_val) if c_val.size() < 64 else z3.Extract(63, 0, c_val)
            else:
                c_val = c_state.get_register(actual_off, 8)
            equiv_conditions.append(p_val == c_val)

        # Check memory equality if requested
        if check_memory:
            equiv_conditions.append(pcode_state.mem == c_state.mem)

        # Formulate query: Not(And(equiv_conditions))
        query = z3.Not(z3.And(*equiv_conditions))
        solver.add(query)

        # 6. Solve with Z3
        check_res = solver.check()
        c_val_out = c_state.return_val if c_state.return_val is not None else c_state.get_register(0, 8)

        if check_res == z3.unsat:
            return VerificationResult(
                obligation_id=obligation_id,
                equivalent=True,
                status="UNSAT",
                details="Formally proven equivalent: no input exists where native P-code diverges from decompiled C.",
                pcode_out=str(pcode_state.get_register(0, 8)),
                c_out=str(c_val_out),
            )

        elif check_res == z3.sat:
            model = solver.model()
            cex: Dict[str, Any] = {}
            for d in model.decls():
                cex[d.name()] = str(model[d])

            return VerificationResult(
                obligation_id=obligation_id,
                equivalent=False,
                status="SAT",
                details="SMT Divergence Detected: Found counterexample inputs producing non-equivalent outputs.",
                counterexample=cex,
                model_inputs=cex,
                pcode_out=str(pcode_state.get_register(0, 8)),
                c_out=str(c_val_out),
            )

        else:
            reason = solver.reason_unknown()
            return VerificationResult(
                obligation_id=obligation_id,
                equivalent=False,
                status="UNKNOWN",
                details=f"SMT Solver returned UNKNOWN (timeout or non-linear constraint: {reason})",
            )

    def verify_byte_sequences(
        self,
        bytes_a: bytes,
        bytes_b: bytes,
        arch: str = "arm64",
        base_addr: int = 0x1000,
        output_regs: Optional[List[str]] = None,
        backend: str = "auto",
        check_memory: bool = True,
    ) -> EquivalenceResult:
        """
        Lifts two machine byte sequences (`bytes_a` and `bytes_b`) via `UnifiedPcodeLifter`
        for `arch` (`"arm64"`, `"x86_64"`, or `"x86"`) and proves or refutes their semantic
        equivalence using Z3 bit-vector SMT solving.
        """
        if not bytes_a or not bytes_b:
            return VerificationResult(
                obligation_id=None,
                equivalent=False,
                status="UNKNOWN",
                details="Empty byte sequence provided for SMT equivalence verification.",
            )

        lifter = UnifiedPcodeLifter(arch=arch, backend=backend)
        ops_a, backend_a = lifter.lift_with_provenance(bytes_a, base_addr=base_addr, backend=backend)
        ops_b, _ = lifter.lift_with_provenance(bytes_b, base_addr=base_addr, backend=backend)

        if not ops_a or not ops_b:
            return VerificationResult(
                obligation_id=None,
                equivalent=False,
                status="UNKNOWN",
                details="Lifter produced no P-code operations for byte sequence.",
                backend_used=backend_a,
            )

        base_state = SymbolicState(name_prefix="")
        num_gprs = 32 if lifter.arch == "arm64" else 16
        for i in range(num_gprs):
            base_state.get_register(i * 8, 8)

        state_a = base_state.clone()
        self.pcode_sim.execute_block(state_a, ops_a)

        state_b = base_state.clone()
        self.pcode_sim.execute_block(state_b, ops_b)

        if state_a.is_unknown or state_b.is_unknown:
            reason = state_a.unknown_reason or state_b.unknown_reason or "Unknown operation encountered"
            return VerificationResult(
                obligation_id=None,
                equivalent=False,
                status="UNKNOWN",
                details=f"SMT Equivalence Undecidable: {reason}",
                pcode_out=str(state_a.get_register(0, 8)),
                c_out=str(state_b.get_register(0, 8)),
                backend_used=backend_a,
            )

        target_regs: List[Tuple[int, int]] = []
        if output_regs:
            for r_spec in output_regs:
                if isinstance(r_spec, int):
                    target_regs.append((r_spec, 8))
                else:
                    resolved = self.c_eval._resolve_var_target(base_state, str(r_spec))
                    if resolved is not None:
                        target_regs.append(resolved)
                    elif str(r_spec).lower() in CANONICAL_REG_OFFSETS:
                        target_regs.append((CANONICAL_REG_OFFSETS[str(r_spec).lower()], 8))
                    else:
                        return VerificationResult(
                            obligation_id=None,
                            equivalent=False,
                            status="UNKNOWN",
                            details=f"Unrecognized output register '{r_spec}' for arch '{arch}'.",
                            backend_used=backend_a,
                        )
        else:
            written_gprs: Set[int] = set()
            for op in ops_a + ops_b:
                if op.output and op.output.space == AddressSpace.REGISTER and isinstance(op.output.offset, int):
                    if 0 <= op.output.offset < 0x100:
                        written_gprs.add(op.output.offset)
            if not written_gprs:
                written_gprs.add(0)
            for off in sorted(written_gprs):
                target_regs.append((off, 8))

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)

        equiv_conditions: List[z3.BoolRef] = []
        for reg_off, reg_sz in target_regs:
            va = state_a.get_register(reg_off, reg_sz)
            vb = state_b.get_register(reg_off, reg_sz)
            equiv_conditions.append(va == vb)

        if check_memory:
            equiv_conditions.append(state_a.mem == state_b.mem)

        solver.add(z3.Not(z3.And(*equiv_conditions)))
        check_res = solver.check()

        primary_off, primary_sz = target_regs[0] if target_regs else (0, 8)
        out_a_str = str(state_a.get_register(primary_off, primary_sz))
        out_b_str = str(state_b.get_register(primary_off, primary_sz))

        if check_res == z3.unsat:
            return VerificationResult(
                obligation_id=None,
                equivalent=True,
                status="UNSAT",
                details=f"Formally proven equivalent across {arch} byte sequences via {backend_a} lifter.",
                pcode_out=out_a_str,
                c_out=out_b_str,
                backend_used=backend_a,
            )
        elif check_res == z3.sat:
            model = solver.model()
            cex: Dict[str, Any] = {d.name(): str(model[d]) for d in model.decls()}
            return VerificationResult(
                obligation_id=None,
                equivalent=False,
                status="SAT",
                details="SMT Divergence Detected: Found counterexample inputs producing non-equivalent outputs.",
                counterexample=cex,
                model_inputs=cex,
                pcode_out=out_a_str,
                c_out=out_b_str,
                backend_used=backend_a,
            )
        else:
            reason = solver.reason_unknown()
            return VerificationResult(
                obligation_id=None,
                equivalent=False,
                status="UNKNOWN",
                details=f"SMT Solver returned UNKNOWN (timeout or non-linear constraint: {reason})",
                backend_used=backend_a,
            )

    def verify_obligation(self, obligation: ProofObligation) -> VerificationResult:
        """
        Formally verifies an EvidenceLedger obligation.
        Supports FUNCTION_HOOK and STRUCT_FIELD_RENAME obligations.
        """
        obl_id = obligation.obligation_id
        obl_type = obligation.obligation_type
        evidence = obligation.evidence

        # 1. FUNCTION_HOOK Equivalence Verification
        if obl_type in (ObligationType.FUNCTION_HOOK, ObligationType.FUNCTION_RENAME):
            decompiled_c = evidence.get("decompiled_c") or evidence.get("c_code")
            machine_bytes = evidence.get("machine_bytes")
            pcode_ops = evidence.get("pcode_ops")
            struct_fields = evidence.get("struct_fields", {})
            param_map = evidence.get("param_map", {})

            if not decompiled_c:
                return VerificationResult(
                    obligation_id=obl_id,
                    equivalent=False,
                    status="ERROR",
                    details="Missing decompiled_c in obligation evidence.",
                )

            # Lift machine bytes to P-code if raw bytes provided
            if pcode_ops is None and machine_bytes is not None:
                if isinstance(machine_bytes, str):
                    machine_bytes = bytes.fromhex(machine_bytes.replace(" ", "").replace("0x", ""))
                base_pc = obligation.target_address or 0x1000
                pcode_ops = self.lifter.lift_block(base_pc, machine_bytes)

            if not pcode_ops:
                return VerificationResult(
                    obligation_id=obl_id,
                    equivalent=False,
                    status="ERROR",
                    details="Missing machine_bytes or pcode_ops in obligation evidence.",
                )

            # Ensure pcode_ops contains PcodeOp instances even if deserialized from JSON
            deserialized_ops: List[PcodeOp] = []
            for item in pcode_ops:
                if isinstance(item, PcodeOp):
                    deserialized_ops.append(item)
                elif isinstance(item, dict):
                    op_name = item.get("opcode", "COPY")
                    opcode = PcodeOpcode[op_name] if isinstance(op_name, str) else PcodeOpcode(op_name)
                    inputs = []
                    for v in item.get("inputs", []):
                        if isinstance(v, Varnode):
                            inputs.append(v)
                        else:
                            sp_val = v.get("space", "ram")
                            space = AddressSpace(sp_val) if isinstance(sp_val, str) else sp_val
                            off = v.get("offset", 0)
                            if isinstance(off, str) and off.startswith("0x"):
                                off = int(off, 16)
                            inputs.append(Varnode(space=space, offset=int(off), size=int(v.get("size", 8))))
                    out = None
                    if item.get("output"):
                        o_val = item["output"]
                        if isinstance(o_val, Varnode):
                            out = o_val
                        else:
                            sp_val = o_val.get("space", "ram")
                            space = AddressSpace(sp_val) if isinstance(sp_val, str) else sp_val
                            off = o_val.get("offset", 0)
                            if isinstance(off, str) and off.startswith("0x"):
                                off = int(off, 16)
                            out = Varnode(space=space, offset=int(off), size=int(o_val.get("size", 8)))
                    pc_val = item.get("pc", 0)
                    if isinstance(pc_val, str) and pc_val.startswith("0x"):
                        pc_val = int(pc_val, 16)
                    deserialized_ops.append(PcodeOp(opcode=opcode, inputs=inputs, output=out, pc=int(pc_val)))
            pcode_ops = deserialized_ops

            # Extract struct field displacements from evidence if present
            if not struct_fields and "field_displacements" in evidence:
                struct_fields = {
                    f["name"]: (f["offset"], f.get("access_size", 4))
                    for f in evidence["field_displacements"]
                    if "name" in f and "offset" in f
                }

            # If param_map not provided, check param_names in evidence
            if not param_map and "param_names" in evidence:
                p_names = evidence["param_names"]
                # Default calling convention: param 0 -> x0, param 1 -> w1 or w2, etc.
                param_map = {name: f"x{i}" for i, name in enumerate(p_names)}

            res = self.verify_equivalence(
                pcode_ops=pcode_ops,
                c_code_or_ast=decompiled_c,
                struct_fields=struct_fields,
                param_map=param_map,
                obligation_id=obl_id,
            )

            # Update obligation status and record check result
            chk = CheckResult(
                check_name="SMTPcodeEquivalenceCheck",
                passed=res.equivalent,
                message=res.details,
                details=res.to_dict(),
            )
            obligation.verification_results.append(chk.to_dict())
            if res.equivalent:
                obligation.status = ObligationStatus.VERIFIED
            else:
                obligation.status = ObligationStatus.REJECTED

            return res

        # 2. STRUCT_FIELD_RENAME Equivalence Verification
        elif obl_type in (ObligationType.STRUCT_FIELD_RENAME, ObligationType.STRUCT_DEFINITION):
            field_name = obligation.proposed_name
            offset = evidence.get("offset")
            access_size = evidence.get("access_size", 4)
            c_expr = evidence.get("c_expression") or f"player->{field_name}"

            if offset is None and "field_displacements" in evidence:
                for f in evidence["field_displacements"]:
                    if f.get("name") == field_name:
                        offset = f.get("offset")
                        access_size = f.get("access_size", 4)
                        break

            machine_bytes = evidence.get("machine_bytes") or evidence.get("instruction_bytes")
            pcode_ops = evidence.get("pcode_ops")

            # Soundness: must lift real instruction bytes or P-code supplied with obligation; if none supplied => UNKNOWN
            if machine_bytes is None and pcode_ops is None:
                res = VerificationResult(
                    obligation_id=obl_id,
                    equivalent=False,
                    status="UNKNOWN",
                    details=f"No real instruction bytes or P-code supplied with struct field obligation for '{field_name}'",
                )
                chk = CheckResult(
                    check_name="SMTStructFieldEquivalenceCheck",
                    passed=False,
                    message=res.details,
                    details=res.to_dict(),
                )
                obligation.verification_results.append(chk.to_dict())
                obligation.status = ObligationStatus.REJECTED
                return res

            if pcode_ops is None and machine_bytes is not None:
                if isinstance(machine_bytes, str):
                    machine_bytes = bytes.fromhex(machine_bytes.replace(" ", "").replace("0x", ""))
                base_pc = obligation.target_address or 0x1000
                pcode_ops = self.lifter.lift_block(base_pc, machine_bytes)

            struct_fields = {field_name: (offset, access_size)} if offset is not None else {}
            param_map = evidence.get("param_map") or {"player": "x0"}
            c_stmt = f"w1 = {c_expr};" if "return" not in c_expr and "=" not in c_expr else c_expr

            res = self.verify_equivalence(
                pcode_ops=pcode_ops,
                c_code_or_ast=c_stmt,
                struct_fields=struct_fields,
                param_map=param_map,
                obligation_id=obl_id,
                tracked_registers=[8],  # register x1
                check_memory=False,
            )

            chk = CheckResult(
                check_name="SMTStructFieldEquivalenceCheck",
                passed=res.equivalent,
                message=res.details,
                details=res.to_dict(),
            )
            obligation.verification_results.append(chk.to_dict())
            if res.equivalent:
                obligation.status = ObligationStatus.VERIFIED
            else:
                obligation.status = ObligationStatus.REJECTED

            return res

        else:
            return VerificationResult(
                obligation_id=obl_id,
                equivalent=False,
                status="UNKNOWN",
                details=f"Obligation type '{obl_type}' is unsupported or unknown for SMT equivalence check.",
            )

    def verify_ledger(
        self,
        ledger: ReconstructionObligationLedger,
        status_filter: Optional[Set[ObligationStatus]] = None,
    ) -> Dict[str, VerificationResult]:
        """Verifies all pending obligations in ledger with SMT evidence."""
        if status_filter is None:
            status_filter = {ObligationStatus.PENDING}

        results: Dict[str, VerificationResult] = {}
        for obl in ledger.list_obligations():
            if obl.status in status_filter:
                res = self.verify_obligation(obl)
                results[obl.obligation_id] = res

        ledger.save()
        return results


# ==============================================================================
# Standalone CLI / Demo
# ==============================================================================

if __name__ == "__main__":
    print("=== SuperGhidra SMT P-Code Equivalence Verifier ===")
    verifier = SMTPcodeVerifier()

    # Demo 1: TakeDamage function:
    # Machine instructions (ARM64):
    #   ldr w1, [x0, #0x24]   (load health)
    #   sub w1, w1, w2        (health - damage)
    #   str w1, [x0, #0x24]   (store health back)
    #   ret
    ops = [
        # u0 = x0 + 0x24
        PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 0x24, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
        # w1 = mem[u0] (4 bytes)
        PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8)], Varnode(AddressSpace.REGISTER, 8, 4)),
        # w1 = w1 - w2 (reg 8 - reg 16)
        PcodeOp(PcodeOpcode.INT_SUB, [Varnode(AddressSpace.REGISTER, 8, 4), Varnode(AddressSpace.REGISTER, 16, 4)], Varnode(AddressSpace.REGISTER, 8, 4)),
        # mem[u0] = w1
        PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.REGISTER, 8, 4)]),
    ]

    c_code_equiv = "player->m_health = player->m_health - damage;"
    fields = {"m_health": (0x24, 4)}
    params = {"player": "x0", "damage": "w2"}

    print("\n1. Verifying provably equivalent TakeDamage hook:")
    res_pass = verifier.verify_equivalence(
        pcode_ops=ops,
        c_code_or_ast=c_code_equiv,
        struct_fields=fields,
        param_map=params,
        check_memory=True,
    )
    print(f"Result: {res_pass.status} (Equivalent: {res_pass.equivalent})")
    print(f"Details: {res_pass.details}")

    print("\n2. Verifying divergent / buggy TakeDamage mutation (+ instead of -):")
    c_code_buggy = "player->m_health = player->m_health + damage;"
    res_fail = verifier.verify_equivalence(
        pcode_ops=ops,
        c_code_or_ast=c_code_buggy,
        struct_fields=fields,
        param_map=params,
        check_memory=True,
    )
    print(f"Result: {res_fail.status} (Equivalent: {res_fail.equivalent})")
    print(f"Details: {res_fail.details}")
    print(f"Counterexample found by Z3: {res_fail.counterexample}")
